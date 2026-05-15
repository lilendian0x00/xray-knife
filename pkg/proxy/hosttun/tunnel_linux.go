//go:build linux

package hosttun

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lilendian0x00/xray-knife/v10/pkg/core/protocol"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	boxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	dns_transport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/socks"
	sing_tun "github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

const tunInboundTag = "tun-in"

// buildDNSServer mirrors netns/tunnel_linux.go. Kept local so the two
// modes can diverge if needed (e.g. host-tun supporting system DNS).
func buildDNSServer(cfg Config) (option.DNSServerOptions, func(*dns.TransportRegistry), error) {
	dnsAddr := strings.TrimSpace(cfg.DNS)
	if dnsAddr == "" {
		dnsAddr = "1.1.1.1"
	}
	dnsType := strings.ToLower(strings.TrimSpace(cfg.DNSType))
	if dnsType == "" {
		dnsType = "udp"
	}

	remote := option.RemoteDNSServerOptions{
		RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
			DialerOptions: option.DialerOptions{Detour: "proxy-out"},
		},
		DNSServerAddressOptions: option.DNSServerAddressOptions{Server: dnsAddr},
	}

	srv := option.DNSServerOptions{Tag: "remote-dns", Type: dnsType}
	switch dnsType {
	case "udp":
		srv.Options = &remote
		return srv, func(r *dns.TransportRegistry) { dns_transport.RegisterUDP(r) }, nil
	case "tcp":
		srv.Options = &remote
		return srv, func(r *dns.TransportRegistry) { dns_transport.RegisterTCP(r) }, nil
	case "tls":
		srv.Options = &option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: remote}
		return srv, func(r *dns.TransportRegistry) { dns_transport.RegisterTLS(r) }, nil
	case "https":
		path := "/dns-query"
		host := dnsAddr
		if strings.HasPrefix(host, "https://") {
			host = strings.TrimPrefix(host, "https://")
			if i := strings.Index(host, "/"); i >= 0 {
				path = host[i:]
				host = host[:i]
			}
		}
		remote.Server = host
		srv.Options = &option.RemoteHTTPSDNSServerOptions{
			RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: remote},
			Path:                      path,
		}
		return srv, func(r *dns.TransportRegistry) { dns_transport.RegisterHTTPS(r) }, nil
	default:
		return option.DNSServerOptions{}, nil, fmt.Errorf("unsupported dns-type %q (allowed: udp, tcp, tls, https)", dnsType)
	}
}

// Start brings up a sing-box TUN inbound in the root network namespace.
// Routes a default-route worth of traffic into the local SOCKS proxy.
// Returns the running sing-box instance — caller owns its lifecycle.
//
// Caller is responsible for ensuring the exclusion list in cfg.RouteExcludeCIDRs
// contains everything needed to keep the SSH session alive and to
// prevent the upstream proxy dial from looping back through TUN.
func Start(ctx context.Context, cfg Config) (protocol.Instance, error) {
	if cfg.PhysIface == "" {
		return nil, fmt.Errorf("PhysIface is required (set via --bind)")
	}

	tunPrefix, err := netip.ParsePrefix(cfg.TunAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid TUN address %q: %w", cfg.TunAddr, err)
	}

	excludePrefixes := make([]netip.Prefix, 0, len(cfg.RouteExcludeCIDRs))
	for _, c := range cfg.RouteExcludeCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude CIDR %q: %w", c, err)
		}
		excludePrefixes = append(excludePrefixes, p)
	}

	tunOpts := option.TunInboundOptions{
		InterfaceName:       cfg.TunName,
		MTU:                 cfg.TunMTU,
		Address:             badoption.Listable[netip.Prefix]{tunPrefix},
		AutoRoute:           true,
		StrictRoute:         false, // host-tun must let excludes win
		Stack:               "gvisor",
		RouteExcludeAddress: badoption.Listable[netip.Prefix](excludePrefixes),
	}

	socksOpts := option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     cfg.ProxyAddr,
			ServerPort: cfg.ProxyPort,
		},
		Username: cfg.SocksUser,
		Password: cfg.SocksPass,
		// Bind the SOCKS dialer to the physical interface so the dial
		// to 127.0.0.1:PROXY goes through loopback under the right
		// routing context, never through TUN.
		DialerOptions: option.DialerOptions{
			BindInterface: "lo",
		},
	}

	dnsServer, registerDNS, err := buildDNSServer(cfg)
	if err != nil {
		return nil, err
	}

	opts := option.Options{
		Inbounds: []option.Inbound{{
			Type:    "tun",
			Tag:     tunInboundTag,
			Options: &tunOpts,
		}},
		Outbounds: []option.Outbound{{
			Type:    "socks",
			Tag:     "proxy-out",
			Options: &socksOpts,
		}},
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{dnsServer},
				Final:   "remote-dns",
			},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{
				{
					Type: "default",
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Inbound: badoption.Listable[string]{tunInboundTag},
						},
						RuleAction: option.RuleAction{
							Action:       "sniff",
							SniffOptions: option.RouteActionSniff{},
						},
					},
				},
				{
					Type: "default",
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Protocol: badoption.Listable[string]{"dns"},
						},
						RuleAction: option.RuleAction{
							Action: "hijack-dns",
						},
					},
				},
			},
			Final: "proxy-out",
			// Pin "default" to the physical NIC so sing-box's own
			// outbound dials (e.g. the SOCKS connect to 127.0.0.1
			// and the DNS-over-proxy dial) don't try to leave via
			// the TUN they just created.
			AutoDetectInterface: false,
			DefaultInterface:    cfg.PhysIface,
		},
		Log: &option.LogOptions{Disabled: true},
	}

	boxCtx := service.ContextWithDefaultRegistry(ctx)

	inboundRegistry := inbound.NewRegistry()
	sing_tun.RegisterInbound(inboundRegistry)

	outboundRegistry := boxOutbound.NewRegistry()
	socks.RegisterOutbound(outboundRegistry)

	dnsTransportRegistry := dns.NewTransportRegistry()
	registerDNS(dnsTransportRegistry)

	boxCtx = box.Context(boxCtx, inboundRegistry, outboundRegistry, endpoint.NewRegistry(), dnsTransportRegistry, boxService.NewRegistry())

	instance, err := box.New(box.Options{
		Options: opts,
		Context: boxCtx,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create host-tun instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, fmt.Errorf("failed to start host-tun: %w", err)
	}

	return instance, nil
}
