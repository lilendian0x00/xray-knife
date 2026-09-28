//go:build linux

package netns

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
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

// buildDNSServer constructs the sing-box DNSServerOptions for the configured
// resolver and transport. It also returns a function that registers the
// matching transport(s) on a TransportRegistry, since each transport type
// needs its own Register call.
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
		// Strip optional leading scheme so cfg.DNS can be either
		// "1.1.1.1" or "https://1.1.1.1/dns-query".
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

const tunInboundTag = "tun-in"

// StartTunnel starts a sing-box instance whose TUN inbound lives inside
// the named namespace and whose SOCKS outbound dials the proxy listener
// on the host loopback.
//
// The instance itself runs in the host namespace: sing-tun enters the
// target namespace (on a throwaway locked thread) only to create the
// device and to install and later remove its routes and rules. That keeps
// three things right that running the whole instance "inside" the
// namespace could not guarantee, because Go spawns new worker threads
// from its template thread in the host namespace:
//   - the SOCKS dial is a plain host-loopback connection,
//   - teardown deletes the rules inside the namespace, not the host's
//     (sing-tun's cleanup removes every rule in its priority block),
//   - systemd-resolved on the host is never pointed at the namespace's
//     TUN (sing-tun skips resolvectl when a netns is set).
func StartTunnel(ctx context.Context, nsName string, cfg Config) (protocol.Instance, error) {
	if err := ValidateName(nsName); err != nil {
		return nil, err
	}
	tunPrefix, err := netip.ParsePrefix(cfg.TunAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TUN address %q: %w", cfg.TunAddr, err)
	}

	// Sniff fields on InboundOptions were removed at sing-box 1.13 final;
	// migrate to a route rule action ("sniff") to stay forward-compatible.
	tunOpts := option.TunInboundOptions{
		InterfaceName: cfg.TunName,
		NetNs:         filepath.Join(netnsRunDir, nsName),
		MTU:           cfg.TunMTU,
		Address:       badoption.Listable[netip.Prefix]{tunPrefix},
		AutoRoute:     true,
		// StrictRoute also installs an IPv6 "unreachable" rule (the TUN
		// has no IPv6 address), so nothing in the namespace can bypass
		// the tunnel.
		StrictRoute: true,
		Stack:       "gvisor",
	}

	socksOpts := option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     cfg.ProxyAddr,
			ServerPort: cfg.ProxyPort,
		},
		Username: cfg.SocksUser,
		Password: cfg.SocksPass,
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
				// Sniff all TUN traffic so we can pick up SNI/host etc.
				// Replaces the deprecated InboundOptions.Sniff fields.
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
				// Hijack DNS so queries go through the configured DNS
				// transport (over proxy-out) instead of leaking via TUN.
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
			// The instance dials from the host namespace, where the TUN
			// does not exist; plain default routing reaches the listener.
			AutoDetectInterface: false,
		},
		Log: &option.LogOptions{Disabled: true},
	}

	// Set up registries in the context so box.New() can find the TUN
	// inbound and SOCKS outbound protocol handlers.
	boxCtx := service.ContextWithDefaultRegistry(ctx)

	inboundRegistry := inbound.NewRegistry()
	sing_tun.RegisterInbound(inboundRegistry)

	outboundRegistry := boxOutbound.NewRegistry()
	socks.RegisterOutbound(outboundRegistry)

	dnsTransportRegistry := dns.NewTransportRegistry()
	registerDNS(dnsTransportRegistry)

	boxCtx = box.Context(boxCtx, inboundRegistry, outboundRegistry, endpoint.NewRegistry(), dnsTransportRegistry, boxService.NewRegistry(), certificate.NewRegistry())

	instance, err := box.New(box.Options{
		Options: opts,
		Context: boxCtx,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, fmt.Errorf("failed to start tunnel: %w", err)
	}

	return instance, nil
}
