//go:build linux

package hosttun

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net/netip"
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
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/socks"
	sing_tun "github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
	"github.com/vishvananda/netlink"
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
//
// Start fills in the iproute2 table, rule index and bypass priority it
// picked, so the caller can record them for crash recovery.
func Start(ctx context.Context, cfgp *Config) (protocol.Instance, error) {
	cfg := *cfgp
	if cfg.PhysIface == "" {
		return nil, fmt.Errorf("PhysIface is required (set via --bind)")
	}

	tunPrefix, err := netip.ParsePrefix(cfg.TunAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid TUN address %q: %w", cfg.TunAddr, err)
	}
	if !tunPrefix.Addr().Is4() {
		return nil, fmt.Errorf("TUN address %q must be IPv4 (use the IPv6 address option for IPv6)", cfg.TunAddr)
	}
	tunAddrs := badoption.Listable[netip.Prefix]{tunPrefix}
	if cfg.TunAddr6 != "" {
		tunPrefix6, err := netip.ParsePrefix(cfg.TunAddr6)
		if err != nil {
			return nil, fmt.Errorf("invalid TUN IPv6 address %q: %w", cfg.TunAddr6, err)
		}
		if !tunPrefix6.Addr().Is6() || tunPrefix6.Addr().Is4In6() {
			return nil, fmt.Errorf("TUN IPv6 address %q is not an IPv6 prefix", cfg.TunAddr6)
		}
		// Giving the TUN an IPv6 address is what makes sing-tun install
		// the IPv6 default route and rules; without it IPv6 egress
		// bypasses the tunnel entirely.
		tunAddrs = append(tunAddrs, tunPrefix6)
	}

	tableIndex, ruleIndex := cfg.RouteTableIndex, cfg.RouteRuleIndex
	if tableIndex == 0 || ruleIndex == 0 {
		t, start, err := pickRouteIndices()
		if err != nil {
			return nil, fmt.Errorf("pick iproute2 table/rule index: %w", err)
		}
		if tableIndex == 0 {
			tableIndex = t
		}
		if ruleIndex == 0 {
			cfgp.BypassPriority = start
			ruleIndex = start + 1
		}
	}
	if cfgp.BypassPriority == 0 {
		cfgp.BypassPriority = ruleIndex - 1
	}
	cfgp.RouteTableIndex, cfgp.RouteRuleIndex = tableIndex, ruleIndex

	excludePrefixes := make([]netip.Prefix, 0, len(cfg.RouteExcludeCIDRs))
	for _, c := range cfg.RouteExcludeCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude CIDR %q: %w", c, err)
		}
		excludePrefixes = append(excludePrefixes, p)
	}

	tunOpts := option.TunInboundOptions{
		InterfaceName: cfg.TunName,
		MTU:           cfg.TunMTU,
		Address:       tunAddrs,
		AutoRoute:     true,
		// Strict route adds an "unreachable" rule for an address family
		// the TUN has no address in, at the start of sing-tun's block —
		// ahead of the route excludes, which are routes, not rules. With
		// the kill switch that turns "no IPv6 capture" into "no IPv6";
		// the caller keeps IPv6 SSH peers and excluded ranges reachable
		// with Bypass rules one priority earlier.
		StrictRoute:         cfg.StrictRoute,
		Stack:               "gvisor",
		RouteExcludeAddress: badoption.Listable[netip.Prefix](excludePrefixes),
		IPRoute2TableIndex:  tableIndex,
		IPRoute2RuleIndex:   ruleIndex,
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
			AbstractDialerOptions: option.AbstractDialerOptions{
				BindInterface: "lo",
			},
		},
	}

	dnsServer, registerDNS, err := buildDNSServer(cfg)
	if err != nil {
		return nil, err
	}

	outbounds := []option.Outbound{{
		Type:    "socks",
		Tag:     "proxy-out",
		Options: &socksOpts,
	}}
	var directRule []option.Rule
	if len(cfg.DirectCIDRs) > 0 {
		// Addresses carved out of the excludes so DNS to them gets
		// hijacked (e.g. the LAN router): everything that is not DNS
		// leaves on the uplink as before.
		outbounds = append(outbounds, option.Outbound{
			Type: "direct",
			Tag:  "direct-out",
			Options: &option.DirectOutboundOptions{
				DialerOptions: option.DialerOptions{
					AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: cfg.PhysIface},
				},
			},
		})
		directRule = []option.Rule{{
			Type: "default",
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					IPCIDR: badoption.Listable[string](cfg.DirectCIDRs),
				},
				RuleAction: option.RuleAction{
					Action:       "route",
					RouteOptions: option.RouteActionOptions{Outbound: "direct-out"},
				},
			},
		}}
	}

	opts := option.Options{
		Inbounds: []option.Inbound{{
			Type:    "tun",
			Tag:     tunInboundTag,
			Options: &tunOpts,
		}},
		Outbounds: outbounds,
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{dnsServer},
				Final:   "remote-dns",
			},
		},
		Route: &option.RouteOptions{
			Rules: append([]option.Rule{
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
			}, directRule...),
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
	direct.RegisterOutbound(outboundRegistry)

	dnsTransportRegistry := dns.NewTransportRegistry()
	registerDNS(dnsTransportRegistry)

	boxCtx = box.Context(boxCtx, inboundRegistry, outboundRegistry, endpoint.NewRegistry(), dnsTransportRegistry, boxService.NewRegistry(), certificate.NewRegistry())

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

// pickRouteIndices returns an iproute2 table index and a first rule
// priority that nothing on the host uses yet, so neither our rules nor
// our teardown can collide with another TUN (sing-box, mihomo, a second
// xray-knife) that sticks to sing-box's 2022/9000 defaults.
func pickRouteIndices() (table, rule int, err error) {
	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return 0, 0, fmt.Errorf("list rules: %w", err)
	}
	usedPrio := make(map[int]bool, len(rules))
	usedTable := make(map[int]bool, len(rules))
	for _, r := range rules {
		usedPrio[r.Priority] = true
		usedTable[r.Table] = true
	}
	rule = freeRuleBlock(usedPrio)
	if rule == 0 {
		return 0, 0, errors.New("no free block of ip rule priorities between 9100 and 32000")
	}
	for i := 0; i < 128; i++ {
		t := 20000 + mathrand.IntN(40000)
		if usedTable[t] {
			continue
		}
		routes, rErr := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: t}, netlink.RT_FILTER_TABLE)
		if rErr == nil && len(routes) == 0 {
			return t, rule, nil
		}
	}
	return 0, 0, errors.New("no unused iproute2 table index found")
}
