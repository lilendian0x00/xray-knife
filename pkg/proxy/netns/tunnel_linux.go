//go:build linux

package netns

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"

	"github.com/lilendian0x00/xray-knife/v9/pkg/core/protocol"

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
	"github.com/vishvananda/netns"
)

const tunInboundTag = "tun-in"

// StartTunnel creates a sing-box instance inside the given named namespace
// with a TUN inbound (capturing all traffic via gvisor stack) and a SOCKS
// outbound pointing at the host proxy through the veth pair.
//
// The TUN device and routing rules are created inside the namespace.
// The entire setup runs on a dedicated, permanently-locked OS thread that
// terminates when its goroutine exits — so the target namespace can never
// leak back into the Go scheduler's thread pool. Sing-box worker threads
// spawned during Start() inherit the target namespace, which is desired.
func StartTunnel(ctx context.Context, nsName string, cfg Config) (protocol.Instance, error) {
	type result struct {
		instance protocol.Instance
		err      error
	}
	ch := make(chan result, 1)

	go func() {
		// Lock this goroutine to its OS thread for life. We deliberately
		// do NOT defer UnlockOSThread: when this goroutine exits, the Go
		// runtime terminates the locked thread, ensuring the polluted-NS
		// thread is never recycled.
		runtime.LockOSThread()

		instance, err := buildAndStartTunnel(ctx, nsName, cfg)
		ch <- result{instance: instance, err: err}
		// goroutine returns → locked thread dies in target NS.
	}()

	r := <-ch
	return r.instance, r.err
}

// buildAndStartTunnel runs entirely on the locked thread inside the target
// namespace. On error it returns with the thread still in target NS — but
// since the calling goroutine terminates immediately, the thread dies too.
func buildAndStartTunnel(ctx context.Context, nsName string, cfg Config) (protocol.Instance, error) {
	nsPath := fmt.Sprintf("/var/run/netns/%s", nsName)
	targetNS, err := netns.GetFromPath(nsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open namespace %q: %w", nsName, err)
	}
	defer targetNS.Close()

	if err := netns.Set(targetNS); err != nil {
		return nil, fmt.Errorf("failed to enter namespace: %w", err)
	}

	tunPrefix, err := netip.ParsePrefix(cfg.TunAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TUN address %q: %w", cfg.TunAddr, err)
	}
	hostPrefix, err := netip.ParsePrefix(cfg.HostIP + "/32")
	if err != nil {
		return nil, fmt.Errorf("failed to parse host IP %q: %w", cfg.HostIP, err)
	}

	// Sniff fields on InboundOptions were removed at sing-box 1.13 final;
	// migrate to a route rule action ("sniff") to stay forward-compatible.
	tunOpts := option.TunInboundOptions{
		InterfaceName: cfg.TunName,
		MTU:           cfg.TunMTU,
		Address:       badoption.Listable[netip.Prefix]{tunPrefix},
		AutoRoute:     true,
		StrictRoute:   true,
		Stack:         "gvisor",
		// Exclude the upstream SOCKS proxy IP from TUN capture so the
		// SOCKS dialer reaches the host via veth, not back through TUN.
		RouteExcludeAddress: badoption.Listable[netip.Prefix]{hostPrefix},
	}

	// Pin SOCKS dialer to the veth interface inside the namespace.
	// Combined with AutoDetectInterface=false below, this prevents
	// sing-box from binding the dialer to the TUN device (which would
	// cause a routing loop).
	socksOpts := option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     cfg.ProxyAddr,
			ServerPort: cfg.ProxyPort,
		},
		Username: cfg.SocksUser,
		Password: cfg.SocksPass,
		DialerOptions: option.DialerOptions{
			BindInterface: cfg.VethNS,
		},
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
				Servers: []option.DNSServerOptions{
					{
						Type: "tcp",
						Tag:  "remote-dns",
						Options: &option.RemoteDNSServerOptions{
							RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
								DialerOptions: option.DialerOptions{
									Detour: "proxy-out",
								},
							},
							DNSServerAddressOptions: option.DNSServerAddressOptions{
								Server: "1.1.1.1",
							},
						},
					},
				},
				Final: "remote-dns",
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
			// Inside a single-purpose netns with one veth + one tun, the
			// kernel default route is via TUN (StrictRoute installs it).
			// AutoDetectInterface would resolve "default interface" to
			// the TUN itself, causing the SOCKS dialer to loop back into
			// gvisor. Pin to the veth instead.
			AutoDetectInterface: false,
			DefaultInterface:    cfg.VethNS,
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
	dns_transport.RegisterTCP(dnsTransportRegistry)

	boxCtx = box.Context(boxCtx, inboundRegistry, outboundRegistry, endpoint.NewRegistry(), dnsTransportRegistry, boxService.NewRegistry())

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
