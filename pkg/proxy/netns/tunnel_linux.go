//go:build linux

package netns

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"

	"github.com/lilendian0x00/xray-knife/v7/pkg/core/protocol"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	boxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/socks"
	sing_tun "github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
	"github.com/vishvananda/netns"
)

// StartTunnel creates a sing-box instance inside the given named namespace
// with a TUN inbound (capturing all traffic via gvisor stack) and a SOCKS
// outbound pointing at the host proxy through the veth pair.
//
// The TUN device and routing rules are created inside the namespace.
// After Start(), the gvisor stack keeps running in its own goroutines
// and the calling thread returns to the host namespace.
func StartTunnel(ctx context.Context, nsName string, cfg Config) (protocol.Instance, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNS, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get host namespace: %w", err)
	}
	defer hostNS.Close()

	nsPath := fmt.Sprintf("/var/run/netns/%s", nsName)
	targetNS, err := netns.GetFromPath(nsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open namespace %q: %w", nsName, err)
	}
	defer targetNS.Close()

	if err := netns.Set(targetNS); err != nil {
		return nil, fmt.Errorf("failed to enter namespace: %w", err)
	}
	// Ensure we return to host namespace when done.
	defer netns.Set(hostNS)

	// Build sing-box options.
	tunPrefix, err := netip.ParsePrefix(cfg.TunAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TUN address %q: %w", cfg.TunAddr, err)
	}

	tunOpts := option.TunInboundOptions{
		InterfaceName: cfg.TunName,
		MTU:           cfg.TunMTU,
		Address:       badoption.Listable[netip.Prefix]{tunPrefix},
		AutoRoute:     true,
		StrictRoute:   true,
		Stack:         "gvisor",
		InboundOptions: option.InboundOptions{
			SniffEnabled:             true,
			SniffOverrideDestination: true,
		},
	}

	socksOpts := option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     cfg.ProxyAddr,
			ServerPort: cfg.ProxyPort,
		},
		Username: cfg.SocksUser,
		Password: cfg.SocksPass,
	}

	opts := option.Options{
		Inbounds: []option.Inbound{{
			Type:    "tun",
			Tag:     "tun-in",
			Options: &tunOpts,
		}},
		Outbounds: []option.Outbound{{
			Type:    "socks",
			Tag:     "proxy-out",
			Options: &socksOpts,
		}},
		Route: &option.RouteOptions{
			Final:               "proxy-out",
			AutoDetectInterface: true,
		},
		Log: &option.LogOptions{Disabled: true},
	}

	// Set up registries in the context so box.New() can find
	// the TUN inbound and SOCKS outbound protocol handlers.
	boxCtx := service.ContextWithDefaultRegistry(ctx)

	inboundRegistry := inbound.NewRegistry()
	sing_tun.RegisterInbound(inboundRegistry)

	outboundRegistry := boxOutbound.NewRegistry()
	socks.RegisterOutbound(outboundRegistry)

	boxCtx = box.Context(boxCtx, inboundRegistry, outboundRegistry, endpoint.NewRegistry(), dns.NewTransportRegistry(), boxService.NewRegistry())

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
