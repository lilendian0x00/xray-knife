package singbox

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/lilendian0x00/xray-knife/v9/pkg/core/protocol"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	boxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/wireguard"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// setDetour sets the Detour field on the outbound's concrete options type.
// All supported outbound option types embed DialerOptions which contains Detour.
func setDetour(outbound *option.Outbound, detourTag string) error {
	switch o := outbound.Options.(type) {
	case *option.VLESSOutboundOptions:
		o.Detour = detourTag
	case *option.VMessOutboundOptions:
		o.Detour = detourTag
	case *option.TrojanOutboundOptions:
		o.Detour = detourTag
	case *option.ShadowsocksOutboundOptions:
		o.Detour = detourTag
	case *option.Hysteria2OutboundOptions:
		o.Detour = detourTag
	case *option.LegacyWireGuardOutboundOptions:
		o.Detour = detourTag
	case *option.SOCKSOutboundOptions:
		o.Detour = detourTag
	default:
		return fmt.Errorf("unsupported outbound options type for detour: %T", outbound.Options)
	}
	return nil
}

// MakeChainedInstance builds a sing-box instance with multiple outbounds
// chained together via Detour. Hop 0 is the entry point, hop N-1 is the exit.
func (c *Core) MakeChainedInstance(ctx context.Context, hops []protocol.Protocol) (protocol.Instance, error) {
	if len(hops) < 2 {
		return nil, fmt.Errorf("chain requires at least 2 hops, got %d", len(hops))
	}

	var outbounds []option.Outbound

	for i, hop := range hops {
		out := hop.(Protocol)
		outOpts, err := out.CraftOutboundOptions(c.AllowInsecure)
		if err != nil {
			return nil, fmt.Errorf("chain hop %d: failed to craft outbound options: %w", i, err)
		}

		outOpts.Tag = fmt.Sprintf("chain-%d", i)

		// For all hops except the last, set the Detour to route through
		// the next hop in the chain.
		if i < len(hops)-1 {
			if err := setDetour(outOpts, fmt.Sprintf("chain-%d", i+1)); err != nil {
				return nil, fmt.Errorf("chain hop %d: %w", i, err)
			}
		}

		outbounds = append(outbounds, *outOpts)
	}

	opts := option.Options{
		Inbounds:  []option.Inbound{},
		Outbounds: outbounds,
		Route: &option.RouteOptions{
			Final: "chain-0",
		},
		Log: &option.LogOptions{
			Disabled: true,
		},
	}

	if c.Verbose {
		opts.Log = &option.LogOptions{
			Disabled: false,
			Level:    "trace",
		}
	}

	if c.Inbound != nil {
		opts.Inbounds = append(opts.Inbounds, *c.Inbound)
	}

	singboxInstance, err := box.New(box.Options{
		Options: opts,
		Context: ctx,
	})
	if err != nil {
		return nil, fmt.Errorf("chain: failed to create sing-box instance: %w", err)
	}

	return singboxInstance, nil
}

// MakeChainedHttpClient builds a chained sing-box instance and returns an
// http.Client that routes traffic through the entry outbound (chain-0).
func (c *Core) MakeChainedHttpClient(ctx context.Context, hops []protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	if len(hops) < 2 {
		return nil, nil, fmt.Errorf("chain requires at least 2 hops, got %d", len(hops))
	}

	var outbounds []option.Outbound

	for i, hop := range hops {
		out := hop.(Protocol)
		outOpts, err := out.CraftOutboundOptions(c.AllowInsecure)
		if err != nil {
			return nil, nil, fmt.Errorf("chain hop %d: failed to craft outbound options: %w", i, err)
		}

		outOpts.Tag = fmt.Sprintf("chain-%d", i)

		if i < len(hops)-1 {
			if err := setDetour(outOpts, fmt.Sprintf("chain-%d", i+1)); err != nil {
				return nil, nil, fmt.Errorf("chain hop %d: %w", i, err)
			}
		}

		outbounds = append(outbounds, *outOpts)
	}

	opts := option.Options{
		Inbounds:  []option.Inbound{},
		Outbounds: outbounds,
		Route: &option.RouteOptions{
			Final: "chain-0",
		},
		Log: &option.LogOptions{
			Disabled: true,
		},
	}
	if c.Verbose {
		opts.Log = &option.LogOptions{
			Disabled: false,
			Level:    "trace",
		}
	}

	ctx = service.ContextWithDefaultRegistry(ctx)
	outboundRegistry := boxOutbound.NewRegistry()
	hysteria2.RegisterOutbound(outboundRegistry)
	shadowsocks.RegisterOutbound(outboundRegistry)
	socks.RegisterOutbound(outboundRegistry)
	trojan.RegisterOutbound(outboundRegistry)
	vless.RegisterOutbound(outboundRegistry)
	vmess.RegisterOutbound(outboundRegistry)
	wireguard.RegisterOutbound(outboundRegistry)

	ctx = box.Context(ctx, inbound.NewRegistry(), outboundRegistry, endpoint.NewRegistry(), dns.NewTransportRegistry(), boxService.NewRegistry())

	instance, err := box.New(box.Options{
		Options: opts,
		Context: ctx,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("chain: failed to create sing-box instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, nil, fmt.Errorf("chain: failed to start sing-box instance: %w", err)
	}

	// Retrieve the entry outbound adapter (chain-0).
	outboundAdapter, ok := instance.Outbound().Outbound("chain-0")
	if !ok {
		instance.Close()
		return nil, nil, fmt.Errorf("chain: outbound adapter not found for tag chain-0")
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return outboundAdapter.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
	}

	return &http.Client{
		Transport: tr,
		Timeout:   maxDelay,
	}, instance, nil
}
