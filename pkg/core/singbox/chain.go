package singbox

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/sagernet/sing-box/option"
)

// dialerOptions returns the DialerOptions embedded in the outbound's
// concrete options type.
func dialerOptions(outbound *option.Outbound) (*option.DialerOptions, error) {
	switch o := outbound.Options.(type) {
	case *option.VLESSOutboundOptions:
		return &o.DialerOptions, nil
	case *option.VMessOutboundOptions:
		return &o.DialerOptions, nil
	case *option.TrojanOutboundOptions:
		return &o.DialerOptions, nil
	case *option.ShadowsocksOutboundOptions:
		return &o.DialerOptions, nil
	case *option.Hysteria2OutboundOptions:
		return &o.DialerOptions, nil
	case *option.WireGuardEndpointOptions:
		return &o.DialerOptions, nil
	case *option.SOCKSOutboundOptions:
		return &o.DialerOptions, nil
	case *option.TUICOutboundOptions:
		return &o.DialerOptions, nil
	case *option.HysteriaOutboundOptions:
		return &o.DialerOptions, nil
	case *option.AnyTLSOutboundOptions:
		return &o.DialerOptions, nil
	case *option.SSHOutboundOptions:
		return &o.DialerOptions, nil
	case *option.HTTPOutboundOptions:
		return &o.DialerOptions, nil
	default:
		return nil, fmt.Errorf("unsupported outbound options type: %T", outbound.Options)
	}
}

// setDetour makes the outbound dial through the outbound tagged detourTag.
func setDetour(outbound *option.Outbound, detourTag string) error {
	d, err := dialerOptions(outbound)
	if err != nil {
		return fmt.Errorf("cannot set detour: %w", err)
	}
	d.Detour = detourTag
	return nil
}

func chainTag(i int) string { return fmt.Sprintf("chain-%d", i) }

// craftChain crafts the hops of a chain. Hop 0 is the entry, dialed directly
// from this machine; every later hop is dialed through the one before it, so
// hop N-1 is the exit that reaches the destination. The returned tag is the
// exit's, which is where traffic must be routed.
func (c *Core) craftChain(hops []protocol.Protocol) ([]option.Outbound, string, error) {
	if len(hops) < 2 {
		return nil, "", fmt.Errorf("chain requires at least 2 hops, got %d", len(hops))
	}

	outbounds := make([]option.Outbound, 0, len(hops))
	for i, hop := range hops {
		out, err := c.craftOutbound(hop, chainTag(i), i == 0)
		if err != nil {
			return nil, "", fmt.Errorf("chain hop %d: failed to craft outbound options: %w", i, err)
		}
		if i > 0 {
			if err := setDetour(&out, chainTag(i-1)); err != nil {
				return nil, "", fmt.Errorf("chain hop %d: %w", i, err)
			}
		}
		outbounds = append(outbounds, out)
	}
	return outbounds, chainTag(len(hops) - 1), nil
}

// MakeChainedInstance builds a sing-box instance with multiple outbounds
// chained together via Detour. Hop 0 is the entry point, hop N-1 is the exit.
func (c *Core) MakeChainedInstance(ctx context.Context, hops []protocol.Protocol) (protocol.Instance, error) {
	outbounds, exitTag, err := c.craftChain(hops)
	if err != nil {
		return nil, err
	}

	opts := option.Options{
		Route: &option.RouteOptions{
			Final: exitTag,
		},
	}
	placeOutbounds(&opts, outbounds...)
	if err := c.withInbound(&opts); err != nil {
		return nil, err
	}

	singboxInstance, err := c.newBox(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("chain: failed to create sing-box instance: %w", err)
	}

	return singboxInstance, nil
}

// MakeChainedHttpClient builds a chained sing-box instance and returns an
// http.Client that routes traffic through the whole chain (it dials the exit
// hop, which reaches its server through the hops before it).
func (c *Core) MakeChainedHttpClient(ctx context.Context, hops []protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	outbounds, exitTag, err := c.craftChain(hops)
	if err != nil {
		return nil, nil, err
	}

	opts := option.Options{
		Route: &option.RouteOptions{
			Final: exitTag,
		},
	}
	placeOutbounds(&opts, outbounds...)
	if len(opts.Endpoints) > 0 {
		preferIPv4(&opts)
	}

	client, instance, err := c.startHttpClient(ctx, opts, exitTag, maxDelay)
	if err != nil {
		return nil, nil, fmt.Errorf("chain: %w", err)
	}
	return client, instance, nil
}
