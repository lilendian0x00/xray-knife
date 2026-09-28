package xray

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

func chainTag(i int) string { return fmt.Sprintf("chain-%d", i) }

// MakeChainedInstance builds an xray-core instance with multiple outbounds
// chained together. Hop 0 is the ENTRY: the only hop dialed directly from
// this machine (with BindInterface and Fragment applied). Hop N-1 is the
// EXIT: it connects to the destination and receives the inbound traffic.
// Each hop i > 0 reaches its own server through hop i-1.
func (c *Core) MakeChainedInstance(ctx context.Context, hops []protocol.Protocol) (protocol.Instance, error) {
	if len(hops) < 2 {
		return nil, fmt.Errorf("chain requires at least 2 hops, got %d", len(hops))
	}
	if err := c.buildable(); err != nil {
		return nil, err
	}

	built := make([]*conf.OutboundDetourConfig, len(hops))
	for i, hop := range hops {
		out, err := asProtocol(hop)
		if err != nil {
			return nil, fmt.Errorf("chain hop %d: %w", i, err)
		}
		c.warnInsecure(out)
		ob, err := out.BuildOutboundDetourConfig(c.AllowInsecure)
		if err != nil {
			return nil, fmt.Errorf("chain hop %d: failed to build outbound config: %w", i, err)
		}
		ob.Tag = chainTag(i)
		if i > 0 {
			// Dial through the previous hop at the socket level, so this
			// hop keeps its own transport and TLS/REALITY (see chainThrough).
			chainThrough(ob, chainTag(i-1))
		}
		built[i] = ob
	}

	if err := c.prepareEntry(built[0], hops[0].ConvertToGeneralConfig().Address); err != nil {
		return nil, fmt.Errorf("chain hop 0: %w", err)
	}

	// xray's default route is the first outbound, and traffic must enter
	// at the exit hop, so list the hops from exit to entry.
	ordered := make([]*conf.OutboundDetourConfig, 0, len(built))
	for i := len(built) - 1; i >= 0; i-- {
		ordered = append(ordered, built[i])
	}

	server, err := c.newInstance(ordered)
	if err != nil {
		return nil, fmt.Errorf("chain: failed to create xray instance: %w", err)
	}
	return server, nil
}

// MakeChainedHttpClient builds a chained xray instance and returns an
// http.Client whose requests travel entry -> ... -> exit.
func (c *Core) MakeChainedHttpClient(ctx context.Context, hops []protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	instance, err := c.MakeChainedInstance(ctx, hops)
	if err != nil {
		return nil, nil, err
	}
	return httpClientFor(instance.(*core.Instance), maxDelay), instance, nil
}
