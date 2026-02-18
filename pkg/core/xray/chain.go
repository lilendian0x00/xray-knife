package xray

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/lilendian0x00/xray-knife/v9/pkg/core/protocol"

	"github.com/xtls/xray-core/app/dispatcher"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// MakeChainedInstance builds an xray-core instance with multiple outbounds
// chained together. Hop 0 is the entry point (receives inbound traffic),
// hop N-1 is the exit (connects to the destination). Each intermediate hop
// uses ProxySettings to dial through the next hop.
func (c *Core) MakeChainedInstance(ctx context.Context, hops []protocol.Protocol) (protocol.Instance, error) {
	if len(hops) < 2 {
		return nil, fmt.Errorf("chain requires at least 2 hops, got %d", len(hops))
	}

	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&applog.Config{
				ErrorLogType:  c.LogType,
				AccessLogType: c.LogType,
				ErrorLogLevel: c.LogLevel,
				EnableDnsLog:  false,
			}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
	}

	// Build all outbound handlers for the chain.
	for i, hop := range hops {
		out := hop.(Protocol)
		ob, err := out.BuildOutboundDetourConfig(c.AllowInsecure)
		if err != nil {
			return nil, fmt.Errorf("chain hop %d: failed to build outbound config: %w", i, err)
		}

		ob.Tag = fmt.Sprintf("chain-%d", i)

		// For all hops except the last, set ProxySettings to route through
		// the next hop in the chain.
		if i < len(hops)-1 {
			ob.ProxySettings = &conf.ProxyConfig{
				Tag: fmt.Sprintf("chain-%d", i+1),
			}
		}

		built, err := ob.Build()
		if err != nil {
			return nil, fmt.Errorf("chain hop %d: failed to build outbound handler: %w", i, err)
		}
		clientConfig.Outbound = append(clientConfig.Outbound, built)
	}

	// Add inbound if configured.
	if c.Inbound != nil {
		clientConfig.App = append(clientConfig.App, serial.ToTypedMessage(&proxyman.InboundConfig{}))
		ibc, err := c.Inbound.BuildInboundDetourConfig()
		if err != nil {
			return nil, fmt.Errorf("chain: failed to build inbound config: %w", err)
		}
		ibcBuilt, err := ibc.Build()
		if err != nil {
			return nil, fmt.Errorf("chain: failed to build inbound handler: %w", err)
		}
		clientConfig.Inbound = []*core.InboundHandlerConfig{ibcBuilt}
	}

	server, err := core.New(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("chain: failed to create xray instance: %w", err)
	}
	return server, nil
}

// MakeChainedHttpClient builds a chained xray instance and returns an
// http.Client that routes traffic through the entry outbound (chain-0).
func (c *Core) MakeChainedHttpClient(ctx context.Context, hops []protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	instance, err := c.MakeChainedInstance(ctx, hops)
	if err != nil {
		return nil, nil, err
	}

	xrayInstance := instance.(*core.Instance)

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := xraynet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, xrayInstance, dest)
		},
	}

	return &http.Client{
		Transport: tr,
		Timeout:   maxDelay,
	}, instance, nil
}
