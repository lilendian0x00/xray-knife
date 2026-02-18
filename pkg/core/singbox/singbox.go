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
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type Core struct {
	Inbound *option.Inbound

	// Log
	Verbose bool
	Log     logger.ContextLogger

	AllowInsecure bool
}

func (c *Core) Name() string {
	return "singbox"
}

type ServiceOption = func(c *Core)

func WithInbound(inbound protocol.Protocol) ServiceOption {
	return func(c *Core) {
		in := inbound.(Protocol)
		c.Inbound = in.CraftInboundOptions()
	}
}

func WithCustomLogLevel(logOptions option.LogOptions) ServiceOption {
	return func(c *Core) {
		l, _ := log.New(log.Options{
			Options: logOptions,
		})
		c.Log = l.Logger()
	}
}

func NewSingboxService(verbose bool, allowInsecure bool, opts ...ServiceOption) *Core {
	s := &Core{
		Inbound:       nil,
		Verbose:       verbose,
		AllowInsecure: allowInsecure,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.Log == nil {
		l, _ := log.New(log.Options{
			Options: option.LogOptions{Disabled: true},
		})
		s.Log = l.Logger()
	}

	if verbose {
		l, _ := log.New(log.Options{
			Options: option.LogOptions{
				Disabled: false,
				Level:    "trace",
			},
		})
		s.Log = l.Logger()
	}

	return s
}

type FakeInstance struct {
}

func (f *FakeInstance) Start() error {
	return nil
}

func (f *FakeInstance) Close() error {
	return nil
}

func (c *Core) SetInbound(inbound protocol.Protocol) error {
	i := inbound.(Protocol)
	c.Inbound = i.CraftInboundOptions()
	return nil
}

func (c *Core) MakeInstance(ctx context.Context, outbound protocol.Protocol) (protocol.Instance, error) {
	out := outbound.(Protocol)

	outOpts, err := out.CraftOutboundOptions(c.AllowInsecure)
	if err != nil {
		return nil, err
	}

	opts := option.Options{
		Inbounds: []option.Inbound{},
		Outbounds: []option.Outbound{
			*outOpts,
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
		return nil, err
	}

	return singboxInstance, nil
}

func (c *Core) MakeHttpClient(ctx context.Context, outbound protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	out := outbound.(Protocol)

	outOpts, err := out.CraftOutboundOptions(c.AllowInsecure)
	if err != nil {
		return nil, nil, err
	}
	outboundTag := "http_client_outbound"
	outOpts.Tag = outboundTag

	opts := option.Options{
		Inbounds: []option.Inbound{},
		Outbounds: []option.Outbound{
			*outOpts,
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
		return nil, nil, err
	}

	if err := instance.Start(); err != nil {
		return nil, nil, err
	}

	// Retrieve the outbound adapter from the router
	outboundAdapter, ok := instance.Outbound().Outbound(outboundTag)
	if !ok {
		var available []string
		for _, o := range instance.Outbound().Outbounds() {
			available = append(available, fmt.Sprintf("%s(%s)", o.Tag(), o.Type()))
		}
		instance.Close()
		return nil, nil, fmt.Errorf("outbound adapter not found for tag: %s. Available: %v", outboundTag, available)
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return outboundAdapter.DialContext(ctx, network, M.ParseSocksaddr(addr))
	}

	if out.Name() == protocol.WireguardIdentifier {
		dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, lookupErr := net.LookupIP(host)
			if lookupErr != nil {
				return nil, lookupErr
			}
			return outboundAdapter.DialContext(ctx, network, M.ParseSocksaddr(ips[0].To4().String()+":"+port))
		}
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       dialFunc,
	}

	return &http.Client{
		Transport: tr,
		Timeout:   maxDelay,
	}, instance, nil
}

//
//func (c *Core) MakeDial() func(ctx context.Context, v *Instance, dest net.Destination) (net.Conn, error) {
//
//}
