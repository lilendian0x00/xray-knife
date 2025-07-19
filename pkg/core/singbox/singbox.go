package singbox

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/lilendian0x00/xray-knife/v6/pkg/core/protocol"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
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

	craftOutbound, err := out.CraftOutbound(ctx, c.Log, c.AllowInsecure)
	if err != nil {
		return nil, nil, err
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return craftOutbound.DialContext(ctx, network, M.ParseSocksaddr(addr))
	}

	if craftOutbound.Type() == protocol.WireguardIdentifier {
		dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, lookupErr := net.LookupIP(host)
			if lookupErr != nil {
				return nil, lookupErr
			}
			return craftOutbound.DialContext(ctx, network, M.ParseSocksaddr(ips[0].To4().String()+":"+port))
		}
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       dialFunc,
	}

	return &http.Client{
		Transport: tr,
		Timeout:   maxDelay,
	}, &FakeInstance{}, nil
}

//
//func (c *Core) MakeDial() func(ctx context.Context, v *Instance, dest net.Destination) (net.Conn, error) {
//
//}
