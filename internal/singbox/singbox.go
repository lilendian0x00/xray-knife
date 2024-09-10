package singbox

import (
	"context"
	"fmt"
	"github.com/lilendian0x00/xray-knife/internal/protocol"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"net/http"
	"time"
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

func (c *Core) MakeInstance(outbound protocol.Protocol) (protocol.Instance, error) {
	out := outbound.(Protocol)

	outOpts, err := out.CraftOutboundOptions()
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
		Context: context.Background(),
	})

	if err != nil {
		return nil, err
	}

	return singboxInstance, nil
}

func (c *Core) MakeHttpClient(outbound protocol.Protocol) (*http.Client, protocol.Instance, error) {
	out := outbound.(Protocol)

	craftOutbound, err := out.CraftOutbound(context.Background(), c.Log)
	if err != nil {
		fmt.Println(err.Error())
		return nil, nil, err
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return craftOutbound.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
	}

	return &http.Client{
		Transport: tr,
		Timeout:   time.Duration(5) * time.Second,
	}, &FakeInstance{}, nil
}

//
//func (c *Core) MakeDial() func(ctx context.Context, v *Instance, dest net.Destination) (net.Conn, error) {
//
//}
