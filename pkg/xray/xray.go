package xray

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/lilendian0x00/xray-knife/v5/pkg/protocol"

	"github.com/xtls/xray-core/app/dispatcher"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	commlog "github.com/xtls/xray-core/common/log"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"

	// The following deps are necessary as they register handlers in their init functions.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
)

type Core struct {
	Inbound Protocol

	// Log
	Verbose  bool
	LogType  applog.LogType
	LogLevel commlog.Severity

	AllowInsecure bool
}

func (c *Core) Name() string {
	return "xray"
}

type ServiceOption = func(c *Core)

func WithCustomLogLevel(logType applog.LogType, LogLevel commlog.Severity) ServiceOption {
	return func(c *Core) {
		c.LogType = logType
		c.LogLevel = LogLevel
	}
}

func WithInbound(inbound Protocol) ServiceOption {
	return func(c *Core) {
		//i := inbound.(Protocol)
		c.Inbound = inbound
	}
}

func NewXrayService(verbose bool, allowInsecure bool, opts ...ServiceOption) *Core {
	s := &Core{
		Inbound:       nil,
		Verbose:       verbose,
		LogType:       applog.LogType_None,
		LogLevel:      commlog.Severity_Unknown,
		AllowInsecure: allowInsecure,
	}

	if verbose {
		s.LogType = applog.LogType_Console
		s.LogLevel = commlog.Severity_Debug
		commlog.RegisterHandler(commlog.NewLogger(commlog.CreateStderrLogWriter()))
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (c *Core) SetInbound(inbound protocol.Protocol) error {
	c.Inbound = inbound.(Protocol)
	return nil
}

func (c *Core) MakeInstance(outbound protocol.Protocol) (protocol.Instance, error) {
	out := outbound.(Protocol)

	ob, err := out.BuildOutboundDetourConfig(c.AllowInsecure)
	if err != nil {
		return nil, err
	}
	built, err1 := ob.Build()
	if err1 != nil {
		return nil, err1
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
	if c.Inbound != nil {
		clientConfig.App = append(clientConfig.App, serial.ToTypedMessage(&proxyman.InboundConfig{}))
		ibc, err := c.Inbound.BuildInboundDetourConfig()
		if err != nil {
			return nil, err
		}
		ibcBuilt, err1 := ibc.Build()
		if err1 != nil {
			return nil, err1
		}
		clientConfig.Inbound = []*core.InboundHandlerConfig{ibcBuilt}
	}
	clientConfig.Outbound = []*core.OutboundHandlerConfig{built}

	server, err2 := core.New(clientConfig)
	if err2 != nil {
		return nil, err2
	}
	return server, nil
}

func (c *Core) MakeHttpClient(outbound protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	out := outbound.(Protocol)
	instance, err := c.MakeInstance(out)
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

//func (c *Core) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
//	dest, err := xraynet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
//	if err != nil {
//		return nil, err
//	}
//	return core.Dial(ctx, , dest)
//}

//func newHttpClient(inst *core.Instance, timeout time.Duration) (*http.Client, error) {
//	if inst == nil {
//		return nil, errors.New("core instance nil")
//	}
//	tr := &http.Transport{
//		DisableKeepAlives: true,
//		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
//			dest, err := xraynet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
//			if err != nil {
//				return nil, err
//			}
//			return core.Dial(ctx, inst, dest)
//		},
//	}
//
//	c := &http.Client{
//		Transport: tr,
//		Timeout:   timeout,
//	}
//
//	return c, nil
//}

//func ParseXrayConfig(configLink string) (Protocol, error) {
//	// Read config from STDIN if it's not passed to the function
//	if configLink == "" {
//		reader := bufio.NewReader(os.Stdin)
//		fmt.Println("Reading config from STDIN:")
//		text, _ := reader.ReadString('\n')
//		configLink = text
//		fmt.Printf("\n")
//	}
//
//	// Remove any space
//	configLink = strings.TrimSpace(configLink)
//
//	// Factory method to create protocol
//	protocol, err := CreateProtocol(configLink)
//	if err != nil {
//		return nil, errors.New("invalid protocol type")
//	}
//
//	// Parse protocol from link
//	err = protocol.Parse(configLink)
//	if err != nil {
//		return protocol, err
//	}
//
//	return protocol, nil
//}
