package xray

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/xtls/xray-core/app/dispatcher"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	commlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	// The following deps are necessary as they register handlers in their init functions.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	"os"
	"strings"
)

type Service struct {
	// Log
	Verbose  bool
	LogType  applog.LogType
	LogLevel commlog.Severity

	AllowInsecure bool
}

type ServiceOption = func(c *Service)

func WithCustomLogLevel(logType applog.LogType, LogLevel commlog.Severity) ServiceOption {
	return func(c *Service) {
		c.LogType = logType
		c.LogLevel = LogLevel
	}
}

func NewXrayService(verbose bool, allowInsecure bool, opts ...ServiceOption) *Service {
	s := &Service{
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

func (x *Service) StartXray(conf Protocol) (*core.Instance, error) {
	ob, err := conf.BuildOutboundDetourConfig(x.AllowInsecure)
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
				ErrorLogType:  x.LogType,
				AccessLogType: x.LogType,
				ErrorLogLevel: x.LogLevel,
				EnableDnsLog:  false,
			}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
	}
	//config.Inbound = []*core.InboundHandlerConfig{}
	clientConfig.Outbound = []*core.OutboundHandlerConfig{built}

	server, err2 := core.New(clientConfig)
	if err2 != nil {
		return nil, err2
	}
	return server, nil
}

func ParseXrayConfig(configLink string) (Protocol, error) {
	if configLink == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Reading config from STDIN:")
		text, _ := reader.ReadString('\n')
		configLink = text
		fmt.Printf("\n")
	}

	var protocol Protocol

	if strings.HasPrefix(configLink, "vmess://") {
		protocol = &Vmess{}
	} else if strings.HasPrefix(configLink, "vless://") {
		protocol = &Vless{}
	} else if strings.HasPrefix(configLink, "ss://") {
		protocol = &Shadowsocks{}
	} else if strings.HasPrefix(configLink, "trojan://") {
		protocol = &Trojan{}
	} else {
		return protocol, errors.New("Invalid protocol type! ")
	}

	trimmed := strings.TrimSpace(configLink)

	err := protocol.Parse(trimmed)
	if err != nil {
		return protocol, err
	}
	return protocol, nil
}
