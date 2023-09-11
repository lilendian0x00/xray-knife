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

func StartXray(conf Protocol, verbose, allowInsecure bool) (*core.Instance, error) {

	loglevel := commlog.Severity_Unknown
	logType := applog.LogType_None
	if verbose {
		logType = applog.LogType_Console
		loglevel = commlog.Severity_Debug
	}

	ob, err := conf.BuildOutboundDetourConfig(allowInsecure)
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
				ErrorLogType:  logType,
				AccessLogType: logType,
				ErrorLogLevel: loglevel,
				EnableDnsLog:  false,
			}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
	}

	commlog.RegisterHandler(commlog.NewLogger(commlog.CreateStderrLogWriter()))
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
