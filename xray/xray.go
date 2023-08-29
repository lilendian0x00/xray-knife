package xray

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/xtls/xray-core/app/dispatcher"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
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
	built, err := ob.Build()
	if err != nil {
		return nil, err
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

	server, err1 := core.New(clientConfig)
	common.Must(err1)
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

	rm1 := strings.TrimSuffix(configLink, "\r\n")
	rm2 := strings.TrimSuffix(rm1, "\n")

	err := protocol.Parse(rm2)
	if err != nil {
		return protocol, err
	}
	return protocol, nil
}
