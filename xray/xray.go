package xray

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/xtls/xray-core/app/dispatcher"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	commlog "github.com/xtls/xray-core/common/log"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	// The following deps are necessary as they register handlers in their init functions.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
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

func MeasureDelay(inst *core.Instance, timeout time.Duration, showBody bool, dest string, httpMethod string) (int64, int, error) {
	start := time.Now()
	code, body, err := CoreHTTPRequest(inst, timeout, httpMethod, dest)
	if err != nil {
		return -1, -1, err
	}
	//fmt.Printf("%s: %d\n", color.YellowString("Status code"), code)
	if showBody {
		fmt.Printf("Response body: \n%s\n", body)
	}
	return time.Since(start).Milliseconds(), code, nil
}

func httpClient(inst *core.Instance, timeout time.Duration) (*http.Client, error) {
	if inst == nil {
		return nil, errors.New("core instance nil")
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := xraynet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, inst, dest)
		},
	}

	c := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	return c, nil
}

func CoreHTTPRequest(inst *core.Instance, timeout time.Duration, method, dest string) (int, []byte, error) {
	c, err := httpClient(inst, timeout)
	if err != nil {
		return 0, nil, err
	}

	req, _ := http.NewRequest(method, dest, nil)
	resp, err := c.Do(req)
	if err != nil {
		return -1, nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
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
