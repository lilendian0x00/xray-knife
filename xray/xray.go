package xray

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xtls/xray-core/app/dispatcher"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	commlog "github.com/xtls/xray-core/common/log"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func convertToOutbound(v *GeneralConfig, useMux, allowInsecure bool) (*core.OutboundHandlerConfig, error) {
	out := &conf.OutboundDetourConfig{}
	out.Tag = "proxy"
	out.Protocol = v.Protocol
	out.MuxSettings = &conf.MuxConfig{}
	if useMux {
		out.MuxSettings.Enabled = true
		out.MuxSettings.Concurrency = 8
	}

	p := conf.TransportProtocol(v.Network)
	s := &conf.StreamConfig{
		Network:  &p,
		Security: v.TLS,
	}

	if v.Protocol == "vmess" {
		if v.TLS == "reality" {
			s.REALITYSettings = &conf.REALITYConfig{
				Show:         false,
				Dest:         nil,
				Type:         "",
				Xver:         0,
				ServerNames:  []string{v.SNI},
				MinClientVer: "",
				MaxClientVer: "",
				MaxTimeDiff:  0,
				ShortIds:     nil,
				Fingerprint:  "",
				ServerName:   "",
				PublicKey:    "",
				ShortId:      "",
				SpiderX:      "",
			}
		}
	}

	switch v.Network {
	case "tcp":
		s.TCPSettings = &conf.TCPConfig{}
		if v.Type == "" || v.Type == "none" {
			s.TCPSettings.HeaderConfig = json.RawMessage([]byte(`{ "type": "none" }`))
		} else {
			pathb, _ := json.Marshal(strings.Split(v.Path, ","))
			hostb, _ := json.Marshal(strings.Split(v.Host, ","))
			s.TCPSettings.HeaderConfig = json.RawMessage([]byte(fmt.Sprintf(`
			{
				"type": "http",
				"request": {
					"path": %s,
					"headers": {
						"Host": %s
					}
				}
			}
			`, string(pathb), string(hostb))))
		}
	case "kcp":
		s.KCPSettings = &conf.KCPConfig{}
		s.KCPSettings.HeaderConfig = json.RawMessage([]byte(fmt.Sprintf(`{ "type": "%s" }`, v.Type)))
	case "ws":
		s.WSSettings = &conf.WebSocketConfig{}
		s.WSSettings.Path = v.Path
		s.WSSettings.Headers = map[string]string{
			"Host": v.Host,
		}
	case "h2", "http":
		s.HTTPSettings = &conf.HTTPConfig{
			Path: v.Path,
		}
		if v.Host != "" {
			h := conf.StringList(strings.Split(v.Host, ","))
			s.HTTPSettings.Host = &h
		}
	}

	if v.TLS == "tls" {
		s.TLSSettings = &conf.TLSConfig{
			Insecure:    allowInsecure,
			Fingerprint: v.TlsFingerprint,
		}
		if v.SNI != "" {
			s.TLSSettings.ServerName = v.SNI
		} else {
			s.TLSSettings.ServerName = v.Host
		}
		if v.ALPN != "" {
			//s.TLSSettings.ALPN = v.ALPN
		}
	}

	out.StreamSetting = s
	oset := json.RawMessage([]byte(fmt.Sprintf(`{
  "vnext": [
    {
      "address": "%s",
      "port": %v,
      "users": [
        {
          "id": "%s",
          "alterId": %v,
          "security": "auto"
        }
      ]
    }
  ]
}`, v.Address, v.Port, v.ID, v.Aid)))
	out.Settings = &oset
	return out.Build()
}

func StartXray(conf GeneralConfig, verbose, useMux, allowInsecure bool) (*core.Instance, error) {
	loglevel := commlog.Severity_Error
	if verbose {
		loglevel = commlog.Severity_Debug
	}

	ob, err := convertToOutbound(&conf, useMux, allowInsecure)
	if err != nil {
		return nil, err
	}
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&applog.Config{
				ErrorLogType:  applog.LogType_Console,
				ErrorLogLevel: loglevel,
			}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
	}

	commlog.RegisterHandler(commlog.NewLogger(commlog.CreateStderrLogWriter()))
	config.Outbound = []*core.OutboundHandlerConfig{ob}
	server, err := core.New(config)
	if err != nil {
		return nil, err
	}

	return server, nil
}

func MeasureDelay(inst *core.Instance, timeout time.Duration, dest string) (int64, error) {
	start := time.Now()
	code, _, err := CoreHTTPRequest(inst, timeout, "GET", dest)
	if err != nil {
		return -1, err
	}
	if code > 399 {
		return -1, fmt.Errorf("status incorrect (>= 400): %d", code)
	}
	return time.Since(start).Milliseconds(), nil
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

	}

	var protocol Protocol

	if strings.HasPrefix(configLink, "vmess://") {
		protocol = &Vmess{}
	} else if strings.HasPrefix(configLink, "vless://") {
		protocol = &Vless{}
	} else {
		return protocol, errors.New("Wrong protocol type! ")
	}

	err := protocol.Parse(configLink)
	if err != nil {
		return protocol, err
	}
	return protocol, nil
}
