package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/lilendian0x00/xray-knife/v3/pkg/protocol"
	"github.com/lilendian0x00/xray-knife/v3/utils"

	"github.com/fatih/color"
	"github.com/xtls/xray-core/infra/conf"
)

func NewTrojan(link string) Protocol {
	return &Trojan{OrigLink: link}
}

func (t *Trojan) Name() string {
	return "trojan"
}

func (t *Trojan) Parse() error {
	if !strings.HasPrefix(t.OrigLink, protocol.TrojanIdentifier) {
		return fmt.Errorf("trojan unreconized: %s", t.OrigLink)
	}
	uri, err := url.Parse(t.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse Trojan link: %w", err)
	}

	t.Password = uri.User.String()
	t.Address, t.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port for Trojan link: %w", err)
	}

	if utils.IsIPv6(t.Address) {
		t.Address = "[" + t.Address + "]"
	}

	query := uri.Query()

	// Explicitly parse known query parameters
	t.Flow = query.Get("flow")
	t.Security = query.Get("security") // "tls", "reality", or "" (none)
	t.SNI = query.Get("sni")
	t.ALPN = query.Get("alpn")
	t.TlsFingerprint = query.Get("fp")
	t.Type = query.Get("type") // network type
	t.Host = query.Get("host") // for ws, http
	t.Path = query.Get("path") // for ws, http path
	t.HeaderType = query.Get("headerType")
	t.ServiceName = query.Get("serviceName")
	t.Mode = query.Get("mode")
	t.PublicKey = query.Get("pbk")
	t.ShortIds = query.Get("sid")
	t.SpiderX = query.Get("spx")
	t.AllowInsecure = query.Get("allowInsecure")
	t.QuicSecurity = query.Get("quicSecurity")
	t.Key = query.Get("key")
	t.Authority = query.Get("authority")

	unescapedRemark, err := url.PathUnescape(uri.Fragment)
	if err != nil {
		t.Remark = uri.Fragment
	} else {
		t.Remark = unescapedRemark
	}

	// Apply defaults or adjustments
	if t.HeaderType == "xhttp" || t.HeaderType == "http" || t.Type == "ws" || t.Type == "h2" || t.Type == "xhttp" {
		if t.Path == "" {
			t.Path = "/"
		}
	}

	if t.Type == "" {
		t.Type = "tcp" // Default network for Trojan
	}
	if t.Security == "" { // Trojan typically implies TLS
		t.Security = "tls"
	}
	if (t.Security == "tls" || t.Security == "reality") && t.TlsFingerprint == "" {
		t.TlsFingerprint = "chrome"
	}

	return nil
}

func (t *Trojan) DetailsStr() string {
	copyV := *t
	if copyV.Flow == "" || copyV.Type == "grpc" {
		copyV.Flow = "none"
	}
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), t.Name(),
		color.RedString("Remark"), t.Remark,
		color.RedString("Network"), t.Type,
		color.RedString("Address"), t.Address,
		color.RedString("Port"), t.Port,
		color.RedString("Password"), t.Password,
		color.RedString("Flow"), copyV.Flow,
	)

	if copyV.Type == "" {

	} else if copyV.Type == "xhttp" || copyV.Type == "http" || copyV.Type == "httpupgrade" || copyV.Type == "ws" || copyV.Type == "h2" || copyV.Type == "splithttp" {
		info += fmt.Sprintf("%s: %s\n%s: %s\n",
			color.RedString("Host"), copyV.Host,
			color.RedString("Path"), copyV.Path)
	} else if copyV.Type == "kcp" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("KCP Seed"), copyV.Path)
	} else if copyV.Type == "grpc" {
		if copyV.ServiceName == "" {
			copyV.ServiceName = "none"
		}
		info += fmt.Sprintf("%s: %s\n", color.RedString("ServiceName"), copyV.ServiceName)
	}

	if copyV.Security == "reality" {
		info += fmt.Sprintf("%s: reality\n", color.RedString("TLS"))
		if copyV.SpiderX == "" {
			copyV.SpiderX = "none"
		}
		info += fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n",
			color.RedString("Public key"), copyV.PublicKey,
			color.RedString("SNI"), copyV.SNI,
			color.RedString("ShortID"), copyV.ShortIds,
			color.RedString("SpiderX"), copyV.SpiderX,
			color.RedString("Fingerprint"), copyV.TlsFingerprint,
		)
	} else if copyV.Security == "tls" {
		info += fmt.Sprintf("%s: tls\n", color.RedString("TLS"))
		if len(copyV.SNI) == 0 {
			if copyV.Host != "" {
				copyV.SNI = copyV.Host
			} else {
				copyV.SNI = "none"
			}
		}
		if len(copyV.ALPN) == 0 {
			copyV.ALPN = "none"
		}
		if copyV.TlsFingerprint == "" {
			copyV.TlsFingerprint = "none"
		}
		info += fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n",
			color.RedString("SNI"), copyV.SNI,
			color.RedString("ALPN"), copyV.ALPN,
			color.RedString("Fingerprint"), copyV.TlsFingerprint)

		if t.AllowInsecure != "" {
			info += fmt.Sprintf("%s: %v\n",
				color.RedString("Insecure"), t.AllowInsecure)
		}
	} else {
		info += fmt.Sprintf("%s: none\n", color.RedString("TLS"))
	}
	return info
}

func (t *Trojan) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = t.Name()
	g.Address = t.Address
	g.Host = t.Host
	g.ID = t.Password
	g.Path = t.Path
	g.Port = t.Port
	g.Remark = t.Remark
	g.SNI = t.SNI
	g.ALPN = t.ALPN
	if t.Security == "" {
		g.TLS = "none"
	} else {
		g.TLS = t.Security
	}
	g.TlsFingerprint = t.TlsFingerprint
	g.ServiceName = t.ServiceName
	g.Mode = t.Mode
	g.Type = t.Type
	g.OrigLink = t.OrigLink

	return g
}

func (t *Trojan) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	out := &conf.OutboundDetourConfig{}
	out.Tag = "proxy"
	out.Protocol = t.Name()

	p := conf.TransportProtocol(t.Type)
	s := &conf.StreamConfig{
		Network:  &p,
		Security: t.Security,
	}

	switch t.Type {
	case "tcp":
		s.TCPSettings = &conf.TCPConfig{}
		if t.HeaderType == "" || t.HeaderType == "none" {
			s.TCPSettings.HeaderConfig = json.RawMessage([]byte(`{ "type": "none" }`))
		} else { // headerType=http
			pathb, _ := json.Marshal(strings.Split(t.Path, ","))
			hostb, _ := json.Marshal(strings.Split(t.Host, ","))
			s.TCPSettings.HeaderConfig = json.RawMessage([]byte(fmt.Sprintf(`
			{
				"type": "http",
				"request": {
					"path": %s,
					"headers": {
						"Host": %s,
						"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"
					}
				}
			}
			`, string(pathb), string(hostb))))
		}
		break
	case "kcp":
		s.KCPSettings = &conf.KCPConfig{}
		s.KCPSettings.HeaderConfig = json.RawMessage([]byte(fmt.Sprintf(`{ "type": "%s" }`, t.Type)))
		break
	case "ws":
		s.WSSettings = &conf.WebSocketConfig{}
		s.WSSettings.Path = t.Path
		s.WSSettings.Headers = map[string]string{
			"Host":       t.Host,
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
		}
		break
	//case "h2", "http":
	case "xhttp":
		s.XHTTPSettings = &conf.SplitHTTPConfig{
			Host: t.Host,
			Path: t.Path,
			Mode: t.Mode,
		}
		//if v.Host != "" {
		//	h := conf.StringList(strings.Split(v.Host, ","))
		//	s.XHTTPSettings.Host = &h
		//}
		if t.Mode == "" {
			s.XHTTPSettings.Mode = "auto"
		}
		break
	case "httpupgrade":
		s.HTTPUPGRADESettings = &conf.HttpUpgradeConfig{
			Host: t.Host,
			Path: t.Path,
		}
	case "splithttp":
		s.SplitHTTPSettings = &conf.SplitHTTPConfig{
			Host: t.Host,
			Path: t.Path,
		}
	case "grpc":
		if len(t.ServiceName) > 0 {
			if t.ServiceName[0] == '/' {
				t.ServiceName = t.ServiceName[1:]
			}
		}
		multiMode := false
		if t.Mode != "gun" {
			multiMode = true
		}
		s.GRPCSettings = &conf.GRPCConfig{
			Authority:          t.Authority,
			InitialWindowsSize: 65536,
			HealthCheckTimeout: 20,
			MultiMode:          multiMode,
			IdleTimeout:        60,
			ServiceName:        t.ServiceName,
		}

		t.Flow = ""
		break
		//case "quic":
		//	tp := "none"
		//	if t.HeaderType != "" {
		//		tp = t.HeaderType
		//	}
		//
		//	s.QUICSettings = &conf.QUICConfig{
		//		Header:   json.RawMessage(fmt.Sprintf(`{ "type": "%s" }`, tp)),
		//		Security: t.QuicSecurity,
		//		Key:      t.Key,
		//	}
		//	break
	}

	if t.Security == "tls" {
		var insecure = allowInsecure
		if t.AllowInsecure != "" {
			if t.AllowInsecure == "1" || t.AllowInsecure == "true" {
				insecure = true
			}
		}

		if t.TlsFingerprint == "" {
			t.TlsFingerprint = "chrome"
		}
		s.TLSSettings = &conf.TLSConfig{
			Fingerprint: t.TlsFingerprint,
			Insecure:    insecure,
		}
		if t.AllowInsecure == "1" {
			s.TLSSettings.Insecure = true
		}

		if t.SNI != "" {
			s.TLSSettings.ServerName = t.SNI
		} else {
			s.TLSSettings.ServerName = t.Host
		}
		if t.ALPN != "" {
			s.TLSSettings.ALPN = &conf.StringList{t.ALPN}
		}
	} else if t.Security == "reality" {
		s.REALITYSettings = &conf.REALITYConfig{
			Show:        false,
			Fingerprint: t.TlsFingerprint,
			ServerName:  t.SNI,
			PublicKey:   t.PublicKey,
			ShortId:     t.ShortIds,
			SpiderX:     t.SpiderX,
		}
	}

	out.StreamSetting = s
	oset := json.RawMessage(fmt.Sprintf(`{
  "servers": [
    {
      "address": "%s",
      "method": "chacha20",
      "port": %v,
	  "password": "%s",
	  "ota": false,
	  "flow": "%s"
    }
  ]
}`, t.Address, t.Port, t.Password, t.Flow))
	out.Settings = &oset
	return out, nil
}

func (t *Trojan) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	return nil, nil
}
