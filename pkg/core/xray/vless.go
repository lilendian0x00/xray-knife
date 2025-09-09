package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	net2 "github.com/GFW-knocker/Xray-core/common/net"

	"github.com/lilendian0x00/xray-knife/v7/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v7/utils"

	"github.com/GFW-knocker/Xray-core/infra/conf"
	"github.com/fatih/color"
)

func NewVless(link string) Protocol {
	return &Vless{OrigLink: link}
}

func (v *Vless) Name() string {
	return "vless"
}

func (v *Vless) Parse() error {
	if !strings.HasPrefix(v.OrigLink, protocol.VlessIdentifier) {
		return fmt.Errorf("vless unreconized: %s", v.OrigLink)
	}

	uri, err := url.Parse(v.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse VLESS link: %w", err)
	}

	v.ID = uri.User.String()

	v.Address, v.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port for VLESS link: %w", err)
	}

	if utils.IsIPv6(v.Address) {
		v.Address = "[" + v.Address + "]"
	}

	query := uri.Query()

	// Explicitly parse known query parameters
	v.Encryption = query.Get("encryption") // Typically "none" for VLESS
	v.Security = query.Get("security")     // "tls", "reality", or "" (none)
	v.ALPN = query.Get("alpn")
	v.TlsFingerprint = query.Get("fp") // fingerprint
	v.Type = query.Get("type")         // network type: "tcp", "ws", "grpc", "quic", etc.

	// Validate host and sni parameters before assigning them
	sni := query.Get("sni")
	if !utils.IsValidHostOrSNI(sni) {
		return fmt.Errorf("invalid characters in 'sni' parameter: %s", sni)
	}
	host := query.Get("host")
	if !utils.IsValidHostOrSNI(host) {
		return fmt.Errorf("invalid characters in 'host' parameter: %s", host)
	}

	v.SNI = sni
	v.Host = host
	v.Host = query.Get("host")   // for ws, http
	v.Path = query.Get("path")   // for ws, http path, or kcp seed
	v.Extra = query.Get("extra") // XHTTP extra
	v.Flow = query.Get("flow")
	v.PublicKey = query.Get("pbk")               // reality public key
	v.ShortIds = query.Get("sid")                // reality short ID
	v.SpiderX = query.Get("spx")                 // reality spiderX
	v.HeaderType = query.Get("headerType")       // e.g., "http" for TCP HTTP obfuscation
	v.ServiceName = query.Get("serviceName")     // grpc service name
	v.Mode = query.Get("mode")                   // grpc mode (gun, multi) or xhttp mode
	v.AllowInsecure = query.Get("allowInsecure") // "1", "true", or ""
	v.QuicSecurity = query.Get("quicSecurity")   // QUIC security: "none", "aes-128-gcm", etc.
	v.Key = query.Get("key")                     // QUIC key
	v.Authority = query.Get("authority")         // GRPC authority

	unescapedRemark, err := url.PathUnescape(uri.Fragment)
	if err != nil {
		v.Remark = uri.Fragment // Use raw fragment if unescaping fails
	} else {
		v.Remark = unescapedRemark
	}

	// Apply defaults or adjustments after parsing
	if v.HeaderType == "http" || v.Type == "ws" || v.Type == "h2" || v.Type == "xhttp" {
		if v.Path == "" {
			v.Path = "/"
		}
	}
	if v.Type == "" && (v.Security == "tls" || v.Security == "reality" || v.Security == "") { // Default to tcp if not specified otherwise for typical streams
		v.Type = "tcp"
	}
	if v.Security == "tls" || v.Security == "reality" {
		if v.TlsFingerprint == "" {
			v.TlsFingerprint = "chrome" // Default fingerprint if TLS/REALITY is used
		}
	}

	return nil
}

func (v *Vless) DetailsStr() string {
	copyV := *v
	if copyV.Flow == "" || copyV.Type == "grpc" {
		copyV.Flow = "none"
	}
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), v.Name(),
		color.RedString("Remark"), v.Remark,
		color.RedString("Network"), v.Type,
		color.RedString("Address"), v.Address,
		color.RedString("Port"), v.Port,
		color.RedString("UUID"), v.ID,
		color.RedString("Flow"), copyV.Flow)
	if copyV.Type == "" {

	} else if copyV.Type == "xhttp" || copyV.HeaderType == "http" || copyV.Type == "httpupgrade" || copyV.Type == "ws" || copyV.Type == "h2" || copyV.Type == "splithttp" {
		info += fmt.Sprintf("%s: %s\n%s: %s\n",
			color.RedString("Host"), copyV.Host,
			color.RedString("Path"), copyV.Path)
	} else if copyV.Type == "kcp" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("KCP Seed"), copyV.Path)
	} else if copyV.Type == "grpc" {
		if copyV.ServiceName == "" {
			copyV.ServiceName = "none"
		}
		if copyV.Authority == "" {
			copyV.Authority = "none"
		}
		info += fmt.Sprintf("%s: %s\n%s: %s\n",
			color.RedString("ServiceName"), copyV.ServiceName,
			color.RedString("Authority"), copyV.Authority)
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

		if v.AllowInsecure != "" {
			info += fmt.Sprintf("%s: %v\n",
				color.RedString("Insecure"), v.AllowInsecure)
		}
	} else {
		info += fmt.Sprintf("%s: none\n", color.RedString("TLS"))
	}

	return info
}

func (v *Vless) GetLink() string {
	if v.OrigLink != "" {
		return v.OrigLink
	} else {
		baseURL := url.URL{
			Scheme: "vless",
			User:   url.User(v.ID),
			Host:   net.JoinHostPort(v.Address, v.Port),
		}

		params := url.Values{}

		addQueryParam := func(key, value string) {
			if value != "" {
				params.Add(key, value)
			}
		}

		addQueryParam("encryption", v.Encryption)
		addQueryParam("security", v.Security)
		addQueryParam("sni", v.SNI)
		addQueryParam("alpn", v.ALPN)
		addQueryParam("fp", v.TlsFingerprint)
		addQueryParam("type", v.Type)
		addQueryParam("host", v.Host)
		addQueryParam("path", v.Path)
		addQueryParam("flow", v.Flow)
		addQueryParam("pbk", v.PublicKey)
		addQueryParam("sid", v.ShortIds)
		addQueryParam("spx", v.SpiderX)
		addQueryParam("headerType", v.HeaderType)
		addQueryParam("serviceName", v.ServiceName)
		addQueryParam("mode", v.Mode)
		addQueryParam("allowInsecure", v.AllowInsecure)
		addQueryParam("quicSecurity", v.QuicSecurity)
		addQueryParam("key", v.Key)
		addQueryParam("authority", v.Authority)

		baseURL.RawQuery = params.Encode()

		if v.Remark != "" {
			baseURL.Fragment = v.Remark
		}

		return baseURL.String()
	}
}

func (v *Vless) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = v.Name()
	g.Address = v.Address
	g.Host = v.Host
	g.ID = v.ID
	g.Path = v.Path
	g.Port = v.Port
	g.Remark = v.Remark
	if v.Security == "" {
		g.TLS = "none"
	} else {
		g.TLS = v.Security
	}
	g.SNI = v.SNI
	g.ALPN = v.ALPN
	g.TlsFingerprint = v.TlsFingerprint
	g.Authority = v.Authority
	g.ServiceName = v.ServiceName
	g.Mode = v.Mode
	g.Type = v.Type
	g.OrigLink = v.GetLink()

	return g
}

func (v *Vless) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	out := &conf.OutboundDetourConfig{}
	out.Tag = "proxy"
	out.Protocol = v.Name()

	p := conf.TransportProtocol(v.Type)
	s := &conf.StreamConfig{
		Network:  &p,
		Security: v.Security,
	}

	switch v.Type {
	case "raw":
		s.RAWSettings = &conf.TCPConfig{}
		if v.HeaderType == "" || v.HeaderType == "none" {
			s.RAWSettings.HeaderConfig = json.RawMessage([]byte(`{ "type": "none" }`))
		} else { // headerType=http
			pathb, _ := json.Marshal(strings.Split(v.Path, ","))
			hostb, _ := json.Marshal(strings.Split(v.Host, ","))
			s.RAWSettings.HeaderConfig = []byte(fmt.Sprintf(`
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
			`, string(pathb), string(hostb)))
		}
	case "tcp":
		s.TCPSettings = &conf.TCPConfig{}
		if v.HeaderType == "" || v.HeaderType == "none" {
			s.TCPSettings.HeaderConfig = json.RawMessage([]byte(`{ "type": "none" }`))
		} else { // headerType=http
			pathb, _ := json.Marshal(strings.Split(v.Path, ","))
			hostb, _ := json.Marshal(strings.Split(v.Host, ","))
			s.TCPSettings.HeaderConfig = []byte(fmt.Sprintf(`
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
			`, string(pathb), string(hostb)))
		}
		break
	case "kcp":
		s.KCPSettings = &conf.KCPConfig{}
		s.KCPSettings.HeaderConfig = json.RawMessage([]byte(fmt.Sprintf(`{ "type": "%s" }`, v.Type)))
		break
	case "ws":
		s.WSSettings = &conf.WebSocketConfig{}
		s.WSSettings.Path = v.Path
		s.WSSettings.Headers = map[string]string{
			"Host":       v.Host,
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
		}
		break
	case "xhttp":
		s.XHTTPSettings = &conf.SplitHTTPConfig{
			Host: v.Host,
			Path: v.Path,
			Mode: v.Mode,
		}
		// decode the percent-encoded JSON from the URL
		if v.Extra != "" {
			decoded, err := url.QueryUnescape(v.Extra)
			if err != nil {
				return nil, fmt.Errorf("invalid extra parameter: %w", err)
			}
			s.XHTTPSettings.Extra = json.RawMessage(decoded)
		}

		if v.Mode == "" {
			s.XHTTPSettings.Mode = "auto"
		}
	case "httpupgrade":
		s.HTTPUPGRADESettings = &conf.HttpUpgradeConfig{
			Host: v.Host,
			Path: v.Path,
		}
		break
	case "splithttp":
		s.SplitHTTPSettings = &conf.SplitHTTPConfig{
			Host: v.Host,
			Path: v.Path,
		}
		break
	case "grpc":
		if len(v.ServiceName) > 0 {
			if v.ServiceName[0] == '/' {
				v.ServiceName = v.ServiceName[1:]
			}
		}
		multiMode := false
		if v.Mode != "gun" {
			multiMode = true
		}

		s.GRPCSettings = &conf.GRPCConfig{
			Authority:           v.Authority,
			ServiceName:         v.ServiceName,
			MultiMode:           multiMode,
			IdleTimeout:         60,
			HealthCheckTimeout:  20,
			PermitWithoutStream: false,
			InitialWindowsSize:  65536,
			UserAgent:           "",
		}
		v.Flow = ""
		break
	case "quic":
		s.QUICSettings = &conf.QUICConfig{
			Header:   json.RawMessage(fmt.Sprintf(`{ "type": "%s" }`, v.HeaderType)),
			Security: v.QuicSecurity,
			Key:      v.Key,
		}
		break
	}

	if v.Security == "tls" {
		var insecureFlag = allowInsecure // Use the passed-in parameter
		if v.AllowInsecure == "1" || v.AllowInsecure == "true" {
			insecureFlag = true
		}

		fp := v.TlsFingerprint
		if fp == "" {
			fp = "chrome"
		}
		s.TLSSettings = &conf.TLSConfig{
			Fingerprint: fp,
			Insecure:    insecureFlag,
		}
		if v.SNI != "" {
			s.TLSSettings.ServerName = v.SNI
		} else {
			s.TLSSettings.ServerName = v.Host // Fallback to Host if SNI is empty
		}
		if v.ALPN != "" {
			alpns := conf.StringList(strings.Split(v.ALPN, ","))
			s.TLSSettings.ALPN = &alpns
		}
	} else if v.Security == "reality" {
		fp := v.TlsFingerprint
		if fp == "" {
			fp = "chrome"
		}
		s.REALITYSettings = &conf.REALITYConfig{
			Show:        false,
			Fingerprint: fp,
			ServerName:  v.SNI,
			PublicKey:   v.PublicKey,
			ShortId:     v.ShortIds,
			SpiderX:     v.SpiderX,
		}
	}

	out.StreamSetting = s
	oset := json.RawMessage(fmt.Sprintf(`{
  "vnext": [
    {
      "address": "%s",
      "port": %s, 
      "users": [
        {
          "id": "%s",
		  "alterId": 0,
          "security": "auto",
          "flow": "%s",
          "encryption": "none"
        }
      ]
    }
  ]
}`, v.Address, v.Port, v.ID, v.Flow))
	out.Settings = &oset
	return out, nil
}

func (v *Vless) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	p := conf.TransportProtocol(v.Type)
	streamConfig := &conf.StreamConfig{
		Network:  &p,
		Security: v.Security,
	}

	switch v.Type {
	case "tcp":
		streamConfig.TCPSettings = &conf.TCPConfig{}
		if v.HeaderType == "" || v.HeaderType == "none" {
			streamConfig.TCPSettings.HeaderConfig = json.RawMessage([]byte(`{ "type": "none" }`))
		} else { // headerType=http
			pathb, _ := json.Marshal(strings.Split(v.Path, ","))
			hostb, _ := json.Marshal(strings.Split(v.Host, ","))
			streamConfig.TCPSettings.HeaderConfig = []byte(fmt.Sprintf(`
			{
				"type": "http",
				"request": {
					"path": %s,
					"headers": {
						"Host": %s
					}
				}
			}
			`, string(pathb), string(hostb)))
		}
	case "kcp":
		streamConfig.KCPSettings = &conf.KCPConfig{}
		streamConfig.KCPSettings.HeaderConfig = json.RawMessage([]byte(fmt.Sprintf(`{ "type": "%s" }`, v.Type)))
	case "ws":
		streamConfig.WSSettings = &conf.WebSocketConfig{}
		streamConfig.WSSettings.Path = v.Path
		streamConfig.WSSettings.Headers = map[string]string{
			"Host": v.Host,
		}
	case "xhttp":
		streamConfig.XHTTPSettings = &conf.SplitHTTPConfig{
			Host: v.Host,
			Path: v.Path,
			Mode: v.Mode,
		}
		if v.Mode == "" {
			streamConfig.XHTTPSettings.Mode = "auto"
		}
	case "httpupgrade":
		streamConfig.HTTPUPGRADESettings = &conf.HttpUpgradeConfig{
			Host: v.Host,
			Path: v.Path,
		}
	case "splithttp":
		streamConfig.SplitHTTPSettings = &conf.SplitHTTPConfig{
			Host: v.Host,
			Path: v.Path,
		}
	case "grpc":
		if len(v.ServiceName) > 0 {
			if v.ServiceName[0] == '/' {
				v.ServiceName = v.ServiceName[1:]
			}
		}
		multiMode := false
		if v.Mode != "gun" {
			multiMode = true
		}

		streamConfig.GRPCSettings = &conf.GRPCConfig{
			Authority:           v.Authority,
			ServiceName:         v.ServiceName,
			MultiMode:           multiMode,
			IdleTimeout:         60,
			HealthCheckTimeout:  20,
			PermitWithoutStream: false,
			InitialWindowsSize:  65536,
			UserAgent:           "",
		}
	}

	if v.Security == "tls" && v.CertFile != "" && v.KeyFile != "" {
		streamConfig.TLSSettings = &conf.TLSConfig{
			ServerName: v.SNI,
			Certs: []*conf.TLSCertConfig{
				{
					KeyFile:  v.KeyFile,
					CertFile: v.CertFile,
				},
			},
		}
		if v.ALPN != "" {
			alpns := conf.StringList(strings.Split(v.ALPN, ","))
			streamConfig.TLSSettings.ALPN = &alpns
		}
	} else if v.Security != "none" && v.Security != "" {
		// If security is requested but certs are missing, fallback to no security for inbound.
		streamConfig.Security = "none"
	}

	clients := fmt.Sprintf(`{
      "id": "%s",
      "flow": "%s"
    }`, v.ID, v.Flow)

	settings := json.RawMessage(fmt.Sprintf(`{
	  "clients": [ %s ],
      "decryption": "none"
	}`, clients))

	uint32Value, err := strconv.ParseUint(v.Port, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("error converting port string to uint32: %w", err)
	}
	uint32Result := uint32(uint32Value)

	in := &conf.InboundDetourConfig{
		Protocol:      v.Name(),
		Tag:           v.Name(),
		Settings:      &settings,
		StreamSetting: streamConfig,
		ListenOn:      &conf.Address{Address: net2.ParseAddress(v.Address)},
		PortList: &conf.PortList{Range: []conf.PortRange{
			{From: uint32Result, To: uint32Result},
		}},
	}

	return in, nil
}
