package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"github.com/xtls/xray-core/infra/conf"

	"github.com/lilendian0x00/xray-knife/v2/utils"
)

func NewTrojan() Protocol {
	return &Trojan{}
}

func (t *Trojan) Name() string {
	return "trojan"
}

func (t *Trojan) Parse(configLink string) error {
	if !strings.HasPrefix(configLink, trojanIdentifier) {
		return fmt.Errorf("trojan unreconized: %s", configLink)
	}
	uri, err := url.Parse(configLink)
	if err != nil {
		return err
	}

	t.Password = uri.User.String()
	t.Address, t.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	if utils.IsIPv6(t.Address) {
		t.Address = "[" + t.Address + "]"
	}
	// Get the type of the struct
	structType := reflect.TypeOf(*t)

	// Get the number of fields in the struct
	numFields := structType.NumField()

	// Iterate over each field of the struct
	for i := 0; i < numFields; i++ {
		field := structType.Field(i)
		tag := field.Tag.Get("json")

		// If the query value exists for the field, set it
		if values, ok := uri.Query()[tag]; ok {
			value := values[0]
			v := reflect.ValueOf(t).Elem().FieldByName(field.Name)

			switch v.Type().String() {
			case "string":
				v.SetString(value)
			case "int":
				var intValue int
				fmt.Sscanf(value, "%d", &intValue)
				v.SetInt(int64(intValue))
			}
		}
	}

	t.Remark, err = url.PathUnescape(uri.Fragment)
	if err != nil {
		t.Remark = uri.Fragment
	}
	t.OrigLink = configLink

	if t.HeaderType == "http" || t.Type == "ws" || t.Type == "h2" {
		if t.Path == "" {
			t.Path = "/"
		}
	}

	if t.Type == "" {
		t.Type = "tcp"
	}
	if t.Security == "" {
		t.Security = "tls"
	}
	if t.TlsFingerprint == "" {
		t.TlsFingerprint = "chrome"
	}

	return nil
}

func (t *Trojan) DetailsStr() string {
	copyV := *t
	if copyV.Flow == "" || copyV.Type == "grpc" {
		copyV.Flow = "none"
	}
	result := make([][2]string, 0, 20)
	result = append(result, [][2]string{
		{"Protocol", t.Name()},
		{"Remark", t.Remark},
		{"Network", t.Type},
		{"Address", t.Address},
		{"Port", t.Port},
		{"Password", t.Password},
		{"Flow", copyV.Flow},
	}...)

	// Type
	switch {
	case slices.Contains([]string{"http", "httpupgrade", "ws", "h2", "splithttp"}, copyV.Type):
		result = append(result, [][2]string{
			{"Host", copyV.Host},
			{"Path", copyV.Path},
		}...)
	case copyV.Type == "kcp":
		result = append(result, [2]string{"KCP Seed", copyV.Path})
	case copyV.Type == "grpc":
		if copyV.ServiceName == "" {
			copyV.ServiceName = "none"
		}
		result = append(result, [][2]string{
			{"ServiceName", copyV.ServiceName},
			{"Authority", copyV.Authority},
		}...)
	}

	switch copyV.Security {
	case "reality":
		if copyV.SpiderX == "" {
			copyV.SpiderX = "none"
		}
		result = append(result, [][2]string{
			{"TLS", "reality"},
			{"Public key", copyV.PublicKey},
			{"SNI", copyV.SNI},
			{"ShortID", copyV.ShortIds},
			{"SpiderX", copyV.SpiderX},
			{"Fingerprint", copyV.TlsFingerprint},
		}...)
	case "tls":
		if copyV.SNI == "" {
			copyV.SNI = "none"
			if copyV.Host != "" {
				copyV.SNI = copyV.Host
			}
		}
		if copyV.ALPN == "" {
			copyV.ALPN = "none"
		}
		if copyV.TlsFingerprint == "" {
			copyV.TlsFingerprint = "none"
		}
		result = append(result, [][2]string{
			{"TLS", "tls"},
			{"SNI", copyV.SNI},
			{"ALPN", copyV.ALPN},
			{"Fingerprint", copyV.TlsFingerprint},
		}...)
	default:
		result = append(result, [2]string{"TLS", "none"})
	}

	return detailsToStr(result)
}

func (t *Trojan) ConvertToGeneralConfig() GeneralConfig {
	var g GeneralConfig
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
	g.Authority = t.Authority
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
	case "h2", "http":
		s.HTTPSettings = &conf.HTTPConfig{
			Path: t.Path,
		}
		if t.Host != "" {
			h := conf.StringList(strings.Split(t.Host, ","))
			s.HTTPSettings.Host = &h
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
		s.GRPCConfig = &conf.GRPCConfig{
			InitialWindowsSize: 65536,
			HealthCheckTimeout: 20,
			MultiMode:          multiMode,
			IdleTimeout:        60,
			Authority:          t.Authority,
			ServiceName:        t.ServiceName,
		}

		t.Flow = ""
		break
	case "quic":
		tp := "none"
		if t.HeaderType != "" {
			tp = t.HeaderType
		}

		s.QUICSettings = &conf.QUICConfig{
			Header:   json.RawMessage([]byte(fmt.Sprintf(`{ "type": "%s" }`, tp))),
			Security: t.QuicSecurity,
			Key:      t.Key,
		}
		break
	}

	if t.Security == "tls" {
		if t.TlsFingerprint == "" {
			t.TlsFingerprint = "chrome"
		}
		s.TLSSettings = &conf.TLSConfig{
			Fingerprint: t.TlsFingerprint,
			Insecure:    allowInsecure,
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
	oset := json.RawMessage([]byte(fmt.Sprintf(`{
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
}`, t.Address, t.Port, t.Password, t.Flow)))
	out.Settings = &oset
	return out, nil
}

func (t *Trojan) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	return nil, nil
}
