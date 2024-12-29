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

func NewVless() Protocol {
	return &Vless{}
}

func (v *Vless) Name() string {
	return "vless"
}

func (v *Vless) Parse(configLink string) error {
	if !strings.HasPrefix(configLink, vlessIdentifier) {
		return fmt.Errorf("vless unreconized: %s", configLink)
	}

	uri, err := url.Parse(configLink)
	if err != nil {
		return err
	}

	v.ID = uri.User.String()

	v.Address, v.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	if utils.IsIPv6(v.Address) {
		v.Address = "[" + v.Address + "]"
	}

	// Get the type of the struct
	t := reflect.TypeOf(*v)

	// Get the number of fields in the struct
	numFields := t.NumField()

	// Iterate over each field of the struct
	for i := 0; i < numFields; i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")

		// If the query value exists for the field, set it
		if values, ok := uri.Query()[tag]; ok {
			value := values[0]
			v := reflect.ValueOf(v).Elem().FieldByName(field.Name)

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

	v.Remark, err = url.PathUnescape(uri.Fragment)
	if err != nil {
		v.Remark = uri.Fragment
	}
	// portUint, err := strconv.ParseUint(address[1], 10, 16)
	// if err != nil {
	//	fmt.Fprintf(os.Stderr, "%v", err)
	//	os.Exit(1)
	// }
	// v.Port = uint16(portUint)
	v.OrigLink = configLink

	if v.HeaderType == "http" || v.Type == "ws" || v.Type == "h2" {
		if v.Path == "" {
			v.Path = "/"
		}
	}

	return nil
}

func (v *Vless) DetailsStr() string {
	return detailsToStr(v.details())
}

func (v *Vless) DetailsMap() map[string]string {
	return detailsToMap(v.details())
}

func (v *Vless) details() [][2]string {
	copyV := *v
	if copyV.Flow == "" || copyV.Type == "grpc" {
		copyV.Flow = "none"
	}
	result := make([][2]string, 0, 20)
	result = append(result, [][2]string{
		{"Protocol", v.Name()},
		{"Remark", v.Remark},
		{"Network", v.Type},
		{"Address", v.Address},
		{"Port", v.Port},
		{"UUID", v.ID},
		{"Flow", copyV.Flow},
	}...)

	// Type
	switch {
	case copyV.HeaderType == "http" || slices.Contains([]string{"httpupgrade", "ws", "h2", "splithttp"}, copyV.Type):
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
		if copyV.Authority == "" {
			copyV.Authority = "none"
		}
		result = append(result, [][2]string{
			{"ServiceName", copyV.ServiceName},
			{"Authority", copyV.Authority},
		}...)
	}

	// Security
	switch copyV.Security {
	case "reality":
		if copyV.SpiderX == "" {
			copyV.SpiderX = "none"
		}
		result = append(result, [][2]string{
			{"TLS", copyV.Security},
			{"Public key", copyV.PublicKey},
			{"SNI", copyV.SNI},
			{"ShortID", copyV.ShortIds},
			{"SpiderX", copyV.SpiderX},
			{"Fingerprint", copyV.TlsFingerprint},
		}...)
	case "tls":
		if len(copyV.SNI) == 0 {
			copyV.SNI = "none"
			if copyV.Host != "" {
				copyV.SNI = copyV.Host
			}
		}
		if len(copyV.ALPN) == 0 {
			copyV.ALPN = "none"
		}
		if copyV.TlsFingerprint == "" {
			copyV.TlsFingerprint = "none"
		}
		result = append(result, [][2]string{
			{"TLS", copyV.Security},
			{"SNI", copyV.SNI},
			{"ALPN", copyV.ALPN},
			{"Fingerprint", copyV.TlsFingerprint},
		}...)
	default:
		result = append(result, [2]string{"TLS", "tls"})
	}

	return result
}

func (v *Vless) ConvertToGeneralConfig() GeneralConfig {
	var g GeneralConfig
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
	g.OrigLink = v.OrigLink

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
	case "tcp":
		s.TCPSettings = &conf.TCPConfig{}
		if v.HeaderType == "" || v.HeaderType == "none" {
			s.TCPSettings.HeaderConfig = json.RawMessage([]byte(`{ "type": "none" }`))
		} else { // headerType=http
			pathb, _ := json.Marshal(strings.Split(v.Path, ","))
			hostb, _ := json.Marshal(strings.Split(v.Host, ","))
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
	case "h2", "http":
		s.HTTPSettings = &conf.HTTPConfig{
			Path: v.Path,
		}
		if v.Host != "" {
			h := conf.StringList(strings.Split(v.Host, ","))
			s.HTTPSettings.Host = &h
		}
		break
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
		if v.Type != "gun" {
			multiMode = true
		}
		s.GRPCConfig = &conf.GRPCConfig{
			Authority:           v.Authority,
			ServiceName:         v.ServiceName,
			MultiMode:           multiMode,
			IdleTimeout:         60,
			HealthCheckTimeout:  20,
			PermitWithoutStream: false,
			InitialWindowsSize:  65536,
			UserAgent:           "",
		}
		if v.Mode != "gun" {
			s.GRPCConfig.MultiMode = true
		}
		v.Flow = ""
		break
	case "quic":
		t := "none"
		if v.HeaderType != "" {
			t = v.HeaderType
		}

		s.QUICSettings = &conf.QUICConfig{
			Header:   json.RawMessage([]byte(fmt.Sprintf(`{ "type": "%s" }`, t))),
			Security: v.QuicSecurity,
			Key:      v.Key,
		}
		break
	}

	if v.Security == "tls" {
		if v.TlsFingerprint == "" {
			v.TlsFingerprint = "chrome"
		}
		s.TLSSettings = &conf.TLSConfig{
			Fingerprint: v.TlsFingerprint,
			Insecure:    allowInsecure,
		}
		if v.SNI != "" {
			s.TLSSettings.ServerName = v.SNI
		} else {
			s.TLSSettings.ServerName = v.Host
		}
		if v.ALPN != "" {
			s.TLSSettings.ALPN = &conf.StringList{v.ALPN}
		}
	} else if v.Security == "reality" {
		s.REALITYSettings = &conf.REALITYConfig{
			Show:        false,
			Fingerprint: v.TlsFingerprint,
			ServerName:  v.SNI,
			PublicKey:   v.PublicKey,
			ShortId:     v.ShortIds,
			SpiderX:     v.SpiderX,
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
		  "alterId": 0,
          "security": "auto",
          "flow": "%s",
          "encryption": "none"
        }
      ]
    }
  ]
}`, v.Address, v.Port, v.ID, v.Flow)))
	out.Settings = &oset
	return out, nil
}

func (v *Vless) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	return nil, nil
}
