package xray

import (
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/lilendian0x00/xray-knife/v2/pkg/protocol"
	"github.com/lilendian0x00/xray-knife/v2/utils"
	"github.com/xtls/xray-core/infra/conf"
	"net"
	"net/url"
	"reflect"
	"strings"
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
	//portUint, err := strconv.ParseUint(address[1], 10, 16)
	//if err != nil {
	//	fmt.Fprintf(os.Stderr, "%v", err)
	//	os.Exit(1)
	//}
	//v.Port = uint16(portUint)

	if v.HeaderType == "http" || v.Type == "ws" || v.Type == "h2" {
		if v.Path == "" {
			v.Path = "/"
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

	} else if copyV.HeaderType == "xhttp" || copyV.HeaderType == "http" || copyV.Type == "httpupgrade" || copyV.Type == "ws" || copyV.Type == "h2" || copyV.Type == "splithttp" {
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
	//case "", "http":
	case "xhttp":
		s.XHTTPSettings = &conf.SplitHTTPConfig{
			Host: v.Host,
			Path: v.Path,
			Mode: v.Mode,
		}
		//if v.Host != "" {
		//	h := conf.StringList(strings.Split(v.Host, ","))
		//	s.XHTTPSettings.Host = &h
		//}
		if v.Mode == "" {
			s.XHTTPSettings.Mode = "auto"
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
		//case "quic":
		//	t := "none"
		//	if v.HeaderType != "" {
		//		t = v.HeaderType
		//	}
		//
		//	s.QUICSettings = &conf.QUICConfig{
		//		Header:   json.RawMessage([]byte(fmt.Sprintf(`{ "type": "%s" }`, t))),
		//		Security: v.QuicSecurity,
		//		Key:      v.Key,
		//	}
		//	break
	}

	if v.Security == "tls" {
		var insecure = allowInsecure
		if v.AllowInsecure != "" {
			if v.AllowInsecure == "1" || v.AllowInsecure == "true" {
				insecure = true
			}
		}

		if v.TlsFingerprint == "" {
			v.TlsFingerprint = "chrome"
		}
		s.TLSSettings = &conf.TLSConfig{
			Fingerprint: v.TlsFingerprint,
			Insecure:    insecure,
		}
		if v.SNI != "" {
			s.TLSSettings.ServerName = v.SNI
		} else {
			s.TLSSettings.ServerName = v.Host
		}
		if v.ALPN != "" {
			alpns := conf.StringList(strings.Split(v.ALPN, ","))
			s.TLSSettings.ALPN = &alpns
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
	oset := json.RawMessage(fmt.Sprintf(`{
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
}`, v.Address, v.Port, v.ID, v.Flow))
	out.Settings = &oset
	return out, nil
}

func (v *Vless) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	return nil, nil
}
