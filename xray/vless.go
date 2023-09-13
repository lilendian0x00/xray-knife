package xray

import (
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/xtls/xray-core/infra/conf"
	"net/url"
	"reflect"
	"strings"
)

func (v *Vless) Parse(configLink string) error {
	if !strings.HasPrefix(configLink, "vless://") {
		return fmt.Errorf("vmess unreconized: %s", configLink)
	}

	uri, err := url.Parse(configLink)
	if err != nil {
		return err
	}

	v.ID = uri.User.String()
	host := strings.Split(uri.Host, ":")
	v.Address = host[0]
	v.Port = host[1]

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
	v.OrigLink = configLink

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
	info := fmt.Sprintf("%s: Vless\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"),
		color.RedString("Remark"), v.Remark,
		color.RedString("Network"), v.Type,
		color.RedString("Address"), v.Address,
		color.RedString("Port"), v.Port,
		color.RedString("UUID"), v.ID,
		color.RedString("Flow"), copyV.Flow)
	if copyV.Type == "" {

	} else if copyV.HeaderType == "http" || copyV.Type == "ws" || copyV.Type == "h2" {
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
			copyV.SNI = copyV.Host
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
	} else {
		info += fmt.Sprintf("%s: none\n", color.RedString("TLS"))
	}
	return info
}

func (v *Vless) ConvertToGeneralConfig() GeneralConfig {
	var g GeneralConfig
	g.Protocol = "vless"
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
	g.ServiceName = v.ServiceName
	g.Mode = v.Mode
	g.Type = v.Type
	g.OrigLink = v.OrigLink

	return g
}

func (v *Vless) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	out := &conf.OutboundDetourConfig{}
	out.Tag = "proxy"
	out.Protocol = "vless"

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
	case "grpc":
		multiMode := false
		if v.Mode != "gun" {
			multiMode = true
		}
		s.GRPCConfig = &conf.GRPCConfig{
			InitialWindowsSize: 65536,
			HealthCheckTimeout: 20,
			MultiMode:          multiMode,
			IdleTimeout:        60,
			ServiceName:        v.ServiceName,
		}

		v.Flow = ""
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
