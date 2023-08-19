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

func (t *Trojan) Parse(configLink string) error {
	if !strings.HasPrefix(configLink, "trojan://") {
		return fmt.Errorf("vmess unreconized: %s", configLink)
	}
	nonProtocolPart := configLink[9:]

	secondPart := strings.SplitN(nonProtocolPart, "@", 2)
	uuid := secondPart[0]
	t.Password = uuid

	thirdPart := strings.Split(secondPart[1], "?")
	address := strings.Split(thirdPart[0], ":")
	t.Address = address[0]
	t.Port = address[1]

	queryPart := strings.Join(thirdPart[1:], "?")
	lastIndex := strings.LastIndex(queryPart, "#")
	rmRemark := queryPart[0:lastIndex]

	queryValues, err := url.ParseQuery(rmRemark)
	if err != nil {
		return err
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
		if values, ok := queryValues[tag]; ok {
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

	remarkIndex := strings.LastIndex(configLink, "#")
	remarkStr, _, _ := strings.Cut(configLink[remarkIndex+1:], "\n")

	t.Remark, err = url.PathUnescape(remarkStr)
	if err != nil {
		t.Remark = remarkStr
	}

	//portUint, err := strconv.ParseUint(address[1], 10, 16)
	//if err != nil {
	//	fmt.Fprintf(os.Stderr, "%v", err)
	//	os.Exit(1)
	//}
	//v.Port = uint16(portUint)
	t.OrigLink = configLink

	return nil
}

func (t *Trojan) DetailsStr() string {
	copyV := *t
	if copyV.Flow == "" || copyV.Type == "grpc" {
		copyV.Flow = "none"
	}
	info := fmt.Sprintf("%s: Trojan\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"),
		color.RedString("Remark"), t.Remark,
		color.RedString("Network"), t.Type,
		color.RedString("IP"), t.Address,
		color.RedString("Port"), t.Port,
		color.RedString("Password"), t.Password,
		color.RedString("Flow"), copyV.Flow,
	)

	if copyV.Type == "" {

	} else if copyV.Type == "http" || copyV.Type == "ws" || copyV.Type == "h2" {
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

	if copyV.Security == "tls" {
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

func (t *Trojan) ConvertToGeneralConfig() (GeneralConfig, error) {
	var g GeneralConfig
	g.Protocol = "trojan"
	g.Address = t.Address
	g.Host = t.Host
	g.ID = t.Password
	g.Path = t.Path
	g.Port = t.Port
	g.Remark = t.Remark
	g.SNI = t.SNI
	g.ALPN = t.ALPN
	g.TlsFingerprint = t.TlsFingerprint
	g.ServiceName = t.ServiceName
	g.Mode = t.Mode
	g.Type = t.Type
	g.OrigLink = t.OrigLink

	return g, nil
}

func (t *Trojan) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	out := &conf.OutboundDetourConfig{}
	out.Tag = "proxy"
	out.Protocol = "trojan"

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
						"Host": %s
					}
				}
			}
			`, string(pathb), string(hostb))))
		}
	case "kcp":
		s.KCPSettings = &conf.KCPConfig{}
		s.KCPSettings.HeaderConfig = json.RawMessage([]byte(fmt.Sprintf(`{ "type": "%s" }`, t.Type)))
	case "ws":
		s.WSSettings = &conf.WebSocketConfig{}
		s.WSSettings.Path = t.Path
		s.WSSettings.Headers = map[string]string{
			"Host": t.Host,
		}
	case "h2", "http":
		s.HTTPSettings = &conf.HTTPConfig{
			Path: t.Path,
		}
		if t.Host != "" {
			h := conf.StringList(strings.Split(t.Host, ","))
			s.HTTPSettings.Host = &h
		}
	case "grpc":
		multiMode := false
		if t.Mode != "gun" {
			multiMode = true
		}
		s.GRPCConfig = &conf.GRPCConfig{
			InitialWindowsSize: 65536,
			HealthCheckTimeout: 20,
			MultiMode:          multiMode,
			IdleTimeout:        60,
			ServiceName:        t.ServiceName,
		}

		t.Flow = ""
	}

	if t.Security == "tls" {
		if t.TlsFingerprint == "" {
			t.TlsFingerprint = "chrome"
		}
		s.TLSSettings = &conf.TLSConfig{
			Fingerprint: t.TlsFingerprint,
			Insecure:    allowInsecure,
		}
		if t.SNI != "" {
			s.TLSSettings.ServerName = t.SNI
		} else {
			s.TLSSettings.ServerName = t.Host
		}
		if t.ALPN != "" {
			s.TLSSettings.ALPN = &conf.StringList{t.ALPN}
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
}`, t.Address, t.Port, t.Password, t.Flow)))
	out.Settings = &oset
	return out, nil
}
