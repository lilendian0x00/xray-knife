package xray

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
)

func (v *Vless) Parse(configLink string) error {
	if !strings.HasPrefix(configLink, "vless://") {
		return fmt.Errorf("vmess unreconized: %s", configLink)
	}
	nonProtocolPart := configLink[8:]

	secondPart := strings.Split(nonProtocolPart, "@")
	uuid := secondPart[0]

	thirdPart := strings.Split(secondPart[1], "?")
	address := strings.Split(thirdPart[0], ":")

	queryValues, err := url.ParseQuery(strings.Join(thirdPart[1:], "?"))
	if err != nil {
		return err
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
		if values, ok := queryValues[tag]; ok {
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

	remarkIndex := strings.LastIndex(configLink, "#")
	remarkStr, _, _ := strings.Cut(configLink[remarkIndex+1:], "\n")

	v.Remark = remarkStr
	v.ID = uuid
	v.Address = address[0]
	portUint, err := strconv.ParseUint(address[1], 10, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
	v.Port = uint16(portUint)
	v.OrigLink = configLink

	return nil
}

func (v *Vless) DetailsStr() string {
	info := fmt.Sprintf("Protocol: Vless\nRemark: %s\nNetwork: %s\nIP: %s\nPort: %v\nUUID: %s\n", v.Remark, v.Type, v.Address, v.Port, v.ID)
	if v.Type == "" {

	} else if v.Type == "http" || v.Type == "ws" || v.Type == "h2" {
		info += fmt.Sprintf("Host: %s\nPath: %s\n", v.Host, v.Path)
	} else if v.Type == "kcp" {
		info += fmt.Sprintf("KCP Seed: %s\n", v.Path)
	} else if v.Type == "grpc" {
		info += fmt.Sprintf("ServiceName: %s\nPath: %s\n", v.Host, v.Path)
	}

	if v.Security == "reality" {
		info += fmt.Sprintf("TLS: reality\n")
		info += fmt.Sprintf("SNI: %s\nShordID: %s\nSpiderX: %s\nFingerprint: %s\n", v.SNI, v.ShortIds, v.SpiderX, v.TlsFingerprint)
	} else if v.Security == "tls" {
		info += fmt.Sprintf("TLS: tls\n")
		info += fmt.Sprintf("SNI: %s\nALPN:%s\nFingerprint: %s\n", v.SNI, v.ALPN, v.TlsFingerprint)
	} else {
		info += fmt.Sprintf("TLS: none\n")
	}
	return info
}

func (v *Vless) ConvertToGeneralConfig() (GeneralConfig, error) {
	var g GeneralConfig
	g.Protocol = "vless"
	g.Address = v.Address
	g.Host = v.Host
	g.ID = v.ID
	g.Path = v.Path
	g.Port = v.Port
	g.Remark = v.Remark
	g.SNI = v.SNI
	g.ALPN = v.ALPN
	g.TlsFingerprint = v.TlsFingerprint
	g.Type = v.Type
	g.OrigLink = v.OrigLink

	return g, nil
}
