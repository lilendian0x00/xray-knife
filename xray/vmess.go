package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"xray-knife/utils"
)

func method1(v *Vmess, link string) error {
	b64encoded := link[8:]
	decoded, err := utils.Base64Decode(b64encoded)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(decoded, v); err != nil {
		return err
	}
	return nil
}

func method2(v *Vmess, link string) error {
	fullUrl, err := url.Parse(link)
	if err != nil {
		return err
	}
	b64encodedPart := fullUrl.Host
	decoded, err := utils.Base64Decode(b64encodedPart)
	if err != nil {
		return err
	}
	suhp := strings.Split(string(decoded), ":") // security, uuid, address, port
	if len(suhp) != 3 {
		return errors.New(fmt.Sprintf("vmess unreconized: security:addr:port -> %s", suhp))
	}
	v.Security = suhp[0]
	comb := strings.Split(suhp[1], "@") // ID@ADDR
	v.ID = comb[0]
	v.Address = comb[1]
	parseUint, err := strconv.ParseUint(suhp[2], 10, 16)
	if err != nil {
		return err
	}
	v.Port = uint16(parseUint)

	v.Aid = 0

	queryValues := fullUrl.Query()
	if value := queryValues.Get("remarks"); value != "" {
		v.Remark = value
	}

	if value := queryValues.Get("path"); value != "" {
		v.Path = value
	}

	if value := queryValues.Get("tls"); value == "1" {
		v.TLS = "tls"
	}

	if value := queryValues.Get("obfs"); value != "" {
		switch value {
		case "websocket":
			v.Network = "ws"
			v.Type = "none"
		case "none":
			v.Network = "tcp"
			v.Type = "none"
		}
	}
	if value := queryValues.Get("obfsParam"); value != "" {
		v.Host = value
	}
	if value := queryValues.Get("peer"); value != "" {
		v.SNI = value
	} else {
		if v.TLS == "tls" {
			v.SNI = v.Host
		}
	}

	return nil
}

func (v *Vmess) Parse(configLink string) error {
	if !strings.HasPrefix(configLink, "vmess://") {
		return fmt.Errorf("vmess unreconized: %s", configLink)
	}

	if err := method1(v, configLink); err == nil {

	} else if err = method2(v, configLink); err == nil {

	}

	v.OrigLink = configLink

	return nil
}

func (v *Vmess) DetailsStr() string {
	info := fmt.Sprintf("Protocol: Vmess\nRemark: %s\nNetwork: %s\nIP: %s\nPort: %v\nUUID: %s\nType: %s\nTLS: %s\nPATH: %s\n", v.Remark, v.Network, v.Address, v.Port, v.ID, v.Type, v.TLS, v.Path)
	if len(v.TLS) != 0 {
		if len(v.ALPN) == 0 {
			v.ALPN = "none"
		}
		if len(v.TlsFingerprint) == 0 {
			v.TlsFingerprint = "none"
		}
		info += fmt.Sprintf("TLS: yes\nSNI: %s\nALPN: %s\nFingerprint: %s\n", v.SNI, v.ALPN, v.TlsFingerprint)
	}
	return info
}

func (v *Vmess) ConvertToGeneralConfig() (GeneralConfig, error) {
	var g GeneralConfig
	g.Protocol = "vmess"
	g.Address = v.Address
	g.Aid = v.Aid
	g.Host = v.Host
	g.ID = v.ID
	g.Network = v.Network
	g.Path = v.Path
	g.Port = v.Port
	g.Remark = v.Remark
	g.TLS = v.TLS
	g.SNI = v.SNI
	g.ALPN = v.ALPN
	g.TlsFingerprint = v.TlsFingerprint
	g.Type = v.Type
	g.OrigLink = v.OrigLink

	return g, nil
}
