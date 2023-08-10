package xray

import (
	"encoding/json"
	"fmt"
	"strings"
	"xray-knife/utils"
)

func (v *Vmess) Parse(configLink string) error {
	if !strings.HasPrefix(configLink, "vmess://") {
		return fmt.Errorf("vmess unreconized: %s", configLink)
	}

	b64 := configLink[8:]
	decoded, err := utils.Base64Decode(b64)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(decoded, v); err != nil {
		return err
	}
	v.OrigLink = configLink

	return nil
}

func (v *Vmess) DetailsStr() string {
	info := fmt.Sprintf("Protocol: Vless\nRemark: %s\nNetwork: %s\nIP: %s\nPort: %v\nUUID: %s\nType: %s\nTLS: %s\nPATH: %s\n", v.Remark, v.Network, v.Address, v.Port, v.ID, v.Type, v.TLS, v.Path)
	if len(v.TLS) != 0 {
		info += fmt.Sprintf("TLS: yes\nSNI: %s\nALPN:%s\nFingerprint: %s\n", v.SNI, v.ALPN, v.TlsFingerprint)
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
