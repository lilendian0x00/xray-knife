package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/xtls/xray-core/infra/conf"
	"net/url"
	"strings"
	"xray-knife/utils"
)

func (s *Shadowsocks) Parse(configLink string) error {
	if !strings.HasPrefix(configLink, "ss://") {
		return fmt.Errorf("vmess unreconized: %s", configLink)
	}
	nonProtocolPart := configLink[5:]

	secondPart := strings.SplitN(nonProtocolPart, "@", 2)

	// Encryption part - b64 encoded (EncryptionType : Password)
	encryption, err := utils.Base64Decode(secondPart[0])
	if err != nil {
		return errors.New("Error when decoding secret part ")
	}
	secretPart := strings.SplitN(string(encryption), ":", 2)
	s.Encryption = secretPart[0] // Encryption Type
	s.Password = secretPart[1]   // Encryption Password

	hostPortRemark := strings.SplitN(secondPart[1], ":", 2)
	s.Address = hostPortRemark[0]

	PortRemark := strings.SplitN(hostPortRemark[1], "#", 2)
	s.Port = PortRemark[0]

	remarkStr, _, _ := strings.Cut(PortRemark[1], "\n")

	s.Remark, err = url.PathUnescape(remarkStr)
	if err != nil {
		s.Remark = remarkStr
	}
	s.OrigLink = configLink

	return nil
}

func (s *Shadowsocks) DetailsStr() string {
	info := fmt.Sprintf("%s: Shadowsocks\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"),
		color.RedString("Remark"), s.Remark,
		color.RedString("IP"), s.Address,
		color.RedString("Port"), s.Port,
		color.RedString("Encryption"), s.Encryption,
		color.RedString("Password"), s.Password)
	return info
}

func (s *Shadowsocks) ConvertToGeneralConfig() GeneralConfig {
	var g GeneralConfig
	g.Protocol = "Shadowsocks"
	g.Address = s.Address
	g.ID = s.Password
	g.Port = s.Port
	g.Remark = s.Remark
	g.OrigLink = s.OrigLink

	return g
}

func (s *Shadowsocks) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	out := &conf.OutboundDetourConfig{}
	out.Tag = "proxy"
	out.Protocol = "shadowsocks"

	streamConf := &conf.StreamConfig{}

	out.StreamSetting = streamConf
	oset := json.RawMessage([]byte(fmt.Sprintf(`{
  "servers": [
	{
		"address": "%s",
		"port": %v,
		"password": "%s",
		"method": "%s",
		"uot": true
	}
  ]
}`, s.Address, s.Port, s.Password, s.Encryption)))
	out.Settings = &oset
	return out, nil
}
