package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/xtls/xray-core/infra/conf"
	"net"
	"net/url"
	"strings"
	"xray-knife/utils"
)

func (s *Shadowsocks) Parse(configLink string) error {
	if !strings.HasPrefix(configLink, "ss://") {
		return fmt.Errorf("vmess unreconized: %s", configLink)
	}

	uri, err := url.Parse(configLink)
	if err != nil {
		return err
	}

	secondPart := strings.SplitN(configLink[5:], "@", 2)

	var decoded []byte
	// Encryption part - b64 encoded (EncryptionType : Password)
	if len(secondPart) > 1 {
		decoded, err = utils.Base64Decode(secondPart[0])
		if err != nil {
			return errors.New("Error when decoding secret part ")
		}
	} else {
		return errors.New("Invalid config link ")
	}
	fmt.Println(string(decoded))
	link := "ss://" + string(decoded) + "@" + secondPart[1]
	uri, err = url.Parse(link)
	if err != nil {
		return err
	}

	s.Encryption = uri.User.Username()  // Encryption Type
	s.Password, _ = uri.User.Password() // Encryption Password

	//hostPortRemark := strings.SplitN(secondPart[1], ":", 2)

	s.Address, s.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	s.Remark, err = url.PathUnescape(uri.Fragment)
	if err != nil {
		s.Remark = uri.Fragment
	}

	//s.Address = hostPortRemark[0]
	//
	//PortRemark := strings.SplitN(hostPortRemark[1], "#", 2)
	//s.Port = PortRemark[0]

	//remarkStr, _, _ := strings.Cut(PortRemark[1], "\n")

	//s.Remark, err = url.PathUnescape(remarkStr)
	//if err != nil {
	//	s.Remark = remarkStr
	//}
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
