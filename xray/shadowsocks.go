package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/xtls/xray-core/infra/conf"

	"github.com/lilendian0x00/xray-knife/v2/utils"
)

func NewShadowsocks() Protocol {
	return &Shadowsocks{}
}

func (s *Shadowsocks) Name() string {
	return "shadowsocks"
}

func (s *Shadowsocks) Parse(configLink string) error {
	if !strings.HasPrefix(configLink, ShadowsocksIdentifier) {
		return fmt.Errorf("shadowsocks unreconized: %s", configLink)
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
			return errors.New("error when decoding secret part")
		}
	} else {
		return errors.New("invalid config link")
	}

	// link := "ss://" + string(decoded) + "@" + secondPart[1]
	// uri, err := url.Parse(link)
	// if err != nil {
	//	return err
	// }
	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		return errors.New("error when decoding secret part")
	}

	s.Encryption = creds[0] // Encryption Type
	s.Password = creds[1]   // Encryption Password

	// hostPortRemark := strings.SplitN(secondPart[1], ":", 2)

	s.Address, s.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	if utils.IsIPv6(s.Address) {
		s.Address = "[" + s.Address + "]"
	}

	s.Remark, err = url.PathUnescape(uri.Fragment)
	if err != nil {
		s.Remark = uri.Fragment
	}

	// s.Address = hostPortRemark[0]
	//
	// PortRemark := strings.SplitN(hostPortRemark[1], "#", 2)
	// s.Port = PortRemark[0]

	// remarkStr, _, _ := strings.Cut(PortRemark[1], "\n")

	// s.Remark, err = url.PathUnescape(remarkStr)
	// if err != nil {
	//	s.Remark = remarkStr
	// }
	s.OrigLink = configLink

	return nil
}

func (s *Shadowsocks) DetailsStr() string {
	return detailsToStr(s.details())
}

func (s *Shadowsocks) DetailsMap() map[string]string {
	return detailsToMap(s.details())
}

func (s *Shadowsocks) details() [][2]string {
	return [][2]string{
		{"Protocol", s.Name()},
		{"Remark", s.Remark},
		{"IP", s.Address},
		{"Port", s.Port},
		{"Encryption", s.Encryption},
		{"Password", s.Password},
	}
}

func (s *Shadowsocks) ConvertToGeneralConfig() GeneralConfig {
	var g GeneralConfig
	g.Protocol = s.Name()
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
	out.Protocol = s.Name()

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

func (s *Shadowsocks) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	return nil, nil
}
