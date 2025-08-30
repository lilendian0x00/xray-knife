package xray

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	net2 "github.com/GFW-knocker/Xray-core/common/net"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v7/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v7/utils"

	"github.com/GFW-knocker/Xray-core/infra/conf"
	"github.com/fatih/color"
)

func NewShadowsocks(link string) Protocol {
	return &Shadowsocks{OrigLink: link}
}

func (s *Shadowsocks) Name() string {
	return "shadowsocks"
}

func (s *Shadowsocks) Parse() error {
	if !strings.HasPrefix(s.OrigLink, protocol.ShadowsocksIdentifier) {
		return fmt.Errorf("shadowsocks unreconized: %s", s.OrigLink)
	}

	uri, err := url.Parse(s.OrigLink)
	if err != nil {
		return err
	}

	secondPart := strings.SplitN(s.OrigLink[5:], "@", 2)

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

	//link := "ss://" + string(decoded) + "@" + secondPart[1]
	//uri, err := url.Parse(link)
	//if err != nil {
	//	return err
	//}
	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		return errors.New("error when decoding secret part")
	}

	s.Encryption = creds[0] // Encryption Type
	s.Password = creds[1]   // Encryption Password

	//hostPortRemark := strings.SplitN(secondPart[1], ":", 2)

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

	//s.Address = hostPortRemark[0]
	//
	//PortRemark := strings.SplitN(hostPortRemark[1], "#", 2)
	//s.Port = PortRemark[0]

	//remarkStr, _, _ := strings.Cut(PortRemark[1], "\n")

	//s.Remark, err = url.PathUnescape(remarkStr)
	//if err != nil {
	//	s.Remark = remarkStr
	//}

	return nil
}

func (s *Shadowsocks) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), s.Name(),
		color.RedString("Remark"), s.Remark,
		color.RedString("IP"), s.Address,
		color.RedString("Port"), s.Port,
		color.RedString("Encryption"), s.Encryption,
		color.RedString("Password"), s.Password)
	return info
}

func (s *Shadowsocks) GetLink() string {
	if s.OrigLink != "" {
		return s.OrigLink
	} else {
		creds := fmt.Sprintf("%s:%s", s.Encryption, s.Password)
		encodedCreds := base64.StdEncoding.EncodeToString([]byte(creds))

		// The Userinfo part in ss links is the base64 encoded string
		// We construct the final URL string manually as url.URL doesn't handle this specific format directly
		hostPart := net.JoinHostPort(s.Address, s.Port)
		link := fmt.Sprintf("ss://%s@%s", encodedCreds, hostPart)
		if s.Remark != "" {
			link += "#" + url.PathEscape(s.Remark)
		}
		return link
	}
}

func (s *Shadowsocks) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = s.Name()
	g.Address = s.Address
	g.ID = s.Password
	g.Port = s.Port
	g.Remark = s.Remark
	g.OrigLink = s.GetLink()

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
		"uot": false
	}
  ]
}`, s.Address, s.Port, s.Password, s.Encryption)))
	out.Settings = &oset
	return out, nil
}

func (s *Shadowsocks) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	port, err := strconv.ParseUint(s.Port, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("error converting port string to uint32: %w", err)
	}
	uint32Port := uint32(port)

	settingsJSON := fmt.Sprintf(`{
      "method": "%s",
      "password": "%s",
      "network": "tcp,udp"
    }`, s.Encryption, s.Password)

	settings := json.RawMessage(settingsJSON)

	in := &conf.InboundDetourConfig{
		Protocol: s.Name(),
		Tag:      s.Name(),
		ListenOn: &conf.Address{Address: net2.ParseAddress(s.Address)},
		PortList: &conf.PortList{Range: []conf.PortRange{
			{From: uint32Port, To: uint32Port},
		}},
		Settings: &settings,
	}
	return in, nil
}
