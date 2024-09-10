package xray

import (
	"encoding/json"
	"fmt"
	"github.com/lilendian0x00/xray-knife/internal/protocol"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/lilendian0x00/xray-knife/utils"
	net2 "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

func NewSocks(link string) Protocol {
	return &Socks{OrigLink: link}
}

func (s *Socks) Name() string {
	return "socks"
}

func (s *Socks) Parse() error {
	if !strings.HasPrefix(s.OrigLink, protocol.SocksIdentifier) {
		return fmt.Errorf("socks unreconized: %s", s.OrigLink)
	}

	var err error = nil

	uri, err := url.Parse(s.OrigLink)
	if err != nil {
		return err
	}
	s.Remark = uri.Fragment
	s.Address, s.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	if len(uri.User.String()) != 0 {
		userB64, _ := utils.Base64Decode(uri.User.String())
		creds := strings.Split(string(userB64), ":")
		s.Username = creds[0]
		s.Password = creds[1]
	}

	s.OrigLink = s.OrigLink

	return err
}

func (s *Socks) DetailsStr() string {
	copyV := *s

	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n",
		color.RedString("Protocol"), s.Name(),
		color.RedString("Remark"), copyV.Remark,
		color.RedString("Network"), "tcp",
		color.RedString("Address"), copyV.Address,
		color.RedString("Port"), copyV.Port,
	)

	if len(copyV.Username) != 0 && len(copyV.Password) != 0 {
		info += color.RedString("Username") + ": " + copyV.Username
		info += "\n"
		info += color.RedString("Password") + ": " + copyV.Password
	}

	return info
}

func (s *Socks) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = s.Name()
	g.Address = s.Address
	g.Port = fmt.Sprintf("%v", s.Port)
	g.Remark = s.Remark

	g.OrigLink = s.OrigLink

	return g
}

func (s *Socks) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	out := &conf.OutboundDetourConfig{}
	out.Tag = "proxy"
	out.Protocol = "socks"

	p := conf.TransportProtocol("tcp")
	sc := &conf.StreamConfig{
		Network: &p,
	}

	sc.TCPSettings = &conf.TCPConfig{}

	out.StreamSetting = sc
	var users string
	if s.Username != "" {
		users += fmt.Sprintf("{\n \"user\": \"%s\",\n\"pass\": \"%s\" \n}", s.Username, s.Password)
	}
	oset := json.RawMessage([]byte(fmt.Sprintf(`{
  "servers": [
    {
      "address": "%s",
      "port": %v,
      "users": [
         %s
      ]
    }
  ]
}`, s.Address, s.Port, users)))

	out.Settings = &oset
	return out, nil
}

func (s *Socks) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	p := conf.TransportProtocol("tcp")
	in := &conf.InboundDetourConfig{
		Protocol: s.Name(),
		Tag:      s.Name(),
		Settings: nil,
		StreamSetting: &conf.StreamConfig{
			Network: &p,
		},
		ListenOn: &conf.Address{},
	}
	// Convert string to uint32
	uint32Value, err := strconv.ParseUint(s.Port, 10, 32)
	if err != nil {
		log.Fatalln("Error converting string to uint32:", err)
	}

	// Convert uint64 to uint32
	uint32Result := uint32(uint32Value)

	// Parse addr
	in.ListenOn.Address = net2.ParseAddress(s.Address)
	in.PortList = &conf.PortList{Range: []conf.PortRange{
		{From: uint32Result, To: uint32Result},
	}}

	var auth = "noauth"
	var accounts = ""
	if len(s.Username) != 0 {
		auth = "password"
		accounts = fmt.Sprintf("{\n\"user\": \"%s\",\n\"pass\": \"%s\"\n}", s.Username, s.Password)
	}

	oset := json.RawMessage([]byte(fmt.Sprintf(`{
	  "auth": "%s",
        "accounts": [
    		%s
  		],
        "udp": true,
        "allowTransparent": false
	}`, auth, accounts)))
	in.Settings = &oset

	return in, nil
}
