package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v4/pkg/protocol"
	"github.com/lilendian0x00/xray-knife/v4/utils"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing/common/logger"
	"github.com/xtls/xray-core/infra/conf"
)

func NewSocks(link string) Protocol {
	return &Socks{OrigLink: link}
}

func (s *Socks) Name() string {
	return protocol.SocksIdentifier
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

func (s *Socks) GetLink() string {
	return s.OrigLink
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

func (s *Socks) CraftInboundOptions() *option.Inbound {
	port, _ := strconv.Atoi(s.Port)
	addr, _ := netip.ParseAddr(s.Address)

	opts := option.SocksInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:                      option.NewListenAddress(addr),
			ListenPort:                  uint16(port),
			TCPFastOpen:                 false,
			TCPMultiPath:                false,
			UDPFragment:                 nil,
			UDPFragmentDefault:          false,
			UDPTimeout:                  0,
			ProxyProtocol:               false,
			ProxyProtocolAcceptNoHeader: false,
			Detour:                      "",
			InboundOptions:              option.InboundOptions{},
		},
		Users: nil,
	}
	return &option.Inbound{
		Type:         s.Name(),
		SocksOptions: opts,
	}
}

func (s *Socks) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	// Port type checker
	var port, _ = strconv.Atoi(s.Port)

	opts := option.SocksOutboundOptions{
		DialerOptions: option.DialerOptions{},
		ServerOptions: option.ServerOptions{
			Server:     s.Address,
			ServerPort: uint16(port),
		},
		Username: s.Username,
		Password: s.Password,
	}

	return &option.Outbound{
		Type:         s.Name(),
		SocksOptions: opts,
	}, nil
}

func (s *Socks) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {
	options, err := s.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	out, err := outbound.New(ctx, adapter.RouterFromContext(ctx), l, "out_socks", *options)
	if err != nil {
		return nil, err
	}

	return out, nil
}
