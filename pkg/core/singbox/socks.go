package singbox

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/sagernet/sing/common/auth"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/utils"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sing_socks "github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
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

	uri, remark, err := parseShareLink(s.OrigLink)
	if err != nil {
		return err
	}
	s.Remark = remark
	s.Address, s.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	if uri.User != nil && len(uri.User.String()) != 0 {
		if password, hasPassword := uri.User.Password(); hasPassword {
			// Plain "user:pass" userinfo.
			s.Username = uri.User.Username()
			s.Password = password
		} else if decoded, decErr := utils.Base64Decode(uri.User.Username()); decErr == nil {
			if user, pass, found := strings.Cut(string(decoded), ":"); found {
				// Base64-encoded "user:pass".
				s.Username = user
				s.Password = pass
			} else {
				// Base64 without a colon: treat the raw userinfo as the username.
				s.Username = uri.User.Username()
			}
		} else {
			// Not base64: treat the raw userinfo as the username.
			s.Username = uri.User.Username()
		}
	}

	return nil
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
		info += "\n"
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

	g.OrigLink = s.GetLink()

	return g
}

func (s *Socks) CraftInboundOptions() (*option.Inbound, error) {
	listen, err := listenOptions(s.Address, s.Port)
	if err != nil {
		return nil, err
	}
	opts := option.SocksInboundOptions{ListenOptions: listen}
	if s.Username != "" && s.Password != "" {
		opts.Users = []auth.User{
			{
				Username: s.Username,
				Password: s.Password,
			},
		}
	}

	return &option.Inbound{
		Type:    s.Name(),
		Options: &opts,
	}, nil
}

func (s *Socks) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	port, err := parsePort(s.Port)
	if err != nil {
		return nil, err
	}

	opts := option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverHost(s.Address),
			ServerPort: port,
		},
		Username: s.Username,
		Password: s.Password,
	}

	return &option.Outbound{
		Type:    s.Name(),
		Options: &opts,
	}, nil
}

func (s *Socks) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {
	options, err := s.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	socksOptions, ok := options.Options.(*option.SOCKSOutboundOptions)
	if !ok {
		return nil, fmt.Errorf("socks: unexpected options type %T", options.Options)
	}
	out, err := sing_socks.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_socks", *socksOptions)
	if err != nil {
		return nil, err
	}

	return out, nil
}
