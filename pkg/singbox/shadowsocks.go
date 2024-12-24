package singbox

import (
	"context"
	"errors"
	"fmt"
	"github.com/lilendian0x00/xray-knife/v2/pkg/protocol"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing/common/logger"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/lilendian0x00/xray-knife/v2/utils"
)

func NewShadowsocks(link string) Protocol {
	return &Shadowsocks{OrigLink: link}
}

func (s *Shadowsocks) Name() string {
	return protocol.ShadowsocksIdentifier
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
			return errors.New("Error when decoding secret part ")
		}
	} else {
		return errors.New("Invalid config link ")
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

func (s *Shadowsocks) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = s.Name()
	g.Address = s.Address
	g.ID = s.Password
	g.Port = s.Port
	g.Remark = s.Remark
	g.OrigLink = s.OrigLink

	return g
}

func (s *Shadowsocks) CraftInboundOptions() *option.Inbound {
	return &option.Inbound{
		Type: "shadowsocks",
	}
}

func (s *Shadowsocks) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	port, _ := strconv.Atoi(s.Port)

	opts := option.ShadowsocksOutboundOptions{
		DialerOptions: option.DialerOptions{},
		ServerOptions: option.ServerOptions{
			Server:     s.Address,
			ServerPort: uint16(port),
		},
		Password: s.Password,
		Method:   s.Encryption,
	}

	return &option.Outbound{
		Type:               "shadowsocks",
		ShadowsocksOptions: opts,
	}, nil
}

func (s *Shadowsocks) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {

	options, err := s.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	out, err := outbound.New(ctx, adapter.RouterFromContext(ctx), l, "out_shadowsocks", *options)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed creating shadowsocks outbound: %v", err))
	}

	return out, nil
}
