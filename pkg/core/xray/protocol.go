package xray

import (
	"errors"
	"net/url"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

func (c *Core) CreateProtocol(configLink string) (protocol.Protocol, error) {
	// Remove any spaces
	configLink = strings.TrimSpace(configLink)

	if mtproto.IsProxyLink(configLink) {
		return nil, mtproto.ErrNotProxyable
	}

	// Parse url
	uri, err := url.Parse(configLink)
	if err != nil {
		return nil, err
	}

	switch uri.Scheme {
	case protocol.VmessIdentifier:
		return NewVmess(configLink), nil
	case protocol.VlessIdentifier:
		return NewVless(configLink), nil
	case protocol.ShadowsocksIdentifier:
		return NewShadowsocks(configLink), nil
	case protocol.TrojanIdentifier:
		return NewTrojan(configLink), nil
	case protocol.SocksIdentifier:
		return NewSocks(configLink), nil
	case protocol.WireguardIdentifier:
		return NewWireguard(configLink), nil
	case protocol.Hysteria2Identifier, "hy2":
		return NewHysteria2(configLink), nil
	default:
		return nil, errors.New("invalid xray protocol")
	}
}
