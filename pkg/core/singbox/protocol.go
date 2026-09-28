package singbox

import (
	"errors"
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

	// Only the scheme matters here; the parsers deal with the rest (a full
	// url.Parse would reject a raw '%' in the remark).
	scheme, rest, ok := strings.Cut(configLink, "://")
	if !ok {
		return nil, errors.New("invalid singbox protocol")
	}
	scheme = strings.ToLower(scheme)
	configLink = scheme + "://" + rest

	switch scheme {
	case protocol.VmessIdentifier:
		return NewVmess(configLink), nil
	case protocol.VlessIdentifier:
		return NewVless(configLink), nil
	case protocol.ShadowsocksIdentifier:
		return NewShadowsocks(configLink), nil
	case protocol.TrojanIdentifier:
		return NewTrojan(configLink), nil
	case protocol.SocksIdentifier, "socks5", "socks5h":
		return NewSocks(configLink), nil
	case protocol.WireguardIdentifier:
		return NewWireguard(configLink), nil
	case protocol.Hysteria2Identifier:
		return NewHysteria2(configLink), nil
	case "hy2":
		return NewHysteria2(configLink), nil
	case protocol.HysteriaIdentifier:
		return NewHysteria(configLink), nil
	case protocol.TuicIdentifier:
		return NewTuic(configLink), nil
	case protocol.AnyTLSIdentifier:
		return NewAnyTLS(configLink), nil
	case protocol.SSHIdentifier:
		return NewSSH(configLink), nil
	case protocol.HTTPIdentifier, protocol.HTTPSIdentifier:
		// Parse rejects web URLs (no explicit port, or a path).
		return NewHTTPProxy(configLink), nil

	default:
		return nil, errors.New("invalid singbox protocol")
	}
}
