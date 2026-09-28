package xray

import (
	"errors"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// NormalizeLink trims a share link and lower-cases its scheme, so
// "VLESS://..." parses like "vless://...". Links without "://" are
// returned trimmed.
func NormalizeLink(link string) string {
	link = strings.TrimSpace(link)
	scheme, rest, found := strings.Cut(link, "://")
	if !found {
		return link
	}
	return strings.ToLower(scheme) + "://" + rest
}

func (c *Core) CreateProtocol(configLink string) (protocol.Protocol, error) {
	configLink = NormalizeLink(configLink)

	if mtproto.IsProxyLink(configLink) {
		return nil, mtproto.ErrNotProxyable
	}

	// Read the scheme without url.Parse: a remark such as "#100%" is not
	// a valid URL fragment, but the link is otherwise fine.
	scheme, _, found := strings.Cut(configLink, "://")
	if !found {
		return nil, errors.New("invalid xray protocol")
	}

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
	case protocol.Hysteria2Identifier, "hy2":
		return NewHysteria2(configLink), nil
	default:
		return nil, errors.New("invalid xray protocol")
	}
}

// SingboxReason reports why a parsed link should run on sing-box rather
// than xray-core, or "" when xray can carry it. insecure is the caller's
// global --insecure setting. Reasons:
//   - a transport xray-core removed (h2/http, quic),
//   - a Shadowsocks plugin or legacy stream cipher,
//   - a request to skip TLS verification: xray-core can only pin or verify,
//     so self-signed servers would always fail there. Links that pin their
//     certificate ("pcs") stay on xray, as do transports and features only
//     xray implements (xhttp, kcp, REALITY, TCP HTTP obfuscation).
func SingboxReason(p Protocol, insecure bool) string {
	switch v := p.(type) {
	case *Shadowsocks:
		if v.Plugin != "" {
			// Only move plugins sing-box implements; others fail on both
			// cores, and xray reports that clearly at build time.
			name, _, _ := strings.Cut(v.Plugin, ";")
			switch strings.TrimSpace(name) {
			case "obfs-local", "simple-obfs", "v2ray-plugin":
				return "shadowsocks plugin " + name
			}
			return ""
		}
		return v.xrayUnsupported()
	case *Vless:
		ts := v.transport()
		if enc := strings.ToLower(v.Encryption); enc != "" && enc != "none" {
			// VLESS encryption is xray-only; sing-box would drop it. Keep the
			// link on xray even when insecure TLS then can't be honoured.
			return removedTransport(&ts)
		}
		return ts.singboxReason(insecure || v.wantsInsecure())
	case *Trojan:
		ts := v.transport()
		return ts.singboxReason(insecure || v.wantsInsecure())
	case *Vmess:
		ts := v.transport()
		return ts.singboxReason(insecure || v.wantsInsecure())
	}
	return ""
}

// removedTransport reports a transport only sing-box still implements.
func removedTransport(t *transportSpec) string {
	switch n := t.network(); n {
	case "h2", "http", "quic", "h3":
		return "transport " + n + " (removed from xray-core)"
	}
	return ""
}

func (t *transportSpec) singboxReason(insecure bool) string {
	if reason := removedTransport(t); reason != "" {
		return reason
	}
	// Moving is only worth it when sing-box keeps everything the link
	// says. ECH is dropped by xray-knife's sing-box builders, so such links
	// stay on xray (which warns that insecure can't apply).
	if !insecure || t.security() != "tls" || t.PinnedPeerCertSha256 != "" || t.ECHConfigList != "" {
		return ""
	}
	switch t.network() {
	case "tcp", "raw":
		if ht := strings.ToLower(t.HeaderType); ht != "" && ht != "none" {
			return "" // TCP HTTP obfuscation is xray-only
		}
	case "ws", "grpc", "httpupgrade":
	default:
		return ""
	}
	return "insecure TLS (xray-core cannot skip certificate verification)"
}
