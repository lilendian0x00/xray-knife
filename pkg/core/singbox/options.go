package singbox

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// This file holds the share-link → sing-box option mapping shared by
// vless, vmess and trojan, so the three protocols cannot drift apart.

const wsUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"

// v2rayTransport is the share-link view of a V2Ray transport.
type v2rayTransport struct {
	Network     string // type= (vless, trojan) or net= (vmess)
	HeaderType  string // TCP header obfuscation, "http" or "none"
	Host        string
	Path        string
	ServiceName string // gRPC service name
}

// buildTransport maps a share-link transport onto sing-box options. Plain
// TCP needs no transport at all: sing-box rejects a transport of type "tcp"
// ("unknown transport type: tcp"), so tcp, raw and an empty type yield nil.
func buildTransport(t v2rayTransport) (*option.V2RayTransportOptions, error) {
	switch strings.ToLower(strings.TrimSpace(t.Network)) {
	case "", "tcp", "raw", "none":
		if strings.EqualFold(t.HeaderType, "http") {
			return nil, errors.New("tcp with http header obfuscation is not supported by sing-box (use the xray core)")
		}
		return nil, nil
	case "ws", "websocket":
		path, earlyData := splitEarlyData(t.Path)
		ws := option.V2RayWebsocketOptions{
			Path:    path,
			Headers: badoption.HTTPHeader{"User-Agent": {wsUserAgent}},
		}
		// An empty Host header next to the one net/http derives from the
		// server address makes Go and nginx servers answer 400.
		if t.Host != "" {
			ws.Headers["Host"] = badoption.Listable[string]{t.Host}
		}
		if earlyData > 0 {
			ws.MaxEarlyData = earlyData
			ws.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		}
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket, WebsocketOptions: ws}, nil
	case "http", "h2":
		h := option.V2RayHTTPOptions{Path: t.Path, Method: "GET"}
		if hosts := splitList(t.Host); len(hosts) > 0 {
			h.Host = hosts
		}
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTP, HTTPOptions: h}, nil
	case "httpupgrade":
		return &option.V2RayTransportOptions{
			Type:               C.V2RayTransportTypeHTTPUpgrade,
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{Host: t.Host, Path: t.Path},
		}, nil
	case "grpc", "gun":
		return &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{ServiceName: strings.TrimPrefix(t.ServiceName, "/")},
		}, nil
	case "quic":
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeQUIC}, nil
	default:
		return nil, fmt.Errorf("transport %q is not supported by sing-box (use the xray core)", t.Network)
	}
}

// splitEarlyData strips the v2rayN-style "?ed=2048" early-data hint from a
// WebSocket path and returns the byte count it asked for.
func splitEarlyData(path string) (string, uint32) {
	base, rawQuery, found := strings.Cut(path, "?")
	if !found {
		return path, 0
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return path, 0
	}
	n, err := strconv.ParseUint(q.Get("ed"), 10, 32)
	if err != nil || n == 0 {
		return path, 0
	}
	q.Del("ed")
	if rest := q.Encode(); rest != "" {
		base += "?" + rest
	}
	return base, uint32(n)
}

// tlsParams is the share-link view of an outbound's TLS settings.
type tlsParams struct {
	Security      string // "tls", "reality", "" or "none"
	SNI           string
	ALPN          string
	Fingerprint   string
	AllowInsecure string
	PublicKey     string // REALITY
	ShortID       string // REALITY
	// UTLS allows uTLS (fingerprints, REALITY). Crafting for this binary
	// sets it from the build (utlsAvailable); exports may assume it.
	UTLS bool
}

// buildTLS maps share-link TLS settings onto sing-box options, or returns
// nil when the link has no TLS.
//
// ALPN is only sent when the link asks for it: sing-box's gRPC and HTTP
// transports fall back to h2 only while ALPN is empty, so a blanket
// "http/1.1" breaks them. uTLS is used only when p.UTLS allows it (for this
// binary: the with_utls build tag). Without it Go's TLS stack is used
// instead of failing (plain `go install` builds), except for REALITY, which
// cannot work without uTLS.
func buildTLS(p tlsParams, allowInsecure bool) (*option.OutboundTLSOptions, error) {
	security := strings.ToLower(strings.TrimSpace(p.Security))
	if security != "tls" && security != "reality" {
		return nil, nil
	}
	opts := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: p.SNI,
		Insecure:   allowInsecure || isTrue(p.AllowInsecure),
	}
	if alpn := splitList(p.ALPN); len(alpn) > 0 && !strings.EqualFold(alpn[0], "none") {
		opts.ALPN = alpn
	}

	fp := strings.ToLower(strings.TrimSpace(p.Fingerprint))
	if security == "reality" {
		if !p.UTLS {
			return nil, errors.New("REALITY needs uTLS, which this build lacks (rebuild with -tags with_utls)")
		}
		if fp == "" || fp == "none" {
			fp = "chrome"
		}
		opts.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fp}
		opts.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: p.PublicKey,
			ShortID:   p.ShortID,
		}
		return opts, nil
	}
	if fp != "none" && p.UTLS {
		if fp == "" {
			fp = "chrome"
		}
		opts.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fp}
	}
	return opts, nil
}

// buildStream builds the TLS and transport options of a vless, vmess or
// trojan outbound together, since they constrain each other: the QUIC
// transport needs Go's TLS stack (sing-box cannot hand a uTLS config to
// QUIC), which also rules out REALITY.
func buildStream(tp tlsParams, tr v2rayTransport, allowInsecure bool) (*option.OutboundTLSOptions, *option.V2RayTransportOptions, error) {
	transport, err := buildTransport(tr)
	if err != nil {
		return nil, nil, err
	}
	tlsOpts, err := buildTLS(tp, allowInsecure)
	if err != nil {
		return nil, nil, err
	}
	if transport != nil && transport.Type == C.V2RayTransportTypeQUIC && tlsOpts != nil {
		if tlsOpts.Reality != nil {
			return nil, nil, errors.New("REALITY cannot run over the QUIC transport")
		}
		tlsOpts.UTLS = nil
	}
	return tlsOpts, transport, nil
}

// utlsCrafter is implemented by the protocols whose TLS can use uTLS.
type utlsCrafter interface {
	craftOutbound(allowInsecure, utls bool) (*option.Outbound, error)
}

// CraftOutboundOptionsFor crafts p's outbound like CraftOutboundOptions, but
// with assumeUTLS it crafts as if this build had uTLS: REALITY links and
// uTLS fingerprints (chrome by default) are kept instead of failing or being
// dropped. Exporters that write configs for another sing-box, which ships
// with uTLS, pass assumeUTLS=true; outbounds this binary runs itself must
// come from CraftOutboundOptions (or assumeUTLS=false, the same thing).
func CraftOutboundOptionsFor(p Protocol, allowInsecure, assumeUTLS bool) (*option.Outbound, error) {
	if c, ok := p.(utlsCrafter); ok {
		return c.craftOutbound(allowInsecure, assumeUTLS || utlsAvailable)
	}
	return p.CraftOutboundOptions(allowInsecure)
}

// UTLSAvailable reports whether this build includes uTLS (the with_utls
// build tag), i.e. whether outbounds crafted with uTLS can be instantiated.
func UTLSAvailable() bool { return utlsAvailable }

// listenAddr resolves an inbound listen address to an IP literal. It never
// silently widens to all interfaces: "localhost" becomes 127.0.0.1, "[::1]"
// becomes ::1, an empty address means loopback, and any other non-IP value
// is an error. Pass "0.0.0.0" or "::" to listen everywhere on purpose.
func listenAddr(addr string) (*badoption.Addr, error) {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	switch strings.ToLower(addr) {
	case "", "localhost":
		addr = "127.0.0.1"
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address %q: want an IP address (or localhost)", addr)
	}
	a := badoption.Addr(ip.Unmap())
	return &a, nil
}

// listenOptions builds the ListenOptions of a local inbound.
func listenOptions(addr, port string) (option.ListenOptions, error) {
	listen, err := listenAddr(addr)
	if err != nil {
		return option.ListenOptions{}, err
	}
	p, err := parsePort(port)
	if err != nil {
		return option.ListenOptions{}, err
	}
	return option.ListenOptions{Listen: listen, ListenPort: p}, nil
}

// parsePort parses a TCP/UDP port, rejecting values outside 1-65535.
func parsePort(port string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(port), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid port %q", port)
	}
	return uint16(n), nil
}

// serverHost strips the brackets parsers keep around IPv6 literals, which
// sing-box's ServerOptions do not accept.
func serverHost(addr string) string {
	return strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
}

// parseShareLink parses a share link, taking the "#remark" off first so a
// raw '%' in the remark ("#Speed 100%") cannot fail the whole link. The
// remark is percent-decoded once, leniently.
func parseShareLink(link string) (*url.URL, string, error) {
	base, frag, _ := strings.Cut(strings.TrimSpace(link), "#")
	u, err := url.Parse(base)
	if err != nil {
		return nil, "", err
	}
	remark, err := url.PathUnescape(frag)
	if err != nil {
		remark = frag
	}
	return u, remark, nil
}

// userInfoSecret returns the decoded secret of a "secret@host" or
// "user:pass@host" userinfo. url.Userinfo.String re-escapes the value, so
// "p%40ss" would otherwise be sent verbatim instead of "p@ss".
func userInfoSecret(u *url.Userinfo) string {
	if u == nil {
		return ""
	}
	if pass, ok := u.Password(); ok {
		return u.Username() + ":" + pass
	}
	return u.Username()
}

// quicTLS builds the TLS options of a QUIC protocol (TUIC, Hysteria). QUIC
// needs Go's TLS stack, so there is no uTLS, REALITY or fragmentation.
// defaultALPN is used when the link names none; QUIC cannot negotiate
// without an ALPN.
func quicTLS(sni, alpn string, insecure, disableSNI bool, defaultALPN string) *option.OutboundTLSOptions {
	opts := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: sni,
		Insecure:   insecure,
		DisableSNI: disableSNI,
	}
	if list := splitList(alpn); len(list) > 0 {
		opts.ALPN = list
	} else if defaultALPN != "" {
		opts.ALPN = []string{defaultALPN}
	}
	return opts
}

// queryAny returns the first non-empty value among keys, so one parser
// accepts the spellings different apps emit (allow_insecure, allowInsecure,
// insecure, ...).
func queryAny(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

// splitList splits a comma-separated list, dropping empty items.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func isTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true
	}
	return false
}
