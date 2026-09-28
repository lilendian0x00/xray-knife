package singbox

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	boxHTTP "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

// HTTP(S) proxy links, the form subscription import writes for Clash,
// sing-box and xray "http" proxies:
//
//	http://USER:PASS@host:port#remark
//	https://USER:PASS@host:port?sni=example.com&insecure=1&fp=chrome#remark
//
// https means TLS to the proxy itself. Accepted parameters (aliases in
// parentheses): sni (peer, servername), insecure (allowInsecure,
// skip-cert-verify), fp, alpn.
//
// An explicit port is required and a path is not allowed: that is what
// tells a proxy link from an ordinary web URL (a subscription address, a
// t.me link), which must not be mistaken for a proxy.

// HTTPProxy is an HTTP or HTTPS proxy outbound. (Http, in http.go, is the
// local mixed inbound used in system mode.)
type HTTPProxy struct {
	Remark         string
	Address        string
	Port           string
	Username       string
	Password       string
	TLS            bool // https://
	SNI            string
	ALPN           string
	TlsFingerprint string
	Insecure       bool
	OrigLink       string
}

func NewHTTPProxy(link string) Protocol {
	return &HTTPProxy{OrigLink: link}
}

func (h *HTTPProxy) Name() string { return C.TypeHTTP }

// IsHTTPProxyLink reports whether link is an http:// or https:// proxy
// link rather than a web URL: it needs an explicit port and no path.
func IsHTTPProxyLink(link string) bool {
	base, _, _ := strings.Cut(strings.TrimSpace(link), "#")
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return false
	}
	return u.Hostname() != "" && u.Port() != "" && (u.Path == "" || u.Path == "/") && u.Opaque == ""
}

func (h *HTTPProxy) Parse() error {
	if !IsHTTPProxyLink(h.OrigLink) {
		return fmt.Errorf("not an http(s) proxy link (want scheme://[user:pass@]host:port with no path): %s", h.OrigLink)
	}
	uri, remark, err := parseShareLink(h.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse HTTP proxy link: %w", err)
	}
	h.TLS = strings.EqualFold(uri.Scheme, "https")
	h.Address, h.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port for HTTP proxy link: %w", err)
	}
	if _, err := parsePort(h.Port); err != nil {
		return fmt.Errorf("http proxy: %w", err)
	}
	if uri.User != nil {
		h.Username = uri.User.Username()
		h.Password, _ = uri.User.Password()
	}
	q := uri.Query()
	h.SNI = queryAny(q, "sni", "peer", "servername")
	h.ALPN = q.Get("alpn")
	h.TlsFingerprint = q.Get("fp")
	h.Insecure = isTrue(queryAny(q, "insecure", "allowInsecure", "skip-cert-verify"))
	h.Remark = remark
	return nil
}

func (h *HTTPProxy) DetailsStr() string {
	scheme := "http"
	if h.TLS {
		scheme = "https"
	}
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), scheme,
		color.RedString("Remark"), h.Remark,
		color.RedString("Address"), h.Address,
		color.RedString("Port"), h.Port,
	)
	if h.Username != "" {
		info += fmt.Sprintf("%s: %s\n%s: %s\n", color.RedString("Username"), h.Username, color.RedString("Password"), h.Password)
	}
	if h.TLS {
		info += fmt.Sprintf("%s: %s\n", color.RedString("SNI"), h.SNI)
		if h.Insecure {
			info += fmt.Sprintf("%s: true\n", color.RedString("Insecure"))
		}
	}
	return info
}

func (h *HTTPProxy) GetLink() string { return h.OrigLink }

func (h *HTTPProxy) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = "http"
	g.Address = h.Address
	g.Port = h.Port
	g.ID = h.Username
	g.Remark = h.Remark
	g.Network = "tcp"
	g.TLS = "none"
	if h.TLS {
		g.TLS = "tls"
		g.SNI = h.SNI
		g.ALPN = h.ALPN
		g.TlsFingerprint = h.TlsFingerprint
	}
	g.OrigLink = h.GetLink()
	return g
}

func (h *HTTPProxy) CraftInboundOptions() (*option.Inbound, error) {
	return nil, fmt.Errorf("http proxy link: inbound not supported (use the http/mixed listener)")
}

func (h *HTTPProxy) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	return h.craftOutbound(allowInsecure, utlsAvailable)
}

func (h *HTTPProxy) craftOutbound(allowInsecure, utls bool) (*option.Outbound, error) {
	port, err := parsePort(h.Port)
	if err != nil {
		return nil, err
	}
	opts := option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverHost(h.Address),
			ServerPort: port,
		},
		Username: h.Username,
		Password: h.Password,
	}
	if h.TLS {
		insecure := "0"
		if h.Insecure {
			insecure = "1"
		}
		opts.TLS, err = buildTLS(tlsParams{
			UTLS:          utls,
			Security:      "tls",
			SNI:           h.SNI,
			ALPN:          h.ALPN,
			Fingerprint:   h.TlsFingerprint,
			AllowInsecure: insecure,
		}, allowInsecure)
		if err != nil {
			return nil, err
		}
	}
	return &option.Outbound{
		Type:    h.Name(),
		Options: &opts,
	}, nil
}

func (h *HTTPProxy) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {
	options, err := h.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}
	httpOptions, ok := options.Options.(*option.HTTPOutboundOptions)
	if !ok {
		return nil, fmt.Errorf("http: unexpected options type %T", options.Options)
	}
	return boxHTTP.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_http", *httpOptions)
}
