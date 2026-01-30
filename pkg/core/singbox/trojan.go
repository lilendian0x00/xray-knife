package singbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v7/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v7/utils"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sing_trojan "github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/xtls/xray-core/infra/conf"
)

func NewTrojan(link string) Protocol {
	return &Trojan{OrigLink: link}
}

func (t *Trojan) Name() string {
	return "trojan"
}

func (t *Trojan) Parse() error {
	if !strings.HasPrefix(t.OrigLink, protocol.TrojanIdentifier) {
		return fmt.Errorf("trojan unreconized: %s", t.OrigLink)
	}
	uri, err := url.Parse(t.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse Trojan link: %w", err)
	}

	t.Password = uri.User.String()
	t.Address, t.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port for Trojan link: %w", err)
	}

	if utils.IsIPv6(t.Address) {
		t.Address = "[" + t.Address + "]"
	}

	query := uri.Query()

	// Validate host and sni parameters before assigning them
	sni := query.Get("sni")
	if !utils.IsValidHostOrSNI(sni) {
		return fmt.Errorf("invalid characters in 'sni' parameter: %s", sni)
	}
	host := query.Get("host")
	if !utils.IsValidHostOrSNI(host) {
		return fmt.Errorf("invalid characters in 'host' parameter: %s", host)
	}

	t.SNI = sni
	t.Host = host

	// Explicitly parse known query parameters
	t.Flow = query.Get("flow")         // Note: Trojan flow (like xtls-rprx-vision) is Xray-specific, not standard in Sing-box Trojan.
	t.Security = query.Get("security") // "tls", "reality", or "" (none)
	t.ALPN = query.Get("alpn")
	t.TlsFingerprint = query.Get("fp")
	t.Type = query.Get("type")               // network type
	t.Path = query.Get("path")               // for ws, http path
	t.HeaderType = query.Get("headerType")   // For TCP HTTP Obfuscation (more of an Xray thing)
	t.ServiceName = query.Get("serviceName") // grpc
	t.Mode = query.Get("mode")               // grpc
	t.PublicKey = query.Get("pbk")           // reality
	t.ShortIds = query.Get("sid")            // reality
	t.SpiderX = query.Get("spx")             // reality
	t.AllowInsecure = query.Get("allowInsecure")
	t.QuicSecurity = query.Get("quicSecurity") // For QUIC transport
	t.Key = query.Get("key")                   // For QUIC transport
	// t.Authority = query.Get("authority") // Not a standard Trojan query param

	unescapedRemark, err := url.PathUnescape(uri.Fragment)
	if err != nil {
		t.Remark = uri.Fragment
	} else {
		t.Remark = unescapedRemark
	}

	// Apply defaults or adjustments
	if t.Type == "ws" || t.Type == "http" { // For Sing-box, common transports for Trojan
		if t.Path == "" {
			t.Path = "/"
		}
	}
	if t.Type == "" {
		t.Type = "tcp" // Default for Trojan
	}
	if t.Security == "" { // Trojan almost always implies TLS or REALITY
		t.Security = "tls"
	}
	if (t.Security == "tls" || t.Security == "reality") && t.TlsFingerprint == "" {
		t.TlsFingerprint = "chrome"
	}

	return nil
}

func (t *Trojan) DetailsStr() string {
	copyV := *t
	if copyV.Flow == "" || copyV.Type == "grpc" {
		copyV.Flow = "none"
	}
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), t.Name(),
		color.RedString("Remark"), t.Remark,
		color.RedString("Network"), t.Type,
		color.RedString("Address"), t.Address,
		color.RedString("Port"), t.Port,
		color.RedString("Password"), t.Password,
		color.RedString("Flow"), copyV.Flow,
	)

	if copyV.Type == "" {

	} else if copyV.Type == "http" || copyV.Type == "httpupgrade" || copyV.Type == "ws" || copyV.Type == "h2" || copyV.Type == "splithttp" {
		info += fmt.Sprintf("%s: %s\n%s: %s\n",
			color.RedString("Host"), copyV.Host,
			color.RedString("Path"), copyV.Path)
	} else if copyV.Type == "kcp" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("KCP Seed"), copyV.Path)
	} else if copyV.Type == "grpc" {
		if copyV.ServiceName == "" {
			copyV.ServiceName = "none"
		}
		info += fmt.Sprintf("%s: %s\n", color.RedString("ServiceName"), copyV.ServiceName)
	}

	if copyV.Security == "reality" {
		info += fmt.Sprintf("%s: reality\n", color.RedString("TLS"))
		if copyV.SpiderX == "" {
			copyV.SpiderX = "none"
		}
		info += fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n",
			color.RedString("Public key"), copyV.PublicKey,
			color.RedString("SNI"), copyV.SNI,
			color.RedString("ShortID"), copyV.ShortIds,
			color.RedString("SpiderX"), copyV.SpiderX,
			color.RedString("Fingerprint"), copyV.TlsFingerprint,
		)
	} else if copyV.Security == "tls" {
		info += fmt.Sprintf("%s: tls\n", color.RedString("TLS"))
		if len(copyV.SNI) == 0 {
			if copyV.Host != "" {
				copyV.SNI = copyV.Host
			} else {
				copyV.SNI = "none"
			}
		}
		if len(copyV.ALPN) == 0 {
			copyV.ALPN = "none"
		}
		if copyV.TlsFingerprint == "" {
			copyV.TlsFingerprint = "none"
		}
		info += fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n",
			color.RedString("SNI"), copyV.SNI,
			color.RedString("ALPN"), copyV.ALPN,
			color.RedString("Fingerprint"), copyV.TlsFingerprint)

		if t.AllowInsecure != "" {
			info += fmt.Sprintf("%s: %v\n",
				color.RedString("Insecure"), t.AllowInsecure)
		}
	} else {
		info += fmt.Sprintf("%s: none\n", color.RedString("TLS"))
	}
	return info
}

func (t *Trojan) GetLink() string {
	return t.OrigLink
}

func (t *Trojan) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = t.Name()
	g.Address = t.Address
	g.Host = t.Host
	g.ID = t.Password
	g.Path = t.Path
	g.Port = t.Port
	g.Remark = t.Remark
	g.SNI = t.SNI
	g.ALPN = t.ALPN
	if t.Security == "" {
		g.TLS = "none"
	} else {
		g.TLS = t.Security
	}
	g.TlsFingerprint = t.TlsFingerprint
	g.ServiceName = t.ServiceName
	g.Mode = t.Mode
	g.Type = t.Type
	g.OrigLink = t.GetLink()

	return g
}

func (t *Trojan) CraftInboundOptions() *option.Inbound {
	port, _ := strconv.Atoi(t.Port)
	addr, _ := netip.ParseAddr(t.Address)

	// TODO: Inbound TLS requires certificates, which are not available from a client link.
	// Therefore, TLS is not configured for the inbound.

	var transport = &option.V2RayTransportOptions{
		Type: t.Type,
	}

	switch t.Type {
	case "ws":
		transport.WebsocketOptions = option.V2RayWebsocketOptions{
			Path: t.Path,
		}
	case "grpc":
		if len(t.ServiceName) > 0 && t.ServiceName[0] == '/' {
			t.ServiceName = t.ServiceName[1:]
		}
		transport.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName: t.ServiceName,
		}
	}

	tapAddr := badoption.Addr(addr)
	opts := option.TrojanInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &tapAddr,
			ListenPort: uint16(port),
		},
		Users: []option.TrojanUser{
			{
				Name:     "user",
				Password: t.Password,
			},
		},
		Transport: transport,
	}

	return &option.Inbound{
		Type:    t.Name(),
		Tag:     "trojan-in",
		Options: opts,
	}
}

func (t *Trojan) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	port, _ := strconv.Atoi(t.Port)

	tls := false
	var alpn []string
	var fingerprint string
	var insecure = allowInsecure

	if t.Security == "tls" || t.Security == "reality" {
		tls = true

		alpn = []string{"http/1.1"}
		if t.ALPN != "" && t.ALPN != "none" {
			alpn = strings.Split(t.ALPN, ",")
		}

		fingerprint = "chrome"
		if t.TlsFingerprint != "" && t.TlsFingerprint != "none" {
			fingerprint = t.TlsFingerprint
		}

		if t.AllowInsecure != "" {
			if t.AllowInsecure == "1" || t.AllowInsecure == "true" {
				insecure = true
			}
		}
	}

	var transport = &option.V2RayTransportOptions{
		Type: t.Type,
	}

	switch t.Type {
	case "tcp":
		break
	case "ws":
		transport.WebsocketOptions = option.V2RayWebsocketOptions{
			Path:                t.Path,
			Headers:             badoption.HTTPHeader{},
			MaxEarlyData:        0,
			EarlyDataHeaderName: "",
		}
		transport.WebsocketOptions.Headers["host"] = badoption.Listable[string]{t.Host}
		transport.WebsocketOptions.Headers["User-Agent"] = badoption.Listable[string]{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"}

		break
	case "http":
		transport.HTTPOptions = option.V2RayHTTPOptions{
			Host:        nil,
			Path:        t.Path,
			Method:      "GET",
			Headers:     nil,
			IdleTimeout: 0,
			PingTimeout: 0,
		}
		if t.Host != "" {
			h := conf.StringList(strings.Split(t.Host, ","))
			transport.HTTPOptions.Host = badoption.Listable[string](h)
		}
		break
	case "httpupgrade":
		transport.HTTPUpgradeOptions = option.V2RayHTTPUpgradeOptions{
			Host:    t.Host,
			Path:    t.Path,
			Headers: nil,
		}
		break
	case "grpc":
		// t.Mode Gun & Multi
		if len(t.ServiceName) > 0 {
			if t.ServiceName[0] == '/' {
				t.ServiceName = t.ServiceName[1:]
			}
		}
		transport.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName: t.ServiceName,
		}
		break
	case "quic":
		transport.QUICOptions = option.V2RayQUICOptions{}
		break
	}

	opts := option.TrojanOutboundOptions{
		DialerOptions: option.DialerOptions{},
		ServerOptions: option.ServerOptions{
			Server:     t.Address,
			ServerPort: uint16(port),
		},
		Password:  t.Password,
		Transport: transport,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    tls,
				ServerName: t.SNI,
				ALPN:       alpn,
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: fingerprint,
				},
				Insecure: insecure,
			},
		},
	}
	if t.Security == "reality" {
		opts.TLS.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: t.PublicKey,
			ShortID:   t.ShortIds,
		}
	}

	return &option.Outbound{
		Type:    t.Name(),
		Options: &opts,
	}, nil
}

func (t *Trojan) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {

	options, err := t.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	trojanOptions, _ := options.Options.(option.TrojanOutboundOptions)
	out, err := sing_trojan.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_trojan", trojanOptions)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed creating trojan outbound: %v", err))
	}

	return out, nil
}
