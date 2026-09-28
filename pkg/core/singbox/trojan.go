package singbox

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/utils"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sing_trojan "github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
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
	uri, remark, err := parseShareLink(t.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse Trojan link: %w", err)
	}

	t.Password = userInfoSecret(uri.User)
	t.Address, t.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port for Trojan link: %w", err)
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

	t.Remark = remark

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

func (t *Trojan) CraftInboundOptions() (*option.Inbound, error) {
	listen, err := listenOptions(t.Address, t.Port)
	if err != nil {
		return nil, err
	}

	// TODO: Inbound TLS requires certificates, which are not available from a client link.
	// Therefore, TLS is not configured for the inbound.
	transport, err := buildTransport(v2rayTransport{Network: t.Type, HeaderType: t.HeaderType, Host: t.Host, Path: t.Path, ServiceName: t.ServiceName})
	if err != nil {
		return nil, err
	}

	opts := option.TrojanInboundOptions{
		ListenOptions: listen,
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
		Options: &opts,
	}, nil
}

func (t *Trojan) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	return t.craftOutbound(allowInsecure, utlsAvailable)
}

func (t *Trojan) craftOutbound(allowInsecure, utls bool) (*option.Outbound, error) {
	port, err := parsePort(t.Port)
	if err != nil {
		return nil, err
	}

	tlsOpts, transport, err := buildStream(tlsParams{
		UTLS:          utls,
		Security:      t.Security,
		SNI:           t.SNI,
		ALPN:          t.ALPN,
		Fingerprint:   t.TlsFingerprint,
		AllowInsecure: t.AllowInsecure,
		PublicKey:     t.PublicKey,
		ShortID:       t.ShortIds,
	}, v2rayTransport{Network: t.Type, HeaderType: t.HeaderType, Host: t.Host, Path: t.Path, ServiceName: t.ServiceName}, allowInsecure)
	if err != nil {
		return nil, err
	}

	// xtls flows do not exist for Trojan (xray-core rejects them too); other
	// clients ignore a stray flow= and so does this one.
	opts := option.TrojanOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverHost(t.Address),
			ServerPort: port,
		},
		Password:                    t.Password,
		Transport:                   transport,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOpts},
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

	trojanOptions, ok := options.Options.(*option.TrojanOutboundOptions)
	if !ok {
		return nil, fmt.Errorf("trojan: unexpected options type %T", options.Options)
	}
	out, err := sing_trojan.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_trojan", *trojanOptions)
	if err != nil {
		return nil, fmt.Errorf("failed creating trojan outbound: %w", err)
	}

	return out, nil
}
