package singbox

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/option"
)

// AnyTLS share links, as NekoBox, Hiddify and mihomo emit them:
//
//	anytls://PASSWORD@host:port/?sni=example.com&insecure=1&fp=chrome&alpn=h2#remark
//
// Accepted parameters (aliases in parentheses):
//
//	sni (peer)
//	insecure (allowInsecure, allow_insecure)  1/true
//	fp                                        uTLS fingerprint (chrome by default)
//	alpn
//	security                                  tls (default) or reality, with pbk and sid
//
// AnyTLS runs over TLS on TCP, so --fragment applies to it.

func NewAnyTLS(link string) Protocol {
	return &AnyTLS{OrigLink: link}
}

func (a *AnyTLS) Name() string {
	return protocol.AnyTLSIdentifier
}

func (a *AnyTLS) Parse() error {
	uri, remark, err := parseShareLink(a.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse AnyTLS link: %w", err)
	}
	if uri.Scheme != protocol.AnyTLSIdentifier {
		return fmt.Errorf("anytls unrecognized scheme: %s", uri.Scheme)
	}
	a.Password = userInfoSecret(uri.User)
	if a.Password == "" {
		return errors.New("anytls link has no password")
	}
	a.Address, a.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port for AnyTLS link: %w", err)
	}
	if _, err := parsePort(a.Port); err != nil {
		return fmt.Errorf("anytls: %w", err)
	}

	q := uri.Query()
	a.Security = strings.ToLower(q.Get("security"))
	switch a.Security {
	case "", "tls":
		a.Security = "tls"
	case "reality":
		a.PublicKey = q.Get("pbk")
		a.ShortID = q.Get("sid")
	default:
		return fmt.Errorf("anytls: unsupported security %q (AnyTLS always uses TLS)", a.Security)
	}
	a.SNI = queryAny(q, "sni", "peer")
	a.ALPN = q.Get("alpn")
	a.TlsFingerprint = q.Get("fp")
	a.Insecure = isTrue(queryAny(q, "insecure", "allowInsecure", "allow_insecure"))
	a.Remark = remark
	return nil
}

func (a *AnyTLS) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), a.Name(),
		color.RedString("Remark"), a.Remark,
		color.RedString("Address"), a.Address,
		color.RedString("Port"), a.Port,
		color.RedString("Password"), a.Password,
		color.RedString("TLS"), a.Security,
		color.RedString("SNI"), a.SNI,
	)
	if a.TlsFingerprint != "" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("Fingerprint"), a.TlsFingerprint)
	}
	if a.Insecure {
		info += fmt.Sprintf("%s: true\n", color.RedString("Insecure"))
	}
	return info
}

func (a *AnyTLS) GetLink() string {
	return a.OrigLink
}

func (a *AnyTLS) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = a.Name()
	g.Address = a.Address
	g.Port = a.Port
	g.ID = a.Password
	g.Remark = a.Remark
	g.SNI = a.SNI
	g.ALPN = a.ALPN
	g.TLS = a.Security
	g.TlsFingerprint = a.TlsFingerprint
	g.Network = "tcp"
	g.OrigLink = a.GetLink()
	return g
}

func (a *AnyTLS) CraftInboundOptions() (*option.Inbound, error) {
	return nil, fmt.Errorf("%s: inbound not supported", a.Name())
}

func (a *AnyTLS) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	return a.craftOutbound(allowInsecure, utlsAvailable)
}

func (a *AnyTLS) craftOutbound(allowInsecure, utls bool) (*option.Outbound, error) {
	port, err := parsePort(a.Port)
	if err != nil {
		return nil, err
	}
	insecure := "0"
	if a.Insecure {
		insecure = "1"
	}
	tlsOpts, err := buildTLS(tlsParams{
		UTLS:          utls,
		Security:      a.Security,
		SNI:           a.SNI,
		ALPN:          a.ALPN,
		Fingerprint:   a.TlsFingerprint,
		AllowInsecure: insecure,
		PublicKey:     a.PublicKey,
		ShortID:       a.ShortID,
	}, allowInsecure)
	if err != nil {
		return nil, err
	}
	opts := option.AnyTLSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverHost(a.Address),
			ServerPort: port,
		},
		Password:                    a.Password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOpts},
	}
	return &option.Outbound{
		Type:    a.Name(),
		Options: &opts,
	}, nil
}
