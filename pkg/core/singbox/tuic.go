package singbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sing_tuic "github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

// TUIC v5 share links, in the form v2rayN, NekoBox and Hiddify emit:
//
//	tuic://UUID:PASSWORD@host:port?congestion_control=bbr&udp_relay_mode=native
//	    &alpn=h3&sni=example.com&allow_insecure=1&disable_sni=1#remark
//
// Accepted parameters (aliases in parentheses):
//
//	congestion_control (congestion-control, cc)  cubic, new_reno or bbr
//	udp_relay_mode (udp-relay-mode)              native or quic
//	alpn                                         defaults to h3
//	sni (peer)
//	allow_insecure (allowInsecure, insecure)     1/true
//	disable_sni (disable-sni)                    1/true
//	reduce_rtt (zero_rtt_handshake)              1/true
//
// TUIC v4 links (a token instead of uuid:password) are rejected: sing-box
// only speaks v5.

func NewTuic(link string) Protocol {
	return &Tuic{OrigLink: link}
}

func (t *Tuic) Name() string {
	return protocol.TuicIdentifier
}

func (t *Tuic) Parse() error {
	uri, remark, err := parseShareLink(t.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse TUIC link: %w", err)
	}
	if uri.Scheme != protocol.TuicIdentifier {
		return fmt.Errorf("tuic unrecognized scheme: %s", uri.Scheme)
	}
	if uri.User == nil {
		return errors.New("tuic link has no uuid:password")
	}
	t.UUID = uri.User.Username()
	password, hasPassword := uri.User.Password()
	if !hasPassword {
		return errors.New("tuic link has no password (TUIC v4 token links are not supported)")
	}
	t.Password = password

	t.Address, t.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port for TUIC link: %w", err)
	}
	if _, err := parsePort(t.Port); err != nil {
		return fmt.Errorf("tuic: %w", err)
	}

	q := uri.Query()
	t.CongestionControl = strings.ToLower(queryAny(q, "congestion_control", "congestion-control", "cc"))
	switch t.CongestionControl {
	case "", "cubic", "new_reno", "bbr":
	case "newreno", "new-reno":
		t.CongestionControl = "new_reno"
	default:
		return fmt.Errorf("tuic: unknown congestion control %q", t.CongestionControl)
	}
	t.UDPRelayMode = strings.ToLower(queryAny(q, "udp_relay_mode", "udp-relay-mode"))
	switch t.UDPRelayMode {
	case "", "native", "quic":
	default:
		return fmt.Errorf("tuic: unknown udp relay mode %q", t.UDPRelayMode)
	}
	t.ALPN = q.Get("alpn")
	t.SNI = queryAny(q, "sni", "peer")
	t.Insecure = isTrue(queryAny(q, "allow_insecure", "allowInsecure", "insecure"))
	t.DisableSNI = isTrue(queryAny(q, "disable_sni", "disable-sni"))
	t.ZeroRTT = isTrue(queryAny(q, "reduce_rtt", "zero_rtt_handshake"))
	t.Remark = remark
	return nil
}

func (t *Tuic) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), t.Name(),
		color.RedString("Remark"), t.Remark,
		color.RedString("Address"), t.Address,
		color.RedString("Port"), t.Port,
		color.RedString("UUID"), t.UUID,
		color.RedString("Password"), t.Password,
		color.RedString("SNI"), t.SNI,
	)
	if t.CongestionControl != "" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("Congestion Control"), t.CongestionControl)
	}
	if t.UDPRelayMode != "" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("UDP Relay Mode"), t.UDPRelayMode)
	}
	if t.ALPN != "" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("ALPN"), t.ALPN)
	}
	if t.Insecure {
		info += fmt.Sprintf("%s: true\n", color.RedString("Insecure"))
	}
	return info
}

func (t *Tuic) GetLink() string {
	return t.OrigLink
}

func (t *Tuic) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = t.Name()
	g.Address = t.Address
	g.Port = t.Port
	g.ID = t.UUID
	g.Remark = t.Remark
	g.SNI = t.SNI
	g.ALPN = t.ALPN
	g.TLS = "tls"
	g.Network = "udp"
	g.OrigLink = t.GetLink()
	return g
}

func (t *Tuic) CraftInboundOptions() (*option.Inbound, error) {
	return nil, fmt.Errorf("%s: inbound not supported", t.Name())
}

func (t *Tuic) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	port, err := parsePort(t.Port)
	if err != nil {
		return nil, err
	}
	opts := option.TUICOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverHost(t.Address),
			ServerPort: port,
		},
		UUID:              t.UUID,
		Password:          t.Password,
		CongestionControl: t.CongestionControl,
		UDPRelayMode:      t.UDPRelayMode,
		ZeroRTTHandshake:  t.ZeroRTT,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: quicTLS(t.SNI, t.ALPN, allowInsecure || t.Insecure, t.DisableSNI, "h3"),
		},
	}
	return &option.Outbound{
		Type:    t.Name(),
		Options: &opts,
	}, nil
}

func (t *Tuic) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {
	options, err := t.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}
	tuicOptions, ok := options.Options.(*option.TUICOutboundOptions)
	if !ok {
		return nil, fmt.Errorf("tuic: unexpected options type %T", options.Options)
	}
	return sing_tuic.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_tuic", *tuicOptions)
}
