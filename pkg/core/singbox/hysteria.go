package singbox

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sing_hysteria "github.com/sagernet/sing-box/protocol/hysteria"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

// Hysteria v1 share links, per the Hysteria 1 URI scheme (also what NekoBox
// and Hiddify emit):
//
//	hysteria://host:port?protocol=udp&auth=SECRET&peer=example.com&insecure=1
//	    &upmbps=100&downmbps=100&alpn=hysteria&obfs=xplus&obfsParam=OBFS#remark
//
// Accepted parameters (aliases in parentheses):
//
//	protocol                  udp only; faketcp and wechat-video are not in sing-box
//	auth (auth_str)           authentication string; userinfo is accepted too
//	peer (sni)
//	insecure (allowInsecure)  1/true
//	upmbps (up), downmbps (down)
//	                          required by Hysteria; defaults below when missing
//	alpn                      defaults to "hysteria"
//	obfs, obfsParam           xplus obfuscation password (obfsParam, or obfs when
//	                          it holds the password itself)
//	mport                     port-hopping ranges, as for Hysteria2
//
// Port hopping in the authority ("host:443,20000-30000") works too.

// Hysteria v1 needs both bandwidth hints; these apply when a link has none.
const (
	defaultHysteriaUpMbps   = 10
	defaultHysteriaDownMbps = 50
)

func NewHysteria(link string) Protocol {
	return &Hysteria{OrigLink: link}
}

func (h *Hysteria) Name() string {
	return protocol.HysteriaIdentifier
}

func (h *Hysteria) Parse() error {
	link, hopPorts, err := splitHopPorts(h.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse Hysteria link: %w", err)
	}
	uri, remark, err := parseShareLink(link)
	if err != nil {
		return fmt.Errorf("failed to parse Hysteria link: %w", err)
	}
	if uri.Scheme != protocol.HysteriaIdentifier {
		return fmt.Errorf("hysteria unrecognized scheme: %s", uri.Scheme)
	}

	h.Address, h.Port = uri.Hostname(), uri.Port()
	if h.Address == "" || h.Port == "" {
		return fmt.Errorf("hysteria link needs host:port")
	}
	if _, err := parsePort(h.Port); err != nil {
		return fmt.Errorf("hysteria: %w", err)
	}

	q := uri.Query()
	switch mode := strings.ToLower(q.Get("protocol")); mode {
	case "", "udp":
	default:
		return fmt.Errorf("hysteria transport %q is not supported (only udp)", mode)
	}
	h.Auth = queryAny(q, "auth", "auth_str")
	if h.Auth == "" {
		h.Auth = userInfoSecret(uri.User)
	}
	h.SNI = queryAny(q, "peer", "sni")
	h.ALPN = q.Get("alpn")
	h.Insecure = isTrue(queryAny(q, "insecure", "allowInsecure"))
	if h.UpMbps, err = mbps(queryAny(q, "upmbps", "up"), defaultHysteriaUpMbps); err != nil {
		return fmt.Errorf("hysteria upmbps: %w", err)
	}
	if h.DownMbps, err = mbps(queryAny(q, "downmbps", "down"), defaultHysteriaDownMbps); err != nil {
		return fmt.Errorf("hysteria downmbps: %w", err)
	}
	obfs := q.Get("obfs")
	switch {
	case q.Get("obfsParam") != "":
		h.ObfsPassword = q.Get("obfsParam")
	case obfs != "" && !strings.EqualFold(obfs, "xplus"):
		h.ObfsPassword = obfs
	}

	if mport := q.Get("mport"); mport != "" {
		extra, err := parsePortRanges(mport)
		if err != nil {
			return fmt.Errorf("hysteria mport: %w", err)
		}
		if len(hopPorts) == 0 {
			hopPorts = []string{h.Port + ":" + h.Port}
		}
		hopPorts = append(hopPorts, extra...)
	}
	h.ServerPorts = hopPorts
	h.Remark = remark
	if h.SNI == "" {
		h.SNI = h.Address
	}
	return nil
}

// mbps parses a bandwidth hint such as "100" or "100 Mbps", or returns def.
func mbps(s string, def int) (int, error) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), "mbps"))
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid value %q", s)
	}
	return n, nil
}

func (h *Hysteria) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %d/%d\n",
		color.RedString("Protocol"), h.Name(),
		color.RedString("Remark"), h.Remark,
		color.RedString("Address"), h.Address,
		color.RedString("Port"), h.Port,
		color.RedString("Auth"), h.Auth,
		color.RedString("SNI"), h.SNI,
		color.RedString("Up/Down Mbps"), h.UpMbps, h.DownMbps,
	)
	if len(h.ServerPorts) > 0 {
		info += fmt.Sprintf("%s: %s\n", color.RedString("Hop Ports"), strings.Join(h.ServerPorts, ","))
	}
	if h.ObfsPassword != "" {
		info += fmt.Sprintf("%s: xplus %s\n", color.RedString("Obfuscation"), h.ObfsPassword)
	}
	if h.Insecure {
		info += fmt.Sprintf("%s: true\n", color.RedString("Insecure"))
	}
	return info
}

func (h *Hysteria) GetLink() string {
	return h.OrigLink
}

func (h *Hysteria) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = h.Name()
	g.Address = h.Address
	g.Port = h.Port
	g.ID = h.Auth
	g.Remark = h.Remark
	g.SNI = h.SNI
	g.ALPN = h.ALPN
	g.TLS = "tls"
	g.Network = "udp"
	g.OrigLink = h.GetLink()
	return g
}

func (h *Hysteria) CraftInboundOptions() (*option.Inbound, error) {
	return nil, fmt.Errorf("%s: inbound not supported", h.Name())
}

func (h *Hysteria) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	port, err := parsePort(h.Port)
	if err != nil {
		return nil, err
	}
	opts := option.HysteriaOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverHost(h.Address),
			ServerPort: port,
		},
		UpMbps:     h.UpMbps,
		DownMbps:   h.DownMbps,
		Obfs:       h.ObfsPassword,
		AuthString: h.Auth,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			// sing-quic falls back to the "hysteria" ALPN itself.
			TLS: quicTLS(h.SNI, h.ALPN, allowInsecure || h.Insecure, false, ""),
		},
	}
	if len(h.ServerPorts) > 0 {
		opts.ServerPorts = h.ServerPorts
	}
	return &option.Outbound{
		Type:    h.Name(),
		Options: &opts,
	}, nil
}

func (h *Hysteria) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {
	options, err := h.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}
	hyOptions, ok := options.Options.(*option.HysteriaOutboundOptions)
	if !ok {
		return nil, fmt.Errorf("hysteria: unexpected options type %T", options.Options)
	}
	return sing_hysteria.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_hysteria", *hyOptions)
}
