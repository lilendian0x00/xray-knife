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
	sing_hysteria2 "github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

func NewHysteria2(link string) Protocol {
	return &Hysteria2{OrigLink: link}
}

func (h *Hysteria2) Name() string {
	return protocol.Hysteria2Identifier
}

// defaultHysteria2Port is the port the Hysteria2 URI scheme implies when the
// link has none.
const defaultHysteria2Port = "443"

func (h *Hysteria2) Parse() error {
	link, hopPorts, err := splitHopPorts(h.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse Hysteria2 link: %w", err)
	}
	uri, remark, err := parseShareLink(link)
	if err != nil {
		return fmt.Errorf("failed to parse Hysteria2 link: %w", err)
	}

	if uri.Scheme != protocol.Hysteria2Identifier && uri.Scheme != "hy2" {
		return fmt.Errorf("hysteria2/hy2 unrecognized scheme: %s", uri.Scheme)
	}

	h.Password = userInfoSecret(uri.User) // Hysteria2 password (auth string)

	h.Address, h.Port = uri.Hostname(), uri.Port()
	if h.Address == "" {
		return fmt.Errorf("hysteria2 link has no server address")
	}
	if h.Port == "" {
		h.Port = defaultHysteria2Port
	}
	if _, err := parsePort(h.Port); err != nil {
		return fmt.Errorf("hysteria2: %w", err)
	}

	query := uri.Query()

	// Explicitly parse known query parameters
	h.SNI = query.Get("sni")
	h.ALPN = query.Get("alpn")
	h.ObfusType = query.Get("obfs")
	h.ObfusPassword = query.Get("obfs-password")
	h.Insecure = query.Get("insecure") // "0", "1", "false", "true"
	h.PinSHA256 = query.Get("pinSHA256")

	// Port hopping: "host:443,20000-30000" in the authority, or v2rayN's mport=.
	if mport := query.Get("mport"); mport != "" {
		extra, err := parsePortRanges(mport)
		if err != nil {
			return fmt.Errorf("hysteria2 mport: %w", err)
		}
		if len(hopPorts) == 0 {
			hopPorts = []string{h.Port + ":" + h.Port}
		}
		hopPorts = append(hopPorts, extra...)
	}
	h.ServerPorts = hopPorts

	h.Remark = remark

	// Default SNI to address if not provided, as Hysteria2 TLS needs it.
	if h.SNI == "" {
		h.SNI = h.Address
	}

	return nil
}

// splitHopPorts pulls a Hysteria2 port-hopping list ("443,20000-30000") out
// of the link's authority, which url.Parse rejects, and returns the link
// rewritten to its first port plus the ranges in sing-box's "start:end" form.
// Links without a list come back unchanged with no ranges.
func splitHopPorts(link string) (string, []string, error) {
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok {
		return link, nil, nil
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	hostStart := strings.LastIndex(authority, "@") + 1
	hostPort := authority[hostStart:]
	colon := strings.LastIndex(hostPort, ":")
	if colon < 0 || strings.LastIndex(hostPort, "]") > colon {
		return link, nil, nil
	}
	portSpec := hostPort[colon+1:]
	if !strings.ContainsAny(portSpec, ",-") {
		return link, nil, nil
	}
	ranges, err := parsePortRanges(portSpec)
	if err != nil {
		return "", nil, err
	}
	first, _, _ := strings.Cut(ranges[0], ":")
	rewritten := scheme + "://" + authority[:hostStart] + hostPort[:colon+1] + first + rest[end:]
	return rewritten, ranges, nil
}

// parsePortRanges parses "443,20000-30000" into sing-box server_ports
// entries ("443:443", "20000:30000").
func parsePortRanges(spec string) ([]string, error) {
	var ranges []string
	for _, item := range splitList(spec) {
		lo, hi, isRange := strings.Cut(item, "-")
		start, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		stop := start
		if isRange {
			if stop, err = parsePort(hi); err != nil {
				return nil, err
			}
		}
		if stop < start {
			return nil, fmt.Errorf("invalid port range %q", item)
		}
		ranges = append(ranges, strconv.Itoa(int(start))+":"+strconv.Itoa(int(stop)))
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("empty port list %q", spec)
	}
	return ranges, nil
}

func (h *Hysteria2) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n",
		color.RedString("Protocol"), h.Name(),
		color.RedString("Remark"), h.Remark,
		color.RedString("Address"), h.Address,
		color.RedString("Port"), h.Port,
		color.RedString("Password"), h.Password,
		color.RedString("SNI"), h.SNI)

	if len(h.ServerPorts) > 0 {
		info += fmt.Sprintf("%s: %s\n", color.RedString("Hop Ports"), strings.Join(h.ServerPorts, ","))
	}
	if h.Insecure != "" {
		info += fmt.Sprintf("%s: %v\n",
			color.RedString("Insecure"), h.Insecure)
	}

	if h.ObfusType != "" {
		info += fmt.Sprintf("%s: %s\n%s: %s\n",
			color.RedString("Obfuscation Type"), h.ObfusType,
			color.RedString("Obfuscation Password"), h.ObfusPassword)
	}
	return info
}

func (h *Hysteria2) GetLink() string {
	return h.OrigLink
}

func (h *Hysteria2) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = h.Name()
	g.Address = h.Address
	g.Port = h.Port
	g.Remark = h.Remark
	g.ID = h.Password
	g.SNI = h.SNI
	g.ALPN = h.ALPN
	g.TLS = "tls"
	g.Network = "udp"

	g.OrigLink = h.GetLink()

	return g
}

func (h *Hysteria2) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	port, err := parsePort(h.Port)
	if err != nil {
		return nil, err
	}

	tlsOpts := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: h.SNI,
		Insecure:   allowInsecure || isTrue(h.Insecure),
	}
	if alpn := splitList(h.ALPN); len(alpn) > 0 {
		tlsOpts.ALPN = alpn
	}

	opts := option.Hysteria2OutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverHost(h.Address),
			ServerPort: port,
		},
		Password:                    h.Password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOpts},
	}
	if len(h.ServerPorts) > 0 {
		opts.ServerPorts = h.ServerPorts
	}

	if h.ObfusType != "" {
		opts.Obfs = &option.Hysteria2Obfs{
			Type:     h.ObfusType,
			Password: h.ObfusPassword,
		}
	}

	return &option.Outbound{
		Type:    h.Name(),
		Options: &opts,
	}, nil
}

func (h *Hysteria2) CraftInboundOptions() (*option.Inbound, error) {
	return nil, fmt.Errorf("%s: inbound not supported", h.Name())
}

func (h *Hysteria2) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {
	options, err := h.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	hy2Options, ok := options.Options.(*option.Hysteria2OutboundOptions)
	if !ok {
		return nil, fmt.Errorf("hysteria2: unexpected options type %T", options.Options)
	}
	out, err := sing_hysteria2.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_hysteria2", *hy2Options)
	if err != nil {
		return nil, err
	}

	return out, nil
}
