package singbox

import (
	"context"
	"fmt"
	"github.com/lilendian0x00/xray-knife/v7/pkg/core/protocol"
	"net"
	"net/url"
	"strconv"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing/common/logger"
)

func NewHysteria2(link string) Protocol {
	return &Hysteria2{OrigLink: link}
}

func (h *Hysteria2) Name() string {
	return protocol.Hysteria2Identifier
}

func (h *Hysteria2) Parse() error {
	uri, err := url.Parse(h.OrigLink)
	if err != nil {
		return fmt.Errorf("failed to parse Hysteria2 link: %w", err)
	}

	if uri.Scheme != protocol.Hysteria2Identifier && uri.Scheme != "hy2" {
		return fmt.Errorf("hysteria2/hy2 unrecognized scheme: %s", uri.Scheme)
	}

	h.Password = uri.User.String() // Hysteria2 password (auth string)

	h.Address, h.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port for Hysteria2 link: %w", err)
	}

	query := uri.Query()

	// Explicitly parse known query parameters
	h.SNI = query.Get("sni")
	// ALPN for Hysteria2 is often handled by the protocol itself, but if specified:
	// h.ALPN = query.Get("alpn")
	h.ObfusType = query.Get("obfs")
	h.ObfusPassword = query.Get("obfs-password")
	h.Insecure = query.Get("insecure") // "0", "1", "false", "true"

	unescapedRemark, err := url.PathUnescape(uri.Fragment)
	if err != nil {
		h.Remark = uri.Fragment
	} else {
		h.Remark = unescapedRemark
	}

	// Default SNI to address if not provided, as Hysteria2 TLS needs it.
	if h.SNI == "" {
		h.SNI = h.Address
	}

	return nil
}

func (h *Hysteria2) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n",
		color.RedString("Protocol"), h.Name(),
		color.RedString("Remark"), h.Remark,
		color.RedString("Address"), h.Address,
		color.RedString("Port"), h.Port,
		color.RedString("Password"), h.Password,
		color.RedString("SNI"), h.SNI)

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

	g.OrigLink = h.GetLink()

	return g
}

func (h *Hysteria2) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	port, _ := strconv.Atoi(h.Port)
	var insecure = allowInsecure

	if h.Insecure != "" {
		if h.Insecure == "1" || h.Insecure == "true" {
			insecure = true
		}
	}

	opts := option.Hysteria2OutboundOptions{
		DialerOptions: option.DialerOptions{},
		ServerOptions: option.ServerOptions{
			Server:     h.Address,
			ServerPort: uint16(port),
		},
		Password: h.Password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: h.SNI,
				Insecure:   insecure,
			},
		},
	}

	if h.ObfusType != "" {
		opts.Obfs = &option.Hysteria2Obfs{
			Type:     h.ObfusType,
			Password: h.ObfusPassword,
		}
	}

	return &option.Outbound{
		Type:             h.Name(),
		Hysteria2Options: opts,
	}, nil
}

func (h *Hysteria2) CraftInboundOptions() *option.Inbound {
	return &option.Inbound{
		Type: h.Name(),
	}
}

func (h *Hysteria2) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {
	options, err := h.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	out, err := outbound.New(ctx, adapter.RouterFromContext(ctx), l, "out_hysteria2", *options)
	if err != nil {
		return nil, err
	}

	//out, err := outbound.NewHysteria2(ctx, adapter.RouterFromContext(ctx), l, "out_hysteria2", h.CraftOptions())
	//if err != nil {
	//	return nil, errors.New(fmt.Sprintf("failed creating hysteria2 outbound: %v", err))
	//}

	return out, nil
}
