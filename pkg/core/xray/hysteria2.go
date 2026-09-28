package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/xtls/xray-core/infra/conf"
)

func NewHysteria2(link string) Protocol {
	return &Hysteria2{OrigLink: link}
}

func (h *Hysteria2) Name() string {
	return protocol.Hysteria2Identifier
}

func (h *Hysteria2) Parse() error {
	base, remark := splitRemark(h.OrigLink)
	base, h.Ports = extractPortHopping(base)
	uri, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("failed to parse Hysteria2 link: %w", err)
	}

	// Accept both "hysteria2://" and the common "hy2://" alias.
	if uri.Scheme != protocol.Hysteria2Identifier && uri.Scheme != "hy2" {
		return fmt.Errorf("hysteria2/hy2 unrecognized scheme: %s", uri.Scheme)
	}

	// Hysteria2 auth string, decoded ("user:pass" auth keeps its colon).
	h.Password = userSecret(uri.User)

	// The URI scheme defaults the port to 443 when it is omitted.
	h.Address = uri.Hostname()
	h.Port = uri.Port()
	if h.Port == "" {
		h.Port = "443"
	}
	if h.Address == "" {
		return fmt.Errorf("hysteria2 link has no server address")
	}

	query := uri.Query()
	h.SNI = strings.TrimSpace(query.Get("sni"))
	h.ObfusType = query.Get("obfs")
	h.ObfusPassword = query.Get("obfs-password")
	h.Insecure = query.Get("insecure") // "0", "1", "false", "true"
	h.PinSHA256 = query.Get("pinSHA256")
	if mport := query.Get("mport"); mport != "" && h.Ports == "" {
		h.Ports = mport
	}

	if h.SNI != "" && !validSNI(h.SNI) {
		return fmt.Errorf("invalid characters in 'sni' parameter: %q", h.SNI)
	}

	h.Remark = remark

	// Hysteria2 mandates TLS, which needs a server name. Fall back to the
	// (unbracketed) address when SNI is omitted.
	if h.SNI == "" {
		h.SNI = h.Address
	}

	return nil
}

// extractPortHopping rewrites "host:443,20000-30000" (port hopping) to
// "host:443" so url.Parse accepts it, returning the full port spec.
func extractPortHopping(link string) (string, string) {
	scheme, rest, found := strings.Cut(link, "://")
	if !found {
		return link, ""
	}
	end := strings.IndexAny(rest, "/?")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	colon := strings.LastIndex(authority, ":")
	if colon < 0 || strings.LastIndex(authority, "]") > colon {
		return link, ""
	}
	ports := authority[colon+1:]
	if !strings.ContainsAny(ports, ",-") {
		return link, ""
	}
	first := ports
	if i := strings.IndexAny(first, ",-"); i >= 0 {
		first = first[:i]
	}
	return scheme + "://" + authority[:colon+1] + first + rest[end:], ports
}

func (h *Hysteria2) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), h.Name(),
		color.RedString("Remark"), h.Remark,
		color.RedString("Network"), "quic",
		color.RedString("Address"), h.Address,
		color.RedString("Port"), h.Port,
		color.RedString("SNI"), h.SNI)

	if h.Insecure != nil && h.Insecure != "" {
		info += fmt.Sprintf("%s: %v\n", color.RedString("Insecure"), h.Insecure)
	}
	if h.ObfusType != "" {
		info += fmt.Sprintf("%s: %s\n%s: %s\n",
			color.RedString("Obfs"), h.ObfusType,
			color.RedString("Obfs-Password"), h.ObfusPassword)
	}
	if h.Ports != "" {
		info += fmt.Sprintf("%s: %s (xray core uses port %s only)\n", color.RedString("Port hopping"), h.Ports, h.Port)
	}
	return info
}

func (h *Hysteria2) GetLink() string {
	if h.OrigLink != "" {
		return h.OrigLink
	}
	baseURL := url.URL{
		Scheme: protocol.Hysteria2Identifier,
		User:   url.User(h.Password),
		Host:   net.JoinHostPort(h.Address, h.Port),
	}
	params := url.Values{}
	addQueryParam := func(key, value string) {
		if value != "" {
			params.Add(key, value)
		}
	}
	addQueryParam("sni", h.SNI)
	addQueryParam("obfs", h.ObfusType)
	addQueryParam("obfs-password", h.ObfusPassword)
	addQueryParam("pinSHA256", h.PinSHA256)
	if s, ok := h.Insecure.(string); ok {
		addQueryParam("insecure", s)
	}
	baseURL.RawQuery = params.Encode()
	if h.Remark != "" {
		baseURL.Fragment = h.Remark
	}
	return baseURL.String()
}

func (h *Hysteria2) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = h.Name()
	g.Address = h.Address
	g.Port = h.Port
	g.Remark = h.Remark
	g.SNI = h.SNI
	g.TLS = "tls"
	g.Network = "udp"
	g.OrigLink = h.GetLink()
	return g
}

// wantsInsecure reports whether the link asks to skip certificate checks.
func (h *Hysteria2) wantsInsecure() bool { return truthy(h.Insecure) }

func (h *Hysteria2) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	portNum, err := parsePort(h.Port)
	if err != nil {
		return nil, err
	}

	// Outbound settings only carry version + endpoint (HysteriaClientConfig).
	settingsBytes, err := json.Marshal(map[string]interface{}{
		"version": 2,
		"address": h.Address,
		"port":    portNum,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal hysteria2 settings: %w", err)
	}
	oset := json.RawMessage(settingsBytes)

	// The auth string lives in the transport's hysteriaSettings; TLS/SNI is
	// read from the stream security settings (tls.ConfigFromStreamSettings).
	// Certificate checks can only be relaxed by pinning (pinSHA256): see
	// transportSpec.applyOutboundSecurity.
	network := conf.TransportProtocol("hysteria")
	s := &conf.StreamConfig{
		Network:  &network,
		Security: "tls",
		HysteriaSettings: &conf.HysteriaConfig{
			Version: 2,
			Auth:    h.Password,
		},
		TLSSettings: &conf.TLSConfig{
			ServerName:           h.SNI,
			PinnedPeerCertSha256: h.PinSHA256,
		},
	}

	switch strings.ToLower(h.ObfusType) {
	case "", "none":
	case "salamander":
		// xray-core moved Hysteria2's obfuscation into finalmask.
		mask, err := json.Marshal(map[string]string{"password": h.ObfusPassword})
		if err != nil {
			return nil, err
		}
		raw := json.RawMessage(mask)
		s.FinalMask = &conf.FinalMask{Udp: []conf.Mask{{Type: "salamander", Settings: &raw}}}
	default:
		return nil, fmt.Errorf("unsupported hysteria2 obfs %q", h.ObfusType)
	}

	return &conf.OutboundDetourConfig{
		Tag:           "proxy",
		Protocol:      "hysteria", // xray-core registers Hysteria2 as "hysteria"
		Settings:      &oset,
		StreamSetting: s,
	}, nil
}

func (h *Hysteria2) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	return nil, fmt.Errorf("creating a Hysteria2 inbound from a client link is not supported")
}
