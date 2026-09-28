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

func NewTrojan(link string) Protocol {
	return &Trojan{OrigLink: link}
}

func (t *Trojan) Name() string {
	return "trojan"
}

func (t *Trojan) Parse() error {
	if !strings.HasPrefix(t.OrigLink, protocol.TrojanIdentifier+"://") {
		return fmt.Errorf("trojan unreconized: %s", t.OrigLink)
	}
	base, remark := splitRemark(t.OrigLink)
	uri, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("failed to parse Trojan link: %w", err)
	}

	// Decoded password: "p%40ss" must be sent as "p@ss".
	t.Password = userSecret(uri.User)
	t.Address, t.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port for Trojan link: %w", err)
	}

	query := uri.Query()

	// Explicitly parse known query parameters
	t.Flow = query.Get("flow")
	t.Security = query.Get("security") // "tls", "reality", or "" (none)
	t.ALPN = query.Get("alpn")
	t.TlsFingerprint = query.Get("fp")
	t.Type = query.Get("type") // network type

	// Validate host and sni parameters before assigning them
	sni := strings.TrimSpace(query.Get("sni"))
	if !validSNI(sni) {
		return fmt.Errorf("invalid characters in 'sni' parameter: %q", sni)
	}
	host := strings.TrimSpace(query.Get("host"))
	if !validHostList(host) {
		return fmt.Errorf("invalid characters in 'host' parameter: %q", host)
	}

	t.SNI = sni
	t.Host = host
	t.Path = query.Get("path") // for ws, http path
	t.HeaderType = query.Get("headerType")
	t.ServiceName = query.Get("serviceName")
	t.Mode = query.Get("mode")
	t.PublicKey = query.Get("pbk")
	t.ShortIds = query.Get("sid")
	t.SpiderX = query.Get("spx")
	t.Mldsa65Verify = query.Get("pqv")
	t.AllowInsecure = firstQuery(query, "allowInsecure", "insecure", "allow_insecure")
	t.QuicSecurity = query.Get("quicSecurity")
	t.Key = query.Get("key")
	t.Authority = query.Get("authority")
	t.PinnedPeerCertSha256 = query.Get("pcs") // TLS cert SHA-256 pin(s)
	t.VerifyPeerCertByName = query.Get("vcn") // names to verify the cert against
	t.ECHConfigList = query.Get("ech")        // Encrypted Client Hello

	t.Remark = remark

	// Apply defaults or adjustments
	if t.HeaderType == "xhttp" || t.HeaderType == "http" || t.Type == "ws" || t.Type == "h2" || t.Type == "xhttp" {
		if t.Path == "" {
			t.Path = "/"
		}
	}

	if t.Type == "" {
		t.Type = "tcp" // Default network for Trojan
	}
	if t.Security == "" { // Trojan typically implies TLS
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

	if copyV.Type == "xhttp" || copyV.Type == "http" || copyV.Type == "httpupgrade" || copyV.Type == "ws" || copyV.Type == "h2" || copyV.Type == "splithttp" {
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
		if t.PinnedPeerCertSha256 != "" {
			info += fmt.Sprintf("%s: %s\n",
				color.RedString("Pinned cert"), t.PinnedPeerCertSha256)
		}
	} else {
		info += fmt.Sprintf("%s: none\n", color.RedString("TLS"))
	}
	return info
}

func (t *Trojan) GetLink() string {
	if t.OrigLink != "" {
		return t.OrigLink
	} else {
		baseURL := url.URL{
			Scheme: "trojan",
			User:   url.User(t.Password),
			Host:   net.JoinHostPort(t.Address, t.Port),
		}

		params := url.Values{}
		addQueryParam := func(key, value string) {
			if value != "" {
				params.Add(key, value)
			}
		}

		addQueryParam("flow", t.Flow)
		addQueryParam("security", t.Security)
		addQueryParam("sni", t.SNI)
		addQueryParam("alpn", t.ALPN)
		addQueryParam("fp", t.TlsFingerprint)
		addQueryParam("type", t.Type)
		addQueryParam("host", t.Host)
		addQueryParam("path", t.Path)
		addQueryParam("headerType", t.HeaderType)
		addQueryParam("serviceName", t.ServiceName)
		addQueryParam("mode", t.Mode)
		addQueryParam("pbk", t.PublicKey)
		addQueryParam("sid", t.ShortIds)
		addQueryParam("spx", t.SpiderX)
		addQueryParam("pqv", t.Mldsa65Verify)
		addQueryParam("allowInsecure", t.AllowInsecure)
		addQueryParam("quicSecurity", t.QuicSecurity)
		addQueryParam("key", t.Key)
		addQueryParam("authority", t.Authority)
		addQueryParam("pcs", t.PinnedPeerCertSha256)
		addQueryParam("vcn", t.VerifyPeerCertByName)
		addQueryParam("ech", t.ECHConfigList)

		baseURL.RawQuery = params.Encode()

		if t.Remark != "" {
			baseURL.Fragment = t.Remark
		}

		return baseURL.String()
	}
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

// transport describes the link's transport and security for the shared
// stream builders.
func (t *Trojan) transport() transportSpec {
	return transportSpec{
		Network:              t.Type,
		HeaderType:           t.HeaderType,
		Host:                 t.Host,
		Path:                 t.Path,
		Mode:                 t.Mode,
		ServiceName:          t.ServiceName,
		Authority:            t.Authority,
		Security:             t.Security,
		SNI:                  t.SNI,
		ALPN:                 t.ALPN,
		Fingerprint:          t.TlsFingerprint,
		PinnedPeerCertSha256: t.PinnedPeerCertSha256,
		VerifyPeerCertByName: t.VerifyPeerCertByName,
		ECHConfigList:        t.ECHConfigList,
		PublicKey:            t.PublicKey,
		ShortID:              t.ShortIds,
		SpiderX:              t.SpiderX,
		Mldsa65Verify:        t.Mldsa65Verify,
	}
}

// wantsInsecure reports whether the link asks to skip certificate checks.
func (t *Trojan) wantsInsecure() bool { return truthy(t.AllowInsecure) }

func (t *Trojan) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	ts := t.transport()
	s, err := ts.outboundStream()
	if err != nil {
		return nil, err
	}

	portNum, err := parsePort(t.Port)
	if err != nil {
		return nil, err
	}

	// Build Settings via json.Marshal on a typed map to avoid JSON injection
	// when password/address contain special chars. "flow" is left out on
	// purpose: xray-core removed Trojan flows and hard-errors on them, while
	// other clients ignore the parameter.
	settingsBytes, err := json.Marshal(map[string]interface{}{
		"servers": []map[string]interface{}{{
			"address":  t.Address,
			"port":     portNum,
			"password": t.Password,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal trojan settings: %w", err)
	}
	oset := json.RawMessage(settingsBytes)
	return &conf.OutboundDetourConfig{
		Tag:           "proxy",
		Protocol:      t.Name(),
		Settings:      &oset,
		StreamSetting: s,
	}, nil
}

func (t *Trojan) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	ts := t.transport()
	// Inbound TLS/REALITY requires certs, which aren't in the link.
	stream, err := ts.inboundStream("", "")
	if err != nil {
		return nil, err
	}
	settings := map[string]interface{}{
		"clients": []map[string]interface{}{{"password": t.Password}},
	}
	return inboundDetour(t.Name(), t.Address, t.Port, settings, stream)
}
