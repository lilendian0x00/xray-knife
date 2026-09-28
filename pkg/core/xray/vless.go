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

func NewVless(link string) Protocol {
	return &Vless{OrigLink: link}
}

func (v *Vless) Name() string {
	return "vless"
}

func (v *Vless) Parse() error {
	if !strings.HasPrefix(v.OrigLink, protocol.VlessIdentifier+"://") {
		return fmt.Errorf("vless unreconized: %s", v.OrigLink)
	}

	base, remark := splitRemark(v.OrigLink)
	uri, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("failed to parse VLESS link: %w", err)
	}

	v.ID = userSecret(uri.User)

	// SplitHostPort strips IPv6 brackets; Address is kept unbracketed.
	v.Address, v.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return fmt.Errorf("failed to split host and port for VLESS link: %w", err)
	}

	query := uri.Query()

	// Explicitly parse known query parameters
	v.Encryption = query.Get("encryption") // Typically "none" for VLESS
	v.Security = query.Get("security")     // "tls", "reality", or "" (none)
	v.ALPN = query.Get("alpn")
	v.TlsFingerprint = query.Get("fp") // fingerprint
	v.Type = query.Get("type")         // network type: "tcp", "ws", "grpc", "xhttp", etc.

	sni := strings.TrimSpace(query.Get("sni"))
	if !validSNI(sni) {
		return fmt.Errorf("invalid characters in 'sni' parameter: %q", sni)
	}
	host := strings.TrimSpace(query.Get("host"))
	if !validHostList(host) {
		return fmt.Errorf("invalid characters in 'host' parameter: %q", host)
	}

	v.SNI = sni
	v.Host = host                // for ws, http
	v.Path = query.Get("path")   // for ws, http path
	v.Extra = query.Get("extra") // XHTTP extra
	v.Flow = query.Get("flow")
	v.PublicKey = query.Get("pbk")                                                     // reality public key
	v.ShortIds = query.Get("sid")                                                      // reality short ID
	v.SpiderX = query.Get("spx")                                                       // reality spiderX
	v.Mldsa65Verify = query.Get("pqv")                                                 // reality post-quantum ML-DSA-65 verify key
	v.HeaderType = query.Get("headerType")                                             // e.g., "http" for TCP HTTP obfuscation
	v.ServiceName = query.Get("serviceName")                                           // grpc service name
	v.Mode = query.Get("mode")                                                         // grpc mode (gun, multi) or xhttp mode
	v.AllowInsecure = firstQuery(query, "allowInsecure", "insecure", "allow_insecure") // "1", "true", or ""
	v.QuicSecurity = query.Get("quicSecurity")                                         // QUIC security: "none", "aes-128-gcm", etc.
	v.Key = query.Get("key")                                                           // QUIC key
	v.Authority = query.Get("authority")                                               // GRPC authority
	v.PinnedPeerCertSha256 = query.Get("pcs")                                          // TLS cert SHA-256 pin(s)
	v.VerifyPeerCertByName = query.Get("vcn")                                          // names to verify the cert against
	v.ECHConfigList = query.Get("ech")                                                 // Encrypted Client Hello

	v.Remark = remark

	// Apply defaults or adjustments after parsing
	if v.HeaderType == "http" || v.Type == "ws" || v.Type == "h2" || v.Type == "xhttp" {
		if v.Path == "" {
			v.Path = "/"
		}
	}
	// Plain TCP is the default transport whatever the security layer.
	if v.Type == "" {
		v.Type = "tcp"
	}
	if v.Security == "tls" || v.Security == "reality" {
		if v.TlsFingerprint == "" {
			v.TlsFingerprint = "chrome" // Default fingerprint if TLS/REALITY is used
		}
	}

	return nil
}

func (v *Vless) DetailsStr() string {
	copyV := *v
	if copyV.Flow == "" || copyV.Type == "grpc" {
		copyV.Flow = "none"
	}
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), v.Name(),
		color.RedString("Remark"), v.Remark,
		color.RedString("Network"), v.Type,
		color.RedString("Address"), v.Address,
		color.RedString("Port"), v.Port,
		color.RedString("UUID"), v.ID,
		color.RedString("Flow"), copyV.Flow)
	if copyV.Type == "xhttp" || copyV.HeaderType == "http" || copyV.Type == "httpupgrade" || copyV.Type == "ws" || copyV.Type == "h2" || copyV.Type == "splithttp" {
		info += fmt.Sprintf("%s: %s\n%s: %s\n",
			color.RedString("Host"), copyV.Host,
			color.RedString("Path"), copyV.Path)
	} else if copyV.Type == "kcp" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("KCP Seed"), copyV.Path)
	} else if copyV.Type == "grpc" {
		if copyV.ServiceName == "" {
			copyV.ServiceName = "none"
		}
		if copyV.Authority == "" {
			copyV.Authority = "none"
		}
		info += fmt.Sprintf("%s: %s\n%s: %s\n",
			color.RedString("ServiceName"), copyV.ServiceName,
			color.RedString("Authority"), copyV.Authority)
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

		if v.AllowInsecure != "" {
			info += fmt.Sprintf("%s: %v\n",
				color.RedString("Insecure"), v.AllowInsecure)
		}
		if v.PinnedPeerCertSha256 != "" {
			info += fmt.Sprintf("%s: %s\n",
				color.RedString("Pinned cert"), v.PinnedPeerCertSha256)
		}
		if v.VerifyPeerCertByName != "" {
			info += fmt.Sprintf("%s: %s\n",
				color.RedString("Verify cert by name"), v.VerifyPeerCertByName)
		}
		if v.ECHConfigList != "" {
			info += fmt.Sprintf("%s: yes\n", color.RedString("ECH"))
		}
	} else {
		info += fmt.Sprintf("%s: none\n", color.RedString("TLS"))
	}

	if copyV.Encryption != "" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("Encryption"), copyV.Encryption)
	} else {
		info += fmt.Sprintf("%s: none\n", color.RedString("Encryption"))
	}

	return info
}

func (v *Vless) GetLink() string {
	if v.OrigLink != "" {
		return v.OrigLink
	} else {
		baseURL := url.URL{
			Scheme: "vless",
			User:   url.User(v.ID),
			Host:   net.JoinHostPort(v.Address, v.Port),
		}

		params := url.Values{}

		addQueryParam := func(key, value string) {
			if value != "" {
				params.Add(key, value)
			}
		}

		addQueryParam("encryption", v.Encryption)
		addQueryParam("security", v.Security)
		addQueryParam("sni", v.SNI)
		addQueryParam("alpn", v.ALPN)
		addQueryParam("fp", v.TlsFingerprint)
		addQueryParam("type", v.Type)
		addQueryParam("host", v.Host)
		addQueryParam("path", v.Path)
		addQueryParam("flow", v.Flow)
		addQueryParam("pbk", v.PublicKey)
		addQueryParam("sid", v.ShortIds)
		addQueryParam("spx", v.SpiderX)
		addQueryParam("pqv", v.Mldsa65Verify)
		addQueryParam("headerType", v.HeaderType)
		addQueryParam("serviceName", v.ServiceName)
		addQueryParam("mode", v.Mode)
		addQueryParam("extra", v.Extra)
		addQueryParam("allowInsecure", v.AllowInsecure)
		addQueryParam("quicSecurity", v.QuicSecurity)
		addQueryParam("key", v.Key)
		addQueryParam("authority", v.Authority)
		addQueryParam("pcs", v.PinnedPeerCertSha256)
		addQueryParam("vcn", v.VerifyPeerCertByName)
		addQueryParam("ech", v.ECHConfigList)

		baseURL.RawQuery = params.Encode()

		if v.Remark != "" {
			baseURL.Fragment = v.Remark
		}

		return baseURL.String()
	}
}

func (v *Vless) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = v.Name()
	g.Address = v.Address
	g.Host = v.Host
	g.ID = v.ID
	g.Path = v.Path
	g.Port = v.Port
	g.Remark = v.Remark
	if v.Security == "" {
		g.TLS = "none"
	} else {
		g.TLS = v.Security
	}
	g.SNI = v.SNI
	g.ALPN = v.ALPN
	g.TlsFingerprint = v.TlsFingerprint
	g.Authority = v.Authority
	g.ServiceName = v.ServiceName
	g.Mode = v.Mode
	g.Type = v.Type
	g.OrigLink = v.GetLink()

	return g
}

// transport describes the link's transport and security for the shared
// stream builders.
func (v *Vless) transport() transportSpec {
	return transportSpec{
		Network:              v.Type,
		HeaderType:           v.HeaderType,
		Host:                 v.Host,
		Path:                 v.Path,
		Mode:                 v.Mode,
		ServiceName:          v.ServiceName,
		Authority:            v.Authority,
		Extra:                v.Extra,
		Security:             v.Security,
		SNI:                  v.SNI,
		ALPN:                 v.ALPN,
		Fingerprint:          v.TlsFingerprint,
		PinnedPeerCertSha256: v.PinnedPeerCertSha256,
		VerifyPeerCertByName: v.VerifyPeerCertByName,
		ECHConfigList:        v.ECHConfigList,
		PublicKey:            v.PublicKey,
		ShortID:              v.ShortIds,
		SpiderX:              v.SpiderX,
		Mldsa65Verify:        v.Mldsa65Verify,
	}
}

// wantsInsecure reports whether the link asks to skip certificate checks.
func (v *Vless) wantsInsecure() bool { return truthy(v.AllowInsecure) }

func (v *Vless) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	ts := v.transport()
	s, err := ts.outboundStream()
	if err != nil {
		return nil, err
	}

	portNum, err := parsePort(v.Port)
	if err != nil {
		return nil, err
	}

	// gRPC can't carry XTLS flows.
	flow := v.Flow
	if ts.network() == "grpc" {
		flow = ""
	}

	// Build Settings via json.Marshal on a typed map so passwords/UUIDs
	// containing quotes don't corrupt the output, and so we don't
	// hand-roll fields that aren't in xray-core's schema.
	user := map[string]interface{}{
		"id":         v.ID,
		"security":   "auto",
		"encryption": "none",
	}
	if flow != "" {
		user["flow"] = flow
	}
	if v.Encryption != "" {
		user["encryption"] = v.Encryption
	}
	settingsBytes, err := json.Marshal(map[string]interface{}{
		"vnext": []map[string]interface{}{
			{
				"address": v.Address,
				"port":    portNum,
				"users":   []map[string]interface{}{user},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal vless settings: %w", err)
	}
	oset := json.RawMessage(settingsBytes)
	return &conf.OutboundDetourConfig{
		Tag:           "proxy",
		Protocol:      v.Name(),
		Settings:      &oset,
		StreamSetting: s,
	}, nil
}

func (v *Vless) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	ts := v.transport()
	stream, err := ts.inboundStream(v.CertFile, v.KeyFile)
	if err != nil {
		return nil, err
	}
	client := map[string]interface{}{"id": v.ID}
	if v.Flow != "" && ts.network() != "grpc" {
		client["flow"] = v.Flow
	}
	settings := map[string]interface{}{
		"clients":    []interface{}{client},
		"decryption": "none",
	}
	return inboundDetour(v.Name(), v.Address, v.Port, settings, stream)
}
