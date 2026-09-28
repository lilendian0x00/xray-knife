package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/xtls/xray-core/infra/conf"
)

// browserUA is sent on outbound HTTP-based transports so the handshake
// looks like a browser rather than Go's default client.
const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"

// transportSpec is the transport and security part of a VLESS, Trojan or
// VMess link. The three protocols share it so their stream settings are
// built by one code path.
type transportSpec struct {
	Network     string // tcp, raw, ws, grpc, xhttp, splithttp, httpupgrade, kcp
	HeaderType  string // "http" enables TCP HTTP obfuscation
	Host        string // Host header(s), comma-separated for TCP HTTP obfuscation
	Path        string
	Mode        string // xhttp mode, or "multi" for gRPC multiMode
	ServiceName string // gRPC
	Authority   string // gRPC
	Extra       string // xhttp "extra" (raw JSON)

	Security             string // "", "none", "tls" or "reality"
	SNI                  string
	ALPN                 string
	Fingerprint          string
	PinnedPeerCertSha256 string // "pcs"
	VerifyPeerCertByName string // "vcn"
	ECHConfigList        string // "ech"

	// REALITY
	PublicKey     string
	ShortID       string
	SpiderX       string
	Mldsa65Verify string
}

// network returns the canonical transport name, "tcp" when unset.
func (t *transportSpec) network() string {
	switch n := strings.ToLower(strings.TrimSpace(t.Network)); n {
	case "":
		return "tcp"
	case "websocket":
		return "ws"
	case "mkcp":
		return "kcp"
	default:
		return n
	}
}

// security returns the lower-cased security layer, "none" when unset.
func (t *transportSpec) security() string {
	s := strings.ToLower(strings.TrimSpace(t.Security))
	if s == "" {
		return "none"
	}
	return s
}

// streamConfig builds the transport part of the stream settings. The
// outbound flag adds client-only headers (User-Agent).
func (t *transportSpec) streamConfig(outbound bool) (*conf.StreamConfig, error) {
	netName := t.network()
	p := conf.TransportProtocol(netName)
	s := &conf.StreamConfig{Network: &p, Security: t.security()}

	switch netName {
	case "tcp", "raw":
		tcp := &conf.TCPConfig{HeaderConfig: t.tcpHeader(outbound)}
		if netName == "raw" {
			s.RAWSettings = tcp
		} else {
			s.TCPSettings = tcp
		}
	case "kcp":
		// mKCP "header" & "seed" were removed from xray-core (they now
		// hard-error in Build()); use a bare mKCP config.
		s.KCPSettings = &conf.KCPConfig{}
	case "ws":
		// The independent "host" field replaces the deprecated Host header.
		s.WSSettings = &conf.WebSocketConfig{Path: t.Path, Host: t.Host}
		if outbound {
			s.WSSettings.Headers = map[string]string{"User-Agent": browserUA}
		}
	case "xhttp":
		cfg := &conf.SplitHTTPConfig{Host: t.Host, Path: t.Path, Mode: t.Mode}
		if cfg.Mode == "" {
			cfg.Mode = "auto"
		}
		// Extra was percent-decoded once by the query parser and holds raw
		// JSON. Don't unescape it again: that corrupts '+' and '%'.
		if outbound && t.Extra != "" {
			if !json.Valid([]byte(t.Extra)) {
				return nil, fmt.Errorf("xhttp extra is not valid JSON")
			}
			cfg.Extra = json.RawMessage(t.Extra)
		}
		s.XHTTPSettings = cfg
	case "splithttp":
		s.SplitHTTPSettings = &conf.SplitHTTPConfig{Host: t.Host, Path: t.Path}
	case "httpupgrade":
		s.HTTPUPGRADESettings = &conf.HttpUpgradeConfig{Host: t.Host, Path: t.Path}
	case "grpc":
		s.GRPCSettings = &conf.GRPCConfig{
			Authority:          t.Authority,
			ServiceName:        strings.TrimPrefix(t.ServiceName, "/"),
			MultiMode:          t.Mode == "multi", // default is "gun"
			IdleTimeout:        60,
			HealthCheckTimeout: 20,
			InitialWindowsSize: 65536,
		}
	case "h2", "http", "h3", "quic":
		return nil, fmt.Errorf("transport %q was removed from xray-core; use the sing-box or automatic core for this link", netName)
	default:
		return nil, fmt.Errorf("unsupported transport %q", t.Network)
	}
	return s, nil
}

// tcpHeader returns the TCP header config: none, or HTTP obfuscation.
func (t *transportSpec) tcpHeader(outbound bool) json.RawMessage {
	if ht := strings.ToLower(t.HeaderType); ht == "" || ht == "none" {
		return json.RawMessage(`{"type":"none"}`)
	}
	paths := splitList(t.Path)
	if len(paths) == 0 {
		paths = []string{"/"}
	}
	headers := map[string]interface{}{}
	if hosts := splitList(t.Host); len(hosts) > 0 {
		headers["Host"] = hosts
	}
	if outbound {
		headers["User-Agent"] = browserUA
	}
	b, _ := json.Marshal(map[string]interface{}{
		"type": "http",
		"request": map[string]interface{}{
			"path":    paths,
			"headers": headers,
		},
	})
	return b
}

// serverName is the TLS server name: the SNI, else the first Host.
func (t *transportSpec) serverName() string {
	if t.SNI != "" {
		return t.SNI
	}
	hosts := splitList(t.Host)
	if len(hosts) == 0 {
		return ""
	}
	if h, _, err := net.SplitHostPort(hosts[0]); err == nil {
		return h
	}
	return hosts[0]
}

// fingerprint returns the uTLS fingerprint, "chrome" when unset.
func (t *transportSpec) fingerprint() string {
	if t.Fingerprint == "" {
		return "chrome"
	}
	return t.Fingerprint
}

// applyOutboundSecurity adds the TLS or REALITY client settings.
//
// xray-core removed "allowInsecure" (Build() hard-errors on it), and its
// replacement "verifyPeerCertByName" still verifies the chain against the
// system roots, so an insecure request cannot be honoured on this core:
// self-signed servers need "pcs" (a certificate pin) or the sing-box core.
// The automatic core routes such links to sing-box (see PrefersSingbox).
func (t *transportSpec) applyOutboundSecurity(s *conf.StreamConfig) {
	switch t.security() {
	case "tls":
		s.TLSSettings = &conf.TLSConfig{
			Fingerprint:          t.fingerprint(),
			ServerName:           t.serverName(),
			PinnedPeerCertSha256: t.PinnedPeerCertSha256,
			VerifyPeerCertByName: t.VerifyPeerCertByName,
			ECHConfigList:        t.ECHConfigList,
		}
		if alpn := splitList(t.ALPN); len(alpn) > 0 {
			l := conf.StringList(alpn)
			s.TLSSettings.ALPN = &l
		}
	case "reality":
		s.REALITYSettings = &conf.REALITYConfig{
			Show:          false,
			Fingerprint:   t.fingerprint(),
			ServerName:    t.SNI,
			PublicKey:     t.PublicKey,
			ShortId:       t.ShortID,
			SpiderX:       t.SpiderX,
			Mldsa65Verify: t.Mldsa65Verify,
		}
	}
}

// applyInboundSecurity adds server TLS when certificate files are given.
// Links carry no server keys, so TLS without files and REALITY fall back
// to plaintext for inbounds.
func (t *transportSpec) applyInboundSecurity(s *conf.StreamConfig, certFile, keyFile string) {
	if t.security() == "tls" && certFile != "" && keyFile != "" {
		s.TLSSettings = &conf.TLSConfig{
			ServerName: t.SNI,
			Certs:      []*conf.TLSCertConfig{{CertFile: certFile, KeyFile: keyFile}},
		}
		if alpn := splitList(t.ALPN); len(alpn) > 0 {
			l := conf.StringList(alpn)
			s.TLSSettings.ALPN = &l
		}
		return
	}
	s.Security = "none"
}

// outboundStream builds the full client stream settings.
func (t *transportSpec) outboundStream() (*conf.StreamConfig, error) {
	s, err := t.streamConfig(true)
	if err != nil {
		return nil, err
	}
	t.applyOutboundSecurity(s)
	return s, nil
}

// inboundStream builds the full server stream settings.
func (t *transportSpec) inboundStream(certFile, keyFile string) (*conf.StreamConfig, error) {
	s, err := t.streamConfig(false)
	if err != nil {
		return nil, err
	}
	t.applyInboundSecurity(s, certFile, keyFile)
	return s, nil
}

// inboundDetour assembles an inbound on listen:port with the given
// settings (marshalled to JSON) and stream.
func inboundDetour(tag, listen, port string, settings interface{}, stream *conf.StreamConfig) (*conf.InboundDetourConfig, error) {
	portNum, err := parsePort(port)
	if err != nil {
		return nil, err
	}
	addr, err := listenAddress(listen)
	if err != nil {
		return nil, err
	}
	in := &conf.InboundDetourConfig{
		Protocol:      tag,
		Tag:           tag,
		StreamSetting: stream,
		ListenOn:      &conf.Address{Address: parseXrayAddress(addr)},
		PortList: &conf.PortList{Range: []conf.PortRange{
			{From: uint32(portNum), To: uint32(portNum)},
		}},
	}
	if settings != nil {
		raw, err := json.Marshal(settings)
		if err != nil {
			return nil, fmt.Errorf("marshal %s inbound settings: %w", tag, err)
		}
		msg := json.RawMessage(raw)
		in.Settings = &msg
	}
	return in, nil
}
