package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// This file turns the fields of a structured config entry (Clash proxy,
// sing-box or xray outbound) into the share-link forms xray-knife's
// parsers read. Each builder takes already-normalised values; the format
// decoders do the field mapping.

// stream is the transport and TLS part of a VLESS, VMess or Trojan entry.
type stream struct {
	Network     string // tcp, ws, grpc, h2, httpupgrade, xhttp, kcp, quic
	HeaderType  string // "http" for TCP HTTP obfuscation
	Host        string // comma-separated when several
	Path        string
	ServiceName string // gRPC
	Authority   string // gRPC
	Mode        string // gRPC "multi" or the xhttp mode
	Extra       string // xhttp extra JSON
	Seed        string // mKCP seed

	Security    string // "", "tls" or "reality"
	SNI         string
	ALPN        []string
	Fingerprint string
	Insecure    bool
	PinSHA256   string // certificate pin(s), comma-separated hex
	VerifyNames string // verifyPeerCertByName
	ECH         string

	PublicKey     string // REALITY
	ShortID       string
	SpiderX       string
	Mldsa65Verify string
}

// params is url.Values that ignores empty values.
type params url.Values

func (p params) set(key, value string) {
	if value != "" {
		url.Values(p).Set(key, value)
	}
}

func (p params) flag(key string, on bool) {
	if on {
		url.Values(p).Set(key, "1")
	}
}

// shareURL assembles scheme://user@host:port?query#name.
func shareURL(scheme string, user *url.Userinfo, server string, port int, query params, name string) string {
	u := url.URL{
		Scheme:   scheme,
		User:     user,
		Host:     net.JoinHostPort(server, strconv.Itoa(port)),
		RawQuery: url.Values(query).Encode(),
		Fragment: name,
	}
	return u.String()
}

// streamQuery writes the shared VLESS/Trojan query parameters.
func streamQuery(q params, s stream) {
	network := s.Network
	if network == "" {
		network = "tcp"
	}
	q.set("type", network)
	q.set("headerType", s.HeaderType)
	q.set("host", s.Host)
	q.set("path", s.Path)
	q.set("serviceName", s.ServiceName)
	q.set("authority", s.Authority)
	q.set("mode", s.Mode)
	q.set("extra", s.Extra)
	q.set("seed", s.Seed)
	security := s.Security
	if security == "" {
		security = "none"
	}
	q.set("security", security)
	q.set("sni", s.SNI)
	q.set("alpn", strings.Join(s.ALPN, ","))
	q.set("fp", s.Fingerprint)
	q.flag("allowInsecure", s.Insecure)
	q.set("pcs", s.PinSHA256)
	q.set("vcn", s.VerifyNames)
	q.set("ech", s.ECH)
	q.set("pbk", s.PublicKey)
	q.set("sid", s.ShortID)
	q.set("spx", s.SpiderX)
	q.set("pqv", s.Mldsa65Verify)
}

func vlessLink(name, server string, port int, uuid, flow, encryption string, s stream) string {
	q := params{}
	if encryption == "" {
		encryption = "none"
	}
	q.set("encryption", encryption)
	q.set("flow", flow)
	streamQuery(q, s)
	return shareURL("vless", url.User(uuid), server, port, q, name)
}

func trojanLink(name, server string, port int, password string, s stream) string {
	q := params{}
	if s.Security == "" {
		s.Security = "tls"
	}
	streamQuery(q, s)
	return shareURL("trojan", url.User(password), server, port, q, name)
}

// vmessLink builds the v2rayN base64 JSON form.
func vmessLink(name, server string, port int, uuid string, alterID int, cipher string, s stream) string {
	fields := map[string]interface{}{
		"v":    "2",
		"ps":   name,
		"add":  server,
		"port": strconv.Itoa(port),
		"id":   uuid,
	}
	set := func(key, value string) {
		if value != "" {
			fields[key] = value
		}
	}
	if alterID > 0 {
		fields["aid"] = strconv.Itoa(alterID)
	}
	set("scy", cipher)
	network := s.Network
	if network == "" {
		network = "tcp"
	}
	fields["net"] = network
	// VMess reuses "type" and "path": the TCP header type, the gRPC mode
	// and service name, or the xhttp mode.
	switch network {
	case "tcp":
		set("type", s.HeaderType)
		set("path", s.Path)
		set("host", s.Host)
	case "grpc":
		set("type", s.Mode)
		set("path", s.ServiceName)
		set("host", s.Authority)
	case "xhttp":
		set("type", s.Mode)
		set("path", s.Path)
		set("host", s.Host)
	default:
		set("path", s.Path)
		set("host", s.Host)
	}
	if s.Security == "tls" {
		fields["tls"] = "tls"
		set("sni", s.SNI)
		set("alpn", strings.Join(s.ALPN, ","))
		set("fp", s.Fingerprint)
		set("pcs", s.PinSHA256)
		set("vcn", s.VerifyNames)
		set("ech", s.ECH)
		if s.Insecure {
			fields["allowInsecure"] = "1"
		}
	}
	b, _ := json.Marshal(fields)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

// ssLink builds a SIP002 link. SS-2022 keys go in plain (percent-encoded)
// userinfo as SIP022 requires; other methods use base64url.
func ssLink(name, server string, port int, method, password, plugin string) string {
	var user string
	if strings.HasPrefix(strings.ToLower(method), "2022-") {
		user = url.PathEscape(method) + ":" + url.PathEscape(password)
	} else {
		user = base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
	}
	link := "ss://" + user + "@" + net.JoinHostPort(server, strconv.Itoa(port))
	if plugin != "" {
		link += "/?plugin=" + url.QueryEscape(plugin)
	}
	return link + fragment(name)
}

func socksLink(name, server string, port int, username, password string) string {
	var user *url.Userinfo
	if username != "" || password != "" {
		user = url.UserPassword(username, password)
	}
	return shareURL("socks", user, server, port, params{}, name)
}

type httpOpts struct {
	Username, Password string
	TLS                bool // https://
	SNI, Fingerprint   string
	ALPN               []string
	Insecure           bool
}

// httpLink builds http://user:pass@host:port, or https://...?sni=... for
// HTTP proxies over TLS.
func httpLink(name, server string, port int, o httpOpts) string {
	var user *url.Userinfo
	if o.Username != "" || o.Password != "" {
		user = url.UserPassword(o.Username, o.Password)
	}
	scheme, q := "http", params{}
	if o.TLS {
		scheme = "https"
		q.set("sni", o.SNI)
		q.set("fp", o.Fingerprint)
		q.set("alpn", strings.Join(o.ALPN, ","))
		q.flag("insecure", o.Insecure)
	}
	return shareURL(scheme, user, server, port, q, name)
}

type hysteria2Opts struct {
	Password, SNI, Obfs, ObfsPassword, PinSHA256 string
	Insecure                                     bool
	ALPN                                         []string
	Ports                                        string // hopping ranges, "20000-30000,40000-41000"
}

func hysteria2Link(name, server string, port int, o hysteria2Opts) string {
	q := params{}
	q.set("sni", o.SNI)
	q.set("obfs", o.Obfs)
	q.set("obfs-password", o.ObfsPassword)
	q.set("pinSHA256", o.PinSHA256)
	q.set("alpn", strings.Join(o.ALPN, ","))
	q.set("mport", o.Ports)
	q.flag("insecure", o.Insecure)
	return shareURL("hysteria2", url.User(o.Password), server, port, q, name)
}

type hysteriaOpts struct {
	Auth, SNI, Obfs, Protocol string
	UpMbps, DownMbps          int
	Insecure                  bool
	ALPN                      []string
	Ports                     string
}

// hysteriaLink builds a Hysteria v1 link (hysteria://host:port?...).
func hysteriaLink(name, server string, port int, o hysteriaOpts) string {
	q := params{}
	q.set("protocol", o.Protocol)
	q.set("auth", o.Auth)
	q.set("peer", o.SNI)
	q.flag("insecure", o.Insecure)
	if o.UpMbps > 0 {
		q.set("upmbps", strconv.Itoa(o.UpMbps))
	}
	if o.DownMbps > 0 {
		q.set("downmbps", strconv.Itoa(o.DownMbps))
	}
	q.set("alpn", strings.Join(o.ALPN, ","))
	if o.Obfs != "" {
		q.set("obfs", "xplus")
		q.set("obfsParam", o.Obfs)
	}
	q.set("mport", o.Ports)
	return shareURL("hysteria", nil, server, port, q, name)
}

type tuicOpts struct {
	UUID, Password, SNI, CongestionControl, UDPRelayMode string
	ALPN                                                 []string
	Insecure, DisableSNI, ZeroRTT                        bool
}

// tuicLink builds a TUIC v5 link (tuic://uuid:password@host:port?...).
func tuicLink(name, server string, port int, o tuicOpts) string {
	q := params{}
	q.set("sni", o.SNI)
	q.set("alpn", strings.Join(o.ALPN, ","))
	q.set("congestion_control", o.CongestionControl)
	q.set("udp_relay_mode", o.UDPRelayMode)
	q.flag("allow_insecure", o.Insecure)
	q.flag("disable_sni", o.DisableSNI)
	q.flag("reduce_rtt", o.ZeroRTT)
	return shareURL("tuic", url.UserPassword(o.UUID, o.Password), server, port, q, name)
}

type anytlsOpts struct {
	Password, SNI, Fingerprint string
	ALPN                       []string
	Insecure                   bool
	Security                   string // "" (TLS) or "reality"
	PublicKey, ShortID         string
}

func anytlsLink(name, server string, port int, o anytlsOpts) string {
	q := params{}
	if o.Security == "reality" {
		q.set("security", "reality")
		q.set("pbk", o.PublicKey)
		q.set("sid", o.ShortID)
	}
	q.set("sni", o.SNI)
	q.set("alpn", strings.Join(o.ALPN, ","))
	q.set("fp", o.Fingerprint)
	q.flag("insecure", o.Insecure)
	return shareURL("anytls", url.User(o.Password), server, port, q, name)
}

type sshOpts struct {
	User, Password, PrivateKey, Passphrase string
	HostKeys                               []string
}

// sshLink builds ssh://user:password@host:port?pk=PEM&pkp=&hk=KEY.
func sshLink(name, server string, port int, o sshOpts) string {
	q := url.Values{}
	if o.PrivateKey != "" {
		q.Set("pk", o.PrivateKey)
	}
	if o.Passphrase != "" {
		q.Set("pkp", o.Passphrase)
	}
	for _, hk := range o.HostKeys {
		q.Add("hk", hk)
	}
	user := url.User(o.User)
	if o.Password != "" {
		user = url.UserPassword(o.User, o.Password)
	}
	return shareURL("ssh", user, server, port, params(q), name)
}

type wireguardOpts struct {
	PrivateKey, PublicKey, PreSharedKey string
	Addresses, AllowedIPs               []string
	MTU, KeepAlive                      int
	Reserved                            []int
}

func wireguardLink(name, server string, port int, o wireguardOpts) string {
	q := params{}
	q.set("publickey", o.PublicKey)
	q.set("presharedkey", o.PreSharedKey)
	q.set("address", strings.Join(o.Addresses, ","))
	q.set("allowedips", strings.Join(o.AllowedIPs, ","))
	if o.MTU > 0 {
		q.set("mtu", strconv.Itoa(o.MTU))
	}
	if o.KeepAlive > 0 {
		q.set("keepalive", strconv.Itoa(o.KeepAlive))
	}
	if len(o.Reserved) > 0 {
		parts := make([]string, len(o.Reserved))
		for i, r := range o.Reserved {
			parts[i] = strconv.Itoa(r)
		}
		q.set("reserved", strings.Join(parts, ","))
	}
	// Keys are standard base64; escape "/" and "+" so no parser splits
	// or mangles them.
	return "wireguard://" + url.QueryEscape(o.PrivateKey) + "@" +
		net.JoinHostPort(server, strconv.Itoa(port)) + "?" + url.Values(q).Encode() + fragment(name)
}

// decodeBase64 accepts standard or URL-safe base64, padded or not.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func fragment(name string) string {
	if name == "" {
		return ""
	}
	return "#" + (&url.URL{Fragment: name}).EscapedFragment()
}

// skip is an entry that could not become a link; reason is counted.
type skip struct{ reason string }

func (s *skip) Error() string { return s.reason }

func skipf(format string, args ...interface{}) error {
	return &skip{reason: fmt.Sprintf(format, args...)}
}
