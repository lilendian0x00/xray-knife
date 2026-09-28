package convert

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"

	"gopkg.in/yaml.v3"
)

// ClashOptions shapes the Clash / mihomo document. Zero values pick the
// defaults noted on each field.
type ClashOptions struct {
	MixedPort     int    // local HTTP+SOCKS port, default 7890
	SelectGroup   string // select group name, default "PROXY"
	AutoGroup     string // url-test group name, default "auto"
	TestURL       string // url-test probe, default https://www.gstatic.com/generate_204
	TestInterval  int    // url-test interval in seconds, default 300
	TestTolerance int    // url-test tolerance in ms, default 50
}

func (o *ClashOptions) defaults() {
	if o.MixedPort == 0 {
		o.MixedPort = 7890
	}
	if o.SelectGroup == "" {
		o.SelectGroup = "PROXY"
	}
	if o.AutoGroup == "" {
		o.AutoGroup = "auto"
	}
	if o.TestURL == "" {
		o.TestURL = "https://www.gstatic.com/generate_204"
	}
	if o.TestInterval == 0 {
		o.TestInterval = 300
	}
	if o.TestTolerance == 0 {
		o.TestTolerance = 50
	}
}

// ToClash renders links as a Clash / mihomo config.
func ToClash(links []string, opts ClashOptions) ([]byte, *Report, error) {
	opts.defaults()
	r := &Report{}
	xc := xray.NewXrayService(false, false)
	sc := singbox.NewSingboxService(false, false)
	entries := parseAll(links, r, func(link string) (protocol.Protocol, error) {
		// xray's parsers carry every field Clash can use for the protocols
		// it knows; the rest only have sing-box parsers.
		switch scheme(link) {
		case protocol.TuicIdentifier, protocol.AnyTLSIdentifier, protocol.HysteriaIdentifier, protocol.SSHIdentifier,
			protocol.HTTPIdentifier, protocol.HTTPSIdentifier:
			return sc.CreateProtocol(link)
		}
		return xc.CreateProtocol(link)
	})

	// Proxy names share one namespace with the groups and mihomo's
	// built-in policies; a proxy called "auto" or "DIRECT" would shadow them.
	used := names{opts.SelectGroup: true, opts.AutoGroup: true}
	for _, builtin := range []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"} {
		used[builtin] = true
	}
	var proxies []interface{}
	var proxyNames []string
	for _, e := range entries {
		g := e.proto.ConvertToGeneralConfig()
		name := used.take(e.name, g.Protocol, e.index)
		m, err := clashProxy(e.proto, name)
		if err != nil {
			delete(used, name)
			r.skip(e.index, e.name, "%v", err)
			continue
		}
		proxies = append(proxies, m)
		proxyNames = append(proxyNames, name)
	}
	r.Converted = len(proxies)
	if len(proxies) == 0 {
		return nil, r, ErrNothingToExport
	}

	doc := ordered{
		{"mixed-port", opts.MixedPort},
		{"allow-lan", false},
		{"mode", "rule"},
		{"log-level", "warning"},
		{"proxies", proxies},
		{"proxy-groups", []interface{}{
			ordered{
				{"name", opts.SelectGroup},
				{"type", "select"},
				{"proxies", append([]string{opts.AutoGroup}, proxyNames...)},
			},
			ordered{
				{"name", opts.AutoGroup},
				{"type", "url-test"},
				{"proxies", proxyNames},
				{"url", opts.TestURL},
				{"interval", opts.TestInterval},
				{"tolerance", opts.TestTolerance},
			},
		}},
		{"rules", []string{"MATCH," + opts.SelectGroup}},
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, r, err
	}
	return out, r, nil
}

// clashProxy maps one parsed link to a Clash proxy entry.
func clashProxy(p protocol.Protocol, name string) (ordered, error) {
	g := p.ConvertToGeneralConfig()
	port, err := strconv.Atoi(g.Port)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q", g.Port)
	}
	m := ordered{{"name", name}}
	base := func(typ, server string) {
		m.add("type", typ)
		m.add("server", server)
		m.add("port", port)
	}

	switch v := p.(type) {
	case *xray.Vless:
		base("vless", v.Address)
		m.add("uuid", v.ID)
		m.add("udp", true)
		m.add("flow", v.Flow)
		if v.Encryption != "none" {
			m.add("encryption", v.Encryption)
		}
		if err := clashTransport(&m, v.Type, v.HeaderType, v.Host, v.Path, v.ServiceName, v.Mode); err != nil {
			return nil, err
		}
		clashSecurity(&m, v.Security, v.SNI, v.ALPN, v.TlsFingerprint, v.AllowInsecure, v.PinnedPeerCertSha256, v.ECHConfigList, v.PublicKey, v.ShortIds)
	case *xray.Vmess:
		base("vmess", v.Address)
		m.add("uuid", v.ID)
		aid, _ := strconv.Atoi(g.Aid)
		m.set("alterId", aid) // required by mihomo, even when 0
		cipher := v.Security
		if cipher == "" {
			cipher = "auto"
		}
		m.add("cipher", cipher)
		m.add("udp", true)
		// VMess JSON overloads "type" and "path" (see xray.Vmess.transport);
		// Clash has no gRPC authority, so "host" is dropped for gRPC.
		headerType, mode, service, host, path := "", "", "", v.Host, v.Path
		switch strings.ToLower(v.Network) {
		case "", "tcp", "raw":
			headerType = v.Type
		case "grpc":
			mode, service, host, path = v.Type, v.Path, "", ""
		case "xhttp":
			mode = v.Type
		}
		if err := clashTransport(&m, v.Network, headerType, host, path, service, mode); err != nil {
			return nil, err
		}
		if strings.EqualFold(v.TLS, "tls") {
			insecure := ""
			if truthy(v.AllowInsecure) {
				insecure = "1"
			}
			clashSecurity(&m, "tls", v.SNI, v.ALPN, v.TlsFingerprint, insecure, v.PinnedPeerCertSha256, v.ECHConfigList, "", "")
		}
	case *xray.Trojan:
		if v.Security != "tls" && v.Security != "reality" {
			return nil, fmt.Errorf("trojan without TLS has no Clash equivalent")
		}
		base("trojan", v.Address)
		m.add("password", v.Password)
		m.add("udp", true)
		if err := clashTransport(&m, v.Type, v.HeaderType, v.Host, v.Path, v.ServiceName, v.Mode); err != nil {
			return nil, err
		}
		clashSecurity(&m, v.Security, v.SNI, v.ALPN, v.TlsFingerprint, v.AllowInsecure, v.PinnedPeerCertSha256, v.ECHConfigList, v.PublicKey, v.ShortIds)
		// Clash trojan is always TLS: the flag is implied, the SNI key is "sni".
		m.remove("tls")
		m.rename("servername", "sni")
	case *xray.Shadowsocks:
		base("ss", v.Address)
		m.add("cipher", v.Encryption)
		m.add("password", v.Password)
		m.add("udp", true)
		if v.Plugin != "" {
			plugin, opts, err := clashPlugin(v.Plugin)
			if err != nil {
				return nil, err
			}
			m.add("plugin", plugin)
			m.add("plugin-opts", opts)
		}
	case *xray.Socks:
		base("socks5", v.Address)
		m.add("username", v.Username)
		m.add("password", v.Password)
		m.add("udp", true)
	case *xray.Wireguard:
		host, _, err := net.SplitHostPort(v.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid wireguard endpoint %q", v.Endpoint)
		}
		base("wireguard", host)
		// mihomo takes one address per family (ip, ipv6); extra ones have
		// no Clash form and are dropped.
		var ip4, ip6 string
		for _, a := range splitList(v.LocalAddress) {
			ip := strings.SplitN(a, "/", 2)[0]
			if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
				if ip6 == "" {
					ip6 = a
				}
			} else if ip4 == "" {
				ip4 = a
			}
		}
		m.add("ip", ip4)
		m.add("ipv6", ip6)
		m.add("private-key", v.SecretKey)
		m.add("public-key", v.PublicKey)
		m.add("pre-shared-key", v.PreSharedKey)
		m.add("allowed-ips", splitList(v.AllowedIPs))
		if r := reservedList(v.Reserved); len(r) > 0 {
			m.add("reserved", r)
		}
		m.add("mtu", int(v.Mtu))
		m.add("persistent-keepalive", int(v.KeepAlive))
		m.add("udp", true)
	case *xray.Hysteria2:
		base("hysteria2", v.Address)
		m.add("password", v.Password)
		m.add("ports", v.Ports)
		m.add("sni", v.SNI)
		m.add("skip-cert-verify", truthy(v.Insecure))
		if v.ObfusType != "" {
			m.add("obfs", v.ObfusType)
			m.add("obfs-password", v.ObfusPassword)
		}
		m.add("fingerprint", v.PinSHA256)
	case *singbox.Tuic:
		base("tuic", v.Address)
		m.add("uuid", v.UUID)
		m.add("password", v.Password)
		m.add("sni", v.SNI)
		m.add("alpn", splitList(v.ALPN))
		m.add("congestion-controller", v.CongestionControl)
		m.add("udp-relay-mode", v.UDPRelayMode)
		m.add("skip-cert-verify", v.Insecure)
		m.add("disable-sni", v.DisableSNI)
		m.add("reduce-rtt", v.ZeroRTT)
	case *singbox.AnyTLS:
		base("anytls", v.Address)
		m.add("password", v.Password)
		m.add("sni", v.SNI)
		m.add("alpn", splitList(v.ALPN))
		m.add("client-fingerprint", v.TlsFingerprint)
		m.add("skip-cert-verify", v.Insecure)
		if v.Security == "reality" {
			m.add("reality-opts", ordered{{"public-key", v.PublicKey}, {"short-id", v.ShortID}})
		}
	case *singbox.Hysteria:
		base("hysteria", v.Address)
		m.add("auth-str", v.Auth)
		m.add("up", v.UpMbps)
		m.add("down", v.DownMbps)
		m.add("sni", v.SNI)
		m.add("alpn", splitList(v.ALPN))
		m.add("obfs", v.ObfsPassword)
		m.add("skip-cert-verify", v.Insecure)
		m.add("ports", hopPorts(v.ServerPorts))
	case *singbox.HTTPProxy:
		base("http", v.Address)
		m.add("username", v.Username)
		m.add("password", v.Password)
		if v.TLS {
			m.add("tls", true)
			m.add("sni", v.SNI)
			m.add("client-fingerprint", v.TlsFingerprint)
			m.add("skip-cert-verify", v.Insecure)
		}
	case *singbox.SSH:
		base("ssh", v.Address)
		m.add("username", v.User)
		m.add("password", v.Password)
		m.add("private-key", v.PrivateKey)
		m.add("private-key-passphrase", v.PrivateKeyPassphrase)
		m.add("host-key", v.HostKeys)
	default:
		return nil, fmt.Errorf("%s has no Clash equivalent", g.Protocol)
	}
	return m, nil
}

// clashTransport adds network and *-opts for vless/vmess/trojan.
func clashTransport(m *ordered, network, headerType, host, path, serviceName, mode string) error {
	switch strings.ToLower(network) {
	case "", "tcp", "raw":
		if strings.EqualFold(headerType, "http") {
			paths := splitList(path)
			if len(paths) == 0 {
				paths = []string{"/"}
			}
			opts := ordered{{"method", "GET"}, {"path", paths}}
			if hosts := splitList(host); len(hosts) > 0 {
				opts.add("headers", ordered{{"Host", hosts}})
			}
			m.add("network", "http")
			m.add("http-opts", opts)
		}
	case "ws", "httpupgrade":
		p, ed := splitEarlyData(path)
		opts := ordered{}
		opts.add("path", p)
		if host != "" {
			opts.add("headers", ordered{{"Host", host}})
		}
		if strings.EqualFold(network, "httpupgrade") {
			opts.add("v2ray-http-upgrade", true)
		} else if ed > 0 {
			opts.add("max-early-data", ed)
			opts.add("early-data-header-name", "Sec-WebSocket-Protocol")
		}
		m.add("network", "ws")
		m.add("ws-opts", opts)
	case "grpc":
		m.add("network", "grpc")
		m.add("grpc-opts", ordered{{"grpc-service-name", strings.TrimPrefix(serviceName, "/")}})
	case "h2", "http":
		opts := ordered{}
		opts.add("host", splitList(host))
		opts.add("path", path)
		m.add("network", "h2")
		m.add("h2-opts", opts)
	case "xhttp", "splithttp":
		opts := ordered{}
		opts.add("path", path)
		opts.add("host", host)
		opts.add("mode", mode)
		m.add("network", "xhttp")
		m.add("xhttp-opts", opts)
	default:
		return fmt.Errorf("transport %s has no Clash equivalent", network)
	}
	return nil
}

// clashSecurity adds the TLS or REALITY keys.
func clashSecurity(m *ordered, security, sni, alpn, fp, insecure, pin, ech, publicKey, shortID string) {
	switch strings.ToLower(security) {
	case "tls", "reality":
	default:
		return
	}
	m.add("tls", true)
	m.add("servername", sni)
	m.add("alpn", splitList(alpn))
	m.add("client-fingerprint", fp)
	m.add("skip-cert-verify", truthy(insecure))
	m.add("fingerprint", pin)
	if ech != "" {
		m.add("ech-opts", ordered{{"enable", true}, {"config", ech}})
	}
	if strings.EqualFold(security, "reality") {
		m.add("reality-opts", ordered{{"public-key", publicKey}, {"short-id", shortID}})
	}
}

// clashPlugin maps a SIP003 plugin string to Clash plugin + plugin-opts.
func clashPlugin(spec string) (string, ordered, error) {
	parts := strings.Split(spec, ";")
	name := strings.TrimSpace(parts[0])
	kv := map[string]string{}
	flags := map[string]bool{}
	for _, p := range parts[1:] {
		k, v, hasValue := strings.Cut(strings.TrimSpace(p), "=")
		if hasValue {
			kv[k] = v
		} else if k != "" {
			flags[k] = true
		}
	}
	switch name {
	case "obfs-local", "simple-obfs":
		opts := ordered{{"mode", kv["obfs"]}}
		opts.add("host", kv["obfs-host"])
		return "obfs", opts, nil
	case "v2ray-plugin":
		mode := kv["mode"]
		if mode == "" {
			mode = "websocket"
		}
		opts := ordered{{"mode", mode}}
		opts.add("host", kv["host"])
		opts.add("path", kv["path"])
		opts.add("tls", flags["tls"])
		opts.add("mux", kv["mux"] == "1" || flags["mux"])
		return "v2ray-plugin", opts, nil
	}
	return "", nil, fmt.Errorf("shadowsocks plugin %s has no Clash equivalent", name)
}

// splitEarlyData removes xray's "ed=N" early-data marker from a
// WebSocket path.
func splitEarlyData(path string) (string, int) {
	p, rawQuery, found := strings.Cut(path, "?")
	if !found {
		return path, 0
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil || q.Get("ed") == "" {
		return path, 0
	}
	ed, _ := strconv.Atoi(q.Get("ed"))
	q.Del("ed")
	if rest := q.Encode(); rest != "" {
		p += "?" + rest
	}
	return p, ed
}

// hopPorts renders sing-box server_ports ("20000:30000") as mihomo ports.
func hopPorts(ranges []string) string {
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		lo, hi, _ := strings.Cut(r, ":")
		if hi == "" || hi == lo {
			out = append(out, lo)
		} else {
			out = append(out, lo+"-"+hi)
		}
	}
	return strings.Join(out, ",")
}

// reservedList turns WireGuard reserved ("1,2,3" or base64) into ints.
func reservedList(s string) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.Contains(s, ",") {
		var out []int
		for _, part := range strings.Split(s, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return nil
			}
			out = append(out, n)
		}
		return out
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			out := make([]int, len(b))
			for i, c := range b {
				out[i] = int(c)
			}
			return out
		}
	}
	return nil
}

func truthy(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes":
			return true
		}
	case float64:
		return t != 0
	}
	return false
}

// ordered is a YAML mapping that keeps insertion order (Clash users read
// these files; name/type/server first is the convention).
type ordered []kv

type kv struct {
	key   string
	value interface{}
}

// add appends key unless value is empty (zero string, false, 0, empty
// list), so optional Clash keys are simply absent.
func (o *ordered) add(key string, value interface{}) {
	switch v := value.(type) {
	case string:
		if v == "" {
			return
		}
	case bool:
		if !v {
			return
		}
	case int:
		if v == 0 {
			return
		}
	case []string:
		if len(v) == 0 {
			return
		}
	case []int:
		if len(v) == 0 {
			return
		}
	case ordered:
		if len(v) == 0 {
			return
		}
	case nil:
		return
	}
	*o = append(*o, kv{key, value})
}

// set appends key whatever its value (for required keys that may be zero).
func (o *ordered) set(key string, value interface{}) {
	*o = append(*o, kv{key, value})
}

func (o *ordered) remove(key string) {
	out := (*o)[:0]
	for _, e := range *o {
		if e.key != key {
			out = append(out, e)
		}
	}
	*o = out
}

func (o *ordered) rename(from, to string) {
	for i := range *o {
		if (*o)[i].key == from {
			(*o)[i].key = to
		}
	}
}

// MarshalYAML emits the mapping in insertion order.
func (o ordered) MarshalYAML() (interface{}, error) {
	n := &yaml.Node{Kind: yaml.MappingNode}
	for _, e := range o {
		var value yaml.Node
		if err := value.Encode(e.value); err != nil {
			return nil, err
		}
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: e.key}, &value)
	}
	return n, nil
}
