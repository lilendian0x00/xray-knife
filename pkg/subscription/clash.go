package subscription

import (
	"strconv"
	"strings"
)

// clashToLink converts one Clash / mihomo "proxies:" entry.
func clashToLink(p map[string]interface{}) (string, bool, error) {
	typ := strings.ToLower(str(p, "type"))
	name := str(p, "name")
	if typ == "" {
		return "", true, skipf("clash proxy without type")
	}
	server, port, err := endpoint(str(p, "server"), integer(p, "port"))
	switch typ {
	case "direct", "reject", "dns", "pass":
		return "", false, nil // not a proxy
	}
	if err != nil {
		return "", true, err
	}

	switch typ {
	case "vmess":
		s, err := clashStream(p, boolean(p, "tls"))
		if err != nil {
			return "", true, err
		}
		cipher := str(p, "cipher")
		if cipher == "" {
			cipher = "auto"
		}
		return vmessLink(name, server, port, str(p, "uuid"), integer(p, "alterId"), cipher, s), true, nil
	case "vless":
		s, err := clashStream(p, boolean(p, "tls"))
		if err != nil {
			return "", true, err
		}
		return vlessLink(name, server, port, str(p, "uuid"), str(p, "flow"), str(p, "encryption"), s), true, nil
	case "trojan":
		s, err := clashStream(p, true)
		if err != nil {
			return "", true, err
		}
		return trojanLink(name, server, port, str(p, "password"), s), true, nil
	case "ss":
		plugin, err := clashSSPlugin(p)
		if err != nil {
			return "", true, err
		}
		return ssLink(name, server, port, str(p, "cipher"), str(p, "password"), plugin), true, nil
	case "socks5":
		if boolean(p, "tls") {
			return "", true, skipf("socks5 over TLS is not supported")
		}
		return socksLink(name, server, port, str(p, "username"), str(p, "password")), true, nil
	case "http":
		return httpLink(name, server, port, httpOpts{
			Username:    str(p, "username"),
			Password:    str(p, "password"),
			TLS:         boolean(p, "tls"),
			SNI:         firstNonEmpty(str(p, "sni"), str(p, "servername")),
			Fingerprint: str(p, "client-fingerprint"),
			Insecure:    boolean(p, "skip-cert-verify"),
		}), true, nil
	case "hysteria2", "hy2":
		o := hysteria2Opts{
			Password:  str(p, "password"),
			SNI:       firstNonEmpty(str(p, "sni"), str(p, "servername")),
			Insecure:  boolean(p, "skip-cert-verify"),
			ALPN:      strs(p, "alpn"),
			PinSHA256: str(p, "fingerprint"),
			Ports:     clashPorts(p),
		}
		if o.Password == "" {
			o.Password = str(p, "auth")
		}
		if obfs := str(p, "obfs"); obfs != "" {
			o.Obfs, o.ObfsPassword = obfs, str(p, "obfs-password")
		}
		return hysteria2Link(name, server, port, o), true, nil
	case "hysteria":
		proto := strings.ToLower(str(p, "protocol"))
		if proto != "" && proto != "udp" {
			return "", true, skipf("hysteria transport %s is not supported", proto)
		}
		// mihomo: auth-str is the password, auth is its base64 encoding.
		auth := str(p, "auth-str")
		if auth == "" {
			if b, err := decodeBase64(str(p, "auth")); err == nil {
				auth = string(b)
			} else {
				auth = str(p, "auth")
			}
		}
		return hysteriaLink(name, server, port, hysteriaOpts{
			Auth:     auth,
			SNI:      firstNonEmpty(str(p, "sni"), str(p, "servername")),
			Obfs:     str(p, "obfs"),
			Protocol: proto,
			UpMbps:   integer(p, "up"),
			DownMbps: integer(p, "down"),
			Insecure: boolean(p, "skip-cert-verify"),
			ALPN:     strs(p, "alpn"),
			Ports:    clashPorts(p),
		}), true, nil
	case "tuic":
		if str(p, "token") != "" && str(p, "uuid") == "" {
			return "", true, skipf("tuic v4 (token) is not supported")
		}
		return tuicLink(name, server, port, tuicOpts{
			UUID:              str(p, "uuid"),
			Password:          str(p, "password"),
			SNI:               firstNonEmpty(str(p, "sni"), str(p, "servername")),
			CongestionControl: str(p, "congestion-controller"),
			UDPRelayMode:      str(p, "udp-relay-mode"),
			ALPN:              strs(p, "alpn"),
			Insecure:          boolean(p, "skip-cert-verify"),
			DisableSNI:        boolean(p, "disable-sni"),
			ZeroRTT:           boolean(p, "reduce-rtt"),
		}), true, nil
	case "anytls":
		o := anytlsOpts{
			Password:    str(p, "password"),
			SNI:         firstNonEmpty(str(p, "sni"), str(p, "servername")),
			Fingerprint: str(p, "client-fingerprint"),
			ALPN:        strs(p, "alpn"),
			Insecure:    boolean(p, "skip-cert-verify"),
		}
		if r := sub(p, "reality-opts"); r != nil {
			o.Security, o.PublicKey, o.ShortID = "reality", str(r, "public-key"), str(r, "short-id")
		}
		return anytlsLink(name, server, port, o), true, nil
	case "wireguard":
		return clashWireguard(p, name, server, port)
	case "ssh":
		key := str(p, "private-key")
		if key != "" && !strings.Contains(key, "PRIVATE KEY") {
			return "", true, skipf("ssh private key file paths are not supported")
		}
		return sshLink(name, server, port, sshOpts{
			User:       str(p, "username"),
			Password:   str(p, "password"),
			PrivateKey: key,
			Passphrase: str(p, "private-key-passphrase"),
			HostKeys:   strs(p, "host-key"),
		}), true, nil
	default:
		return "", true, skipf("unsupported clash proxy type %s", typ)
	}
}

// clashStream maps network, *-opts and TLS fields of vmess/vless/trojan.
func clashStream(p map[string]interface{}, tls bool) (stream, error) {
	s := stream{Network: strings.ToLower(str(p, "network"))}
	switch s.Network {
	case "", "tcp":
		s.Network = "tcp"
	case "ws":
		o := sub(p, "ws-opts")
		s.Path = str(o, "path")
		s.Host = headerValue(sub(o, "headers"), "Host")
		if boolean(o, "v2ray-http-upgrade") {
			s.Network = "httpupgrade"
		} else if ed := integer(o, "max-early-data"); ed > 0 {
			s.Path = addEarlyData(s.Path, ed)
		}
	case "grpc":
		o := sub(p, "grpc-opts")
		s.ServiceName = str(o, "grpc-service-name")
	case "h2":
		o := sub(p, "h2-opts")
		s.Host = strings.Join(strs(o, "host"), ",")
		s.Path = str(o, "path")
	case "http":
		// Clash "http" is TCP with HTTP/1.1 obfuscation.
		o := sub(p, "http-opts")
		s.Network, s.HeaderType = "tcp", "http"
		s.Path = strings.Join(strs(o, "path"), ",")
		s.Host = headerValue(sub(o, "headers"), "Host")
	case "xhttp":
		o := sub(p, "xhttp-opts")
		s.Path, s.Host, s.Mode = str(o, "path"), str(o, "host"), str(o, "mode")
	default:
		return s, skipf("unsupported clash network %s", s.Network)
	}

	reality := sub(p, "reality-opts")
	switch {
	case reality != nil:
		s.Security = "reality"
		s.PublicKey, s.ShortID = str(reality, "public-key"), str(reality, "short-id")
	case tls:
		s.Security = "tls"
	}
	if s.Security != "" {
		s.SNI = firstNonEmpty(str(p, "servername"), str(p, "sni"))
		s.Fingerprint = str(p, "client-fingerprint")
		s.ALPN = strs(p, "alpn")
		s.Insecure = boolean(p, "skip-cert-verify")
		s.PinSHA256 = str(p, "fingerprint")
		if ech := sub(p, "ech-opts"); boolean(ech, "enable") {
			s.ECH = str(ech, "config")
		}
	}
	return s, nil
}

// clashSSPlugin maps Clash plugin/plugin-opts to a SIP003 plugin string.
func clashSSPlugin(p map[string]interface{}) (string, error) {
	plugin := strings.ToLower(str(p, "plugin"))
	o := sub(p, "plugin-opts")
	switch plugin {
	case "":
		return "", nil
	case "obfs", "obfs-local", "simple-obfs":
		mode := str(o, "mode")
		if mode == "" {
			mode = "http"
		}
		spec := "obfs-local;obfs=" + mode
		if host := str(o, "host"); host != "" {
			spec += ";obfs-host=" + host
		}
		return spec, nil
	case "v2ray-plugin":
		mode := str(o, "mode")
		if mode == "" {
			mode = "websocket"
		}
		spec := "v2ray-plugin;mode=" + mode
		if host := str(o, "host"); host != "" {
			spec += ";host=" + host
		}
		if path := str(o, "path"); path != "" {
			spec += ";path=" + path
		}
		if boolean(o, "tls") {
			spec += ";tls"
		}
		if boolean(o, "mux") {
			spec += ";mux=1"
		}
		return spec, nil
	default:
		return "", skipf("unsupported shadowsocks plugin %s", plugin)
	}
}

func clashWireguard(p map[string]interface{}, name, server string, port int) (string, bool, error) {
	if sub(p, "amnezia-wg-option") != nil {
		return "", true, skipf("amneziawg is not supported")
	}
	o := wireguardOpts{
		PrivateKey:   str(p, "private-key"),
		PublicKey:    str(p, "public-key"),
		PreSharedKey: firstNonEmpty(str(p, "pre-shared-key"), str(p, "preshared-key")),
		MTU:          integer(p, "mtu"),
		KeepAlive:    integer(p, "persistent-keepalive"),
		AllowedIPs:   strs(p, "allowed-ips"),
		Reserved:     reservedBytes(p["reserved"]),
	}
	for _, key := range []string{"ip", "ipv6"} {
		if a := str(p, key); a != "" {
			o.Addresses = append(o.Addresses, a)
		}
	}
	// Multi-peer configs: use the first peer's endpoint and keys.
	if peers := list(p, "peers"); len(peers) > 0 {
		if peer, ok := peers[0].(map[string]interface{}); ok {
			if s, pt, err := endpoint(str(peer, "server"), integer(peer, "port")); err == nil {
				server, port = s, pt
			}
			o.PublicKey = firstNonEmpty(str(peer, "public-key"), o.PublicKey)
			o.PreSharedKey = firstNonEmpty(str(peer, "pre-shared-key"), o.PreSharedKey)
			if r := reservedBytes(peer["reserved"]); len(r) > 0 {
				o.Reserved = r
			}
			if ips := strs(peer, "allowed-ips"); len(ips) > 0 {
				o.AllowedIPs = ips
			}
		}
	}
	if o.PrivateKey == "" || o.PublicKey == "" {
		return "", true, skipf("wireguard without keys")
	}
	return wireguardLink(name, server, port, o), true, nil
}

// clashPorts normalises mihomo port-hopping ("20000-30000,40000:41000").
func clashPorts(p map[string]interface{}) string {
	ports := str(p, "ports")
	if ports == "" {
		return ""
	}
	return strings.ReplaceAll(strings.ReplaceAll(ports, ":", "-"), "/", ",")
}

// reservedBytes reads WireGuard reserved bytes from a list, "a,b,c" or
// base64 string.
func reservedBytes(v interface{}) []int {
	switch t := v.(type) {
	case []interface{}:
		out := make([]int, 0, len(t))
		for _, x := range t {
			n, err := strconv.Atoi(scalar(x))
			if err != nil {
				return nil
			}
			out = append(out, n)
		}
		return out
	case string:
		if strings.Contains(t, ",") {
			var out []int
			for _, part := range strings.Split(t, ",") {
				n, err := strconv.Atoi(strings.TrimSpace(part))
				if err != nil {
					return nil
				}
				out = append(out, n)
			}
			return out
		}
		if b, err := decodeBase64(t); err == nil {
			out := make([]int, len(b))
			for i, c := range b {
				out[i] = int(c)
			}
			return out
		}
	}
	return nil
}

// addEarlyData appends xray's "?ed=N" WebSocket early-data marker.
func addEarlyData(path string, ed int) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	if path == "" {
		path = "/"
	}
	return path + sep + "ed=" + strconv.Itoa(ed)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
