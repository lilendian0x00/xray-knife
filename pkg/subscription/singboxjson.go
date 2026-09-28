package subscription

import (
	"strings"
)

// singboxToLink converts one sing-box outbound or endpoint.
func singboxToLink(o map[string]interface{}) (string, bool, error) {
	typ := strings.ToLower(str(o, "type"))
	name := str(o, "tag")
	switch typ {
	case "direct", "block", "dns", "selector", "urltest":
		return "", false, nil // not a proxy
	}

	if typ == "wireguard" {
		return singboxWireguard(o, name)
	}
	port := integer(o, "server_port")
	if port == 0 && (typ == "hysteria" || typ == "hysteria2") {
		// Port hopping only: the first range's low end is the base port;
		// all ranges travel as mport.
		if ranges := strs(o, "server_ports"); len(ranges) > 0 {
			lo, _, _ := strings.Cut(strings.ReplaceAll(ranges[0], "-", ":"), ":")
			port = integer(map[string]interface{}{"p": lo}, "p")
		}
	}
	server, port, err := endpoint(str(o, "server"), port)
	if err != nil {
		return "", true, err
	}

	switch typ {
	case "vmess":
		s, err := singboxStream(o)
		if err != nil {
			return "", true, err
		}
		return vmessLink(name, server, port, str(o, "uuid"), integer(o, "alter_id"), str(o, "security"), s), true, nil
	case "vless":
		s, err := singboxStream(o)
		if err != nil {
			return "", true, err
		}
		return vlessLink(name, server, port, str(o, "uuid"), str(o, "flow"), "", s), true, nil
	case "trojan":
		s, err := singboxStream(o)
		if err != nil {
			return "", true, err
		}
		if s.Security == "" {
			s.Security = "none" // sing-box Trojan without a tls block is plaintext
		}
		return trojanLink(name, server, port, str(o, "password"), s), true, nil
	case "shadowsocks":
		plugin := ""
		if pluginName := str(o, "plugin"); pluginName != "" {
			switch pluginName {
			case "obfs-local", "v2ray-plugin":
			default:
				return "", true, skipf("unsupported shadowsocks plugin %s", pluginName)
			}
			plugin = pluginName
			if opts := str(o, "plugin_opts"); opts != "" {
				plugin += ";" + opts
			}
		}
		return ssLink(name, server, port, str(o, "method"), str(o, "password"), plugin), true, nil
	case "socks":
		if v := str(o, "version"); v != "" && v != "5" {
			return "", true, skipf("socks%s is not supported", v)
		}
		return socksLink(name, server, port, str(o, "username"), str(o, "password")), true, nil
	case "http":
		tls := sub(o, "tls")
		return httpLink(name, server, port, httpOpts{
			Username:    str(o, "username"),
			Password:    str(o, "password"),
			TLS:         boolean(tls, "enabled"),
			SNI:         str(tls, "server_name"),
			Fingerprint: str(sub(tls, "utls"), "fingerprint"),
			ALPN:        strs(tls, "alpn"),
			Insecure:    boolean(tls, "insecure"),
		}), true, nil
	case "hysteria2":
		tls := sub(o, "tls")
		h := hysteria2Opts{
			Password: str(o, "password"),
			SNI:      str(tls, "server_name"),
			Insecure: boolean(tls, "insecure"),
			ALPN:     strs(tls, "alpn"),
			Ports:    singboxPorts(o),
		}
		if obfs := sub(o, "obfs"); obfs != nil {
			h.Obfs, h.ObfsPassword = str(obfs, "type"), str(obfs, "password")
		}
		if pins := strs(tls, "certificate_public_key_sha256"); len(pins) > 0 {
			return "", true, skipf("hysteria2 public-key pinning is not supported in links")
		}
		return hysteria2Link(name, server, port, h), true, nil
	case "hysteria":
		tls := sub(o, "tls")
		auth := str(o, "auth_str")
		if auth == "" {
			if b, err := decodeBase64(str(o, "auth")); err == nil {
				auth = string(b)
			}
		}
		return hysteriaLink(name, server, port, hysteriaOpts{
			Auth:     auth,
			SNI:      str(tls, "server_name"),
			Obfs:     str(o, "obfs"),
			UpMbps:   integer(o, "up_mbps"),
			DownMbps: integer(o, "down_mbps"),
			Insecure: boolean(tls, "insecure"),
			ALPN:     strs(tls, "alpn"),
			Ports:    singboxPorts(o),
		}), true, nil
	case "tuic":
		tls := sub(o, "tls")
		return tuicLink(name, server, port, tuicOpts{
			UUID:              str(o, "uuid"),
			Password:          str(o, "password"),
			SNI:               str(tls, "server_name"),
			CongestionControl: str(o, "congestion_control"),
			UDPRelayMode:      str(o, "udp_relay_mode"),
			ALPN:              strs(tls, "alpn"),
			Insecure:          boolean(tls, "insecure"),
			DisableSNI:        boolean(tls, "disable_sni"),
			ZeroRTT:           boolean(o, "zero_rtt_handshake"),
		}), true, nil
	case "anytls":
		tls := sub(o, "tls")
		a := anytlsOpts{
			Password:    str(o, "password"),
			SNI:         str(tls, "server_name"),
			Fingerprint: str(sub(tls, "utls"), "fingerprint"),
			ALPN:        strs(tls, "alpn"),
			Insecure:    boolean(tls, "insecure"),
		}
		if r := sub(tls, "reality"); boolean(r, "enabled") {
			a.Security, a.PublicKey, a.ShortID = "reality", str(r, "public_key"), str(r, "short_id")
		}
		return anytlsLink(name, server, port, a), true, nil
	case "ssh":
		if str(o, "private_key_path") != "" {
			return "", true, skipf("ssh private key file paths are not supported")
		}
		return sshLink(name, server, port, sshOpts{
			User:       str(o, "user"),
			Password:   str(o, "password"),
			PrivateKey: strings.Join(strs(o, "private_key"), "\n"),
			Passphrase: str(o, "private_key_passphrase"),
			HostKeys:   strs(o, "host_key"),
		}), true, nil
	default:
		return "", true, skipf("unsupported sing-box outbound type %s", typ)
	}
}

// singboxStream maps the tls and transport blocks of vmess/vless/trojan.
func singboxStream(o map[string]interface{}) (stream, error) {
	var s stream
	if tls := sub(o, "tls"); boolean(tls, "enabled") {
		s.Security = "tls"
		s.SNI = str(tls, "server_name")
		s.ALPN = strs(tls, "alpn")
		s.Insecure = boolean(tls, "insecure")
		if utls := sub(tls, "utls"); boolean(utls, "enabled") {
			s.Fingerprint = str(utls, "fingerprint")
		}
		if r := sub(tls, "reality"); boolean(r, "enabled") {
			s.Security = "reality"
			s.PublicKey, s.ShortID = str(r, "public_key"), str(r, "short_id")
		}
		if ech := sub(tls, "ech"); boolean(ech, "enabled") {
			s.ECH = strings.Join(strs(ech, "config"), "")
		}
	}

	t := sub(o, "transport")
	switch typ := strings.ToLower(str(t, "type")); typ {
	case "":
		s.Network = "tcp"
	case "ws":
		s.Network = "ws"
		s.Path = str(t, "path")
		s.Host = headerValue(sub(t, "headers"), "Host")
		if ed := integer(t, "max_early_data"); ed > 0 {
			s.Path = addEarlyData(s.Path, ed)
		}
	case "grpc":
		s.Network, s.ServiceName = "grpc", str(t, "service_name")
	case "http":
		// sing-box "http" is HTTP/2 over TLS (h2) or plain HTTP.
		s.Network = "h2"
		s.Host = strings.Join(strs(t, "host"), ",")
		s.Path = str(t, "path")
	case "httpupgrade":
		s.Network, s.Host, s.Path = "httpupgrade", str(t, "host"), str(t, "path")
	case "quic":
		s.Network = "quic"
	default:
		return s, skipf("unsupported sing-box transport %s", typ)
	}
	return s, nil
}

// singboxPorts turns server_ports ["20000:30000", "443"] into mport form.
func singboxPorts(o map[string]interface{}) string {
	var ranges []string
	for _, r := range strs(o, "server_ports") {
		ranges = append(ranges, strings.ReplaceAll(r, ":", "-"))
	}
	return strings.Join(ranges, ",")
}

// singboxWireguard handles the 1.11+ endpoint form and the legacy outbound.
func singboxWireguard(o map[string]interface{}, name string) (string, bool, error) {
	w := wireguardOpts{
		PrivateKey: str(o, "private_key"),
		MTU:        integer(o, "mtu"),
		Addresses:  append(strs(o, "address"), strs(o, "local_address")...),
	}
	server, port := str(o, "server"), integer(o, "server_port")
	w.PublicKey = str(o, "peer_public_key")
	w.PreSharedKey = str(o, "pre_shared_key")
	w.Reserved = reservedBytes(o["reserved"])
	if peers := list(o, "peers"); len(peers) > 0 {
		if peer, ok := peers[0].(map[string]interface{}); ok {
			server = firstNonEmpty(str(peer, "address"), str(peer, "server"), server)
			if pt := integer(peer, "port"); pt > 0 {
				port = pt
			} else if pt := integer(peer, "server_port"); pt > 0 {
				port = pt
			}
			w.PublicKey = firstNonEmpty(str(peer, "public_key"), w.PublicKey)
			w.PreSharedKey = firstNonEmpty(str(peer, "pre_shared_key"), w.PreSharedKey)
			w.AllowedIPs = strs(peer, "allowed_ips")
			w.KeepAlive = integer(peer, "persistent_keepalive_interval")
			if r := reservedBytes(peer["reserved"]); len(r) > 0 {
				w.Reserved = r
			}
		}
	}
	server, port, err := endpoint(server, port)
	if err != nil {
		return "", true, err
	}
	if w.PrivateKey == "" || w.PublicKey == "" {
		return "", true, skipf("wireguard without keys")
	}
	return wireguardLink(name, server, port, w), true, nil
}
