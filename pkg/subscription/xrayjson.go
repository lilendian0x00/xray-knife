package subscription

import (
	"strings"
)

// xrayToLink converts one xray outbound. The name is the config-level
// "remarks" when the outbound came from an array of configs, else its tag.
func xrayToLink(o map[string]interface{}) (string, bool, error) {
	proto := strings.ToLower(str(o, "protocol"))
	switch proto {
	case "freedom", "blackhole", "dns", "loopback":
		return "", false, nil // not a proxy
	}
	name := firstNonEmpty(str(o, xrayRemarksKey), str(o, "tag"))
	settings := sub(o, "settings")

	switch proto {
	case "vless", "vmess":
		server, port, user, err := xrayVnext(settings)
		if err != nil {
			return "", true, err
		}
		s, err := xrayStream(sub(o, "streamSettings"))
		if err != nil {
			return "", true, err
		}
		if proto == "vless" {
			return vlessLink(name, server, port, str(user, "id"), str(user, "flow"), str(user, "encryption"), s), true, nil
		}
		return vmessLink(name, server, port, str(user, "id"), integer(user, "alterId"), str(user, "security"), s), true, nil
	case "trojan", "shadowsocks", "socks", "http":
		srv := xrayServer(settings)
		server, port, err := endpoint(str(srv, "address"), integer(srv, "port"))
		if err != nil {
			return "", true, err
		}
		switch proto {
		case "trojan":
			s, err := xrayStream(sub(o, "streamSettings"))
			if err != nil {
				return "", true, err
			}
			if s.Security == "" {
				s.Security = "none"
			}
			return trojanLink(name, server, port, str(srv, "password"), s), true, nil
		case "shadowsocks":
			return ssLink(name, server, port, str(srv, "method"), str(srv, "password"), ""), true, nil
		default:
			// servers[0].users[0], or the flat form's user/pass.
			user, pass := str(srv, "user"), str(srv, "pass")
			if users := list(srv, "users"); len(users) > 0 {
				if u, ok := users[0].(map[string]interface{}); ok {
					user, pass = str(u, "user"), str(u, "pass")
				}
			}
			if proto == "socks" {
				return socksLink(name, server, port, user, pass), true, nil
			}
			ss := sub(o, "streamSettings")
			tls := sub(ss, "tlsSettings")
			return httpLink(name, server, port, httpOpts{
				Username:    user,
				Password:    pass,
				TLS:         strings.EqualFold(str(ss, "security"), "tls"),
				SNI:         str(tls, "serverName"),
				Fingerprint: str(tls, "fingerprint"),
				ALPN:        strs(tls, "alpn"),
				Insecure:    boolean(tls, "allowInsecure"),
			}), true, nil
		}
	case "hysteria":
		server, port, err := endpoint(str(settings, "address"), integer(settings, "port"))
		if err != nil {
			return "", true, err
		}
		ss := sub(o, "streamSettings")
		tls := sub(ss, "tlsSettings")
		h := hysteria2Opts{
			Password:  str(sub(ss, "hysteriaSettings"), "auth"),
			SNI:       str(tls, "serverName"),
			ALPN:      strs(tls, "alpn"),
			PinSHA256: str(tls, "pinnedPeerCertSha256"),
		}
		for _, m := range list(sub(ss, "finalmask"), "udp") {
			if mask, ok := m.(map[string]interface{}); ok && str(mask, "type") == "salamander" {
				h.Obfs, h.ObfsPassword = "salamander", str(sub(mask, "settings"), "password")
			}
		}
		return hysteria2Link(name, server, port, h), true, nil
	case "wireguard":
		w := wireguardOpts{
			PrivateKey: str(settings, "secretKey"),
			Addresses:  strs(settings, "address"),
			MTU:        integer(settings, "mtu"),
			Reserved:   reservedBytes(settings["reserved"]),
		}
		peers := list(settings, "peers")
		if len(peers) == 0 {
			return "", true, skipf("wireguard without peers")
		}
		peer, _ := peers[0].(map[string]interface{})
		w.PublicKey = str(peer, "publicKey")
		w.PreSharedKey = str(peer, "preSharedKey")
		w.AllowedIPs = strs(peer, "allowedIPs")
		w.KeepAlive = integer(peer, "keepAlive")
		host, port := splitEndpoint(str(peer, "endpoint"))
		server, portN, err := endpoint(host, port)
		if err != nil {
			return "", true, err
		}
		if w.PrivateKey == "" || w.PublicKey == "" {
			return "", true, skipf("wireguard without keys")
		}
		return wireguardLink(name, server, portN, w), true, nil
	default:
		return "", true, skipf("unsupported xray outbound protocol %s", proto)
	}
}

// xrayVnext reads the VLESS/VMess server: the classic vnext list or the
// flat form newer xray accepts (address/port/id in settings).
func xrayVnext(settings map[string]interface{}) (string, int, map[string]interface{}, error) {
	if vnext := list(settings, "vnext"); len(vnext) > 0 {
		v, _ := vnext[0].(map[string]interface{})
		var user map[string]interface{}
		if users := list(v, "users"); len(users) > 0 {
			user, _ = users[0].(map[string]interface{})
		}
		server, port, err := endpoint(str(v, "address"), integer(v, "port"))
		if err == nil && str(user, "id") == "" {
			err = skipf("missing user id")
		}
		return server, port, user, err
	}
	server, port, err := endpoint(str(settings, "address"), integer(settings, "port"))
	if err == nil && str(settings, "id") == "" {
		err = skipf("missing user id")
	}
	return server, port, settings, err
}

// xrayServer returns servers[0], or the flat settings object.
func xrayServer(settings map[string]interface{}) map[string]interface{} {
	if servers := list(settings, "servers"); len(servers) > 0 {
		if s, ok := servers[0].(map[string]interface{}); ok {
			return s
		}
	}
	return settings
}

// xrayStream maps streamSettings to the shared stream description.
func xrayStream(ss map[string]interface{}) (stream, error) {
	s := stream{Network: strings.ToLower(str(ss, "network"))}
	switch s.Network {
	case "", "tcp", "raw":
		s.Network = "tcp"
		t := sub(ss, "rawSettings")
		if t == nil {
			t = sub(ss, "tcpSettings")
		}
		if h := sub(t, "header"); strings.EqualFold(str(h, "type"), "http") {
			req := sub(h, "request")
			s.HeaderType = "http"
			s.Path = strings.Join(strs(req, "path"), ",")
			s.Host = headerValue(sub(req, "headers"), "Host")
		}
	case "ws", "websocket":
		s.Network = "ws"
		w := sub(ss, "wsSettings")
		s.Path = str(w, "path")
		s.Host = firstNonEmpty(str(w, "host"), headerValue(sub(w, "headers"), "Host"))
	case "grpc":
		g := sub(ss, "grpcSettings")
		s.ServiceName, s.Authority = str(g, "serviceName"), str(g, "authority")
		if boolean(g, "multiMode") {
			s.Mode = "multi"
		}
	case "xhttp", "splithttp":
		x := sub(ss, "xhttpSettings")
		if x == nil {
			x = sub(ss, "splithttpSettings")
		}
		s.Network = "xhttp"
		s.Host, s.Path, s.Mode = str(x, "host"), str(x, "path"), str(x, "mode")
		if extra := sub(x, "extra"); extra != nil {
			s.Extra = compactJSON(extra)
		}
	case "httpupgrade":
		h := sub(ss, "httpupgradeSettings")
		s.Host, s.Path = str(h, "host"), str(h, "path")
	case "kcp", "mkcp":
		s.Network = "kcp"
		k := sub(ss, "kcpSettings")
		s.HeaderType = str(sub(k, "header"), "type")
		s.Seed = str(k, "seed")
	case "h2", "http":
		h := sub(ss, "httpSettings")
		s.Network = "h2"
		s.Host = strings.Join(strs(h, "host"), ",")
		s.Path = str(h, "path")
	default:
		return s, skipf("unsupported xray network %s", s.Network)
	}

	switch strings.ToLower(str(ss, "security")) {
	case "tls":
		t := sub(ss, "tlsSettings")
		s.Security = "tls"
		s.SNI = str(t, "serverName")
		s.ALPN = strs(t, "alpn")
		s.Fingerprint = str(t, "fingerprint")
		s.Insecure = boolean(t, "allowInsecure")
		s.PinSHA256 = strings.Join(strs(t, "pinnedPeerCertSha256"), ",")
		s.VerifyNames = strings.Join(strs(t, "verifyPeerCertByName"), ",")
		s.ECH = str(t, "echConfigList")
	case "reality":
		r := sub(ss, "realitySettings")
		s.Security = "reality"
		s.SNI = str(r, "serverName")
		s.Fingerprint = str(r, "fingerprint")
		s.PublicKey = firstNonEmpty(str(r, "publicKey"), str(r, "password"))
		s.ShortID = str(r, "shortId")
		s.SpiderX = str(r, "spiderX")
		s.Mldsa65Verify = str(r, "mldsa65Verify")
	}
	return s, nil
}

// splitEndpoint splits "host:port" (IPv6 in brackets) leniently.
func splitEndpoint(ep string) (string, int) {
	i := strings.LastIndex(ep, ":")
	if i < 0 {
		return ep, 0
	}
	port := integer(map[string]interface{}{"p": ep[i+1:]}, "p")
	return ep[:i], port
}
