package core

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestConnectionFingerprintPreservesConnectionOptions(t *testing.T) {
	c := NewAutomaticCore(false, false)
	base := "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=tcp&sni=example.com"
	for _, key := range []string{"pbk", "sid", "flow", "fp", "alpn", "pcs", "pqv", "spx", "encryption", "allowInsecure", "headerType", "authority", "serviceName", "mode", "extra", "quicSecurity", "key", "future-option"} {
		t.Run(key, func(t *testing.T) {
			a := fingerprint(t, c, base+"&"+key+"=one")
			b := fingerprint(t, c, base+"&"+key+"=two")
			if a == b {
				t.Fatal("distinct connection options collapsed")
			}
		})
	}
	for _, tc := range []struct{ name, a, b string }{
		{"socks username", "socks://alice:pass@host:1080", "socks://bob:pass@host:1080"},
		{"socks password", "socks://alice:one@host:1080", "socks://alice:two@host:1080"},
		{"ss cipher", "ss://aes-128-gcm:pass@host:443", "ss://aes-256-gcm:pass@host:443"},
		{"ss plugin", "ss://aes-128-gcm:pass@host:443?plugin=one", "ss://aes-128-gcm:pass@host:443?plugin=two"},
		{"wg public key", "wireguard://secret@host:51820?publickey=one", "wireguard://secret@host:51820?publickey=two"},
		{"wg psk", "wireguard://secret@host:51820?presharedkey=one", "wireguard://secret@host:51820?presharedkey=two"},
		{"wg secret", "wireguard://one@host:51820", "wireguard://two@host:51820"},
		{"hy2 obfuscation", "hy2://pass@host:443?obfs-password=one", "hy2://pass@host:443?obfs-password=two"},
		{"trojan reality", "trojan://pass@host:443?security=reality&pbk=one", "trojan://pass@host:443?security=reality&pbk=two"},
		{"repeated query order", base + "&future=one&future=two", base + "&future=two&future=one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if fingerprint(t, c, tc.a) == fingerprint(t, c, tc.b) {
				t.Fatal("distinct configurations collapsed")
			}
		})
	}
}

func TestConnectionFingerprintEquivalentForms(t *testing.T) {
	c := NewAutomaticCore(false, false)
	for _, tc := range []struct{ name, a, b string }{
		{"remark and query order", "vless://uuid@host:443?type=ws&path=%2Fx#one", "vless://uuid@host:443?path=%2fx&type=ws#two"},
		{"endpoint", "vless://uuid@HOST:0443?type=ws", "vless://uuid@host:443?type=ws"},
		{"ss credentials", "ss://aes-128-gcm:pass@host:443", "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pass")) + "@host:443"},
		{"socks credentials", "socks://alice:pass@host:1080", "socks://" + base64.StdEncoding.EncodeToString([]byte("alice:pass")) + "@host:1080"},
		{"hysteria alias", "hy2://pass@host:443", "hysteria2://pass@host:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if fingerprint(t, c, tc.a) != fingerprint(t, c, tc.b) {
				t.Fatal("equivalent configurations did not collapse")
			}
		})
	}
}

func TestConnectionFingerprintVMess(t *testing.T) {
	c := NewAutomaticCore(false, false)
	a := `{"v":"2","add":"host","port":443,"aid":0,"id":"uuid","net":"tcp","ps":"one","extension":{"large":9007199254740992,"array":[1,2]}}`
	b := `{"extension":{"array":[1,2],"large":9007199254740992},"ps":"two","net":"tcp","id":"uuid","aid":"0","port":"443","add":"host","v":2}`
	encode := func(s string) string { return "vmess://" + base64.StdEncoding.EncodeToString([]byte(s)) }
	if fingerprint(t, c, encode(a)) != fingerprint(t, c, encode(b)) {
		t.Fatal("JSON object order, remark or numeric representation changed identity")
	}
	for _, changed := range []string{
		strings.Replace(a, "9007199254740992", "9007199254740993", 1),
		strings.Replace(a, "[1,2]", "[2,1]", 1),
		strings.Replace(a, `"net":"tcp"`, `"net":"tcp","pcs":"pin"`, 1),
	} {
		if fingerprint(t, c, encode(a)) == fingerprint(t, c, encode(changed)) {
			t.Fatal("VMess connection extension lost")
		}
	}
	legacy := "vmess://" + base64.RawStdEncoding.EncodeToString([]byte("auto:uuid@host:443"))
	if fingerprint(t, c, legacy+"?remarks=one&tls=1") != fingerprint(t, c, legacy+"?tls=1&remarks=two") {
		t.Fatal("legacy VMess remark changed identity")
	}
}

func TestConnectionFingerprintContract(t *testing.T) {
	link := "vless://secret@host:443?type=ws&path=%2F#name"
	x := CoreFactoryWith(XrayCoreType, FactoryOptions{})
	s := CoreFactoryWith(SingboxCoreType, FactoryOptions{})
	a := fingerprint(t, x, link)
	if a != fingerprint(t, s, link) || a != fingerprint(t, x, " \n"+link+"\n") {
		t.Fatal("core selection or surrounding whitespace changed source identity")
	}
	if !strings.HasPrefix(a, ConnectionFingerprintVersion+":") || len(a) != len(ConnectionFingerprintVersion)+1+64 || strings.Contains(a, "secret") {
		t.Fatal("fingerprint must be versioned and hashed")
	}
	for _, bad := range []string{"", "not-a-link-secret", "vless://secret@host:443?future=%ZZ", "vless://secret@host:443?a=1;lost=2"} {
		got, err := ConnectionFingerprint(x, bad)
		if err == nil || got != "" || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid input must produce a redacted error and no identity")
		}
	}
	if _, err := ConnectionFingerprint(nil, link); err == nil {
		t.Fatal("nil core accepted")
	}
}

func fingerprint(t *testing.T, c Core, link string) string {
	t.Helper()
	f, err := ConnectionFingerprint(c, link)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestConnectionFingerprintMTProto(t *testing.T) {
	c := NewAutomaticCore(false, false)
	const key = "00112233445566778899aabbccddeeff"
	raw, err := hex.DecodeString("dd" + key)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)

	same := []string{
		"tg://proxy?server=Proxy.Example.com&port=443&secret=dd" + key,
		"https://t.me/proxy?server=proxy.example.com&port=443&secret=DD" + strings.ToUpper(key) + "#renamed",
		"tg://proxy?secret=" + b64 + "&port=443&server=proxy.example.com",
		"tg://proxy?server=proxy.example.com&port=00443&secret=dd" + key,
	}
	want := fingerprint(t, c, same[0])
	for _, link := range same[1:] {
		if fingerprint(t, c, link) != want {
			t.Errorf("%s did not collapse onto %s", link, same[0])
		}
	}

	for name, other := range map[string]string{
		"secret":         "tg://proxy?server=proxy.example.com&port=443&secret=dd" + strings.Repeat("0", 32),
		"port":           "tg://proxy?server=proxy.example.com&port=444&secret=dd" + key,
		"server":         "tg://proxy?server=other.example.com&port=443&secret=dd" + key,
		"secret type":    "tg://proxy?server=proxy.example.com&port=443&secret=" + key,
		"unknown option": same[0] + "&future-option=one",
	} {
		if fingerprint(t, c, other) == want {
			t.Errorf("distinct %s collapsed", name)
		}
	}
}

func TestFingerprintProtocolMatchesLinkFingerprint(t *testing.T) {
	c := NewAutomaticCore(false, false)
	const id = "00000000-0000-0000-0000-000000000000"
	links := []string{
		"vless://" + id + "@Example.com:443?security=tls&sni=a.com&type=ws&path=%2Fx&future=1#one",
		"vless://" + id + "@1.2.3.4:443?security=tls&type=ws&allowInsecure=1#moved-to-sing-box",
		"trojan://p%40ss@1.2.3.4:443#t",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pass")) + "@host:443#ss",
		"socks://alice:pass@host:1080",
		"hy2://pass@host:443?sni=a.com",
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"host","port":443,"id":"uuid","net":"ws","ps":"x"}`)),
		"tg://proxy?server=proxy.example.com&port=443&secret=dd00112233445566778899aabbccddeeff&future-option=1",
	}
	for _, link := range links {
		p, err := c.CreateProtocol(link)
		if err != nil {
			t.Fatalf("CreateProtocol(%s): %v", link, err)
		}
		if err := p.Parse(); err != nil {
			t.Fatalf("Parse(%s): %v", link, err)
		}
		got, err := FingerprintProtocol(p)
		if err != nil {
			t.Fatalf("FingerprintProtocol(%s): %v", link, err)
		}
		if want := fingerprint(t, c, link); got != want {
			t.Errorf("%s: FingerprintProtocol %s != ConnectionFingerprint %s", link, got, want)
		}
	}
	if _, err := FingerprintProtocol(nil); err == nil {
		t.Fatal("nil protocol accepted")
	}
}

func TestFingerprintNewSchemesAndHopping(t *testing.T) {
	c := NewAutomaticCore(false, false)
	const id = "11111111-1111-1111-1111-111111111111"
	same := [][]string{
		// Port hopping: authority form, mport form, order and ":" spelling.
		{"hysteria2://pw@h.example.com:443,20000-30000/?sni=h.example.com",
			"hysteria2://pw@h.example.com:443/?sni=h.example.com&mport=20000-30000",
			"hy2://pw@h.example.com:443?mport=20000-30000,443&sni=h.example.com"},
		{"hysteria2://pw@h.example.com?sni=h.example.com", "hysteria2://pw@h.example.com:443?sni=h.example.com"},
		{"hysteria://h.example.com:443,5000-6000?auth=pw&peer=h.example.com&upmbps=10&downmbps=50",
			"hysteria://h.example.com:443?auth_str=pw&sni=h.example.com&mport=5000-6000&protocol=udp"},
		{"hysteria://h.example.com:443?auth=pw&peer=p&obfs=xplus&obfsParam=o", "hysteria://h.example.com:443?auth=pw&peer=p&obfs=o"},
		{"tuic://" + id + ":pw@q.example.com:443?sni=q.example.com&congestion_control=bbr&allow_insecure=1",
			"tuic://" + id + ":pw@q.example.com:443?peer=q.example.com&congestion-control=bbr&insecure=true&udp_relay_mode=native"},
		{"anytls://pw@a.example.com:443?sni=a.example.com&insecure=1", "anytls://pw@a.example.com:443?peer=a.example.com&allowInsecure=true&security=tls"},
		{"ssh://u:pw@s.example.com?hk=ssh-ed25519%20AAAA", "ssh://u:pw@s.example.com:22?host_key=ssh-ed25519%20AAAA"},
		// WireGuard keys: raw "+" and "/" or percent-encoded.
		{"wireguard://aa+bb/cc==@1.2.3.4:51820?publickey=x+y/z=&address=10.0.0.2",
			"wireguard://aa%2Bbb%2Fcc%3D%3D@1.2.3.4:51820?publickey=x%2By%2Fz%3D&address=10.0.0.2"},
	}
	for _, group := range same {
		want := fingerprint(t, c, group[0])
		for _, link := range group[1:] {
			if got := fingerprint(t, c, link); got != want {
				t.Errorf("%s did not collapse onto %s", link, group[0])
			}
		}
	}
	for _, pair := range [][2]string{
		{"hysteria2://pw@h.example.com:443?sni=a&mport=20000-30000", "hysteria2://pw@h.example.com:443?sni=a&mport=20000-30001"},
		{"tuic://" + id + ":pw@q:443?congestion_control=bbr", "tuic://" + id + ":pw@q:443?congestion_control=new_reno"},
		{"wireguard://aa+bb@1.2.3.4:51820?publickey=x&address=10.0.0.2", "wireguard://aa bb@1.2.3.4:51820?publickey=x&address=10.0.0.2"},
	} {
		a, errA := ConnectionFingerprint(c, pair[0])
		b, errB := ConnectionFingerprint(c, pair[1])
		if errA == nil && errB == nil && a == b {
			t.Errorf("%s and %s collapsed", pair[0], pair[1])
		}
	}
}

// Canonicalisation follows the parsers exactly: aliases are
// case-sensitive and ranked as the parser ranks them, VMess JSON keys fold
// case as encoding/json does.
func TestFingerprintMatchesParserSemantics(t *testing.T) {
	c := NewAutomaticCore(false, false)
	const id = "11111111-1111-1111-1111-111111111111"
	vm := func(j string) string { return "vmess://" + base64.StdEncoding.EncodeToString([]byte(j)) }
	same := [][2]string{
		{vm(`{"Add":"h.example.com","PORT":"443","id":"u","net":"ws"}`), vm(`{"add":"h.example.com","port":"443","id":"u","net":"ws"}`)},
		{vm(`{"add":"a.example.com","Add":"h.example.com","port":443,"id":"u"}`), vm(`{"add":"h.example.com","port":443,"id":"u"}`)},
		{"tuic://" + id + ":pw@q:443?cc=BBR", "tuic://" + id + ":pw@q:443?congestion_control=bbr"},
		{"tuic://" + id + ":pw@q:443?congestion_control=newreno", "tuic://" + id + ":pw@q:443?congestion_control=new_reno"},
		{"vless://" + id + "@h:443?security=tls&insecure=1&allow_insecure=0", "vless://" + id + "@h:443?security=tls&allowInsecure=1"},
		{"ssh://u:p@h:22?hk=A&host_key=B", "ssh://u:p@h:22?hk=A&hk=B"},
	}
	for _, pair := range same {
		if fingerprint(t, c, pair[0]) != fingerprint(t, c, pair[1]) {
			t.Errorf("%s and %s did not collapse", pair[0], pair[1])
		}
	}
	// The parsers ignore "PEER" (case) and lower-ranked spellings don't
	// override higher ones, so these stay distinct.
	distinct := [][2]string{
		{"tuic://" + id + ":pw@q:443?PEER=a.example.com", "tuic://" + id + ":pw@q:443?sni=a.example.com"},
		{"vless://" + id + "@h:443?security=tls&allowInsecure=0&insecure=1", "vless://" + id + "@h:443?security=tls&allowInsecure=1"},
	}
	for _, pair := range distinct {
		if fingerprint(t, c, pair[0]) == fingerprint(t, c, pair[1]) {
			t.Errorf("%s and %s collapsed", pair[0], pair[1])
		}
	}
}
