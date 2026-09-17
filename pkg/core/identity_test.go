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
