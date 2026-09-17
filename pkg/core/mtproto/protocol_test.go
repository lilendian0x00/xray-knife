package mtproto

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

func TestIsProxyLink(t *testing.T) {
	yes := []string{
		"tg://proxy?server=1.2.3.4&port=443&secret=" + testKeyHex,
		"https://t.me/proxy?server=1.2.3.4&port=443&secret=" + testKeyHex,
		"http://t.me/proxy?server=1.2.3.4&port=443&secret=" + testKeyHex,
		"https://telegram.me/proxy?server=a&port=1&secret=b",
		"https://telegram.dog/proxy?server=a&port=1&secret=b",
		"  tg://proxy?server=a&port=1&secret=b  ",
	}
	no := []string{
		"https://t.me/joinchat/abc",
		"tg://evil/proxy?server=a&port=1&secret=b",
		"tg://proxy/extra?server=a&port=1&secret=b",
		"https://user@t.me/proxy?server=a&port=1&secret=b",
		"https://example.com/proxy?server=a&port=1&secret=b",
		"vless://uuid@host:443?type=tcp",
		"https://t.me/sub-provider/list.txt",
		"",
		"not a link",
	}
	for _, l := range yes {
		if !IsProxyLink(l) {
			t.Errorf("IsProxyLink(%q) = false, want true", l)
		}
	}
	for _, l := range no {
		if IsProxyLink(l) {
			t.Errorf("IsProxyLink(%q) = true, want false", l)
		}
	}
}

func TestMTProtoParse(t *testing.T) {
	fakeHex := "ee" + testKeyHex + hex.EncodeToString([]byte("www.google.com"))
	cases := []struct {
		name     string
		link     string
		wantAddr string
		wantPort string
		wantType SecretType
		wantRem  string
		wantErr  string
	}{
		{name: "tg simple", link: "tg://proxy?server=1.2.3.4&port=443&secret=" + testKeyHex, wantAddr: "1.2.3.4", wantPort: "443", wantType: SecretSimple},
		{name: "t.me faketls", link: "https://t.me/proxy?server=proxy.example.com&port=8443&secret=" + fakeHex, wantAddr: "proxy.example.com", wantPort: "8443", wantType: SecretFakeTLS},
		{name: "fragment remark", link: "tg://proxy?server=1.2.3.4&port=443&secret=dd" + testKeyHex + "#My%20Proxy", wantAddr: "1.2.3.4", wantPort: "443", wantType: SecretSecured, wantRem: "My Proxy"},
		{name: "ipv6 server", link: "tg://proxy?server=2001:db8::1&port=443&secret=" + testKeyHex, wantAddr: "2001:db8::1", wantPort: "443", wantType: SecretSimple},
		{name: "decimal port normalization", link: "tg://proxy?server=a&port=00443&secret=" + testKeyHex, wantAddr: "a", wantPort: "443", wantType: SecretSimple},
		{name: "malformed query", link: "tg://proxy?server=a&port=443&secret=" + testKeyHex + "&extra=%zz", wantErr: "query"},
		{name: "duplicate server", link: "tg://proxy?server=a&server=b&port=443&secret=" + testKeyHex, wantErr: "duplicate"},
		{name: "missing server", link: "tg://proxy?port=443&secret=" + testKeyHex, wantErr: "server"},
		{name: "missing port", link: "tg://proxy?server=a&secret=" + testKeyHex, wantErr: "port"},
		{name: "bad port", link: "tg://proxy?server=a&port=99999&secret=" + testKeyHex, wantErr: "port"},
		{name: "zero port", link: "tg://proxy?server=a&port=0&secret=" + testKeyHex, wantErr: "port"},
		{name: "missing secret", link: "tg://proxy?server=a&port=443", wantErr: "secret"},
		{name: "bad secret", link: "tg://proxy?server=a&port=443&secret=zz", wantErr: "secret"},
		{name: "not a proxy link", link: "vless://uuid@host:443", wantErr: "not an mtproto proxy link"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMTProto(tc.link)
			err := m.Parse()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if m.Address != tc.wantAddr || m.Port != tc.wantPort || m.Secret.Type != tc.wantType || m.Remark != tc.wantRem {
				t.Errorf("got %q:%q %v %q", m.Address, m.Port, m.Secret.Type, m.Remark)
			}
		})
	}
}

func TestMTProtoGetLinkCanonical(t *testing.T) {
	m := NewMTProto("https://t.me/proxy?secret=" + strings.ToUpper(testKeyHex) + "&port=443&server=Proxy.Example.com")
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	want := "tg://proxy?server=Proxy.Example.com&port=443&secret=" + testKeyHex
	if got := m.GetLink(); got != want {
		t.Errorf("GetLink() = %q, want %q", got, want)
	}
	m2 := NewMTProto("tg://proxy?server=a.b&port=1&secret=" + testKeyHex + "#name")
	if err := m2.Parse(); err != nil {
		t.Fatal(err)
	}
	if got := m2.GetLink(); got != "tg://proxy?server=a.b&port=1&secret="+testKeyHex+"#name" {
		t.Errorf("GetLink() with remark = %q", got)
	}
}

// TestMTProtoRoundTripEscaping covers secrets whose standard-base64 spelling
// contains "+", "/" and "=", and remarks with characters that must survive
// the GetLink -> Parse round trip.
func TestMTProtoRoundTripEscaping(t *testing.T) {
	// A key whose standard base64 contains both '+' and '/'.
	rawKey := mustHex(t, "ddfbff00112233445566778899aabbccdd")
	std := base64.StdEncoding.EncodeToString(rawKey)
	if !strings.ContainsAny(std, "+/") || !strings.Contains(std, "=") {
		t.Fatalf("test vector %q must exercise +, / and =", std)
	}
	q := url.Values{}
	q.Set("server", "1.2.3.4")
	q.Set("port", "443")
	q.Set("secret", std)
	m := NewMTProto("tg://proxy?" + q.Encode())
	if err := m.Parse(); err != nil {
		t.Fatalf("standard base64 secret %q: %v", std, err)
	}
	if m.Secret.Hex() != strings.ToLower(hex.EncodeToString(rawKey)) {
		t.Errorf("secret = %s, want %x", m.Secret.Hex(), rawKey)
	}

	for _, remark := range []string{"a b", "with#hash", "100%", "a/b", "a+b", "پروکسی", "emoji 🚀"} {
		src := NewMTProto("tg://proxy?server=1.2.3.4&port=443&secret=" + testKeyHex + "#" + url.PathEscape(remark))
		if err := src.Parse(); err != nil {
			t.Fatalf("remark %q: %v", remark, err)
		}
		if src.Remark != remark {
			t.Errorf("parsed remark = %q, want %q", src.Remark, remark)
		}
		again := NewMTProto(src.GetLink())
		if err := again.Parse(); err != nil {
			t.Fatalf("round trip of remark %q (%s): %v", remark, src.GetLink(), err)
		}
		if again.Remark != remark {
			t.Errorf("round-tripped remark = %q, want %q", again.Remark, remark)
		}
	}

	// IPv6 servers survive the canonical link round trip.
	v6 := NewMTProto("tg://proxy?server=2001:db8::1&port=443&secret=" + testKeyHex)
	if err := v6.Parse(); err != nil {
		t.Fatal(err)
	}
	back := NewMTProto(v6.GetLink())
	if err := back.Parse(); err != nil {
		t.Fatalf("ipv6 round trip (%s): %v", v6.GetLink(), err)
	}
	if back.Address != "2001:db8::1" {
		t.Errorf("ipv6 address = %q", back.Address)
	}
}

func TestMTProtoGeneralConfig(t *testing.T) {
	fakeHex := "ee" + testKeyHex + hex.EncodeToString([]byte("www.google.com"))
	link := "tg://proxy?server=1.2.3.4&port=443&secret=" + fakeHex + "#r"
	m := NewMTProto(link)
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	g := m.ConvertToGeneralConfig()
	want := protocol.GeneralConfig{
		Protocol: protocol.MTProtoIdentifier,
		Address:  "1.2.3.4",
		Port:     "443",
		ID:       fakeHex,
		TLS:      "faketls",
		SNI:      "www.google.com",
		Network:  "tcp",
		Type:     "tcp",
		Remark:   "r",
		OrigLink: link,
	}
	if g != want {
		t.Errorf("GeneralConfig = %+v\nwant %+v", g, want)
	}
	plain := NewMTProto("tg://proxy?server=1.2.3.4&port=443&secret=" + testKeyHex)
	if err := plain.Parse(); err != nil {
		t.Fatal(err)
	}
	if g := plain.ConvertToGeneralConfig(); g.TLS != "none" || g.SNI != "" {
		t.Errorf("plain GeneralConfig TLS=%q SNI=%q, want none/empty", g.TLS, g.SNI)
	}
	if !strings.Contains(m.DetailsStr(), "www.google.com") || !strings.Contains(m.DetailsStr(), "faketls") {
		t.Errorf("DetailsStr missing cloak host or type:\n%s", m.DetailsStr())
	}
	if m.Name() != "mtproto" {
		t.Errorf("Name() = %q", m.Name())
	}
}
