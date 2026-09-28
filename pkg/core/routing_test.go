package core

import (
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
)

func TestAutomaticCoreRoutesByCapability(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000000"
	cases := []struct {
		name     string
		link     string
		insecure bool
		singbox  bool
	}{
		{"plain tls stays on xray", "vless://" + id + "@1.2.3.4:443?security=tls&sni=a.com&type=ws", false, false},
		{"link insecure moves to sing-box", "vless://" + id + "@1.2.3.4:443?security=tls&sni=a.com&type=ws&allowInsecure=1", false, true},
		{"global insecure moves to sing-box", "trojan://pass@1.2.3.4:443?sni=a.com", true, true},
		{"pinned cert stays on xray", "vless://" + id + "@1.2.3.4:443?security=tls&type=tcp&allowInsecure=1&pcs=" + strings.Repeat("ab", 32), false, false},
		{"reality stays on xray", "vless://" + id + "@1.2.3.4:443?security=reality&pbk=k&sid=1&sni=a.com", true, false},
		{"xhttp stays on xray", "vless://" + id + "@1.2.3.4:443?security=tls&type=xhttp&sni=a.com", true, false},
		{"tcp http obfs stays on xray", "vless://" + id + "@1.2.3.4:443?security=tls&type=tcp&headerType=http&sni=a.com", true, false},
		{"removed h2 transport", "vless://" + id + "@1.2.3.4:443?security=tls&type=h2&sni=a.com", false, true},
		{"legacy ss cipher", "ss://aes-256-cfb:pass@1.2.3.4:8388", false, true},
		{"ss plugin", "ss://aes-128-gcm:pass@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp", false, true},
		{"aead ss", "ss://aes-128-gcm:pass@1.2.3.4:8388", false, false},
		{"upper-case scheme", "VLESS://" + id + "@1.2.3.4:443?security=none", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewAutomaticCoreWith(FactoryOptions{InsecureTLS: tc.insecure}).(*AutomaticCore)
			p, err := c.CreateProtocol(tc.link)
			if err != nil {
				t.Fatalf("CreateProtocol: %v", err)
			}
			_, onSingbox := p.(singbox.Protocol)
			_, onXray := p.(xray.Protocol)
			if onSingbox != tc.singbox || onXray == tc.singbox {
				t.Fatalf("created %T, want sing-box=%v", p, tc.singbox)
			}
			// MakeInstance/MakeHttpClient must follow the protocol's core,
			// not re-route by scheme.
			got, err := c.coreFor(p)
			if err != nil {
				t.Fatal(err)
			}
			if want := map[bool]Core{true: c.singboxCore, false: c.xrayCore}[tc.singbox]; got != want {
				t.Fatalf("coreFor(%T) = %s", p, got.Name())
			}
		})
	}
}

func TestAutomaticCoreRemarkWithPercent(t *testing.T) {
	c := NewAutomaticCore(false, false)
	p, err := c.CreateProtocol("vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=none#Speed 100%")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Parse(); err != nil {
		t.Fatal(err)
	}
	if _, err := ConnectionFingerprint(c, "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=none#Speed 100%"); err != nil {
		t.Fatalf("fingerprint rejected a %% remark: %v", err)
	}
}

func TestCoreFactoryAuto(t *testing.T) {
	if _, ok := CoreFactoryWith(AutoCoreType, FactoryOptions{}).(*AutomaticCore); !ok {
		t.Fatal("CoreFactoryWith(AutoCoreType) must return the automatic core")
	}
}

func TestFingerprintDefaultParams(t *testing.T) {
	c := NewAutomaticCore(false, false)
	const id = "00000000-0000-0000-0000-000000000000"
	for _, pair := range [][2]string{
		{"vless://" + id + "@h:443", "vless://" + id + "@h:443?security=none&encryption=none&type=tcp&headerType=none&sni="},
		{"vless://" + id + "@h:443?security=tls", "vless://" + id + "@h:443?security=tls&fp=chrome"},
		{"trojan://p@h:443", "trojan://p@h:443?security=tls&type=raw&fp=chrome"},
	} {
		if fingerprint(t, c, pair[0]) != fingerprint(t, c, pair[1]) {
			t.Errorf("%s and %s did not collapse", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{
		{"trojan://p@h:443", "trojan://p@h:443?security=none"},
		{"vless://" + id + "@h:443", "vless://" + id + "@h:443?fp=chrome&security=none&x=1"},
	} {
		if fingerprint(t, c, pair[0]) == fingerprint(t, c, pair[1]) {
			t.Errorf("%s and %s collapsed", pair[0], pair[1])
		}
	}
}
