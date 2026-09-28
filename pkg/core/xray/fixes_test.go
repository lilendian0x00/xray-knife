package xray

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestBuild_TLSInsecureDoesNotError proves B1 is fixed: a TLS config with
// insecure requested must build (xray-core removed "allowInsecure" and now
// hard-errors on it after 2026-06-01). xray can't skip verification, so
// insecure alone sets nothing; "vcn" from the link is passed through.
func TestBuild_TLSInsecureDoesNotError(t *testing.T) {
	cases := []struct {
		name    string
		link    string
		wantVCN string
	}{
		{"vless-tls", "vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443?encryption=none&security=tls&type=tcp&sni=example.com&allowInsecure=1", ""},
		{"vless-vcn", "vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443?encryption=none&security=tls&type=tcp&sni=fake.example&vcn=real.example", "real.example"},
		{"trojan-tls", "trojan://password@1.2.3.4:443?security=tls&type=tcp&sni=example.com&allowInsecure=1", ""},
		{"vmess-tls", "vmess://" + b64VmessTLS(), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := (&Core{}).CreateProtocol(tc.link)
			if err != nil {
				t.Fatalf("CreateProtocol: %v", err)
			}
			xp := p.(Protocol)
			if err := xp.Parse(); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			ob, err := xp.BuildOutboundDetourConfig(true)
			if err != nil {
				t.Fatalf("BuildOutboundDetourConfig: %v", err)
			}
			if ob.StreamSetting.TLSSettings == nil {
				t.Fatalf("expected TLSSettings")
			}
			if ob.StreamSetting.TLSSettings.AllowInsecure {
				t.Errorf("AllowInsecure must not be set (removed by xray-core)")
			}
			if got := ob.StreamSetting.TLSSettings.VerifyPeerCertByName; got != tc.wantVCN {
				t.Errorf("VerifyPeerCertByName = %q, want %q", got, tc.wantVCN)
			}
			// The full build pipeline must succeed (this is what used to error).
			if _, err := ob.Build(); err != nil {
				t.Fatalf("ob.Build() failed (B1 regression): %v", err)
			}
		})
	}
}

// TestBuild_KCPDoesNotError proves B2 is fixed: mKCP header/seed were removed
// and hard-error; a kcp config must build with bare defaults.
func TestBuild_KCPDoesNotError(t *testing.T) {
	link := "vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443?encryption=none&security=none&type=kcp"
	v := &Vless{OrigLink: link}
	if err := v.Parse(); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ob, err := v.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatalf("BuildOutboundDetourConfig: %v", err)
	}
	if ob.StreamSetting.KCPSettings != nil && ob.StreamSetting.KCPSettings.HeaderConfig != nil {
		t.Errorf("KCP HeaderConfig must be nil (removed by xray-core)")
	}
	if _, err := ob.Build(); err != nil {
		t.Fatalf("ob.Build() failed (B2 regression): %v", err)
	}
}

// TestHysteria2_ParseAndBuild covers the new Hysteria2 support on the xray core.
func TestHysteria2_ParseAndBuild(t *testing.T) {
	for _, link := range []string{
		"hysteria2://s3cret@1.2.3.4:443?sni=example.com&insecure=1#hy2",
		"hy2://s3cret@example.com:8443?sni=example.com#alias",
	} {
		p, err := (&Core{}).CreateProtocol(link)
		if err != nil {
			t.Fatalf("CreateProtocol(%q): %v", link, err)
		}
		xp := p.(Protocol)
		if err := xp.Parse(); err != nil {
			t.Fatalf("Parse(%q): %v", link, err)
		}
		ob, err := xp.BuildOutboundDetourConfig(false)
		if err != nil {
			t.Fatalf("BuildOutboundDetourConfig: %v", err)
		}
		if ob.Protocol != "hysteria" {
			t.Errorf("protocol = %q, want hysteria", ob.Protocol)
		}
		if ob.StreamSetting == nil || ob.StreamSetting.HysteriaSettings == nil {
			t.Fatalf("expected HysteriaSettings")
		}
		if ob.StreamSetting.HysteriaSettings.Auth != "s3cret" {
			t.Errorf("auth = %q, want s3cret", ob.StreamSetting.HysteriaSettings.Auth)
		}
		if ob.StreamSetting.HysteriaSettings.Version != 2 {
			t.Errorf("version = %d, want 2", ob.StreamSetting.HysteriaSettings.Version)
		}
		if _, err := ob.Build(); err != nil {
			t.Fatalf("ob.Build() failed for hysteria2: %v", err)
		}
	}
}

// TestShadowsocks_PlainUserinfo proves B5: plain "method:password" userinfo
// (common for SS-2022) parses without base64.
func TestShadowsocks_PlainUserinfo(t *testing.T) {
	s := &Shadowsocks{OrigLink: "ss://2022-blake3-aes-128-gcm:mypassword123@1.2.3.4:8388#plain"}
	if err := s.Parse(); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if s.Encryption != "2022-blake3-aes-128-gcm" {
		t.Errorf("method = %q", s.Encryption)
	}
	if s.Password != "mypassword123" {
		t.Errorf("password = %q", s.Password)
	}
}

// TestVless_PQV proves M1: REALITY post-quantum verify key round-trips.
func TestVless_PQV(t *testing.T) {
	link := "vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@1.2.3.4:443?encryption=none&security=reality&type=tcp&sni=example.com&pbk=PBK&sid=aa&pqv=SOME_MLDSA_KEY"
	v := &Vless{OrigLink: link}
	if err := v.Parse(); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if v.Mldsa65Verify != "SOME_MLDSA_KEY" {
		t.Fatalf("pqv not parsed: %q", v.Mldsa65Verify)
	}
	ob, err := v.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if ob.StreamSetting.REALITYSettings == nil || ob.StreamSetting.REALITYSettings.Mldsa65Verify != "SOME_MLDSA_KEY" {
		t.Errorf("Mldsa65Verify not set on REALITY config")
	}
	if !strings.Contains(v.GetLink(), "pqv=SOME_MLDSA_KEY") {
		t.Errorf("pqv not in GetLink(): %s", v.GetLink())
	}
}

// TestWireguard_Reserved proves M2: reserved/keepAlive/allowedIPs parse and
// reach the built settings JSON.
func TestWireguard_Reserved(t *testing.T) {
	link := "wireguard://cHJpdmF0ZQ@1.2.3.4:51820?publickey=cHVibGlj&address=10.0.0.2%2F32&reserved=1,2,3&keepalive=25&allowedips=0.0.0.0%2F0#wg"
	w := &Wireguard{OrigLink: link}
	if err := w.Parse(); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if w.Reserved != "1,2,3" {
		t.Errorf("reserved not parsed: %q", w.Reserved)
	}
	if w.KeepAlive != 25 {
		t.Errorf("keepalive = %d", w.KeepAlive)
	}
	ob, err := w.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw, _ := ob.Settings.MarshalJSON()
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("settings not valid json: %v", err)
	}
	if _, ok := cfg["reserved"]; !ok {
		t.Errorf("reserved missing from settings: %s", string(raw))
	}
}

// TestVmess_GrpcMultiModeDefault proves B4: default gRPC mode is gun (not multi).
func TestVmess_GrpcMultiModeDefault(t *testing.T) {
	v := &Vmess{Network: "grpc", Path: "svc", Port: "443", ID: "a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5", Address: "1.2.3.4"}
	ob, err := v.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if ob.StreamSetting.GRPCSettings == nil {
		t.Fatalf("expected GRPCSettings")
	}
	if ob.StreamSetting.GRPCSettings.MultiMode {
		t.Errorf("gRPC MultiMode should default to false (gun) when type unset")
	}
}

// b64VmessTLS returns a base64 vmess payload with tls enabled for the insecure test.
func b64VmessTLS() string {
	j := `{"v":"2","add":"1.2.3.4","port":"443","id":"a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5","aid":"0","net":"tcp","tls":"tls","sni":"example.com","ps":"x"}`
	return base64.StdEncoding.EncodeToString([]byte(j))
}
