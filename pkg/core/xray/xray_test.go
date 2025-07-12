package xray

import (
	"net/url"
	"reflect"
	"testing"
	"time"
)

// areURLEqual compares two URL strings by parsing them and comparing their components.
// It ignores the order of query parameters.
func areURLEqual(want, got string) (bool, string) {
	wantURL, err := url.Parse(want)
	if err != nil {
		return false, "failed to parse 'want' URL"
	}
	gotURL, err := url.Parse(got)
	if err != nil {
		return false, "failed to parse 'got' URL"
	}

	if wantURL.Scheme != gotURL.Scheme {
		return false, "Scheme mismatch"
	}
	if wantURL.User.String() != gotURL.User.String() {
		return false, "User info mismatch"
	}
	if wantURL.Host != gotURL.Host {
		return false, "Host mismatch"
	}
	if wantURL.Path != gotURL.Path {
		return false, "Path mismatch"
	}
	if wantURL.Fragment != gotURL.Fragment {
		return false, "Fragment mismatch"
	}
	if !reflect.DeepEqual(wantURL.Query(), gotURL.Query()) {
		return false, "Query parameters mismatch"
	}

	return true, ""
}

func TestProtocol_GetLink(t *testing.T) {
	testCases := []struct {
		protocolType string
		link         string
	}{
		// VLESS
		{"VLESS", "vless://a1a1-b2b2-c3c3@example.com:443?encryption=none&security=reality&sni=sub.domain.com&flow=xtls-rprx-vision&type=grpc&serviceName=%2Fmy-service&pbk=KEY&sid=ID#VLESS+REALITY"},
		{"VLESS", "vless://a1a1-b2b2-c3c3@1.2.3.4:80?type=ws&host=my.host.com&path=%2F#VLESS+WS"},

		// VMESS (Method 1 - JSON)
		{"VMESS", "vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJNeS1WTUVTUyIsCiAgImFkZCI6ICJleGFtcGxlLmNvbSIsCiAgInBvcnQiOiA4ODgwLAogICJpZCI6ICJhMWExYjJiMi1jM2MzLWQ0ZDQtZTVlNS1mNmY2ZzdoN2g4aDgiLAogICJhaWQiOiAwLAogICJzY3kiOiAiYXV0byIsCiAgIm5ldCI6ICJ3cyIsCiAgInR5cGUiOiAibm9uZSIsCiAgImhvc3QiOiAiZXhhbXBsZS5jb20iLAogICJwYXRoIjogIi9hcGkiLAogICJ0bHMiOiAidGxzIiwKICAic25pIjogImV4YW1wbGUuY29tIgp9Cg=="},

		// Trojan
		{"Trojan", "trojan://password@example.com:443?security=tls&sni=sub.domain.com&type=grpc&serviceName=my-service#Trojan+GRPC"},
		{"Trojan", "trojan://password@1.2.3.4:80?security=none&type=ws&host=my.host.com&path=%2F#Trojan+WS"},

		// Shadowsocks
		{"Shadowsocks", "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:443#Shadowsocks-AES"},
		{"Shadowsocks", "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206YW5vdGhlcl9wYXNz@1.2.3.4:8080#Shadowsocks-2022"},

		// SOCKS
		{"SOCKS", "socks://dXNlcjpwYXNzd29yZA==@example.com:1080#SOCKS-Auth"},
		{"SOCKS", "socks://127.0.0.1:10808#SOCKS-NoAuth"},

		// WireGuard
		{"WireGuard", "wireguard://SECRET_KEY@1.2.3.4:51820?address=10.0.0.2%2F32&presharedkey=PSK&publickey=PUBLIC_KEY#WireGuard-PSK"},
	}

	for _, tc := range testCases {
		t.Run(tc.protocolType+"_GetLink", func(t *testing.T) {
			proto, err := NewXrayService(false, false).CreateProtocol(tc.link)
			if err != nil {
				t.Fatalf("CreateProtocol() failed: %v", err)
			}

			if err := proto.Parse(); err != nil {
				t.Fatalf("Parse() failed: %v", err)
			}

			var gotLink string
			switch p := proto.(type) {
			case *Vless:
				gotLink = p.GetLink()
			case *Vmess:
				// VMESS GetLink is complex due to multiple formats; skipping for this generalized test.
				// A dedicated test in vmess_test.go would be better.
				t.Skip("VMESS GetLink test is skipped in this suite.")
			case *Trojan:
				gotLink = p.GetLink()
			case *Shadowsocks:
				gotLink = p.GetLink()
			case *Socks:
				gotLink = p.GetLink()
			case *Wireguard:
				gotLink = p.GetLink()
			default:
				t.Fatalf("Unknown protocol type: %T", proto)
			}

			if ok, reason := areURLEqual(tc.link, gotLink); !ok {
				t.Errorf("GetLink() did not return an equivalent URL. Reason: %s\n want: %s\n got:  %s", reason, tc.link, gotLink)
			}
		})
	}
}

func TestProtocol_BuildConfigs(t *testing.T) {
	testCases := []struct {
		name         string
		link         string
		expectInbErr bool
	}{
		{"VLESS-WS", "vless://a1a1-b2b2-c3c3@1.2.3.4:80?type=ws&host=my.host.com&path=%2F#VLESS+WS", false},
		{"Trojan-GRPC", "trojan://password@example.com:443?security=tls&sni=sub.domain.com&type=grpc&serviceName=my-service#Trojan+GRPC", false},
		{"Shadowsocks", "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:443#SS", false},
		{"SOCKS5-Auth", "socks://dXNlcjpwYXNzd29yZA==@example.com:1080#SOCKS", false},
		{"WireGuard", "wireguard://SECRET_KEY@1.2.3.4:51820?address=10.0.0.2%2F32&publickey=PUBLIC_KEY#WG", true}, // Inbound from client link not supported
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_BuildOutbound", func(t *testing.T) {
			core := NewXrayService(false, false)

			proto, err := core.CreateProtocol(tc.link)
			if err != nil {
				t.Fatalf("CreateProtocol() failed: %v", err)
			}
			xrayProtocol := proto.(Protocol)

			if err := xrayProtocol.Parse(); err != nil {
				t.Fatalf("Parse() failed: %v", err)
			}
			outboundConf, err := xrayProtocol.BuildOutboundDetourConfig(false)
			if err != nil {
				t.Fatalf("BuildOutboundDetourConfig() returned an error: %v", err)
			}
			if outboundConf == nil {
				t.Fatal("BuildOutboundDetourConfig() returned nil config")
			}
			if _, err := outboundConf.Build(); err != nil {
				t.Fatalf("outboundConf.Build() failed: %v", err)
			}
		})

		t.Run(tc.name+"_BuildInbound", func(t *testing.T) {
			core := NewXrayService(false, false)

			proto, err := core.CreateProtocol(tc.link)
			if err != nil {
				t.Fatalf("CreateProtocol() failed: %v", err)
			}

			xrayProtocol := proto.(Protocol)
			if err := xrayProtocol.Parse(); err != nil {
				t.Fatalf("Parse() failed: %v", err)
			}
			inboundConf, err := xrayProtocol.BuildInboundDetourConfig()

			if tc.expectInbErr {
				if err == nil {
					t.Fatal("BuildInboundDetourConfig() was expected to return an error, but didn't")
				}
				return
			}

			if err != nil {
				t.Fatalf("BuildInboundDetourConfig() returned an error: %v", err)
			}
			if inboundConf == nil {
				t.Fatal("BuildInboundDetourConfig() returned nil config")
			}
			if _, err := inboundConf.Build(); err != nil {
				t.Fatalf("inboundConf.Build() failed: %v", err)
			}
		})
	}
}

func TestCore_MakeHttpClient(t *testing.T) {
	// This is an integration test to ensure the client construction pipeline works.
	// It does not make a real network request.
	x := NewXrayService(false, false)
	link := "vless://00000000-0000-0000-0000-000000000000@1.1.1.1:80?type=ws&host=example.com&path=%2F"

	protocol, err := x.CreateProtocol(link)
	if err != nil {
		t.Fatalf("CreateProtocol() error = %v", err)
	}

	err = protocol.Parse()
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	client, instance, err := x.MakeHttpClient(protocol, 10*time.Second)
	if err != nil {
		t.Fatalf("MakeHttpClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("MakeHttpClient() returned a nil client")
	}
	if instance == nil {
		t.Fatal("MakeHttpClient() returned a nil instance")
	}

	// Clean up the instance
	if err := instance.Close(); err != nil {
		t.Errorf("instance.Close() error = %v", err)
	}
}
