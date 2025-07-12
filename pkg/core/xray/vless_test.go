package xray

import (
	"net/url"
	"reflect"
	"testing"
)

func TestVless_GetLink(t *testing.T) {
	tests := []struct {
		name string
		link string
	}{
		{
			name: "Complex GRPC REALITY link",
			link: "vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@example.com:443?encryption=none&security=reality&sni=sub.domain.com&alpn=h2,http%2F1.1&flow=xtls-rprx-vision&fp=chrome&type=grpc&serviceName=%2Fmy-service&pbk=PUBLIC_KEY&sid=SHORT_ID&spx=%2Fspider#MyRemark",
		},
		{
			name: "Simple WS TLS link",
			link: "vless://b1b1b1b1-c2c2-d3d3-e4e4-f5f5f5f5f5f5@1.2.3.4:8080?encryption=none&security=tls&sni=my.host.com&type=ws&host=my.host.com&path=%2Fws-path#WS+TLS+Config",
		},
		{
			name: "TCP HTTP Header Obfuscation",
			link: "vless://c1c1c1c1-d2d2-e3e3-f4f4-a5a5a5a5a5a5@1.2.3.4:80?encryption=none&security=none&type=tcp&headerType=http&host=some.cdn.com&path=%2F#TCP%2FHTTP",
		},
		{
			name: "No query params or remark",
			link: "vless://d1d1d1d1-e2e2-f3f3-a4a4-b5b5b5b5b5b5@test.com:1234?encryption=none",
		},
		{
			name: "IPv6 Host",
			link: "vless://e1e1e1e1-f2f2-a3a3-b4b4-c5c5c5c5c5c5@[2001:db8::1]:443?encryption=none&security=tls&sni=ipv6.example.com&type=ws&host=ipv6.example.com&path=%2F#IPv6-Test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Vless{}
			v.OrigLink = tt.link
			if err := v.Parse(); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			generatedLink := v.GetLink()

			// To compare links, parse both and compare components, as query order can change.
			originalURL, err := url.Parse(tt.link)
			if err != nil {
				t.Fatalf("Failed to parse original link: %v", err)
			}
			generatedURL, err := url.Parse(generatedLink)
			if err != nil {
				t.Fatalf("Failed to parse generated link: %v", err)
			}

			// Compare components
			if originalURL.Scheme != generatedURL.Scheme {
				t.Errorf("Scheme mismatch: got %q, want %q", generatedURL.Scheme, originalURL.Scheme)
			}
			if originalURL.User.String() != generatedURL.User.String() {
				t.Errorf("User (ID) mismatch: got %q, want %q", generatedURL.User.String(), originalURL.User.String())
			}
			if originalURL.Host != generatedURL.Host {
				t.Errorf("Host mismatch: got %q, want %q", generatedURL.Host, originalURL.Host)
			}
			if originalURL.Fragment != generatedURL.Fragment {
				t.Errorf("Fragment (Remark) mismatch: got %q, want %q", generatedURL.Fragment, originalURL.Fragment)
			}

			originalQuery := originalURL.Query()
			generatedQuery := generatedURL.Query()

			if !reflect.DeepEqual(originalQuery, generatedQuery) {
				t.Errorf("Query params mismatch.")
				t.Logf("Got:  %v", generatedQuery)
				t.Logf("Want: %v", originalQuery)
			}
		})
	}
}
