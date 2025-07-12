package xray

import (
	"net/url"
	"reflect"
	"testing"
)

func TestTrojan_Parse(t *testing.T) {
	// "trojan://fsdfsgfgdfgdfg@1.1.1.1:80?flow=xtls-rprx-vision-udp443&security=tls&sni=example.com&alpn=h2%2Chttp%2F1.1&fp=chrome&type=grpc&serviceName=%2Fgdfgdgdfgdfgfg&mode=gun#exa"
}

func TestTrojan_GetLink(t *testing.T) {
	tests := []struct {
		name string
		link string
	}{
		{
			name: "Complex GRPC REALITY link",
			link: "trojan://password@example.com:443?security=reality&sni=sub.domain.com&alpn=h2,http%2F1.1&flow=xtls-rprx-vision&fp=chrome&type=grpc&serviceName=%2Fmy-service&pbk=PUBLIC_KEY&sid=SHORT_ID&spx=%2Fspider#MyRemark",
		},
		{
			name: "Simple WS TLS link",
			link: "trojan://secret@1.2.3.4:8080?security=tls&sni=my.host.com&type=ws&host=my.host.com&path=%2Fws-path#WS%20TLS%20Config",
		},
		{
			name: "TCP HTTP Header Obfuscation",
			link: "trojan://pass@1.2.3.4:80?security=none&type=tcp&headerType=http&host=some.cdn.com&path=%2F#TCP%2FHTTP",
		},
		{
			name: "No query params or remark",
			link: "trojan://password@test.com:1234",
		},
		{
			name: "IPv6 Host",
			link: "trojan://secret@[2001:db8::1]:443?security=tls&sni=ipv6.example.com&type=ws&host=ipv6.example.com&path=%2F#IPv6-Test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Trojan{}
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
				t.Errorf("User (Password) mismatch: got %q, want %q", generatedURL.User.String(), originalURL.User.String())
			}
			if originalURL.Host != generatedURL.Host {
				t.Errorf("Host mismatch: got %q, want %q", generatedURL.Host, originalURL.Host)
			}
			if originalURL.Fragment != generatedURL.Fragment {
				t.Errorf("Fragment (Remark) mismatch: got %q, want %q", generatedURL.Fragment, originalURL.Fragment)
			}

			originalQuery := originalURL.Query()
			generatedQuery := generatedURL.Query()

			// Since "flow" might be empty and not added, or present and empty, we normalize it for comparison
			if _, ok := originalQuery["flow"]; !ok {
				delete(generatedQuery, "flow")
			}

			if !reflect.DeepEqual(originalQuery, generatedQuery) {
				t.Errorf("Query params mismatch.")
				t.Logf("Got:  %v", generatedQuery)
				t.Logf("Want: %v", originalQuery)
			}
		})
	}
}
