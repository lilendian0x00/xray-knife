package xray

import (
	"net/url"
	"reflect"
	"testing"
)

func TestWireguard_GetLink(t *testing.T) {
	tests := []struct {
		name string
		link string
	}{
		{
			name: "Full Config with PSK",
			link: "wireguard://SECRET_KEY@1.2.3.4:5678?address=10.0.0.2%2F32&mtu=1420&presharedkey=PSK_KEY&publickey=PUBLIC_KEY#My-WG-Config",
		},
		{
			name: "Minimal Config without PSK",
			link: "wireguard://ANOTHER_SECRET_KEY@example.com:51820?address=192.168.1.5%2F24&publickey=ANOTHER_PUBLIC_KEY#Simple-Config",
		},
		{
			name: "Dual Stack Address",
			link: "wireguard://DUAL_STACK_SECRET@2a01::1:1234?address=172.16.0.2%2F32,fd00::2%2F128&publickey=DUAL_STACK_PUBLIC#Dual%20Stack",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Wireguard{}
			v.OrigLink = tt.link
			if err := v.Parse(); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			generatedLink := v.GetLink()

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
			// url.User() automatically decodes the user part, so we compare the original User string
			if originalURL.User.String() != generatedURL.User.String() {
				t.Errorf("User (SecretKey) mismatch: got %q, want %q", generatedURL.User.String(), originalURL.User.String())
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
