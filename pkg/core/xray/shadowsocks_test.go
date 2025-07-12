package xray

import (
	"net/url"
	"testing"
)

func TestShadowSocks_Parse(t *testing.T) {
	// "ss://YWVzLTI1Ni1nY206RXhhbXBsZUAxMjM0@example.com:443#exa"
}

func TestShadowsocks_GetLink(t *testing.T) {
	tests := []struct {
		name string
		ss   *Shadowsocks
		want string
	}{
		{
			name: "Simple AES-256-GCM",
			ss: &Shadowsocks{
				Address:    "example.com",
				Port:       "443",
				Encryption: "aes-256-gcm",
				Password:   "password123",
				Remark:     "Test-Remark",
			},
			want: "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM@example.com:443#Test-Remark",
		},
		{
			name: "No Remark",
			ss: &Shadowsocks{
				Address:    "1.1.1.1",
				Port:       "8080",
				Encryption: "chacha20-ietf-poly1305",
				Password:   "a-very-secret-password",
				Remark:     "",
			},
			want: "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTphLXZlcnktc2VjcmV0LXBhc3N3b3Jk@1.1.1.1:8080",
		},
		{
			name: "Remark with special chars",
			ss: &Shadowsocks{
				Address:    "domain.org",
				Port:       "1234",
				Encryption: "2022-blake3-aes-128-gcm",
				Password:   "another_pass",
				Remark:     "US East (NJ)",
			},
			want: "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206YW5vdGhlcl9wYXNz@domain.org:1234#US%20East%20%28NJ%29",
		},
		{
			name: "Parse and Get should be consistent",
			ss:   &Shadowsocks{OrigLink: "ss://YWVzLTI1Ni1nY206RXhhbXBsZUAxMjM0@example.com:443#My%20Remark"},
			want: "ss://YWVzLTI1Ni1nY206RXhhbXBsZUAxMjM0@example.com:443#My%20Remark",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ss.OrigLink != "" {
				if err := tt.ss.Parse(); err != nil {
					t.Fatalf("Parse() error = %v", err)
				}
			}

			got := tt.ss.GetLink()

			// To handle potential encoding differences or query order, parse and compare.
			gotURL, err := url.Parse(got)
			if err != nil {
				t.Fatalf("Failed to parse generated link: %s", got)
			}
			wantURL, err := url.Parse(tt.want)
			if err != nil {
				t.Fatalf("Failed to parse want link: %s", tt.want)
			}

			if gotURL.String() != wantURL.String() {
				t.Errorf("GetLink() = %v, want %v", got, tt.want)
			}
		})
	}
}
