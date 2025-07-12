package xray

import (
	"testing"
)

func TestSocks_GetLink(t *testing.T) {
	tests := []struct {
		name string
		sock *Socks
		want string
	}{
		{
			name: "SOCKS with auth and remark",
			sock: &Socks{
				Address:  "example.com",
				Port:     "1080",
				Username: "user",
				Password: "password",
				Remark:   "My SOCKS Proxy",
			},
			want: "socks://dXNlcjpwYXNzd29yZA==@example.com:1080#My%20SOCKS%20Proxy",
		},
		{
			name: "SOCKS without auth",
			sock: &Socks{
				Address: "127.0.0.1",
				Port:    "10808",
				Remark:  "Localhost",
			},
			want: "socks://127.0.0.1:10808#Localhost",
		},
		{
			name: "SOCKS with IPv6",
			sock: &Socks{
				Address:  "2001:db8::1",
				Port:     "1080",
				Username: "user-ipv6",
				Password: "pass-ipv6",
				Remark:   "IPv6 Proxy",
			},
			want: "socks://dXNlci1pcHY2OnBhc3MtaXB2Ng==@[2001:db8::1]:1080#IPv6%20Proxy",
		},
		{
			name: "Parse and GetLink consistency",
			sock: &Socks{OrigLink: "socks://dXNlcjpwYXNzd29yZA==@example.com:1080#My%20Proxy"},
			want: "socks://dXNlcjpwYXNzd29yZA==@example.com:1080#My%20Proxy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sock.OrigLink != "" {
				if err := tt.sock.Parse(); err != nil {
					t.Fatalf("Parse() failed: %v", err)
				}
			}
			if got := tt.sock.GetLink(); got != tt.want {
				t.Errorf("GetLink() = %v, want %v", got, tt.want)
			}
		})
	}
}
