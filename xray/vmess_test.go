package xray

import (
	"testing"
)

func TestVmess_Parse(t *testing.T) {
	var v Vmess
	err := v.Parse("vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJUZXN0cmVtYXJrLWIyc2x4bWZpIiwKICAiYWRkIjogIjEyNy4wLjAuMSIsCiAgInBvcnQiOiAyNjYzNSwKICAiaWQiOiAiOTMwZTk0NDQtYzU1ZC00YjcyLTk0NTUtYjk4MTE2ZGFhNGIzIiwKICAic2N5IjogImF1dG8iLAogICJuZXQiOiAidGNwIiwKICAidHlwZSI6ICJub25lIiwKICAidGxzIjogInRscyIKfQ==")
	if err != nil {
		t.Errorf("Error when parsing: %v", err)
	}

	expected := `Protocol: vmess
Remark: Testremark-b2slxmfi
Network: tcp
Address: 127.0.0.1
Port: 26635
UUID: 930e9444-c55d-4b72-9455-b98116daa4b3
TLS: tls
SNI: none
ALPN: none
Fingerprint: none
`

	t.Logf("%s\n", v.DetailsStr())
	if expected != v.DetailsStr() {
		t.Fatalf("expected %q, got %q", expected, v.DetailsStr())
	}
}
