package xray

import (
	"reflect"
	"testing"
)

func TestShadowSocks_Parse(t *testing.T) {
	var ss Shadowsocks
	err := ss.Parse("ss://YWVzLTI1Ni1nY206RXhhbXBsZUAxMjM0@example.com:443#exa")
	if err != nil {
		t.Errorf("Error when parsing: %v", err)
	}

	expected := `Protocol: shadowsocks
Remark: exa
IP: example.com
Port: 443
Encryption: aes-256-gcm
Password: Example@1234
`

	t.Logf("%s\n", ss.DetailsStr())
	if expected != ss.DetailsStr() {
		t.Fatalf("expected %q, got %q", expected, ss.DetailsStr())
	}

	expectedMap := map[string]string{
		"Protocol":   "shadowsocks",
		"Remark":     "exa",
		"IP":         "example.com",
		"Port":       "443",
		"Encryption": "aes-256-gcm",
		"Password":   "Example@1234",
	}

	if !reflect.DeepEqual(expectedMap, ss.DetailsMap()) {
		t.Fatalf("expected %v, got %v", expectedMap, ss.DetailsMap())
	}
}
