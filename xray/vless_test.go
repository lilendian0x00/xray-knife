package xray

import (
	"reflect"
	"testing"
)

func TestVless_Parse(t *testing.T) {
	var v Vless
	err := v.Parse("vless://h1px412i-9138-s9m5-9b86-d47d74dd8541@127.0.0.1:8080?type=tcp&security=reality&pbk=4442383675fc0fb574c3e50abbe7d4c5&fp=chrome&sni=yahoo.com&sid=0c&spx=%2F&flow=xtls-rprx-vision#Myremark")
	if err != nil {
		t.Errorf("Error when parsing: %v", err)
	}

	expected := `Protocol: vless
Remark: Myremark
Network: tcp
Address: 127.0.0.1
Port: 8080
UUID: h1px412i-9138-s9m5-9b86-d47d74dd8541
Flow: xtls-rprx-vision
TLS: reality
Public key: 4442383675fc0fb574c3e50abbe7d4c5
SNI: yahoo.com
ShortID: 0c
SpiderX: /
Fingerprint: chrome
`

	t.Logf("%s\n", v.DetailsStr())
	if expected != v.DetailsStr() {
		t.Fatalf("expected %q, got %q", expected, v.DetailsStr())
	}

	expectedMap := map[string]string{
		"Protocol":    "vless",
		"Remark":      "Myremark",
		"Network":     "tcp",
		"Address":     "127.0.0.1",
		"Port":        "8080",
		"UUID":        "h1px412i-9138-s9m5-9b86-d47d74dd8541",
		"Flow":        "xtls-rprx-vision",
		"TLS":         "reality",
		"Public key":  "4442383675fc0fb574c3e50abbe7d4c5",
		"SNI":         "yahoo.com",
		"ShortID":     "0c",
		"SpiderX":     "/",
		"Fingerprint": "chrome",
	}

	if !reflect.DeepEqual(expectedMap, v.DetailsMap()) {
		t.Fatalf("expected %v, got %v", expectedMap, v.DetailsMap())
	}
}
