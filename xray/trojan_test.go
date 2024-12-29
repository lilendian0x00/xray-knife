package xray

import "testing"

func TestTrojan_Parse(t *testing.T) {
	var ss Trojan
	err := ss.Parse("trojan://fsdfsgfgdfgdfg@1.1.1.1:80?flow=xtls-rprx-vision-udp443&security=tls&sni=example.com&alpn=h2%2Chttp%2F1.1&fp=chrome&type=grpc&serviceName=%2Fgdfgdgdfgdfgdfgfg&mode=gun#exa")
	if err != nil {
		t.Errorf("Error when parsing: %v", err)
	}

	expected := `Protocol: trojan
Remark: exa
Network: grpc
Address: 1.1.1.1
Port: 80
Password: fsdfsgfgdfgdfg
Flow: none
ServiceName: /gdfgdgdfgdfgdfgfg
Authority: 
TLS: tls
SNI: example.com
ALPN: h2,http/1.1
Fingerprint: chrome
`

	t.Logf("%s\n", ss.DetailsStr())
	if expected != ss.DetailsStr() {
		t.Fatalf("expected %q, got %q", expected, ss.DetailsStr())
	}
}
