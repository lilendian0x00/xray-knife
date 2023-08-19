package xray

import "testing"

func TestTrojan_Parse(t *testing.T) {
	var ss Trojan
	err := ss.Parse("trojan://fsdfsgfgdfgdfg@1.1.1.1:80?flow=xtls-rprx-vision-udp443&security=tls&sni=example.com&alpn=h2%2Chttp%2F1.1&fp=chrome&type=grpc&serviceName=%2Fgdfgdgdfgdfgdfgfg&mode=gun#exa")
	if err != nil {
		t.Errorf("Error when parsing: %v", err)
	}
	t.Logf("%s\n", ss.DetailsStr())
}
