package singbox

import "testing"

func TestNewVless(t *testing.T) {
	link := "vless://0090bbba-1118-46ca-87a1-52599cee74ab@laser.kafsabtaheri.com:8085?encryption=none&security=none&sni=laser.kafsabtaheri.com&alpn=h3%2Ch2%2Chttp%2F1.1&fp=chrome&type=ws&host=laser.kafsabtaheri.com&path=%2Firan-mci-irancell-ir#vlessWS"

	vless := NewVless(link)
	err := vless.Parse()
	if err != nil {
		t.Errorf("%s\n", vless.DetailsStr())
		return
	}

	t.Logf("%s\n", vless.DetailsStr())
}
