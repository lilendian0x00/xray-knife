package xray

import (
	"io"
	"testing"
	"time"
)

func TestVless_MakeHttpClient(t *testing.T) {
	x := NewXrayService(false, false)

	config := "vless://0090bbba-1118-46ca-87a1-52599cee74ab@laser.kafsabtaheri.com:8085?encryption=none&security=none&sni=laser.kafsabtaheri.com&alpn=h3%2Ch2%2Chttp%2F1.1&fp=chrome&type=ws&host=laser.kafsabtaheri.com&path=%2Firan-mci-irancell-ir#vlessWS"
	protocol, err := x.CreateProtocol(config)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	err = protocol.Parse()
	if err != nil {
		return
	}

	client, _, err := x.MakeHttpClient(protocol, time.Duration(10)*time.Second)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	resp, err := client.Get("http://httpbin.org/ip")
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	t.Logf("%s\n", string(all))
}
