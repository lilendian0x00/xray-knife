package singbox

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestHysteria2_MakeHttpClient(t *testing.T) {
	s := NewSingboxService(false, false)

	config := "hysteria2://fKt0mUHH2UKx6kl3xdI43yiV@laser.kafsabtaheri.com:8443/?sni=laser.kafsabtaheri.com&alpn=h3%2Ch2%2Chttp%2F1.1&obfs=salamander&obfs-password=HGdgfYUJFGjgD#H"
	protocol, err := s.CreateProtocol(config)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	err = protocol.Parse()
	if err != nil {
		return
	}

	client, _, err := s.MakeHttpClient(context.Background(), protocol, time.Duration(10)*time.Second)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	resp, err := client.Get("http://httpbin.org/ip")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	t.Logf("%s\n", string(all))
}

func TestVless_MakeHttpClient(t *testing.T) {
	s := NewSingboxService(false, false)

	config := "vless://0090bbba-1118-46ca-87a1-52599cee74ab@laser.kafsabtaheri.com:8085?encryption=none&security=none&sni=laser.kafsabtaheri.com&alpn=h3%2Ch2%2Chttp%2F1.1&fp=chrome&type=ws&host=laser.kafsabtaheri.com&path=%2Firan-mci-irancell-ir#vlessWS"
	protocol, err := s.CreateProtocol(config)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	err = protocol.Parse()
	if err != nil {
		return
	}

	client, _, err := s.MakeHttpClient(context.Background(), protocol, time.Duration(10)*time.Second)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	resp, err := client.Get("http://httpbin.org/ip")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	t.Logf("%s\n", string(all))
}

func TestWireguard_MakeHttpClient(t *testing.T) {
	s := NewSingboxService(false, false)

	config := "wireguard://WJD7jPqCgI%2BXxujP3d%2FaqzUOJUjjWvlFIoHnK0AQGmk%3D@188.114.97.225:5279?address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A8f81%3Ad551%3Aa0%3A532e%3Aa2b3%2F128&reserved=98%2C233%2C215&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&mtu=1280&keepalive=5&wnoise=quic&wnoisecount=15&wnoisedelay=1&wpayloadsize=5-10#HELI 2024-12-18 10:02"
	protocol, err := s.CreateProtocol(config)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	err = protocol.Parse()
	if err != nil {
		return
	}

	client, _, err := s.MakeHttpClient(context.Background(), protocol, time.Duration(20)*time.Second)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	resp, err := client.Get("http://httpbin.org")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	resp.Body.Close()

	t.Logf("%s\n", string(all))
}
