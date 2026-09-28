package xray

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
)

func mustFragment(t *testing.T, spec string, noises ...string) *fragment.Options {
	t.Helper()
	f, err := fragment.Build(spec, noises)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFragmentWiring(t *testing.T) {
	c := NewXrayService(false, false,
		WithFragment(mustFragment(t, "tlshello,100-200,10-20", "rand:10-20:5")),
		WithBindInterface("eth-test"))
	v := &Vless{OrigLink: "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls&sni=example.com&type=ws&path=%2F"}
	if err := v.Parse(); err != nil {
		t.Fatal(err)
	}
	ob, err := v.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.prepareEntry(ob, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	so := ob.StreamSetting.SocketSettings
	if so == nil || so.Interface != "eth-test" || so.DialerProxy != "" {
		t.Fatalf("sockopt = %+v: want the bind and no dialerProxy", so)
	}
	fm := ob.StreamSetting.FinalMask
	if fm == nil || len(fm.Tcp) != 1 || fm.Tcp[0].Type != "fragment" || len(fm.Udp) != 0 {
		t.Fatalf("finalmask = %+v, want one TCP fragment mask", fm)
	}
	var settings map[string]string
	if err := json.Unmarshal(*fm.Tcp[0].Settings, &settings); err != nil {
		t.Fatal(err)
	}
	if settings["packets"] != "tlshello" || settings["length"] != "100-200" || settings["delay"] != "10-20" {
		t.Errorf("fragment settings = %v", settings)
	}
	if _, err := ob.Build(); err != nil {
		t.Fatalf("fragmented outbound does not build: %v", err)
	}
}

func TestFragmentSkipsWhereItCannotHelp(t *testing.T) {
	// TCP fragments do nothing for a UDP protocol; noise does nothing for TCP.
	tcpOnly := NewXrayService(false, false, WithFragment(mustFragment(t, "tlshello,10-20,1")))
	w := &Wireguard{OrigLink: "wireguard://c2VjcmV0@1.2.3.4:51820?publickey=cHVi&address=10.0.0.2"}
	if err := w.Parse(); err != nil {
		t.Fatal(err)
	}
	ob, err := w.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tcpOnly.prepareEntry(ob, "1.2.3.4"); err != nil || ob.StreamSetting != nil {
		t.Errorf("TCP fragment attached to a WireGuard outbound: %v %+v", err, ob.StreamSetting)
	}

	noiseOnly := NewXrayService(false, false, WithFragment(mustFragment(t, "", "rand:10-20:5", "str:hello:1", "hex:abcd")))
	v := &Vless{OrigLink: "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls&sni=example.com"}
	if err := v.Parse(); err != nil {
		t.Fatal(err)
	}
	vob, _ := v.BuildOutboundDetourConfig(false)
	if err := noiseOnly.prepareEntry(vob, "1.2.3.4"); err != nil || vob.StreamSetting.FinalMask != nil {
		t.Error("UDP noise attached to a TCP outbound")
	}
	ob2, _ := w.BuildOutboundDetourConfig(false)
	if err := noiseOnly.prepareEntry(ob2, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if fm := ob2.StreamSetting.FinalMask; fm == nil || len(fm.Udp) != 1 || fm.Udp[0].Type != "noise" {
		t.Fatalf("UDP noise not attached to a WireGuard outbound: %+v", ob2.StreamSetting)
	}
	if _, err := ob2.Build(); err != nil {
		t.Fatalf("noise outbound does not build: %v", err)
	}

	// Noise goes after (inside) Hysteria2's salamander obfuscation.
	h := &Hysteria2{OrigLink: "hy2://pw@1.2.3.4:443?sni=a.com&obfs=salamander&obfs-password=x"}
	if err := h.Parse(); err != nil {
		t.Fatal(err)
	}
	hob, _ := h.BuildOutboundDetourConfig(false)
	if err := noiseOnly.prepareEntry(hob, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if udp := hob.StreamSetting.FinalMask.Udp; len(udp) != 2 || udp[0].Type != "salamander" || udp[1].Type != "noise" {
		t.Fatalf("hysteria2 masks = %+v", udp)
	}
	if _, err := hob.Build(); err != nil {
		t.Fatalf("hysteria2 with noise does not build: %v", err)
	}

	off := NewXrayService(false, false, WithFragment(nil))
	vob2, _ := v.BuildOutboundDetourConfig(false)
	if err := off.prepareEntry(vob2, "1.2.3.4"); err != nil || vob2.StreamSetting.SocketSettings != nil || vob2.StreamSetting.FinalMask != nil {
		t.Error("disabled fragment changed the outbound")
	}
}

// TestFragmentSplitsClientHello checks the effect on the wire: with
// fragmentation the server's first read is a small slice of the TLS
// ClientHello instead of the whole record.
func TestFragmentSplitsClientHello(t *testing.T) {
	firstRead := func(t *testing.T, f *fragment.Options) int {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		got := make(chan int, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				got <- -1
				return
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			got <- n
		}()

		c := NewXrayService(false, false, WithFragment(f))
		p, err := c.CreateProtocol("trojan://pass@" + ln.Addr().String() + "?security=tls&sni=example.com&type=tcp")
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Parse(); err != nil {
			t.Fatal(err)
		}
		client, inst, err := c.MakeHttpClient(context.Background(), p, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer inst.Close()
		go func() {
			req, _ := http.NewRequest(http.MethodGet, "http://example.org/", nil)
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
			}
		}()
		select {
		case n := <-got:
			return n
		case <-time.After(5 * time.Second):
			t.Fatal("server never received the handshake")
			return 0
		}
	}

	whole := firstRead(t, nil)
	if whole < 100 {
		t.Fatalf("unfragmented ClientHello first read = %d bytes, want a full record", whole)
	}
	// "tlshello" re-frames each 5-byte slice as its own TLS record, so a
	// fragment on the wire is the 5-byte record header plus 5 bytes.
	split := firstRead(t, mustFragment(t, "tlshello,5-5,30-30"))
	if split <= 0 || split > 10 {
		t.Fatalf("fragmented ClientHello first read = %d bytes, want <= 10 (whole record was %d)", split, whole)
	}
}
