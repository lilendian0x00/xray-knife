package xray

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/features/outbound"
)

// A chained xhttp hop with extra.downloadSettings opens its download
// connection with that leg's own sockopt unless "penetrate" is set; it
// must still go through the previous hop.
func TestChainXHTTPDownloadLegFollowsChain(t *testing.T) {
	rec := &socksRecorder{}
	entry := startSocks(t, "entry", rec)
	listen := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { time.Sleep(time.Second); c.Close() }()
			}
		}()
		return ln.Addr().(*net.TCPAddr).Port
	}
	up, down := listen(), listen()
	extra := fmt.Sprintf(`{"downloadSettings":{"address":"127.0.0.1","port":%d,"network":"xhttp","security":"none","xhttpSettings":{"path":"/d"}}}`, down)
	hop := fmt.Sprintf("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:%d?encryption=none&security=none&type=xhttp&path=%%2Fu&mode=packet-up&extra=%s#x", up, url.QueryEscape(extra))

	c := NewXrayService(false, false)
	client, inst, err := c.MakeChainedHttpClient(context.Background(), parsedHops(t, c, "socks://"+entry, hop), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()
	client.Get("http://example.com/")
	time.Sleep(300 * time.Millisecond)
	relayed := false
	for _, s := range rec.seen() {
		if strings.HasSuffix(s, fmt.Sprint(":", down)) {
			relayed = true
		}
	}
	if !relayed {
		t.Fatalf("download leg bypassed the entry hop; entry saw %v", rec.seen())
	}
}

func TestChainAndBindInheritToSecondaryConnections(t *testing.T) {
	v := parseLink(t, "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls&sni=a.com&type=xhttp&ech=AEX%2B").(*Vless)
	ob, err := v.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	chainThrough(ob, "chain-0")
	so := ob.StreamSetting.SocketSettings
	if !so.Penetrate || ob.StreamSetting.TLSSettings.ECHSocketSettings != so {
		t.Fatalf("chained hop: penetrate=%v ech sockopt=%v", so.Penetrate, ob.StreamSetting.TLSSettings.ECHSocketSettings)
	}

	c := NewXrayService(false, false)
	c.BindInterface = "eth-test"
	ob2, _ := v.BuildOutboundDetourConfig(false)
	if err := c.prepareEntry(ob2, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	so2 := ob2.StreamSetting.SocketSettings
	if so2.Interface != "eth-test" || !so2.Penetrate || ob2.StreamSetting.TLSSettings.ECHSocketSettings != so2 {
		t.Fatalf("bound entry: %+v", so2)
	}
	if _, err := ob2.Build(); err != nil {
		t.Fatal(err)
	}
}

// Loopback and link-local servers are reachable only without the bind;
// an interface that doesn't exist fails the build instead of silently
// dialing unbound.
func TestBindInterfaceChecks(t *testing.T) {
	c := NewXrayService(false, false)
	c.BindInterface = "eth-test"
	for _, server := range []string{"127.0.0.1", "::1", "localhost", "fe80::1", "169.254.1.1"} {
		ob, _ := parseLink(t, "socks://"+net.JoinHostPort(server, "1080")).BuildOutboundDetourConfig(false)
		if err := c.prepareEntry(ob, server); err != nil {
			t.Fatal(err)
		}
		if ob.StreamSetting.SocketSettings != nil && ob.StreamSetting.SocketSettings.Interface != "" {
			t.Errorf("%s: bound to %s", server, ob.StreamSetting.SocketSettings.Interface)
		}
	}

	bad := NewXrayService(false, false, WithBindInterface("xk-no-such-iface0"))
	p := parseLink(t, "socks://1.2.3.4:1080")
	if _, err := bad.MakeInstance(context.Background(), p); err == nil || !strings.Contains(err.Error(), "bind interface") {
		t.Errorf("MakeInstance with a missing interface: %v", err)
	}
	if _, err := bad.MakeChainedInstance(context.Background(), []protocol.Protocol{p, p}); err == nil || !strings.Contains(err.Error(), "bind interface") {
		t.Errorf("chain with a missing interface: %v", err)
	}
	if _, err := bad.MakeSwappableInstance(context.Background(), parsedHops(t, bad, "socks://1.2.3.4:1080")); err == nil {
		t.Error("swappable instance with a missing interface accepted")
	}
}

func TestSingboxReasonKeepsXrayOnlyFeatures(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000000"
	cases := map[string]bool{
		"vless://" + id + "@1.2.3.4:443?security=tls&type=raw&insecure=1":                                                 true, // raw is tcp; "insecure" alias
		"vless://" + id + "@1.2.3.4:443?security=tls&type=ws&allowInsecure=1&ech=AEX%2B":                                  false,
		"vless://" + id + "@1.2.3.4:443?security=tls&type=ws&allowInsecure=1&encryption=mlkem768x25519plus.native.0rtt.x": false,
		"trojan://pw@1.2.3.4:443?type=tcp&allow_insecure=1":                                                               true,
		"ss://none:pw@1.2.3.4:8388":  true,
		"ss://plain:pw@1.2.3.4:8388": true,
	}
	for link, want := range cases {
		if got := SingboxReason(parseLink(t, link), false) != ""; got != want {
			t.Errorf("%s: moves to sing-box = %v, want %v", link, got, want)
		}
	}
	if _, err := (&Shadowsocks{Address: "1.2.3.4", Port: "1", Encryption: "none", Password: "p"}).BuildOutboundDetourConfig(false); err == nil {
		t.Error("xray built an unsupported none cipher")
	}
}

func TestParserStrictness(t *testing.T) {
	for _, link := range []string{
		"vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls&sni=a.com:443",
		"trojan://pw@1.2.3.4:443?sni=a.com,b.com",
		"hy2://pw@1.2.3.4:443?sni=a.com:1",
	} {
		p, _ := (&Core{}).CreateProtocol(link)
		if err := p.Parse(); err == nil {
			t.Errorf("%s: SNI with a port or list accepted", link)
		}
	}
	vm := &Vmess{Address: "1.2.3.4", Port: "443", ID: "id", Network: "tcp", TLS: "reality"}
	if _, err := vm.BuildOutboundDetourConfig(false); err == nil {
		t.Error("vmess REALITY built")
	}

	// Several spellings of one WireGuard key: the same one wins every time.
	link := "wireguard://k@1.2.3.4:51820?PublicKey=AAA&publickey=BBB&PUBLICKEY=CCC&address=10.0.0.2"
	first := parseLink(t, link).(*Wireguard).PublicKey
	for i := 0; i < 50; i++ {
		if got := parseLink(t, link).(*Wireguard).PublicKey; got != first {
			t.Fatalf("public key flips between %q and %q", first, got)
		}
	}
}

// Concurrent swaps must not leak the generation installed between them.
func TestConcurrentSwapsRetireEverything(t *testing.T) {
	rec := &socksRecorder{}
	a := startSocks(t, "A", rec)
	c := NewXrayService(false, false)
	c.Inbound = &Socks{Remark: "l", Address: "127.0.0.1", Port: freePort(t)}
	sw, err := c.MakeSwappableInstance(context.Background(), parsedHops(t, c, "socks://"+a))
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	hops := parsedHops(t, c, "socks://"+a)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sw.Swap(context.Background(), hops, time.Millisecond)
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := len(sw.ohm.(outbound.Manager).ListHandlers(context.Background()))
		if n == 2 { // the switch and the current generation
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d handlers left, want 2", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// senderMark reads the socket mark from a handler's built stream settings.
func senderMark(t *testing.T, h outbound.Handler) int32 {
	t.Helper()
	msg := h.SenderSettings()
	if msg == nil {
		return 0
	}
	inst, err := msg.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	sender, ok := inst.(*proxyman.SenderConfig)
	if !ok || sender.StreamSettings == nil || sender.StreamSettings.SocketSettings == nil {
		return 0
	}
	return sender.StreamSettings.SocketSettings.Mark
}

// Every generation's entry hop — the only outbound that opens sockets —
// carries the mark, including generations installed by Swap.
func TestSwapSocketMark(t *testing.T) {
	rec := &socksRecorder{}
	a, b := startSocks(t, "A", rec), startSocks(t, "B", rec)
	c := NewXrayService(false, false)
	c.Inbound = &Socks{Remark: "l", Address: "127.0.0.1", Port: freePort(t)}
	sw, err := c.MakeSwappableInstance(context.Background(), parsedHops(t, c, "socks://"+a), WithSocketMark(0x2a))
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	if got := senderMark(t, sw.sw); got != 0x2a {
		t.Fatalf("first generation mark = %#x", got)
	}
	if err := sw.Swap(context.Background(), parsedHops(t, c, "socks://"+a, "socks://"+b), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	sw.mu.Lock()
	entry, exit := sw.current[0], sw.current[1]
	sw.mu.Unlock()
	if got := senderMark(t, sw.ohm.GetHandler(entry)); got != 0x2a {
		t.Fatalf("swapped entry hop mark = %#x", got)
	}
	if got := senderMark(t, sw.ohm.GetHandler(exit)); got != 0 {
		t.Fatalf("exit hop dials through the entry and must not be marked: %#x", got)
	}

	plain, err := c.MakeSwappableInstance(context.Background(), parsedHops(t, c, "socks://"+a))
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if got := senderMark(t, plain.sw); got != 0 {
		t.Fatalf("mark set without WithSocketMark: %#x", got)
	}
}
