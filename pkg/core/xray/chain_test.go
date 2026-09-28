package xray

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// socksRecorder is a minimal SOCKS5 server that records the targets it
// was asked to connect to, prefixed with its name.
type socksRecorder struct {
	mu      sync.Mutex
	targets []string
}

func (r *socksRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.targets...)
}

func startSocks(t *testing.T, name string, rec *socksRecorder) string {
	t.Helper()
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
			go serveSocks(c, name, rec)
		}
	}()
	return ln.Addr().String()
}

func serveSocks(c net.Conn, name string, rec *socksRecorder) {
	defer c.Close()
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	var host string
	switch buf[3] {
	case 1:
		io.ReadFull(c, buf[:4])
		host = net.IP(buf[:4]).String()
	case 3:
		io.ReadFull(c, buf[:1])
		l := int(buf[0])
		io.ReadFull(c, buf[:l])
		host = string(buf[:l])
	case 4:
		io.ReadFull(c, buf[:16])
		host = net.IP(buf[:16]).String()
	}
	io.ReadFull(c, buf[:2])
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(buf[:2]))))
	rec.mu.Lock()
	rec.targets = append(rec.targets, name+"->"+target)
	rec.mu.Unlock()
	up, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go io.Copy(up, c)
	io.Copy(c, up)
}

func parsedHops(t *testing.T, c *Core, links ...string) []protocol.Protocol {
	t.Helper()
	var hops []protocol.Protocol
	for _, l := range links {
		p, err := c.CreateProtocol(l)
		if err != nil {
			t.Fatalf("CreateProtocol(%s): %v", l, err)
		}
		if err := p.Parse(); err != nil {
			t.Fatalf("Parse(%s): %v", l, err)
		}
		hops = append(hops, p)
	}
	return hops
}

// TestChainOrderEntryFirst: hop 0 is dialed directly and hop N-1 reaches
// the destination (entry -> exit), matching --chain-links "A|B".
func TestChainOrderEntryFirst(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer web.Close()
	rec := &socksRecorder{}
	entry := startSocks(t, "entry", rec)
	exit := startSocks(t, "exit", rec)

	c := NewXrayService(false, false)
	client, inst, err := c.MakeChainedHttpClient(context.Background(), parsedHops(t, c, "socks://"+entry, "socks://"+exit), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()
	resp, err := client.Get(web.URL)
	if err != nil {
		t.Fatalf("GET through chain: %v", err)
	}
	resp.Body.Close()

	want := []string{"entry->" + exit, "exit->" + web.Listener.Addr().String()}
	got := rec.seen()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("chain path = %v, want %v", got, want)
	}
}

// TestChainKeepsTransportOnLaterHops: a hop behind the entry keeps its own
// transport (here WebSocket) instead of xray piping raw protocol bytes.
func TestChainKeepsTransportOnLaterHops(t *testing.T) {
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	first := make(chan []byte, 1)
	go func() {
		conn, err := server.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		first <- buf[:n]
	}()

	rec := &socksRecorder{}
	entry := startSocks(t, "entry", rec)
	c := NewXrayService(false, false)
	hops := parsedHops(t, c,
		"socks://"+entry,
		"vless://00000000-0000-0000-0000-000000000000@"+server.Addr().String()+"?type=ws&path=%2Fws&host=example.com&security=none",
	)
	client, inst, err := c.MakeChainedHttpClient(context.Background(), hops, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()
	go client.Get("http://example.org/")

	select {
	case b := <-first:
		if !bytes.HasPrefix(b, []byte("GET /ws")) {
			t.Fatalf("exit hop server got %q, want a WebSocket upgrade", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exit hop server never reached")
	}
	if got := rec.seen(); len(got) == 0 || got[0] != "entry->"+server.Addr().String() {
		t.Fatalf("entry hop targets = %v", got)
	}
}

func TestChainRejectsShortAndForeignHops(t *testing.T) {
	c := NewXrayService(false, false)
	if _, err := c.MakeChainedInstance(context.Background(), parsedHops(t, c, "socks://127.0.0.1:1")); err == nil {
		t.Fatal("single-hop chain accepted")
	}
	if _, err := c.MakeChainedInstance(context.Background(), []protocol.Protocol{foreignProtocol{}, foreignProtocol{}}); err == nil {
		t.Fatal("foreign protocol accepted")
	}
	if _, err := c.MakeInstance(context.Background(), foreignProtocol{}); err == nil {
		t.Fatal("MakeInstance accepted a foreign protocol")
	}
	if err := c.SetInbound(foreignProtocol{}); err == nil {
		t.Fatal("SetInbound accepted a foreign protocol")
	}
}

// foreignProtocol is a protocol.Protocol that no xray builder implements.
type foreignProtocol struct{}

func (foreignProtocol) Parse() error       { return nil }
func (foreignProtocol) DetailsStr() string { return "" }
func (foreignProtocol) GetLink() string    { return "foreign://x" }
func (foreignProtocol) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{}
}

// Instances are created and closed all the time (http tester workers,
// health checks) while chains carry traffic. xray-core's dialerProxy read
// a process-global that every core.New rewrote; chains now route through
// chainDialer, so under -race this must stay clean and every request must
// take chain A's own hops.
func TestChainsWhileInstancesComeAndGo(t *testing.T) {
	rec := &socksRecorder{}
	entry, exit := startSocks(t, "entry", rec), startSocks(t, "exit", rec)
	other := startSocks(t, "other", &socksRecorder{})
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer web.Close()

	c := NewXrayService(false, false, WithFragment(mustFragment(t, "tlshello,5-10,0")))
	client, inst, err := c.MakeChainedHttpClient(context.Background(), parsedHops(t, c, "socks://"+entry, "socks://"+exit), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

	// Parsed once here: t.Fatal must not run on the churn goroutine, and
	// building from a parsed link does not mutate it.
	p := parsedHops(t, c, "socks://"+other)[0]
	stop := make(chan struct{})
	churned := make(chan error, 1)
	go func() {
		churned <- func() error {
			for {
				select {
				case <-stop:
					return nil
				default:
				}
				i, err := c.MakeInstance(context.Background(), p)
				if err != nil {
					return err
				}
				if err := i.Start(); err != nil {
					return err
				}
				i.Close()
			}
		}()
	}()

	const requests = 20
	for i := 0; i < requests; i++ {
		resp, err := client.Get(web.URL)
		if err != nil {
			close(stop)
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
	}
	close(stop)
	if err := <-churned; err != nil {
		t.Fatal(err)
	}
	for _, hop := range rec.seen() {
		if !strings.HasPrefix(hop, "entry->"+exit) && !strings.HasPrefix(hop, "exit->"+web.Listener.Addr().String()) {
			t.Fatalf("chain A took a foreign hop: %s", hop)
		}
	}
	if got := len(rec.seen()); got != 2*requests {
		t.Fatalf("%d hops seen, want %d", got, 2*requests)
	}
}
