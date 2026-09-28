package singbox

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/sagernet/sing-box/option"

	xproxy "golang.org/x/net/proxy"
)

func swapSocksClient(t *testing.T, listen string) *http.Client {
	t.Helper()
	d, err := xproxy.SOCKS5("tcp", listen, nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{
		DialContext:       d.(xproxy.ContextDialer).DialContext,
		DisableKeepAlives: true,
	}}
}

func newSwapCore(t *testing.T) (*Core, string) {
	t.Helper()
	port := freePort(t)
	c := NewSingboxService(false, false)
	if err := c.SetInbound(&Socks{Remark: "listener", Address: "127.0.0.1", Port: port}); err != nil {
		t.Fatal(err)
	}
	return c, net.JoinHostPort("127.0.0.1", port)
}

// A download that spans a swap completes, the listener never refuses a
// connection, and new connections use the new outbound.
func TestSwapKeepsListenerAndInFlight(t *testing.T) {
	skipUnderRace(t)
	a, b := startRecordingSocks(t), startRecordingSocks(t)
	const chunks, size = 20, 16 * 1024
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(chunks*size))
		chunk := []byte(strings.Repeat("x", size))
		for i := 0; i < chunks; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(40 * time.Millisecond)
		}
	}))
	defer web.Close()

	c, listen := newSwapCore(t)
	sw, err := c.MakeSwappableInstance(context.Background(), []protocol.Protocol{parseLink(t, c, "socks://"+a.addr)})
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.Start(); err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	client := swapSocksClient(t, listen)

	type result struct {
		n   int64
		err error
	}
	dl := make(chan result, 1)
	go func() {
		resp, err := client.Get(web.URL + "/big")
		if err != nil {
			dl <- result{err: err}
			return
		}
		defer resp.Body.Close()
		n, err := io.Copy(io.Discard, resp.Body)
		dl <- result{n, err}
	}()

	var refused atomic.Int32
	stop, probed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(probed)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if conn, err := net.DialTimeout("tcp", listen, time.Second); err != nil {
				refused.Add(1)
			} else {
				conn.Close()
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	time.Sleep(250 * time.Millisecond)
	if err := sw.Swap(context.Background(), []protocol.Protocol{parseLink(t, c, "socks://"+b.addr)}, 50*time.Millisecond); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	resp, err := client.Get(web.URL + "/small")
	if err != nil {
		t.Fatalf("GET after swap: %v", err)
	}
	resp.Body.Close()
	close(stop)
	<-probed

	res := <-dl
	if res.err != nil || res.n != chunks*size {
		t.Fatalf("in-flight download broken by the swap: n=%d err=%v", res.n, res.err)
	}
	if n := refused.Load(); n != 0 {
		t.Fatalf("listener refused %d connections during the swap", n)
	}
	webAddr := web.Listener.Addr().String()
	if got := a.seen(); len(got) != 1 || got[0] != webAddr {
		t.Fatalf("A saw %v", got)
	}
	if got := b.seen(); len(got) != 1 || got[0] != webAddr {
		t.Fatalf("B saw %v", got)
	}
}

// Chains swap as a unit (entry -> exit) and a chain can replace a chain.
func TestSwapChains(t *testing.T) {
	skipUnderRace(t)
	e1, x1, e2, x2 := startRecordingSocks(t), startRecordingSocks(t), startRecordingSocks(t), startRecordingSocks(t)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer web.Close()

	c, listen := newSwapCore(t)
	hops := func(a, b *recordingSocks) []protocol.Protocol {
		return []protocol.Protocol{parseLink(t, c, "socks://"+a.addr), parseLink(t, c, "socks://"+b.addr)}
	}
	sw, err := c.MakeSwappableInstance(context.Background(), hops(e1, x1))
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.Start(); err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	client := swapSocksClient(t, listen)
	get := func() {
		t.Helper()
		resp, err := client.Get(web.URL)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
	}
	get()
	if err := sw.Swap(context.Background(), hops(e2, x2), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // old generation retired
	get()

	webAddr := web.Listener.Addr().String()
	for name, check := range map[string][]string{
		"e1": {x1.addr}, "x1": {webAddr}, "e2": {x2.addr}, "x2": {webAddr},
	} {
		rec := map[string]*recordingSocks{"e1": e1, "x1": x1, "e2": e2, "x2": x2}[name]
		if got := rec.seen(); strings.Join(got, ",") != strings.Join(check, ",") {
			t.Errorf("%s saw %v, want %v", name, got, check)
		}
	}
}

func TestSwapFailureKeepsCurrent(t *testing.T) {
	skipUnderRace(t)
	a := startRecordingSocks(t)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer web.Close()

	c, listen := newSwapCore(t)
	sw, err := c.MakeSwappableInstance(context.Background(), []protocol.Protocol{parseLink(t, c, "socks://"+a.addr)})
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.Start(); err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	if err := sw.Swap(context.Background(), []protocol.Protocol{foreignProtocol{}}, 0); err == nil {
		t.Fatal("foreign protocol accepted")
	}
	resp, err := swapSocksClient(t, listen).Get(web.URL)
	if err != nil {
		t.Fatalf("GET after failed swap: %v", err)
	}
	resp.Body.Close()
}

// startUnlessRace starts sw except under the race detector, where sing-box's
// own NetworkManager.Start race would drown the result (see skipUnderRace).
// Swap, retirement and Close work on an instance that was never started too,
// so the locking below is still exercised under -race.
func startUnlessRace(t *testing.T, sw *SwappableInstance) {
	t.Helper()
	if raceEnabled {
		return
	}
	if err := sw.Start(); err != nil {
		t.Fatal(err)
	}
}

// A retire timer firing during or after Close must not reach sing-box's
// managers (they panic removing from a closed instance).
func TestSwapRetireRacesClose(t *testing.T) {
	for i := 0; i < 100; i++ {
		c, _ := newSwapCore(t)
		sw, err := c.MakeSwappableInstance(context.Background(), []protocol.Protocol{parseLink(t, c, "socks://127.0.0.1:1")})
		if err != nil {
			t.Fatal(err)
		}
		startUnlessRace(t, sw)
		if err := sw.Swap(context.Background(), []protocol.Protocol{parseLink(t, c, "socks://127.0.0.1:2")}, time.Nanosecond); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = sw.Swap(context.Background(), []protocol.Protocol{parseLink(t, c, "socks://127.0.0.1:3")}, time.Nanosecond)
		}()
		if err := sw.Close(); err != nil {
			t.Fatal(err)
		}
		<-done
		if err := sw.Swap(context.Background(), []protocol.Protocol{parseLink(t, c, "socks://127.0.0.1:4")}, time.Nanosecond); err == nil {
			t.Fatal("Swap after Close succeeded")
		}
		if err := sw.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	}
	time.Sleep(50 * time.Millisecond) // let any late timer fire
}

// Overlapping Swaps each retire their own predecessor, so only the live
// generation survives.
func TestConcurrentSwapsRetireEveryGeneration(t *testing.T) {
	c, _ := newSwapCore(t)
	sw, err := c.MakeSwappableInstance(context.Background(), []protocol.Protocol{parseLink(t, c, "socks://127.0.0.1:1")})
	if err != nil {
		t.Fatal(err)
	}
	startUnlessRace(t, sw)
	defer sw.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sw.Swap(context.Background(), []protocol.Protocol{parseLink(t, c, "socks://127.0.0.1:2")}, time.Millisecond); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	sw.mu.Lock()
	live := sw.current[0].tag
	sw.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var stale []string
		// Retirements edit the manager's slice under sw.mu; read it there.
		sw.mu.Lock()
		for _, o := range sw.box.Outbound().Outbounds() {
			if tag := o.Tag(); strings.HasPrefix(tag, "xk-g") && tag != live {
				stale = append(stale, tag)
			}
		}
		sw.mu.Unlock()
		if len(stale) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("generations never retired: %v (live %s)", stale, live)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// WithSocketMark puts the mark on the instance's route (sing-box's default
// dialer) and on each generation's entry hop. sing-box accepts marks on
// Linux only, so this checks the crafted options rather than a running box.
func TestSwapSocketMark(t *testing.T) {
	c, _ := newSwapCore(t)
	opts, err := c.swapBoxOptions(WithSocketMark(0x2a))
	if err != nil {
		t.Fatal(err)
	}
	if opts.Route.DefaultMark != 0x2a || opts.Route.Final != switchTag || len(opts.Inbounds) != 1 {
		t.Fatalf("route = %+v, inbounds %d", opts.Route, len(opts.Inbounds))
	}
	for _, none := range [][]SwapOption{nil, {WithSocketMark(0)}} {
		if opts, _ := c.swapBoxOptions(none...); opts.Route.DefaultMark != 0 {
			t.Fatalf("unmarked instance got mark %d", opts.Route.DefaultMark)
		}
	}

	s := &SwappableInstance{core: c, mark: 0x2a}
	hops := []protocol.Protocol{parseLink(t, c, "socks://127.0.0.1:1"), parseLink(t, c, "socks://127.0.0.1:2")}
	outs, err := s.craftGeneration(hops, 7)
	if err != nil {
		t.Fatal(err)
	}
	entry := outs[0].Options.(*option.SOCKSOutboundOptions)
	exit := outs[1].Options.(*option.SOCKSOutboundOptions)
	if entry.RoutingMark != 0x2a || exit.RoutingMark != 0 || exit.Detour != outs[0].Tag || outs[1].Tag != "xk-g7-1" {
		t.Fatalf("entry mark %d, exit mark %d detour %q tag %q", entry.RoutingMark, exit.RoutingMark, exit.Detour, outs[1].Tag)
	}
	s.mark = 0
	if outs, _ := s.craftGeneration(hops[:1], 8); outs[0].Options.(*option.SOCKSOutboundOptions).RoutingMark != 0 {
		t.Fatal("unmarked generation got a mark")
	}
}
