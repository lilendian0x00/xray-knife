package xray

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	xproxy "golang.org/x/net/proxy"
)

// slowServer streams chunks*chunkSize bytes over about chunks*interval.
func slowServer(t *testing.T, chunks, chunkSize int, interval time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(chunks*chunkSize))
		chunk := []byte(strings.Repeat("x", chunkSize))
		for i := 0; i < chunks; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(interval)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func socksClient(t *testing.T, listen string) *http.Client {
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

// A download that spans a swap completes, the listener never refuses a
// connection during the swap, and new connections use the new outbound.
func TestSwapKeepsListenerAndInFlight(t *testing.T) {
	rec := &socksRecorder{}
	a := startSocks(t, "A", rec)
	b := startSocks(t, "B", rec)
	web := slowServer(t, 20, 16*1024, 40*time.Millisecond)

	port := freePort(t)
	c := NewXrayService(false, false)
	c.Inbound = &Socks{Remark: "listener", Address: "127.0.0.1", Port: port}
	sw, err := c.MakeSwappableInstance(context.Background(), parsedHops(t, c, "socks://"+a))
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.Start(); err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	listen := net.JoinHostPort("127.0.0.1", port)
	client := socksClient(t, listen)

	// Long download through A.
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

	// Hammer the listener port while the swap happens.
	var refused atomic.Int32
	stop := make(chan struct{})
	probed := make(chan struct{})
	go func() {
		defer close(probed)
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn, err := net.DialTimeout("tcp", listen, time.Second)
			if err != nil {
				refused.Add(1)
			} else {
				conn.Close()
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	time.Sleep(250 * time.Millisecond) // download is mid-flight
	if err := sw.Swap(context.Background(), parsedHops(t, c, "socks://"+b), 50*time.Millisecond); err != nil {
		t.Fatalf("Swap: %v", err)
	}

	// A fresh request goes through B while the old download continues.
	resp, err := client.Get(web.URL + "/small")
	if err != nil {
		t.Fatalf("GET after swap: %v", err)
	}
	resp.Body.Close()
	close(stop)
	<-probed

	res := <-dl
	if res.err != nil || res.n != 20*16*1024 {
		t.Fatalf("in-flight download broken by the swap: n=%d err=%v", res.n, res.err)
	}
	if n := refused.Load(); n != 0 {
		t.Fatalf("listener refused %d connections during the swap", n)
	}
	webAddr := web.Listener.Addr().String()
	seen := rec.seen()
	if len(seen) < 2 || seen[0] != "A->"+webAddr || seen[len(seen)-1] != "B->"+webAddr {
		t.Fatalf("outbound path = %v", seen)
	}
}

// Chains swap as a unit, keep socket-level chaining, and unique tags per
// generation let a chain replace a chain.
func TestSwapChains(t *testing.T) {
	rec := &socksRecorder{}
	e1, x1 := startSocks(t, "e1", rec), startSocks(t, "x1", rec)
	e2, x2 := startSocks(t, "e2", rec), startSocks(t, "x2", rec)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer web.Close()

	port := freePort(t)
	c := NewXrayService(false, false)
	c.Inbound = &Socks{Remark: "listener", Address: "127.0.0.1", Port: port}
	sw, err := c.MakeSwappableInstance(context.Background(), parsedHops(t, c, "socks://"+e1, "socks://"+x1))
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.Start(); err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	client := socksClient(t, net.JoinHostPort("127.0.0.1", port))

	get := func() {
		t.Helper()
		resp, err := client.Get(web.URL)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
	}
	get()
	if err := sw.Swap(context.Background(), parsedHops(t, c, "socks://"+e2, "socks://"+x2), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // let the old generation retire
	get()

	webAddr := web.Listener.Addr().String()
	want := []string{"e1->" + x1, "x1->" + webAddr, "e2->" + x2, "x2->" + webAddr}
	if got := rec.seen(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("path = %v, want %v", got, want)
	}
}

// A failed swap leaves the current outbound serving.
func TestSwapFailureKeepsCurrent(t *testing.T) {
	rec := &socksRecorder{}
	a := startSocks(t, "A", rec)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer web.Close()

	port := freePort(t)
	c := NewXrayService(false, false)
	c.Inbound = &Socks{Remark: "listener", Address: "127.0.0.1", Port: port}
	sw, err := c.MakeSwappableInstance(context.Background(), parsedHops(t, c, "socks://"+a))
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.Start(); err != nil {
		t.Fatal(err)
	}
	defer sw.Close()

	if err := sw.Swap(context.Background(), nil, 0); err == nil {
		t.Fatal("empty swap accepted")
	}
	if err := sw.Swap(context.Background(), []protocol.Protocol{foreignProtocol{}}, 0); err == nil {
		t.Fatal("foreign protocol accepted")
	}
	resp, err := socksClient(t, net.JoinHostPort("127.0.0.1", port)).Get(web.URL)
	if err != nil {
		t.Fatalf("GET after failed swaps: %v", err)
	}
	resp.Body.Close()
}

// The shared fragment outbound stays reachable by every generation.
func TestSwapWithFragment(t *testing.T) {
	rec := &socksRecorder{}
	a, b := startSocks(t, "A", rec), startSocks(t, "B", rec)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer web.Close()

	f, err := fragment.Parse("1-2,1-3,0")
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	c := NewXrayService(false, false, WithFragment(f))
	c.Inbound = &Socks{Remark: "listener", Address: "127.0.0.1", Port: port}
	sw, err := c.MakeSwappableInstance(context.Background(), parsedHops(t, c, "socks://"+a))
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.Start(); err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	client := socksClient(t, net.JoinHostPort("127.0.0.1", port))
	for i, next := range []string{b, a} {
		resp, err := client.Get(web.URL)
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		resp.Body.Close()
		if err := sw.Swap(context.Background(), parsedHops(t, c, "socks://"+next), time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(rec.seen()); got != 2 {
		t.Fatalf("requests seen = %d", got)
	}
}

// Chain hops must resolve inside the instance that owns them. With
// xray-core's dialerProxy (one global manager that each core.New
// repoints), a chain created earlier used to dial through the newest
// instance's hops — here, B's entry — or fail once B was closed.
func TestDialerProxyStaysInItsInstance(t *testing.T) {
	rec := &socksRecorder{}
	e1, x1 := startSocks(t, "e1", rec), startSocks(t, "x1", rec)
	e2, x2 := startSocks(t, "e2", rec), startSocks(t, "x2", rec)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer web.Close()

	c := NewXrayService(false, false)
	clientA, instA, err := c.MakeChainedHttpClient(context.Background(), parsedHops(t, c, "socks://"+e1, "socks://"+x1), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer instA.Close()
	_, instB, err := c.MakeChainedHttpClient(context.Background(), parsedHops(t, c, "socks://"+e2, "socks://"+x2), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	get := func() {
		t.Helper()
		resp, err := clientA.Get(web.URL)
		if err != nil {
			t.Fatalf("GET through chain A: %v", err)
		}
		resp.Body.Close()
	}
	get()
	instB.Close()
	get()

	webAddr := web.Listener.Addr().String()
	want := "e1->" + x1 + " x1->" + webAddr + " e1->" + x1 + " x1->" + webAddr
	if got := strings.Join(rec.seen(), " "); got != want {
		t.Fatalf("chain A path = %s\nwant %s", got, want)
	}
}
