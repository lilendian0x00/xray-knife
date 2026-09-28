package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// upstream is a minimal SOCKS5 proxy standing in for a remote config; it
// counts the connections it relays.
type upstream struct {
	addr  string
	conns atomic.Int32
}

func startUpstream(t *testing.T) *upstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	u := &upstream{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go u.serve(c)
		}
	}()
	return u
}

func (u *upstream) serve(c net.Conn) {
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
		n := int(buf[0])
		io.ReadFull(c, buf[:n])
		host = string(buf[:n])
	case 4:
		io.ReadFull(c, buf[:16])
		host = net.IP(buf[:16]).String()
	}
	io.ReadFull(c, buf[:2])
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(buf[:2]))))
	up, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	u.conns.Add(1)
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go io.Copy(up, c)
	io.Copy(c, up)
}

// A rotation happens while a download runs through the proxy: the
// download finishes, the listening port answers throughout, and new
// connections leave through the newly selected config.
func TestRotationHotSwapsWithoutDroppingTheListener(t *testing.T) {
	const chunks, size = 25, 16 * 1024
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			w.Header().Set("Content-Length", strconv.Itoa(chunks*size))
			chunk := []byte(strings.Repeat("x", size))
			for i := 0; i < chunks; i++ {
				if _, err := w.Write(chunk); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				time.Sleep(40 * time.Millisecond)
			}
			return
		}
		io.WriteString(w, "ok")
	}))
	defer web.Close()

	a, b := startUpstream(t), startUpstream(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()

	svc, err := New(Config{
		CoreType:            "xray",
		InboundProtocol:     "socks",
		ListenAddr:          "127.0.0.1",
		ListenPort:          port,
		ConfigLinks:         []string{"socks://" + a.addr + "#a", "socks://" + b.addr + "#b"},
		MaximumAllowedDelay: 3000,
		BatchSize:           2,
		// xray-core's core.New writes a package global
		// (internet.InitSystemDialer), so parallel test instances trip the
		// race detector upstream; test one config at a time.
		Concurrency:    1,
		HealthCheckURL: web.URL + "/ok",
		DrainTimeout:   1,
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rotate := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		svc.Run(ctx, rotate)
	}()
	select {
	case <-svc.proxyReady:
	case <-time.After(20 * time.Second):
		t.Fatal("proxy never became ready")
	}
	first := svc.GetCurrentDetails().ActiveOutbound.ConfigLink

	user, pass := svc.inboundCredentials()
	listen := net.JoinHostPort("127.0.0.1", port)
	d, err := xproxy.SOCKS5("tcp", listen, &xproxy.Auth{User: user, Password: pass}, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: d.(xproxy.ContextDialer).DialContext, DisableKeepAlives: true}}

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
			if c, err := net.DialTimeout("tcp", listen, time.Second); err != nil {
				refused.Add(1)
			} else {
				c.Close()
			}
			time.Sleep(3 * time.Millisecond)
		}
	}()

	time.Sleep(200 * time.Millisecond)
	rotate <- struct{}{}
	deadline := time.Now().Add(15 * time.Second)
	for svc.GetCurrentDetails().ActiveOutbound.ConfigLink == first {
		if time.Now().After(deadline) {
			t.Fatal("rotation never switched outbounds")
		}
		time.Sleep(20 * time.Millisecond)
	}
	second := svc.GetCurrentDetails().ActiveOutbound.ConfigLink

	newUp := a
	if strings.Contains(second, b.addr) {
		newUp = b
	}
	before := newUp.conns.Load()
	resp, err := client.Get(web.URL + "/ok")
	if err != nil {
		t.Fatalf("GET after rotation: %v", err)
	}
	resp.Body.Close()
	if newUp.conns.Load() <= before {
		t.Fatalf("new connection did not use the new outbound %s", second)
	}

	res := <-dl
	close(stop)
	<-probed
	if res.err != nil || res.n != chunks*size {
		t.Fatalf("download spanning the rotation broke: n=%d err=%v", res.n, res.err)
	}
	if n := refused.Load(); n != 0 {
		t.Fatalf("listener refused %d connections during the rotation", n)
	}
	cancel()
	wg.Wait()
}
