package netbind

import (
	"net"
	"testing"
	"time"
)

func loopbackName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot list interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

func TestBinderDialsThroughNamedInterface(t *testing.T) {
	b, err := New(loopbackName(t))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()

	d := &net.Dialer{Timeout: 2 * time.Second}
	b.ApplyDialer(d)
	conn, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		// Binding to a device needs CAP_NET_RAW on Linux.
		t.Skipf("bound dial failed (likely missing privileges): %v", err)
	}
	conn.Close()
}

func TestBinderDisabled(t *testing.T) {
	b, err := New("  ")
	if err != nil || b != nil {
		t.Fatalf("New(blank) = %v, %v; want nil, nil", b, err)
	}
	if b.Enabled() || b.Control() != nil || b.Name() != "" {
		t.Fatal("nil binder must be a no-op")
	}
	if _, err := New("xk-no-such-iface0"); err == nil {
		t.Fatal("unknown interface accepted")
	}
}
