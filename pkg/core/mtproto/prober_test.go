package mtproto

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

var _ protocol.Prober = (*MTProto)(nil)

func TestProbeAgainstFakeProxy(t *testing.T) {
	key := testKey(t)
	secured := Secret{Type: SecretSecured, Key: key}
	simple := Secret{Type: SecretSimple, Key: key}
	fake := Secret{Type: SecretFakeTLS, Key: key, CloakHost: "www.google.com"}
	otherSecured := Secret{Type: SecretSecured, Key: [16]byte{1, 2, 3}}
	otherFake := Secret{Type: SecretFakeTLS, Key: [16]byte{1, 2, 3}, CloakHost: "www.google.com"}

	cases := []struct {
		name    string
		server  Secret
		client  Secret
		mode    serverMode
		timeout time.Duration
		wantErr string
	}{
		{name: "secured ok", server: secured, client: secured},
		{name: "simple ok", server: simple, client: simple},
		{name: "faketls ok", server: fake, client: fake},
		{name: "secured wrong secret", server: otherSecured, client: secured, wantErr: "read resPQ: EOF (proxy closed connection; wrong secret?)"},
		{name: "faketls wrong secret", server: otherFake, client: fake, wantErr: "faketls: server digest mismatch"},
		{name: "hang", server: secured, client: secured, mode: modeHang, timeout: 300 * time.Millisecond, wantErr: "read resPQ: timeout"},
		{name: "faketls hang", server: fake, client: fake, mode: modeHang, timeout: 300 * time.Millisecond, wantErr: "read resPQ: timeout"},
		{name: "garbage", server: secured, client: secured, mode: modeGarbage, wantErr: "unexpected constructor 0xdeadbeef"},
		{name: "transport error", server: secured, client: secured, mode: modeTransportError, wantErr: "transport error -404"},
		{name: "wrong nonce", server: secured, client: secured, mode: modeWrongNonce, wantErr: "resPQ nonce mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startFakeProxy(t, tc.server, tc.mode)
			m := NewMTProto("tg://proxy?server=127.0.0.1&port=" + srv.port() + "&secret=" + tc.client.Hex())
			if err := m.Parse(); err != nil {
				t.Fatal(err)
			}
			timeout := tc.timeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}
			res, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: timeout})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.ConnectTime <= 0 || res.TTFB < res.ConnectTime || res.Delay < res.TTFB {
				t.Errorf("timings out of order: %+v", res)
			}
			want := tc.client.Type.String() + ", dc2 resPQ ok"
			if res.Detail != want {
				t.Errorf("Detail = %q, want %q", res.Detail, want)
			}
		})
	}
}

// A canceled context must return promptly with context.Canceled rather than a
// timeout, whether the probe waits on the handshake or on the response.
func TestProbeCancellation(t *testing.T) {
	key := testKey(t)
	cases := []struct {
		name   string
		secret Secret
		mode   serverMode
	}{
		{name: "simple response", secret: Secret{Type: SecretSimple, Key: key}, mode: modeHang},
		{name: "secured response", secret: Secret{Type: SecretSecured, Key: key}, mode: modeHang},
		{name: "faketls response", secret: Secret{Type: SecretFakeTLS, Key: key, CloakHost: "www.google.com"}, mode: modeHang},
		{name: "faketls handshake", secret: Secret{Type: SecretFakeTLS, Key: key, CloakHost: "www.google.com"}, mode: modeStallHandshake},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startFakeProxy(t, tc.secret, tc.mode)
			m := NewMTProto("tg://proxy?server=127.0.0.1&port=" + srv.port() + "&secret=" + tc.secret.Hex())
			if err := m.Parse(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				_, err := m.Probe(ctx, protocol.ProbeOptions{Timeout: 30 * time.Second})
				done <- err
			}()
			select {
			case <-srv.reached:
			case <-time.After(5 * time.Second):
				cancel()
				t.Fatal("fake proxy never reached its stall point")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("err = %v, want context.Canceled", err)
				}
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("cancellation reported as a timeout: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Probe did not return promptly after cancellation")
			}
		})
	}
}

func TestProbeDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()

	m := NewMTProto("tg://proxy?server=127.0.0.1&port=" + port + "&secret=" + testKeyHex)
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	_, err = m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 2 * time.Second})
	if err == nil || !strings.HasPrefix(err.Error(), "dial 127.0.0.1:"+port) {
		t.Fatalf("err = %v, want dial error", err)
	}
}

func TestProbeEmptyBindInterfaceIsNoOp(t *testing.T) {
	key := testKey(t)
	secret := Secret{Type: SecretSecured, Key: key}
	srv := startFakeProxy(t, secret, modeOK)
	m := NewMTProto("tg://proxy?server=127.0.0.1&port=" + srv.port() + "&secret=" + secret.Hex())
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 5 * time.Second, BindInterface: ""}); err != nil {
		t.Fatalf("empty BindInterface must not bind: %v", err)
	}
}

func TestProbeUnknownBindInterface(t *testing.T) {
	m := NewMTProto("tg://proxy?server=127.0.0.1&port=1&secret=" + testKeyHex)
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	_, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: time.Second, BindInterface: "no-such-iface0"})
	if err == nil || !strings.Contains(err.Error(), "no-such-iface0") {
		t.Fatalf("err = %v, want interface error", err)
	}
}

// Runs against a real proxy only with XRAY_KNIFE_MTPROTO_LINK set, e.g.
// XRAY_KNIFE_MTPROTO_LINK='tg://proxy?server=…&port=…&secret=…'.
func TestProbeLiveProxy(t *testing.T) {
	link := os.Getenv("XRAY_KNIFE_MTPROTO_LINK")
	if link == "" {
		t.Skip("set XRAY_KNIFE_MTPROTO_LINK to run against a real proxy")
	}
	m := NewMTProto(link)
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	res, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s connect=%s ttfb=%s delay=%s", res.Detail, res.ConnectTime, res.TTFB, res.Delay)
}
