package mtproto

import (
	"context"
	"errors"
	"fmt"
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

func newProbeClient(t *testing.T, srv *fakeProxy, secret Secret) *MTProto {
	t.Helper()
	m := NewMTProto("tg://proxy?server=127.0.0.1&port=" + srv.port() + "&secret=" + secret.Hex())
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	return m
}

// sampleSecrets covers every secret type. Each wraps the stream differently.
func sampleSecrets(t *testing.T) []struct {
	name   string
	secret Secret
} {
	t.Helper()
	key := testKey(t)
	return []struct {
		name   string
		secret Secret
	}{
		{"simple", Secret{Type: SecretSimple, Key: key}},
		{"secured", Secret{Type: SecretSecured, Key: key}},
		{"faketls", Secret{Type: SecretFakeTLS, Key: key, CloakHost: "www.google.com"}},
	}
}

// checkRequests asserts one connection, fresh nonces and increasing message IDs.
func checkRequests(t *testing.T, srv *fakeProxy, want int) {
	t.Helper()
	if got := srv.connections(); got != 1 {
		t.Errorf("accepted %d connections, want 1", got)
	}
	reqs := srv.observed()
	if len(reqs) != want {
		t.Fatalf("server saw %d requests, want %d", len(reqs), want)
	}
	seen := map[[16]byte]bool{}
	var last uint64
	for i, r := range reqs {
		if r.conn != 1 {
			t.Errorf("request %d arrived on connection %d", i, r.conn)
		}
		if seen[r.nonce] {
			t.Errorf("request %d reused nonce %x", i, r.nonce)
		}
		seen[r.nonce] = true
		if i > 0 && r.msgID <= last {
			t.Errorf("request %d message ID %x did not advance past %x", i, r.msgID, last)
		}
		if r.msgID%4 != 0 || uint32(r.msgID) == 0 {
			t.Errorf("request %d message ID %x is not a valid client ID", i, r.msgID)
		}
		last = r.msgID
	}
}

func TestProbeCollectsRequestedSamples(t *testing.T) {
	for _, tc := range sampleSecrets(t) {
		t.Run(tc.name, func(t *testing.T) {
			srv := startFakeProxy(t, tc.secret, modeOK)
			m := newProbeClient(t, srv, tc.secret)

			res, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 5 * time.Second, Samples: 5})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.RTTs) != 5 {
				t.Fatalf("collected %d RTTs, want 5", len(res.RTTs))
			}
			for i, rtt := range res.RTTs {
				if rtt <= 0 {
					t.Errorf("RTT %d = %v, want a positive duration", i, rtt)
				}
			}
			if res.ConnectTime <= 0 || res.TTFB < res.ConnectTime || res.Delay < res.TTFB {
				t.Errorf("timings out of order: %+v", res)
			}
			if res.RTTs[0] > res.Delay {
				t.Errorf("first RTT %v exceeds Delay %v", res.RTTs[0], res.Delay)
			}
			want := tc.secret.Type.String() + ", dc2 resPQ ok, 5/5 samples"
			if res.Detail != want {
				t.Errorf("Detail = %q, want %q", res.Detail, want)
			}
			checkRequests(t, srv, 5)
		})
	}
}

func TestProbeDefaultSampleCount(t *testing.T) {
	secret := Secret{Type: SecretSecured, Key: testKey(t)}
	for _, samples := range []int{0, 1} {
		t.Run(fmt.Sprintf("samples=%d", samples), func(t *testing.T) {
			srv := startFakeProxy(t, secret, modeOK)
			m := newProbeClient(t, srv, secret)

			res, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 5 * time.Second, Samples: samples})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.RTTs) != 1 {
				t.Fatalf("collected %d RTTs, want 1", len(res.RTTs))
			}
			if res.Detail != "secured, dc2 resPQ ok" {
				t.Errorf("Detail = %q, want the unchanged single-sample detail", res.Detail)
			}
			checkRequests(t, srv, 1)
		})
	}
}

func TestProbeMaxSampleCount(t *testing.T) {
	secret := Secret{Type: SecretSecured, Key: testKey(t)}
	srv := startFakeProxy(t, secret, modeOK)
	m := newProbeClient(t, srv, secret)

	res, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 10 * time.Second, Samples: protocol.MaxProbeSamples})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RTTs) != protocol.MaxProbeSamples {
		t.Fatalf("collected %d RTTs, want %d", len(res.RTTs), protocol.MaxProbeSamples)
	}
	checkRequests(t, srv, protocol.MaxProbeSamples)
}

// An out-of-range count must be refused before anything is dialed.
func TestProbeRejectsInvalidSampleCount(t *testing.T) {
	secret := Secret{Type: SecretSecured, Key: testKey(t)}
	for _, samples := range []int{-1, 33, 256} {
		t.Run(fmt.Sprintf("samples=%d", samples), func(t *testing.T) {
			srv := startFakeProxy(t, secret, modeOK)
			m := newProbeClient(t, srv, secret)

			_, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 5 * time.Second, Samples: samples})
			want := fmt.Sprintf("mtproto: probe samples must be between 1 and 32, got %d", samples)
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v, want %q", err, want)
			}
			if got := srv.connections(); got != 0 {
				t.Errorf("dialed %d connections for an invalid count", got)
			}
		})
	}
}

// A proxy that stops answering after sample 1 is still working. The probe keeps
// what it measured.
func TestProbePartialSampling(t *testing.T) {
	for _, mode := range []struct {
		name string
		mode serverMode
	}{
		{"dropped", modeDropAfterFirst},
		{"wrong nonce", modeWrongNonceAfterFirst},
	} {
		for _, tc := range sampleSecrets(t) {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				srv := startFakeProxy(t, tc.secret, mode.mode)
				m := newProbeClient(t, srv, tc.secret)

				res, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 5 * time.Second, Samples: 5})
				if err != nil {
					t.Fatalf("a successful first exchange must not fail: %v", err)
				}
				if len(res.RTTs) != 1 {
					t.Fatalf("collected %d RTTs, want 1", len(res.RTTs))
				}
				if res.ConnectTime <= 0 || res.TTFB <= 0 || res.Delay <= 0 {
					t.Errorf("first-exchange timings must survive: %+v", res)
				}
				want := tc.secret.Type.String() + ", dc2 resPQ ok, 1/5 samples"
				if res.Detail != want {
					t.Errorf("Detail = %q, want %q", res.Detail, want)
				}
			})
		}
	}
}

func TestProbeSamplingCancellation(t *testing.T) {
	secret := Secret{Type: SecretSecured, Key: testKey(t)}
	srv := startFakeProxy(t, secret, modeHangAfterFirst)
	m := newProbeClient(t, srv, secret)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		res protocol.ProbeResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := m.Probe(ctx, protocol.ProbeOptions{Timeout: 30 * time.Second, Samples: 5})
		done <- outcome{res, err}
	}()

	select {
	case <-srv.reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the fake proxy never received a second request")
	}
	cancel()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("cancelling extra samples must not fail the probe: %v", got.err)
		}
		if len(got.res.RTTs) != 1 {
			t.Fatalf("collected %d RTTs, want 1", len(got.res.RTTs))
		}
		if got.res.ConnectTime <= 0 || got.res.TTFB <= 0 || got.res.Delay <= 0 {
			t.Errorf("first-exchange timings must survive: %+v", got.res)
		}
		if got.res.Detail != "secured, dc2 resPQ ok, 1/5 samples" {
			t.Errorf("Detail = %q", got.res.Detail)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Probe did not return promptly after cancellation")
	}
}

// Sampling stops on the probe's own timeout or on an earlier parent deadline.
func TestProbeSamplingDeadline(t *testing.T) {
	secret := Secret{Type: SecretSecured, Key: testKey(t)}
	cases := []struct {
		name      string
		parent    time.Duration // 0 = no parent deadline
		timeout   time.Duration
		expectErr bool
	}{
		{name: "probe timeout", timeout: time.Second},
		{name: "parent deadline", parent: time.Second, timeout: 30 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startFakeProxy(t, secret, modeHangAfterFirst)
			m := newProbeClient(t, srv, secret)

			ctx := context.Background()
			if tc.parent > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.parent)
				defer cancel()
			}
			type outcome struct {
				res protocol.ProbeResult
				err error
			}
			done := make(chan outcome, 1)
			go func() {
				res, err := m.Probe(ctx, protocol.ProbeOptions{Timeout: tc.timeout, Samples: 5})
				done <- outcome{res, err}
			}()

			select {
			case <-srv.reached:
			case <-time.After(5 * time.Second):
				t.Fatal("the fake proxy never received a second request")
			}
			select {
			case got := <-done:
				if got.err != nil {
					t.Fatalf("an expired budget must not fail a probe that already succeeded: %v", got.err)
				}
				if len(got.res.RTTs) != 1 {
					t.Fatalf("collected %d RTTs, want 1", len(got.res.RTTs))
				}
				if got.res.Delay <= 0 || got.res.TTFB <= 0 {
					t.Errorf("first-exchange timings must survive: %+v", got.res)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Probe outlived its budget")
			}
		})
	}
}

// Delay and TTFB cover the first exchange only, so a slow later sample must not
// change them.
func TestProbeLaterSampleDoesNotChangeDelay(t *testing.T) {
	secret := Secret{Type: SecretSecured, Key: testKey(t)}
	srv := startFakeProxy(t, secret, modeSlowSecond)
	m := newProbeClient(t, srv, secret)

	res, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 10 * time.Second, Samples: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RTTs) != 2 {
		t.Fatalf("collected %d RTTs, want 2", len(res.RTTs))
	}
	if res.Delay >= slowSecondDelay || res.TTFB > res.Delay {
		t.Fatalf("first exchange was not measured on its own: %+v", res)
	}
	if res.RTTs[1] < slowSecondDelay {
		t.Errorf("second RTT = %v, want at least %v", res.RTTs[1], slowSecondDelay)
	}
	if res.RTTs[1] <= res.Delay {
		t.Errorf("second RTT %v did not exceed Delay %v", res.RTTs[1], res.Delay)
	}
}

// Like TestProbeLiveProxy but asks for several samples. A live proxy may stop
// early, so only the collected samples are checked.
func TestProbeLiveProxySamples(t *testing.T) {
	link := os.Getenv("XRAY_KNIFE_MTPROTO_LINK")
	if link == "" {
		t.Skip("set XRAY_KNIFE_MTPROTO_LINK to run against a real proxy")
	}
	m := NewMTProto(link)
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	res, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 15 * time.Second, Samples: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RTTs) < 1 || len(res.RTTs) > 5 {
		t.Fatalf("collected %d RTTs, want 1 to 5", len(res.RTTs))
	}
	for i, rtt := range res.RTTs {
		if rtt <= 0 {
			t.Errorf("RTT %d = %v", i, rtt)
		}
	}
	t.Logf("%s delay=%s rtts=%v", res.Detail, res.Delay, res.RTTs)
}
