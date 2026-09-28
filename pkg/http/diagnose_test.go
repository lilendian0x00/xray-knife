package http

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

func TestClassifyError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, classTimeout},
		{fmt.Errorf("dial: %w", os.ErrDeadlineExceeded), classTimeout},
		{&net.OpError{Op: "read", Err: syscall.ECONNRESET}, classReset},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, classRefused},
		{&net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}, classUnreachable},
		{&net.DNSError{Err: "no such host", Name: "x"}, classDNS},
		{errors.New("proxy/vless: failed to read response header > EOF"), classEOF},
		{errors.New("remote error: tls: handshake failure"), classTLS},
		{errors.New("x509: certificate signed by unknown authority"), classTLSCert},
		{errors.New("faketls: server digest mismatch (wrong secret or cloak domain answered)"), classAuth},
		{errors.New("socks: 407 proxy authentication required"), classAuth},
		{errors.New("something odd"), classOther},
		{nil, ""},
	}
	for _, tc := range cases {
		if got := classifyError(tc.err); got != tc.want {
			t.Errorf("classifyError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestIsCensoredAddr(t *testing.T) {
	for _, s := range []string{"10.10.34.35", "127.0.0.1", "0.0.0.0", "192.168.1.1", "198.18.0.5", "::1", "fd00::1", "::ffff:10.10.34.34",
		"224.0.0.251", "ff02::fb", "192.0.2.1", "198.51.100.7", "203.0.113.9", "2001:db8::1"} {
		if !isCensoredAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s not flagged", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "104.16.1.1", "2606:4700::1111", "8.8.8.8"} {
		if isCensoredAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s flagged", s)
		}
	}
}

// fakeResolver answers from a table.
type fakeResolver struct {
	name    string
	answers map[string][]string
	err     error
}

func (f fakeResolver) String() string { return f.name }
func (f fakeResolver) LookupHost(_ context.Context, host string) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	raw, ok := f.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, s := range raw {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func TestDiagnoserResolve(t *testing.T) {
	poisoned := fakeResolver{name: "system DNS", answers: map[string][]string{"blocked.example": {"10.10.34.35"}, "ok.example": {"104.16.1.1"}}}
	trusted := fakeResolver{name: "resolver 1.1.1.1", answers: map[string][]string{"blocked.example": {"104.21.9.9"}, "nx.example": {"104.21.8.8"}, "ok.example": {"104.16.1.1"}}}

	cases := []struct {
		name     string
		d        *Diagnoser
		host     string
		wantKind string
		wantAddr string
	}{
		{"ip literal skips dns", &Diagnoser{System: poisoned}, "[2606:4700::1]", "", "2606:4700::1"},
		// A suspicious answer is only judged once the server fails to answer.
		{"sinkhole answer is still probed", &Diagnoser{System: poisoned, Trusted: trusted}, "blocked.example", "", "10.10.34.35"},
		{"system nxdomain, resolver answers", &Diagnoser{System: poisoned, Trusted: trusted}, "nx.example", FailDNSPoisoned, ""},
		{"nobody resolves", &Diagnoser{System: poisoned, Trusted: trusted}, "gone.example", FailDNS, ""},
		{"clean answer", &Diagnoser{System: poisoned, Trusted: trusted}, "ok.example", "", "104.16.1.1"},
	}
	for _, tc := range cases {
		addrs, diag := tc.d.Resolve(context.Background(), tc.host)
		gotKind := ""
		if diag != nil {
			gotKind = diag.Kind
		}
		if gotKind != tc.wantKind {
			t.Errorf("%s: kind = %q (%v), want %q", tc.name, gotKind, diag, tc.wantKind)
		}
		if tc.wantAddr != "" && (len(addrs) == 0 || addrs[0].String() != tc.wantAddr) {
			t.Errorf("%s: addrs = %v, want %s", tc.name, addrs, tc.wantAddr)
		}
	}
}

// Private, CGNAT and fake-IP answers are normal for fake-IP TUNs, Tailscale
// and LAN servers: they are verdicts only when the server also fails to
// answer, and conclusive only for known sinkholes or a disagreeing resolver.
func TestDiagnoserPoisoningNeedsAFailedDial(t *testing.T) {
	sys := fakeResolver{name: "system DNS", answers: map[string][]string{
		"fakeip.example":   {"198.18.0.5"},
		"tailnet.example":  {"100.101.102.103"},
		"sinkhole.example": {"10.10.34.35"},
		"private.example":  {"10.1.2.3"},
	}}
	trusted := fakeResolver{name: "resolver 1.1.1.1", answers: map[string][]string{
		"private.example": {"104.21.9.9"}, "sinkhole.example": {"104.21.9.10"},
	}}
	cases := []struct {
		name    string
		host    string
		dialErr error
		trusted Resolver
		want    string
		hint    bool
	}{
		{"fake-ip TUN answer that connects", "fakeip.example", nil, nil, "", false},
		{"tailscale answer that connects", "tailnet.example", nil, trusted, "", false},
		{"sinkhole answer that connects", "sinkhole.example", nil, nil, "", false},
		{"sinkhole answer that does not answer", "sinkhole.example", os.ErrDeadlineExceeded, nil, FailDNSPoisoned, false},
		{"bogon answer that does not answer", "private.example", os.ErrDeadlineExceeded, nil, FailTCPTimeout, true},
		{"bogon answer, resolver disagrees", "private.example", os.ErrDeadlineExceeded, trusted, FailDNSPoisoned, false},
	}
	for _, tc := range cases {
		d := &Diagnoser{System: sys, Trusted: tc.trusted, Timeout: time.Second, dial: dialReturning(tc.dialErr)}
		got := d.Server(context.Background(), ServerCheck{Host: tc.host, Port: "443"})
		if got.Kind != tc.want {
			t.Errorf("%s: kind = %q (%s), want %q", tc.name, got.Kind, got.Detail, tc.want)
		}
		if tc.hint != strings.Contains(got.Detail, "possible DNS poisoning") {
			t.Errorf("%s: detail %q, hint expected %v", tc.name, got.Detail, tc.hint)
		}
	}
}

// Every resolved address is tried, as Go's dialer and the cores do: a round
// robin name whose first address is dead is still reachable.
func TestDiagnoserTriesAllAddresses(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	sys := fakeResolver{answers: map[string][]string{"rr.example": {"104.16.0.1", "104.16.0.2", "2606:4700::1"}}}
	d := &Diagnoser{System: sys, Timeout: time.Second}
	d.dial = func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		if addr == "104.16.0.1:443" {
			return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
		}
		return fakeConn{}, nil
	}
	if got := d.Server(context.Background(), ServerCheck{Host: "rr.example", Port: "443"}); got.Kind != "" {
		t.Fatalf("kind = %q (%s), want reachable", got.Kind, got.Detail)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) < 2 {
		t.Fatalf("dialed %v, want the second address tried", dialed)
	}

	// All addresses dead: the first failure explains it.
	allDead := &Diagnoser{System: sys, Timeout: time.Second, dial: dialReturning(syscall.ECONNREFUSED)}
	got := allDead.Server(context.Background(), ServerCheck{Host: "rr.example", Port: "443"})
	if got.Kind != FailTCPRefused || !strings.Contains(got.Detail, "other address") {
		t.Fatalf("all dead: %+v", got)
	}
}

func TestInterleaveFamilies(t *testing.T) {
	in := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("2606:4700::1")}
	got := interleaveFamilies(in)
	if got[0].String() != "1.1.1.1" || got[1].String() != "2606:4700::1" || got[2].String() != "1.0.0.1" {
		t.Fatalf("got %v", got)
	}
}

func TestDoHRedirectPolicy(t *testing.T) {
	via := []*http.Request{{URL: mustURL(t, "https://dns.example/dns-query")}}
	if err := dohRedirectPolicy(&http.Request{URL: mustURL(t, "https://dns.example/other")}, via); err != nil {
		t.Errorf("same-host https redirect refused: %v", err)
	}
	for _, bad := range []string{"http://dns.example/dns-query", "https://evil.example/dns-query"} {
		if err := dohRedirectPolicy(&http.Request{URL: mustURL(t, bad)}, via); err == nil {
			t.Errorf("redirect to %s followed", bad)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// fakeConn is a net.Conn that does nothing; the handshake fake decides.
type fakeConn struct{ net.Conn }

func (fakeConn) Close() error                     { return nil }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

func dialReturning(err error) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		if err != nil {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: err}
		}
		return fakeConn{}, nil
	}
}

func TestDiagnoserServer(t *testing.T) {
	sys := fakeResolver{name: "system DNS", answers: map[string][]string{"srv.example": {"203.0.113.7"}}}
	cases := []struct {
		name      string
		dialErr   error
		handshake error
		tls       bool
		udp       bool
		want      string
	}{
		{"refused", syscall.ECONNREFUSED, nil, true, false, FailTCPRefused},
		{"syn timeout", os.ErrDeadlineExceeded, nil, true, false, FailTCPTimeout},
		{"reset on connect", syscall.ECONNRESET, nil, true, false, FailTCPReset},
		{"unreachable", syscall.ENETUNREACH, nil, true, false, FailTCPUnreach},
		{"sni reset", nil, &net.OpError{Op: "read", Err: syscall.ECONNRESET}, true, false, FailTLSReset},
		{"sni blackhole", nil, context.DeadlineExceeded, true, false, FailTLSTimeout},
		{"tls alert means reachable", nil, errors.New("remote error: tls: unrecognized name"), true, false, ""},
		{"plain tcp ok", nil, nil, false, false, ""},
		{"udp skips tcp", syscall.ECONNREFUSED, nil, false, true, ""},
	}
	for _, tc := range cases {
		d := &Diagnoser{System: sys, Timeout: time.Second, dial: dialReturning(tc.dialErr),
			handshake: func(context.Context, net.Conn, string) error { return tc.handshake }}
		got := d.Server(context.Background(), ServerCheck{Host: "srv.example", Port: "443", TLS: tc.tls, UDP: tc.udp})
		if got.Kind != tc.want {
			t.Errorf("%s: kind = %q (%s), want %q", tc.name, got.Kind, got.Detail, tc.want)
		}
	}
}

func TestDiagnoserCachesPerServer(t *testing.T) {
	dials := 0
	d := &Diagnoser{System: fakeResolver{}, dial: func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	}}
	check := ServerCheck{Host: "192.0.2.1", Port: "443"}
	for i := 0; i < 3; i++ {
		if got := d.Server(context.Background(), check); got.Kind != FailTCPRefused {
			t.Fatalf("kind = %q", got.Kind)
		}
	}
	if dials != 1 {
		t.Fatalf("dialed %d times, want 1", dials)
	}
}

// A verdict is reused only for diagnosisTTL, and old entries are swept.
func TestDiagnoserCacheExpires(t *testing.T) {
	var dials atomic.Int32
	clock := time.Unix(1000, 0)
	d := &Diagnoser{System: fakeResolver{}, now: func() time.Time { return clock },
		dial: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
		}}
	a := ServerCheck{Host: "192.0.2.1", Port: "443"}
	b := ServerCheck{Host: "192.0.2.2", Port: "443"}
	d.Server(context.Background(), a)
	clock = clock.Add(diagnosisTTL - time.Second)
	d.Server(context.Background(), a)
	if dials.Load() != 1 {
		t.Fatalf("fresh verdict re-diagnosed: %d dials", dials.Load())
	}
	clock = clock.Add(time.Second)
	d.Server(context.Background(), a)
	if dials.Load() != 2 {
		t.Fatalf("expired verdict reused: %d dials", dials.Load())
	}
	clock = clock.Add(diagnosisTTL)
	d.Server(context.Background(), b) // sweeps a, now expired
	d.cacheMu.Lock()
	_, kept := d.cache[a]
	n := len(d.cache)
	d.cacheMu.Unlock()
	if kept || n != 1 {
		t.Fatalf("sweep kept expired entries: %d left, a kept=%v", n, kept)
	}
}

// tlsStubProtocol is a stub config whose server speaks TLS.
type tlsStubProtocol struct{ stubProtocol }

func (tlsStubProtocol) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{Protocol: "stub", Address: "192.0.2.10", Port: "443", TLS: "tls", SNI: "front.example"}
}

// errCore hands out a client whose every request fails with err.
func errCore(err error) scriptCore {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, err })}
	return scriptCore{stubCore: stubCore{client: client}}
}

func TestExamineConfigFailureKinds(t *testing.T) {
	eof := errors.New("proxy/vless: failed to read response header > EOF")
	reachable := &Diagnoser{System: fakeResolver{}, dial: dialReturning(nil),
		handshake: func(context.Context, net.Conn, string) error { return nil }}
	blocked := &Diagnoser{System: fakeResolver{}, dial: dialReturning(nil),
		handshake: func(context.Context, net.Conn, string) error {
			return &net.OpError{Op: "read", Err: syscall.ECONNRESET}
		}}

	cases := []struct {
		name       string
		core       scriptCore
		diag       *Diagnoser
		tls        bool
		want       string
		wantReason string
	}{
		{"server fine, tunnel dropped", errCore(eof), reachable, true, FailProxyProtocol, ""},
		{"server fine, request timed out", errCore(context.DeadlineExceeded), reachable, true, FailHTTPTimeout, ""},
		{"sni filtered", errCore(eof), blocked, true, FailTLSReset, diagnosisPrefix + FailTLSReset},
		{"no diagnoser: raw class", errCore(eof), nil, true, classEOF, ""},
		{"cert", errCore(errors.New("x509: certificate has expired")), reachable, true, FailTLSCert, ""},
		{"broken link", scriptCore{create: func(string) (protocol.Protocol, error) { return nil, errors.New("bad link") }}, reachable, true, FailConfig, ""},
	}
	for _, tc := range cases {
		e := newGradeExaminer(nil, nil, 1)
		if tc.tls && tc.core.create == nil {
			tc.core.create = func(string) (protocol.Protocol, error) { return tlsStubProtocol{}, nil }
		}
		e.Core = tc.core
		e.Diagnoser = tc.diag
		e.Logger = log.New(io.Discard, "", 0)
		r, _ := e.ExamineConfig(context.Background(), "stub://config")
		if r.FailureKind != tc.want {
			t.Errorf("%s: kind = %q (reason %q), want %q", tc.name, r.FailureKind, r.Reason, tc.want)
		}
		if tc.wantReason != "" && !strings.Contains(r.Reason, tc.wantReason) {
			t.Errorf("%s: reason %q lacks %q", tc.name, r.Reason, tc.wantReason)
		}
	}

	// Tunnel up, wrong status → http-status; passed → no kind.
	srv := gradeTestServer(t)
	e := newGradeExaminer(srv.Client(), []EndpointCheck{{URL: srv.URL + "/forbidden"}}, 1)
	if r, _ := e.ExamineConfig(context.Background(), "stub://config"); r.FailureKind != FailHTTPStatus {
		t.Errorf("bad status: kind = %q", r.FailureKind)
	}
	e = newGradeExaminer(srv.Client(), []EndpointCheck{{URL: srv.URL + "/ok"}}, 1)
	if r, _ := e.ExamineConfig(context.Background(), "stub://config"); r.FailureKind != "" {
		t.Errorf("passed config got kind %q", r.FailureKind)
	}
}

func TestProberKind(t *testing.T) {
	cases := map[string]string{
		"dial 1.2.3.4:443: connect: connection refused":                           FailTCPRefused,
		"dial 1.2.3.4:443: i/o timeout":                                           FailTCPTimeout,
		"faketls: read ServerHello: read: connection reset by peer":               FailTLSReset,
		"faketls: server digest mismatch (wrong secret or cloak domain answered)": FailProxyAuth,
		"read resPQ: EOF (proxy closed connection; wrong secret?)":                FailProxyAuth,
		"read resPQ: timeout: context deadline exceeded":                          FailProxyTimeout,
		"resPQ nonce mismatch":                                                    FailProxyProtocol,
	}
	for msg, want := range cases {
		if got := proberKind(errors.New(msg)); got != want {
			t.Errorf("proberKind(%q) = %q, want %q", msg, got, want)
		}
	}
}

func TestFailureSummaryAndKindFromReason(t *testing.T) {
	rs := []*Result{
		{Status: StatusPassed},
		{Status: StatusFailed, FailureKind: FailTLSReset},
		{Status: StatusFailed, FailureKind: FailTLSReset},
		{Status: StatusFailed, FailureKind: FailTCPTimeout},
		{Status: StatusBroken, FailureKind: FailConfig},
	}
	if got, want := FailureSummary(rs), "4 not passed: 2 tls-reset, 1 config, 1 tcp-timeout"; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
	if FailureSummary(rs[:1]) != "" {
		t.Error("summary for an all-passed run")
	}
	for _, tc := range []struct{ status, reason, want string }{
		{"passed", "", ""},
		{"broken", "parse protocol: x", FailConfig},
		{"timeout", "", FailSlow},
		{"failed", "https://x: EOF; diagnosis: tls-reset: 1.2.3.4:443 accepted TCP but ...", FailTLSReset},
		{"failed", "https://x: unexpected HTTP status 403", FailHTTPStatus},
		{"failed", "https://x: context deadline exceeded", classTimeout},
	} {
		if got := KindFromReason(tc.status, tc.reason); got != tc.want {
			t.Errorf("KindFromReason(%q, %q) = %q, want %q", tc.status, tc.reason, got, tc.want)
		}
	}
}

// dnsAnswer packs a reply with one A record for q.
func dnsAnswer(t *testing.T, query []byte, a [4]byte) []byte {
	t.Helper()
	var q dnsmessage.Message
	if err := q.Unpack(query); err != nil {
		t.Fatal(err)
	}
	reply := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
	if len(q.Questions) == 1 && q.Questions[0].Type == dnsmessage.TypeA {
		reply.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: a},
		}}
	}
	out, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDoHResolver(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-query" || r.Header.Get("Accept") != "application/dns-message" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		q, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dnsAnswer(t, q, [4]byte{104, 16, 1, 1}))
	}))
	defer srv.Close()
	r, err := NewResolver("doh://"+strings.TrimPrefix(srv.URL, "https://"), "")
	if err != nil {
		t.Fatal(err)
	}
	r.(*dohResolver).client = srv.Client()
	addrs, err := r.LookupHost(context.Background(), "server.example")
	if err != nil || len(addrs) != 1 || addrs[0].String() != "104.16.1.1" {
		t.Fatalf("addrs %v, err %v", addrs, err)
	}
}

func TestUDPResolver(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no UDP on loopback:", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(dnsAnswer(t, buf[:n], [4]byte{203, 0, 113, 9}), addr)
		}
	}()
	r, err := NewResolver(pc.LocalAddr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, "server.example")
	if err != nil || len(addrs) == 0 || addrs[0].String() != "203.0.113.9" {
		t.Fatalf("addrs %v, err %v", addrs, err)
	}
}

func TestNewResolverRejectsNonsense(t *testing.T) {
	for _, bad := range []string{"not a resolver", "doh://", "udp://example.com"} {
		if _, err := NewResolver(bad, ""); err == nil {
			t.Errorf("NewResolver(%q) accepted", bad)
		}
	}
	if _, err := NewExaminer(Options{Resolver: "1.1.1.1", NoDiagnose: true}); err == nil {
		t.Error("a resolver without diagnostics was accepted")
	}
}

// Prescan reports why it dropped each link.
func TestRunPrescanReportsDropKinds(t *testing.T) {
	deadPort := freeClosedPort(t)
	link := fmt.Sprintf("vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@127.0.0.1:%s?encryption=none&security=none&type=tcp#dead", deadPort)
	c := core.CoreFactoryWith(core.XrayCoreType, core.FactoryOptions{})
	res, err := RunPrescan(context.Background(), c, []string{link}, PrescanOptions{Timeout: time.Second}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Dropped) != 1 || res.Dropped[0].Kind != FailTCPRefused {
		t.Fatalf("dropped = %+v", res.Dropped)
	}
	failed := res.DroppedResults()
	if len(failed) != 1 || failed[0].Status != StatusFailed || failed[0].FailureKind != FailTCPRefused || failed[0].ConfigLink != link {
		t.Fatalf("dropped results = %+v", failed)
	}
	if KindFromReason(failed[0].Status, failed[0].Reason) != FailTCPRefused {
		t.Errorf("reason %q does not round-trip its kind", failed[0].Reason)
	}
}

// A stopped pre-scan's unchecked links are not failures: DroppedResults
// must not hand them to callers that persist results.
func TestDroppedResultsSkipsCanceled(t *testing.T) {
	deadPort := freeClosedPort(t)
	link := fmt.Sprintf("vless://a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5@127.0.0.1:%s?encryption=none&security=none&type=tcp#dead", deadPort)
	c := core.CoreFactoryWith(core.XrayCoreType, core.FactoryOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := RunPrescan(ctx, c, []string{link}, PrescanOptions{Timeout: time.Second}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Dropped) != 1 || res.Dropped[0].Kind != FailCanceled {
		t.Fatalf("dropped = %+v", res.Dropped)
	}
	if got := res.DroppedResults(); len(got) != 0 {
		t.Fatalf("canceled drops became results: %+v", got)
	}
}

// Regression: a hostname answering a loopback/private address with a live
// server must survive the prescan (it used to be dropped as dns-poisoned
// without being dialed).
func TestRunPrescanKeepsReachablePrivateAnswer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	link := fmt.Sprintf("trojan://pass@localhost:%d?security=none&type=tcp#x", port)
	parsed := ParseLinks(core.NewAutomaticCore(false, false), []string{link})
	res, err := RunPrescanParsed(context.Background(), parsed, PrescanOptions{Timeout: 2 * time.Second}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ReachableParsed) != 1 || res.FilteredOut != 0 {
		t.Fatalf("reachable server dropped: %+v", res.Dropped)
	}
}
