package dpi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// fakeProto is a parsed link whose GeneralConfig the test controls.
type fakeProto struct {
	link string
	gc   protocol.GeneralConfig
}

func (p *fakeProto) Parse() error       { return nil }
func (p *fakeProto) DetailsStr() string { return p.link }
func (p *fakeProto) GetLink() string    { return p.link }
func (p *fakeProto) ConvertToGeneralConfig() protocol.GeneralConfig {
	gc := p.gc
	gc.OrigLink = p.link
	return gc
}

type nopInstance struct{}

func (nopInstance) Start() error { return nil }
func (nopInstance) Close() error { return nil }

// fakeCore simulates a network where a filter decides per fragment setting
// whether the handshake gets through.
type fakeCore struct {
	opts   core.FactoryOptions
	gc     protocol.GeneralConfig
	target string
	allow  func(f *fragment.Options, link string) error
	mu     *sync.Mutex
	links  *[]string
}

func (c *fakeCore) Name() string { return "fake" }
func (c *fakeCore) CreateProtocol(link string) (protocol.Protocol, error) {
	c.mu.Lock()
	*c.links = append(*c.links, link)
	c.mu.Unlock()
	return &fakeProto{link: link, gc: c.gc}, nil
}
func (c *fakeCore) MakeInstance(context.Context, protocol.Protocol) (protocol.Instance, error) {
	return nopInstance{}, nil
}
func (c *fakeCore) SetInbound(protocol.Protocol) error { return nil }
func (c *fakeCore) MakeHttpClient(_ context.Context, p protocol.Protocol, timeout time.Duration) (*http.Client, protocol.Instance, error) {
	frag := c.opts.Fragment
	link := p.GetLink()
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if err := c.allow(frag, link); err != nil {
				return nil, err
			}
			var d net.Dialer
			return d.DialContext(ctx, network, c.target)
		},
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nopInstance{}, nil
}

type harness struct {
	links []string
	mu    sync.Mutex
}

func newHarness(t *testing.T, gc protocol.GeneralConfig, allow func(*fragment.Options, string) error) (*harness, func(core.CoreType, core.FactoryOptions) core.Core, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	h := &harness{}
	target := strings.TrimPrefix(srv.URL, "http://")
	return h, func(_ core.CoreType, opts core.FactoryOptions) core.Core {
		return &fakeCore{opts: opts, gc: gc, target: target, allow: allow, mu: &h.mu, links: &h.links}
	}, srv.URL + "/generate_204"
}

func resetErr() error {
	return &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
}

// liveAddr returns a listening TCP address (so the direct check passes).
func liveAddr(t *testing.T) (string, string) {
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
			c.Close()
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p
}

// deadAddr returns an address nothing listens on.
func deadAddr(t *testing.T) (string, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	h, p, _ := net.SplitHostPort(addr)
	return h, p
}

func TestRunBaselinePasses(t *testing.T) {
	host, port := liveAddr(t)
	gc := protocol.GeneralConfig{Protocol: "vless", Address: host, Port: port}
	_, newCore, testURL := newHarness(t, gc, func(*fragment.Options, string) error { return nil })

	rep, err := Run(context.Background(), Options{Link: "vless://id@x:1", TestURL: testURL, Attempts: 2, newCore: newCore})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != VerdictNoInterference {
		t.Fatalf("verdict = %q, want %q (%s)", rep.Verdict, VerdictNoInterference, rep.Advice)
	}
	if rep.Best == nil || rep.Best.Profile.Fragment != nil {
		t.Fatalf("best = %+v, want the baseline", rep.Best)
	}
	if !rep.Direct.TCPOK {
		t.Fatalf("direct check failed: %+v", rep.Direct)
	}
}

func TestRunFindsFragment(t *testing.T) {
	host, port := liveAddr(t)
	gc := protocol.GeneralConfig{Protocol: "vless", Address: host, Port: port}
	// The filter resets unfragmented hellos and anything but large tlshello splits.
	allow := func(f *fragment.Options, _ string) error {
		if f.FragmentsTCP() && f.Packets == fragment.PacketsTLSHello && f.Length.Min >= 100 {
			return nil
		}
		return resetErr()
	}
	_, newCore, testURL := newHarness(t, gc, allow)

	var mu sync.Mutex
	seen := 0
	rep, err := Run(context.Background(), Options{
		Link: "vless://id@x:1", TestURL: testURL, Attempts: 2, Threads: 3, newCore: newCore,
		OnResult: func(Result) { mu.Lock(); seen++; mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != VerdictFragmentHelps {
		t.Fatalf("verdict = %q (%s)", rep.Verdict, rep.Advice)
	}
	best := rep.Best.Profile.Fragment
	if best == nil || best.Packets != fragment.PacketsTLSHello || best.Length.Min < 100 {
		t.Fatalf("best profile = %+v", rep.Best.Profile)
	}
	if !strings.Contains(rep.Advice, "--fragment "+rep.Best.Profile.Spec) {
		t.Fatalf("advice lacks the flag: %q", rep.Advice)
	}
	if seen != len(rep.Results) {
		t.Fatalf("OnResult called %d times for %d results", seen, len(rep.Results))
	}
	for _, r := range rep.Results {
		if r.Profile.Name == "baseline" && (r.Status != StatusFail || r.Failures[KindReset] != 2) {
			t.Fatalf("baseline = %+v, want 2 resets", r)
		}
	}
}

func TestRunServerUnreachable(t *testing.T) {
	host, port := deadAddr(t)
	gc := protocol.GeneralConfig{Protocol: "trojan", Address: host, Port: port, TLS: "tls", SNI: "example.com"}
	_, newCore, testURL := newHarness(t, gc, func(*fragment.Options, string) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	})
	rep, err := Run(context.Background(), Options{Link: "trojan://pw@x:1", TestURL: testURL, Attempts: 1, Timeout: 2 * time.Second, newCore: newCore})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != VerdictUnreachable || rep.Direct.TCPOK {
		t.Fatalf("verdict = %q direct = %+v", rep.Verdict, rep.Direct)
	}
	if rep.Best != nil {
		t.Fatalf("best = %+v, want none", rep.Best)
	}
}

func TestRunStopAfter(t *testing.T) {
	host, port := liveAddr(t)
	gc := protocol.GeneralConfig{Protocol: "vless", Address: host, Port: port}
	allow := func(f *fragment.Options, _ string) error {
		if f.FragmentsTCP() {
			return nil
		}
		return resetErr()
	}
	_, newCore, testURL := newHarness(t, gc, allow)
	rep, err := Run(context.Background(), Options{Link: "vless://id@x:1", TestURL: testURL, Attempts: 1, Threads: 1, StopAfter: 1, newCore: newCore})
	if err != nil {
		t.Fatal(err)
	}
	passed, skipped := 0, 0
	for _, r := range rep.Results {
		switch r.Status {
		case StatusPass:
			passed++
		case StatusSkipped:
			skipped++
		}
	}
	if passed != 1 || skipped == 0 {
		t.Fatalf("passed=%d skipped=%d, want 1 pass and the rest skipped", passed, skipped)
	}
	if rep.Verdict != VerdictFragmentHelps {
		t.Fatalf("verdict = %q", rep.Verdict)
	}
}

func TestRunSNIOverride(t *testing.T) {
	host, port := liveAddr(t)
	gc := protocol.GeneralConfig{Protocol: "vless", Address: host, Port: port, Security: "tls", SNI: "blocked.example"}
	allow := func(_ *fragment.Options, link string) error {
		if strings.Contains(link, "sni=front.example") {
			return nil
		}
		return resetErr()
	}
	h, newCore, testURL := newHarness(t, gc, allow)
	rep, err := Run(context.Background(), Options{
		Link: "vless://id@x:1?security=tls&sni=blocked.example#r", TestURL: testURL, Attempts: 1,
		Specs: []string{"tlshello,100-200,10-20"}, SNIs: []string{"front.example"}, newCore: newCore,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 4 {
		t.Fatalf("got %d profiles, want baseline+1 spec, each with and without the SNI", len(rep.Results))
	}
	if rep.Best == nil || rep.Best.Profile.SNI != "front.example" || rep.Verdict != VerdictFragmentHelps {
		t.Fatalf("best = %+v verdict = %q", rep.Best, rep.Verdict)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	found := false
	for _, l := range h.links {
		if strings.Contains(l, "sni=front.example") && strings.HasSuffix(l, "#r") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no rewritten link tested: %q", h.links)
	}
}

func TestRunRejectsUDPAndBadInput(t *testing.T) {
	gc := protocol.GeneralConfig{Protocol: "hysteria2", Address: "127.0.0.1", Port: "443"}
	_, newCore, testURL := newHarness(t, gc, func(*fragment.Options, string) error { return nil })
	if _, err := Run(context.Background(), Options{Link: "hysteria2://pw@x:1", TestURL: testURL, newCore: newCore}); err == nil {
		t.Fatal("hysteria2 accepted: fragmentation cannot apply to UDP")
	}
	if _, err := Run(context.Background(), Options{Link: " ", newCore: newCore}); err == nil {
		t.Fatal("empty link accepted")
	}
	if _, err := Run(context.Background(), Options{Link: "vless://a@b:1", TestURL: "ftp://x", newCore: newCore}); err == nil {
		t.Fatal("non-http test URL accepted")
	}
	if _, err := Run(context.Background(), Options{Link: "vless://a@b:1", Specs: []string{"bogus"}, newCore: newCore}); err == nil {
		t.Fatal("invalid spec accepted")
	}
}

func TestRunCanceled(t *testing.T) {
	host, port := liveAddr(t)
	gc := protocol.GeneralConfig{Protocol: "vless", Address: host, Port: port}
	_, newCore, testURL := newHarness(t, gc, func(*fragment.Options, string) error { return resetErr() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := Run(ctx, Options{Link: "vless://id@x:1", TestURL: testURL, newCore: newCore})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != VerdictCanceled {
		t.Fatalf("verdict = %q", rep.Verdict)
	}
	for _, r := range rep.Results {
		if r.Status == StatusFail {
			t.Fatalf("canceled profile reported as a DPI failure: %+v", r)
		}
	}
}

func TestBuildProfiles(t *testing.T) {
	ps, err := BuildProfiles([]string{"tlshello,100-200,10-20", "TLSHELLO,100-200,10-20", "off"}, []string{"a.example", " "})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 4 {
		t.Fatalf("got %d profiles: %+v", len(ps), ps)
	}
	if ps[0].Name != "baseline" || ps[0].Fragment != nil || ps[2].SNI != "a.example" {
		t.Fatalf("unexpected order: %+v", ps)
	}
	if got := len(Specs(ModeFull)); got != len(fullPackets)*len(fullLengths)*len(fullIntervals) {
		t.Fatalf("full grid has %d specs", got)
	}
	for _, s := range append(Specs(ModeQuick), Specs(ModeFull)...) {
		if _, err := fragment.Parse(s); err != nil {
			t.Errorf("built-in spec %q invalid: %v", s, err)
		}
	}
}

func TestWithSNI(t *testing.T) {
	got, err := WithSNI("vless://id@h:443?security=tls&sni=old.example&type=ws#Speed 100%", "new.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "sni=new.example") || strings.Contains(got, "old.example") || !strings.HasSuffix(got, "#Speed 100%") {
		t.Fatalf("got %q", got)
	}

	vm := "vmess://eyJhZGQiOiJoIiwicG9ydCI6IjQ0MyIsImlkIjoiaWQiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJvbGQuZXhhbXBsZSJ9"
	got, err = WithSNI(vm, "new.example")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := decodeAnyBase64(strings.TrimPrefix(got, "vmess://"))
	if err != nil || !strings.Contains(string(raw), `"sni":"new.example"`) {
		t.Fatalf("vmess rewrite = %s, %v", raw, err)
	}
	if _, err := WithSNI("nonsense", "x"); err == nil {
		t.Fatal("non-link accepted")
	}
}

func TestRandomCase(t *testing.T) {
	if got := RandomCase("example.com"); got != "ExAmPlE.cOm" {
		t.Fatalf("got %q", got)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]error{
		KindTimeout: context.DeadlineExceeded,
		KindReset:   resetErr(),
		KindRefused: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
		KindDNS:     &net.DNSError{Err: "no such host", Name: "x"},
		KindTLS:     errors.New("tls: handshake failure"),
		KindEOF:     fmt.Errorf("wrapped: %w", errors.New("unexpected EOF")),
		KindOther:   errors.New("weird"),
	}
	for want, err := range cases {
		if got := Classify(err); got != want {
			t.Errorf("Classify(%v) = %q, want %q", err, got, want)
		}
	}
	if Classify(nil) != "" {
		t.Error("nil error classified")
	}
}

func TestHowToApply(t *testing.T) {
	frag, _ := fragment.Parse("tlshello,100-200,10-20")
	noise, _ := fragment.Build("", []string{"rand:10-20:10-16"})
	cases := []struct {
		p    Profile
		want string
	}{
		{Profile{Fragment: frag}, "`--fragment tlshello,100-200,10-20`"},
		{Profile{Fragment: noise}, "`--noise rand:10-20:10-16`"},
		{Profile{Fragment: frag, SNI: "a.example"}, "and the SNI set to a.example"},
		{Profile{SNI: "a.example"}, "Set sni=a.example in the link"},
	}
	for _, tc := range cases {
		if got := howToApply(tc.p); !strings.Contains(got, tc.want) {
			t.Errorf("howToApply(%+v) = %q, want it to contain %q", tc.p, got, tc.want)
		}
	}
	if (Profile{Fragment: noise}).Flags() != "--noise rand:10-20:10-16" {
		t.Errorf("noise flags = %q", (Profile{Fragment: noise}).Flags())
	}
}

func TestStopAfterDoesNotMarkPassingAsPartial(t *testing.T) {
	host, port := liveAddr(t)
	gc := protocol.GeneralConfig{Protocol: "vless", Address: host, Port: port}
	allow := func(f *fragment.Options, _ string) error {
		if f.FragmentsTCP() {
			time.Sleep(30 * time.Millisecond) // keep attempts in flight when the stop lands
			return nil
		}
		return resetErr()
	}
	_, newCore, testURL := newHarness(t, gc, allow)
	rep, err := Run(context.Background(), Options{Link: "vless://id@x:1", TestURL: testURL, Attempts: 3, Threads: 4, StopAfter: 1, newCore: newCore})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if r.Status == StatusPartial || (r.Status == StatusFail && r.Profile.Fragment != nil) {
			t.Fatalf("interrupted profile mislabelled: %+v", r)
		}
	}
}
