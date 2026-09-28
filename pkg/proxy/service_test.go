package proxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/sysproxy"
)

func TestFilterBlacklistedKeepsStrikesUntilBanned(t *testing.T) {
	now := time.Now()
	bl := map[string]*blacklistEntry{
		"striking": {strikes: 2},
		"banned":   {strikes: 3, blacklistedUntil: now.Add(time.Minute)},
		"served":   {strikes: 3, blacklistedUntil: now.Add(-time.Second)},
	}
	kept, skipped := filterBlacklisted([]string{"fresh", "striking", "banned", "served"}, bl, now)

	if len(kept) != 3 || kept[0] != "fresh" || kept[1] != "striking" || kept[2] != "served" {
		t.Fatalf("kept = %q", kept)
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	// The old filter deleted every entry without a ban, resetting strikes
	// on every rotation so nothing was ever blacklisted.
	if e := bl["striking"]; e == nil || e.strikes != 2 {
		t.Fatalf("strikes were reset: %+v", e)
	}
	if _, ok := bl["served"]; ok {
		t.Fatal("expired ban not cleared")
	}
}

func TestStrikesAcrossRotationsLeadToBan(t *testing.T) {
	s := &Service{
		config:    Config{BlacklistStrikes: 3, BlacklistDuration: 60},
		blacklist: map[string]*blacklistEntry{},
		logger:    log.New(io.Discard, "", 0),
	}
	for rotation := 0; rotation < 3; rotation++ {
		kept, _ := filterBlacklisted([]string{"bad"}, s.blacklist, time.Now())
		if len(kept) != 1 {
			t.Fatalf("rotation %d: banned too early", rotation)
		}
		s.recordStrike("bad", "failed")
	}
	if kept, skipped := filterBlacklisted([]string{"bad"}, s.blacklist, time.Now()); len(kept) != 0 || skipped != 1 {
		t.Fatalf("config not banned after 3 consecutive failures: kept=%q", kept)
	}

	// A pass in between resets the count.
	s.recordStrike("flaky", "failed")
	s.recordStrike("flaky", "failed")
	s.clearStrikes("flaky")
	s.recordStrike("flaky", "failed")
	if e := s.blacklist["flaky"]; e == nil || e.strikes != 1 || !e.blacklistedUntil.IsZero() {
		t.Fatalf("flaky entry = %+v", e)
	}
	// clearStrikes never lifts an active ban.
	s.clearStrikes("bad")
	if _, ok := s.blacklist["bad"]; !ok {
		t.Fatal("clearStrikes lifted a ban")
	}
}

func TestNormalizeListenAddr(t *testing.T) {
	ok := map[string]string{
		"":               "127.0.0.1",
		"localhost":      "127.0.0.1",
		"LOCALHOST":      "127.0.0.1",
		"127.0.0.1":      "127.0.0.1",
		"0.0.0.0":        "0.0.0.0",
		"[::1]":          "::1",
		"::":             "::",
		" 10.0.0.5 ":     "10.0.0.5",
		"::ffff:1.2.3.4": "1.2.3.4",
	}
	for in, want := range ok {
		got, err := NormalizeListenAddr(in)
		if err != nil || got != want {
			t.Errorf("NormalizeListenAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"example.com", "my-host", "fe80::1%eth0", "1.2.3"} {
		if got, err := NormalizeListenAddr(bad); err == nil {
			t.Errorf("NormalizeListenAddr(%q) = %q, want error (cores widen it to all interfaces)", bad, got)
		}
	}
}

func TestDialableAddr(t *testing.T) {
	for in, want := range map[string]string{"0.0.0.0": "127.0.0.1", "": "127.0.0.1", "::": "::1", "10.1.2.3": "10.1.2.3"} {
		if got := dialableAddr(in); got != want {
			t.Errorf("dialableAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHealthTrackerThreshold(t *testing.T) {
	h := newHealthTracker(0)
	if h.threshold != defaultHealthFailThresh {
		t.Fatalf("default threshold = %d", h.threshold)
	}
	h = newHealthTracker(2)
	if h.record(false) {
		t.Fatal("tripped after one failure")
	}
	h.record(true) // a success resets the run
	if h.record(false) {
		t.Fatal("tripped after a reset")
	}
	if !h.record(false) {
		t.Fatal("did not trip after two consecutive failures")
	}
	if h.fails != 0 {
		t.Fatal("count not reset after tripping")
	}
}

func TestStallBackoffAndNextWait(t *testing.T) {
	var b stallBackoff
	want := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := b.failure(); got != w {
			t.Fatalf("failure %d = %v, want %v", i, got, w)
		}
	}
	b.reset()
	if got := b.failure(); got != stallBackoffMin {
		t.Fatalf("after reset = %v", got)
	}

	s := &Service{config: Config{RotationInterval: 20}}
	b.reset()
	if got := s.nextWait(false, &b); got != 20*time.Second {
		t.Fatalf("normal wait = %v", got)
	}
	b.failure() // 15s
	if got := s.nextWait(true, &b); got != 20*time.Second {
		t.Fatalf("stalled wait should be capped by the interval, got %v", got)
	}
	s.config.RotationInterval = 0
	b.reset()
	if got := s.nextWait(false, &b); got != 0 {
		t.Fatalf("failover-only wait = %v, want 0", got)
	}
	if got := s.nextWait(true, &b); got != stallBackoffMin {
		t.Fatalf("failover-only stalled wait = %v", got)
	}
}

func TestParseCapEff(t *testing.T) {
	status := []byte("Name:\txray-knife\nCapInh:\t0000000000000000\nCapEff:\t0000000000003000\n")
	mask, ok := parseCapEff(status)
	if !ok || mask != 0x3000 {
		t.Fatalf("mask = %x, ok = %v", mask, ok)
	}
	if missing := missingFromMask(mask, []int{capNetAdmin, capNetRaw}); len(missing) != 0 {
		t.Fatalf("missing = %v", missing)
	}
	if missing := missingFromMask(mask, []int{capSysAdmin, capNetAdmin}); len(missing) != 1 || missing[0] != "CAP_SYS_ADMIN" {
		t.Fatalf("missing = %v", missing)
	}
	if _, ok := parseCapEff([]byte("Name:\tx\n")); ok {
		t.Fatal("CapEff found in status without it")
	}
}

// --- fake core for the start/restart paths ---------------------------

type fakeProto struct{ link string }

func (p *fakeProto) Parse() error       { return nil }
func (p *fakeProto) DetailsStr() string { return p.link + "\n" }
func (p *fakeProto) GetLink() string    { return p.link }
func (p *fakeProto) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{OrigLink: p.link}
}

type fakeInstance struct {
	core   *fakeCore
	link   string
	closed bool
}

func (i *fakeInstance) Start() error {
	if i.core.failStart[i.link] {
		return errors.New("bind: address already in use")
	}
	i.core.started = append(i.core.started, i.link)
	return nil
}

func (i *fakeInstance) Close() error { i.closed = true; return nil }

type fakeCore struct {
	failStart map[string]bool
	started   []string
}

func (c *fakeCore) Name() string { return "fake" }
func (c *fakeCore) MakeHttpClient(context.Context, protocol.Protocol, time.Duration) (*http.Client, protocol.Instance, error) {
	return nil, nil, errors.New("not implemented")
}
func (c *fakeCore) CreateProtocol(link string) (protocol.Protocol, error) {
	return &fakeProto{link: link}, nil
}
func (c *fakeCore) MakeInstance(_ context.Context, p protocol.Protocol) (protocol.Instance, error) {
	return &fakeInstance{core: c, link: p.GetLink()}, nil
}
func (c *fakeCore) SetInbound(protocol.Protocol) error { return nil }

func passed(link string) *pkghttp.Result {
	return &pkghttp.Result{ConfigLink: link, Status: "passed", Protocol: &fakeProto{link: link}}
}

func TestStartFirstPassingReleasesPortOnce(t *testing.T) {
	fc := &fakeCore{failStart: map[string]bool{"a": true}}
	s := &Service{core: fc, blacklist: map[string]*blacklistEntry{}, logger: log.New(io.Discard, "", 0)}
	releases := 0
	results := []*pkghttp.Result{
		{ConfigLink: "broken", Status: "failed"},
		passed("a"),
		passed("b"),
	}
	inst, res, ok := s.startFirstPassing(context.Background(), results, nil, func() { releases++ })
	if !ok || res.ConfigLink != "b" || inst == nil {
		t.Fatalf("started %v (ok=%v)", res, ok)
	}
	if releases != 1 {
		t.Fatalf("port released %d times, want 1", releases)
	}
	if s.activeOutbound != res {
		t.Fatal("activeOutbound not updated")
	}
}

// When every candidate fails to start after the listener was released,
// the rotation loop restores the previous outbound instead of leaving the
// port unbound.
func TestRestartOutboundAfterFailedSwitch(t *testing.T) {
	fc := &fakeCore{failStart: map[string]bool{"x": true, "y": true}}
	s := &Service{core: fc, blacklist: map[string]*blacklistEntry{}, logger: log.New(io.Discard, "", 0)}
	released := false
	_, _, ok := s.startFirstPassing(context.Background(), []*pkghttp.Result{passed("x"), passed("y")}, nil, func() { released = true })
	if ok || !released {
		t.Fatalf("ok=%v released=%v", ok, released)
	}
	prev := passed("old")
	inst, err := s.restartOutbound(context.Background(), prev)
	if err != nil || inst == nil {
		t.Fatalf("restartOutbound: %v", err)
	}
	if len(fc.started) != 1 || fc.started[0] != "old" || s.activeOutbound != prev {
		t.Fatalf("started = %v", fc.started)
	}
	if _, err := s.restartOutbound(context.Background(), nil); err == nil {
		t.Fatal("restart without a previous outbound succeeded")
	}
}

// A key pressed while the tunnel is still coming up belongs to the
// deadman (it must not rotate) but cannot confirm a tunnel that is not up.
func TestEarlyEnterIsHeldNotCounted(t *testing.T) {
	s := &Service{deadmanConfirm: make(chan struct{}, 1)}
	s.deadmanArmed.Store(true)
	if !s.ConfirmDeadman() {
		t.Fatal("early ENTER treated as a rotation request")
	}
	select {
	case <-s.deadmanConfirm:
		t.Fatal("early ENTER confirmed the deadman")
	default:
	}
	if !s.earlyEnter.Load() {
		t.Fatal("early ENTER not noted")
	}
	s.deadmanArmed.Store(false)
	if s.ConfirmDeadman() {
		t.Fatal("ENTER after the deadman finished swallowed")
	}
}

type fakeSysproxy struct {
	restored chan struct{}
	block    bool
}

func (f *fakeSysproxy) Get() (*sysproxy.Settings, error) { return &sysproxy.Settings{}, nil }
func (f *fakeSysproxy) Set(string, string) error         { return nil }
func (f *fakeSysproxy) Restore(*sysproxy.Settings) error {
	if f.block {
		select {}
	}
	close(f.restored)
	return nil
}

// A forced exit still puts the OS proxy settings back, and never hangs.
func TestEmergencyCleanup(t *testing.T) {
	t.Setenv("XRAY_KNIFE_HOME", t.TempDir())
	mgr := &fakeSysproxy{restored: make(chan struct{})}
	s := &Service{sysProxyManager: mgr, prevProxySettings: &sysproxy.Settings{}, logger: log.New(io.Discard, "", 0)}
	s.EmergencyCleanup(time.Second)
	select {
	case <-mgr.restored:
	default:
		t.Fatal("system proxy not restored")
	}
	stuck := &Service{sysProxyManager: &fakeSysproxy{block: true}, prevProxySettings: &sysproxy.Settings{}, logger: log.New(io.Discard, "", 0)}
	start := time.Now()
	stuck.EmergencyCleanup(50 * time.Millisecond)
	if time.Since(start) > time.Second {
		t.Fatal("EmergencyCleanup not bounded")
	}
}

// Only the entry hop is dialed from this machine, so only it needs a way
// out of the tunnel.
func TestEntryHopOnly(t *testing.T) {
	hops := []protocol.Protocol{&fakeProto{link: "socks://198.51.100.1:1080"}, &fakeProto{link: "socks://198.51.100.2:1080"}}
	addrs := resolveServers(context.Background(), nil, hopLinks(entryHop(hops)))
	if len(addrs) != 1 || addrs[0].String() != "198.51.100.1" {
		t.Fatalf("addrs = %v", addrs)
	}
	if entryHop(nil) != nil {
		t.Fatal("entryHop(nil) not nil")
	}
	if d := (&Service{}).drainPeriod(); d != time.Minute {
		t.Fatalf("drainPeriod = %v", d)
	}
}

func TestConfirmDeadmanOnlyWhilePending(t *testing.T) {
	s := &Service{deadmanConfirm: make(chan struct{}, 1)}
	if s.ConfirmDeadman() {
		t.Fatal("confirmation accepted with no deadman pending")
	}
	s.deadmanPending.Store(true)
	if !s.ConfirmDeadman() || !s.ConfirmDeadman() {
		t.Fatal("pending deadman not confirmed")
	}
	select {
	case <-s.deadmanConfirm:
	default:
		t.Fatal("confirmation not delivered")
	}
}

func TestNewRejectsUnsafeConfig(t *testing.T) {
	base := Config{CoreType: "xray", ListenPort: "9999", ConfigLinks: []string{"socks://127.0.0.1:1080"}}

	c := base
	c.ListenAddr = "localhost.example"
	if _, err := New(c, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("hostname listen address accepted")
	}
	c = base
	c.FragmentSpec = "tlshello,0"
	if _, err := New(c, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("invalid fragment accepted")
	}
	c = base
	c.HealthCheckURL = "ftp://x"
	if _, err := New(c, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("non-http health URL accepted")
	}
}

// Chain hops given without chain=true (a library or web API caller) still
// run as a chain, and need no database pool, as on the CLI.
func TestNewFixedChainImpliesChain(t *testing.T) {
	t.Setenv("XRAY_KNIFE_HOME", t.TempDir()) // an empty database, were one opened
	svc, err := New(Config{CoreType: "xray", InboundProtocol: "socks", ListenPort: "9999", ChainLinks: chainVless + "|" + chainTrojan}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	if !svc.config.Chain || len(svc.config.ConfigLinks) != 0 {
		t.Fatalf("chain = %v, pool = %v", svc.config.Chain, svc.config.ConfigLinks)
	}
	if svc2, err := New(Config{CoreType: "xray", InboundProtocol: "socks", ListenPort: "9999", ChainLinks: "  ", ConfigLinks: []string{chainVless}}, log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	} else if svc2.config.Chain {
		t.Fatal("blank chainLinks enabled chain mode")
	}
}

// fakeSwapper is a hot-swappable listener that records swaps.
type fakeSwapper struct {
	fakeInstance
	swaps [][]string
	fail  map[string]bool
}

func (f *fakeSwapper) Swap(_ context.Context, hops []protocol.Protocol, _ time.Duration) error {
	links := hopLinks(hops)
	if f.fail[links[0]] {
		return errors.New("build failed")
	}
	f.swaps = append(f.swaps, links)
	return nil
}

// With a hot-swappable listener the port is never released: the winner is
// swapped in, and a candidate that fails to build is skipped.
func TestStartFirstPassingSwapsInPlace(t *testing.T) {
	fc := &fakeCore{}
	s := &Service{core: fc, config: Config{BlacklistStrikes: 3}, blacklist: map[string]*blacklistEntry{}, logger: log.New(io.Discard, "", 0)}
	sw := &fakeSwapper{fail: map[string]bool{"a": true}}
	released := false
	inst, res, ok := s.startFirstPassing(context.Background(), []*pkghttp.Result{passed("a"), passed("b")}, sw, func() { released = true })
	if !ok || res.ConfigLink != "b" || inst != hotSwapper(sw) {
		t.Fatalf("ok=%v res=%v inst=%v", ok, res, inst)
	}
	if released {
		t.Fatal("port released despite hot swap")
	}
	if len(sw.swaps) != 1 || sw.swaps[0][0] != "b" || len(fc.started) != 0 {
		t.Fatalf("swaps=%v started=%v", sw.swaps, fc.started)
	}
	if e := s.blacklist["a"]; e == nil || e.strikes != 1 {
		t.Fatal("failed swap not struck")
	}
}

func TestSwapChainInPlace(t *testing.T) {
	s := &Service{logger: log.New(io.Discard, "", 0)}
	sw := &fakeSwapper{}
	newHops := []protocol.Protocol{&fakeProto{link: "e"}, &fakeProto{link: "x"}}
	inst, ok := s.swapChain(context.Background(), sw, nil, newHops)
	if !ok || inst != protocol.Instance(sw) || len(sw.swaps) != 1 || len(s.activeChainHops) != 2 {
		t.Fatalf("ok=%v swaps=%v hops=%v", ok, sw.swaps, s.activeChainHops)
	}
}

// The host-tun socket mark reaches both cores' swappable listeners; with
// no mark (every other mode) no option is passed.
func TestSwapOptionsCarryTheMark(t *testing.T) {
	s := &Service{}
	if len(s.xraySwapOptions()) != 0 || len(s.singboxSwapOptions()) != 0 {
		t.Fatal("options passed without a mark")
	}
	s.mark = 0x786b0042
	if len(s.xraySwapOptions()) != 1 || len(s.singboxSwapOptions()) != 1 {
		t.Fatal("mark not passed to the cores")
	}
}
