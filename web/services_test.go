package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v11/pkg/scanner"
)

// fakeProxy is a proxyRunner whose Run blocks until cancelled; closeDelay
// simulates a slow teardown.
type fakeProxy struct {
	closeDelay     time.Duration
	closed         atomic.Int32
	runErr         error
	deadmanPending atomic.Bool
	emergency      atomic.Int32
}

func (f *fakeProxy) Run(ctx context.Context, _ <-chan struct{}) error {
	if f.runErr != nil {
		return f.runErr
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeProxy) Close() {
	time.Sleep(f.closeDelay)
	f.closed.Add(1)
}

func (f *fakeProxy) GetCurrentDetails() *proxy.Details { return &proxy.Details{} }

func (f *fakeProxy) ConfirmDeadman() bool { return f.deadmanPending.Swap(false) }

func (f *fakeProxy) EmergencyCleanup(time.Duration) { f.emergency.Add(1) }

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func waitState(t *testing.T, s interface{ Status() ServiceState }, want ...ServiceState) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := s.Status()
		for _, w := range want {
			if got == w {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("state = %s, want one of %v", s.Status(), want)
}

// collect subscribes to the hub and returns a function reporting the status
// events seen so far for eventType.
func collect(t *testing.T, hub *Hub, eventType string) func() []string {
	t.Helper()
	c, _, _, _ := hub.Subscribe(0)
	var mu sync.Mutex
	var seen []string
	go func() {
		for ev := range c.send {
			if ev.Type != eventType {
				continue
			}
			var env struct {
				Data string `json:"data"`
			}
			_ = json.Unmarshal(ev.Data, &env)
			mu.Lock()
			seen = append(seen, env.Data)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() { hub.Unsubscribe(c) })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestProxyStartWhileStoppingIsRejected(t *testing.T) {
	hub := newHub()
	p := NewProxyServiceRunner(quietLogger(), hub)
	first := &fakeProxy{closeDelay: 300 * time.Millisecond}
	var created []*fakeProxy
	p.newService = func(proxy.Config, *log.Logger) (proxyRunner, error) {
		if len(created) == 0 {
			created = append(created, first)
			return first, nil
		}
		f := &fakeProxy{}
		created = append(created, f)
		return f, nil
	}

	if err := p.Start(proxy.Config{}); err != nil {
		t.Fatal(err)
	}
	waitState(t, p, StateRunning)

	stopDone := make(chan error, 1)
	go func() { stopDone <- p.Stop() }()
	waitState(t, p, StateStopping)

	// While the first run is still closing, a new start must be refused
	// rather than racing its teardown.
	err := p.Start(proxy.Config{})
	var ae *apiError
	if !errors.As(err, &ae) || ae.status != http.StatusConflict {
		t.Fatalf("start while stopping: err = %v, want 409", err)
	}
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	if first.closed.Load() != 1 {
		t.Fatalf("first service closed %d times", first.closed.Load())
	}

	// Now a restart works, and the old run can no longer touch it.
	if err := p.Start(proxy.Config{}); err != nil {
		t.Fatal(err)
	}
	waitState(t, p, StateRunning)
	time.Sleep(50 * time.Millisecond)
	if p.Status() != StateRunning {
		t.Fatalf("stale run changed the new run's state to %s", p.Status())
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if created[1].closed.Load() != 1 || first.closed.Load() != 1 {
		t.Fatalf("close counts: first=%d second=%d", first.closed.Load(), created[1].closed.Load())
	}
}

func TestProxyStopStartRace(t *testing.T) {
	hub := newHub()
	p := NewProxyServiceRunner(quietLogger(), hub)
	p.newService = func(proxy.Config, *log.Logger) (proxyRunner, error) { return &fakeProxy{}, nil }
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = p.Start(proxy.Config{}) }()
		go func() { defer wg.Done(); _ = p.Stop() }()
	}
	wg.Wait()
	_ = p.Stop()
	waitState(t, p, StateIdle, StateError)
	if _, err := p.GetDetails(); err == nil {
		t.Fatal("details available after stop")
	}
}

func TestProxyRunErrorEndsWithOneStoppedEvent(t *testing.T) {
	hub := newHub()
	events := collect(t, hub, "proxy_status")
	p := NewProxyServiceRunner(quietLogger(), hub)
	p.newService = func(proxy.Config, *log.Logger) (proxyRunner, error) {
		return &fakeProxy{runErr: errors.New("listener died")}, nil
	}
	if err := p.Start(proxy.Config{}); err != nil {
		t.Fatal(err)
	}
	waitState(t, p, StateError)
	if got := p.Snapshot().Error; got != "listener died" {
		t.Fatalf("snapshot error = %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	stopped := 0
	for _, e := range events() {
		if e == "stopped" {
			stopped++
		}
	}
	if stopped != 1 {
		t.Fatalf("stopped events = %d (%v), want exactly 1", stopped, events())
	}
	// A failed run does not block the next start.
	p.newService = func(proxy.Config, *log.Logger) (proxyRunner, error) { return &fakeProxy{}, nil }
	if err := p.Start(proxy.Config{}); err != nil {
		t.Fatal(err)
	}
	_ = p.Stop()
}

// Building the service (DB query, crash recovery) must not hold the lock
// that /state, SSE and details take; a Stop meanwhile still ends the run.
func TestProxyStartDoesNotBlockReaders(t *testing.T) {
	for _, fail := range []bool{false, true} {
		hub := newHub()
		events := collect(t, hub, "proxy_status")
		p := NewProxyServiceRunner(quietLogger(), hub)
		release := make(chan struct{})
		built := &fakeProxy{}
		p.newService = func(proxy.Config, *log.Logger) (proxyRunner, error) {
			<-release
			if fail {
				return nil, errors.New("no configs")
			}
			return built, nil
		}
		startErr := make(chan error, 1)
		go func() { startErr <- p.Start(proxy.Config{}) }()
		waitState(t, p, StateStarting)

		read := make(chan struct{})
		go func() {
			_ = p.Snapshot()
			_, _ = p.GetDetails()
			p.EmergencyCleanup(time.Second)
			close(read)
		}()
		select {
		case <-read:
		case <-time.After(2 * time.Second):
			t.Fatal("readers blocked while the proxy service was being built")
		}

		stopErr := make(chan error, 1)
		go func() { stopErr <- p.Stop() }()
		waitState(t, p, StateStopping)
		close(release)
		err := <-startErr
		if fail != (err != nil) {
			t.Fatalf("fail=%v: start err = %v", fail, err)
		}
		if err := <-stopErr; err != nil {
			t.Fatalf("fail=%v: stop err = %v", fail, err)
		}
		waitState(t, p, StateIdle, StateError)
		if !fail && built.closed.Load() != 1 {
			t.Fatalf("service built during a stop closed %d times", built.closed.Load())
		}
		time.Sleep(50 * time.Millisecond)
		if got := events(); len(got) == 0 || got[len(got)-1] != "stopped" {
			t.Fatalf("fail=%v: status events = %v, want a final stopped", fail, got)
		}
	}
}

func TestProxyEmergencyCleanupReachesService(t *testing.T) {
	p := NewProxyServiceRunner(quietLogger(), newHub())
	f := &fakeProxy{}
	p.newService = func(proxy.Config, *log.Logger) (proxyRunner, error) { return f, nil }
	p.EmergencyCleanup(time.Second) // idle: nothing to clean
	if err := p.Start(proxy.Config{}); err != nil {
		t.Fatal(err)
	}
	waitState(t, p, StateRunning)
	p.EmergencyCleanup(time.Second)
	if f.emergency.Load() != 1 {
		t.Fatalf("emergency cleanups = %d", f.emergency.Load())
	}
	_ = p.Stop()
}

func TestProxyStartFailureIsBadRequest(t *testing.T) {
	p := NewProxyServiceRunner(quietLogger(), newHub())
	p.newService = func(proxy.Config, *log.Logger) (proxyRunner, error) { return nil, errors.New("no configs") }
	err := p.Start(proxy.Config{})
	var ae *apiError
	if !errors.As(err, &ae) || ae.status != http.StatusBadRequest {
		t.Fatalf("err = %v, want 400", err)
	}
	if p.Status() != StateError {
		t.Fatalf("state = %s", p.Status())
	}
	if err := p.Stop(); err == nil {
		t.Fatal("stop of a failed start should report not running")
	}
}

func TestHttpTestStartRejectsBadInput(t *testing.T) {
	ht := NewHttpTestRunner(quietLogger(), newHub())
	for name, req := range map[string]pkghttp.HttpTestRequest{
		"no links":      {Links: []string{"  ", ""}},
		"probe samples": {Links: []string{"vless://x"}, Options: pkghttp.Options{ProbeSamples: 33}},
		"threads":       {Links: []string{"vless://x"}, ThreadCount: maxHttpThreads + 1},
	} {
		err := ht.Start(req)
		var ae *apiError
		if !errors.As(err, &ae) || ae.status != http.StatusBadRequest {
			t.Errorf("%s: err = %v, want 400", name, err)
		}
	}
	if ht.Status() != StateIdle {
		t.Fatalf("rejected starts changed state to %s", ht.Status())
	}
}

func TestStopWhenIdleIsNotRunning(t *testing.T) {
	ht := NewHttpTestRunner(quietLogger(), newHub())
	err := ht.Stop()
	var ae *apiError
	if !errors.As(err, &ae) || ae.code != codeNotRunning {
		t.Fatalf("err = %v, want not_running", err)
	}
}

func TestBuildCfScanJob(t *testing.T) {
	ok, err := buildCfScanJob(scanner.ScannerConfig{Subnets: []string{"104.16.0.0/24", "1.1.1.1", " "}})
	if err != nil {
		t.Fatal(err)
	}
	if ok.cfg.ThreadCount != defaultScannerThreads || ok.cfg.Port != 443 || len(ok.cfg.Subnets) != 2 {
		t.Fatalf("job = %+v", ok.cfg)
	}
	if ok.cfg.Subnets[0] != "1.1.1.1/32" && ok.cfg.Subnets[1] != "1.1.1.1/32" {
		t.Fatalf("bare IP not normalised: %q", ok.cfg.Subnets)
	}
	for name, cfg := range map[string]scanner.ScannerConfig{
		"empty":         {},
		"bad cidr":      {Subnets: []string{"1.2.3.4/33"}},
		"garbage":       {Subnets: []string{"not-an-ip"}},
		"ipv6 /32":      {Subnets: []string{"2606:4700::/32"}},
		"ipv6 /64":      {Subnets: []string{"2001:db8::/64"}},
		"ipv4 /0":       {Subnets: []string{"0.0.0.0/0"}},
		"neg threads":   {Subnets: []string{"1.1.1.1"}, ThreadCount: -1},
		"huge threads":  {Subnets: []string{"1.1.1.1"}, ThreadCount: maxScannerThreads + 1},
		"neg top":       {Subnets: []string{"1.1.1.1"}, SpeedtestTop: -1},
		"bad port":      {Subnets: []string{"1.1.1.1"}, Port: 70000},
		"neg retry":     {Subnets: []string{"1.1.1.1"}, RetryCount: -2},
		"sum too large": {Subnets: []string{"10.0.0.0/8", "11.0.0.0/8"}, MaxIPs: maxIPsPerScan},
		"above cap":     {Subnets: []string{"10.0.0.0/8"}},
		"neg max ips":   {Subnets: []string{"1.1.1.1"}, MaxIPs: -1},
		"neg sample":    {Subnets: []string{"1.1.1.1"}, SamplePerSubnet: -1},
	} {
		_, err := buildCfScanJob(cfg)
		var ae *apiError
		if !errors.As(err, &ae) || ae.status != http.StatusBadRequest {
			t.Errorf("%s: err = %v, want 400", name, err)
		}
	}
	// A narrow IPv6 range is fine, and so is a huge one when sampled or
	// an IPv4 /8 with a raised cap.
	for name, cfg := range map[string]scanner.ScannerConfig{
		"ipv6 /120":        {Subnets: []string{"2606:4700::/120"}},
		"ipv6 /32 sampled": {Subnets: []string{"2606:4700::/32"}, SamplePerSubnet: 1},
		"ipv4 /8 raised":   {Subnets: []string{"10.0.0.0/8"}, MaxIPs: maxIPsPerScan},
	} {
		if _, err := buildCfScanJob(cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateProxyConfig(t *testing.T) {
	links := []string{" vless://a ", "", "trojan://b"}
	cfg, err := validateProxyConfig(&proxyStartRequest{Config: proxy.Config{ConfigLinks: links, ListenAddr: "localhost"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "127.0.0.1" || cfg.ListenPort != "9999" || len(cfg.ConfigLinks) != 2 || cfg.ConfigLinks[0] != "vless://a" {
		t.Fatalf("cfg = %+v", cfg)
	}
	cfg, err = validateProxyConfig(&proxyStartRequest{Config: proxy.Config{ListenAddr: "[::1]", ListenPort: "1080"}, ConfigLinksLower: []string{"vless://a"}}, false)
	if err != nil || cfg.ListenAddr != "::1" || len(cfg.ConfigLinks) != 1 {
		t.Fatalf("cfg = %+v err=%v", cfg, err)
	}
	// Same rules as the CLI (proxy.NormalizeListenAddr).
	for in, want := range map[string]string{"ip6-localhost": "::1", "localhost.": "127.0.0.1"} {
		cfg, err = validateProxyConfig(&proxyStartRequest{Config: proxy.Config{ListenAddr: in, ConfigLinks: links}}, false)
		if err != nil || cfg.ListenAddr != want {
			t.Fatalf("%s: listen = %q err=%v", in, cfg.ListenAddr, err)
		}
	}

	f := false
	for name, req := range map[string]*proxyStartRequest{
		"app mode disabled": {Config: proxy.Config{Mode: "app", ConfigLinks: links}},
		"tun mode disabled": {Config: proxy.Config{Mode: "host-tun", ConfigLinks: links}},
		"unknown mode":      {Config: proxy.Config{Mode: "bogus", ConfigLinks: links}},
		"hostname listen":   {Config: proxy.Config{ListenAddr: "example.com", ConfigLinks: links}},
		"bad port":          {Config: proxy.Config{ListenPort: "0", ConfigLinks: links}},
		"port text":         {Config: proxy.Config{ListenPort: "abc", ConfigLinks: links}},
		"bad rotation":      {Config: proxy.Config{ChainRotation: "sideways", ConfigLinks: links}},
		"kill switch":       {Config: proxy.Config{Mode: "system", KillSwitch: true, ConfigLinks: links}},
	} {
		if _, err := validateProxyConfig(req, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// With host modes allowed: namespace names are checked, the deadman
	// must be off, and excludePrivate defaults to true like the CLI.
	for name, req := range map[string]*proxyStartRequest{
		"ns traversal": {Config: proxy.Config{Mode: "app", NamespaceName: "../../etc", ConfigLinks: links}},
		"ns dots":      {Config: proxy.Config{Mode: "app", NamespaceName: "a..b", ConfigLinks: links}},
		"shell":        {Config: proxy.Config{Mode: "app", Shell: true, ConfigLinks: links}},
	} {
		if _, err := validateProxyConfig(req, true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cfg, err = validateProxyConfig(&proxyStartRequest{Config: proxy.Config{Mode: "host-tun", ConfigLinks: links}}, true)
	if err != nil || !cfg.HostTunExcludePrivate || cfg.HostTunDeadman != defaultHostTunDeadman || !cfg.ExternalDeadmanConfirm {
		t.Fatalf("host-tun defaults: excludePrivate=%v deadman=%d external=%v err=%v", cfg.HostTunExcludePrivate, cfg.HostTunDeadman, cfg.ExternalDeadmanConfirm, err)
	}
	var off uint16
	cfg, err = validateProxyConfig(&proxyStartRequest{Config: proxy.Config{Mode: "host-tun", ConfigLinks: links}, HostTunExcludePrivatePtr: &f, HostTunDeadmanPtr: &off}, true)
	if err != nil || cfg.HostTunExcludePrivate || cfg.HostTunDeadman != 0 {
		t.Fatalf("explicit false/0 ignored: %+v %d err=%v", cfg.HostTunExcludePrivate, cfg.HostTunDeadman, err)
	}
}

func TestProxyStartRequestDecodesPtrOverride(t *testing.T) {
	var req proxyStartRequest
	if err := json.Unmarshal([]byte(`{"hostTunExcludePrivate": false, "configLinks": ["vless://x"], "listenPort": "1080"}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.HostTunExcludePrivatePtr == nil || *req.HostTunExcludePrivatePtr {
		t.Fatal("explicit false not captured")
	}
	if len(req.ConfigLinksLower) != 1 || req.ListenPort != "1080" {
		t.Fatalf("req = %+v", req)
	}
}

func TestHttpSummaryFailureKinds(t *testing.T) {
	var s httpSummary
	for _, r := range []*pkghttp.Result{
		{Status: "passed"},
		{Status: "failed", FailureKind: pkghttp.FailTLSReset},
		{Status: "failed", FailureKind: pkghttp.FailTLSReset},
		{Status: "semi-passed", FailureKind: pkghttp.FailSlow},
		{Status: "broken"},
	} {
		s.add(r)
	}
	kinds := s.failureKinds()
	if kinds[pkghttp.FailTLSReset] != 2 || kinds[pkghttp.FailSlow] != 1 || kinds[pkghttp.FailOther] != 1 || len(kinds) != 3 {
		t.Fatalf("kinds = %v", kinds)
	}
	if sum := s.snapshot(); sum["total"] != 5 || sum["passed"] != 1 || sum["failed"] != 2 {
		t.Fatalf("summary = %v", sum)
	}
}

// Links the prescan drops still show up as failed results with their kind,
// and the final event carries the failure-kind counts.
func TestHttpTestPrescanDropsBecomeResults(t *testing.T) {
	t.Setenv("XRAY_KNIFE_HOME", t.TempDir())
	prev := httpTesterHistoryFile
	httpTesterHistoryFile = filepath.Join(t.TempDir(), "http-results.csv")
	t.Cleanup(func() { httpTesterHistoryFile = prev })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()
	link := "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:" + port + "?security=none&type=tcp#closed"

	hub := newHub()
	c, _, _, _ := hub.Subscribe(0)
	defer hub.Unsubscribe(c)
	ht := NewHttpTestRunner(quietLogger(), hub)
	body := httpTestRequestBody{Links: []string{link}, ThreadCount: 1, Prescan: true, PrescanTimeout: 1000,
		Options: pkghttp.Options{MaxDelay: 2000, Timeout: 2000}}
	job, err := body.buildJob(quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := ht.Start(job); err != nil {
		t.Fatal(err)
	}
	var result *pkghttp.Result
	var kinds map[string]any
	deadline := time.After(20 * time.Second)
	for kinds == nil {
		select {
		case ev := <-c.send:
			switch ev.Type {
			case "http_result":
				var env struct {
					Data pkghttp.Result `json:"data"`
				}
				if err := json.Unmarshal(ev.Data, &env); err != nil {
					t.Fatal(err)
				}
				result = &env.Data
			case "http_test_status":
				var env struct {
					Data         string         `json:"data"`
					FailureKinds map[string]any `json:"failureKinds"`
				}
				_ = json.Unmarshal(ev.Data, &env)
				if env.Data == "finished" {
					kinds = env.FailureKinds
				}
			}
		case <-deadline:
			t.Fatal("no finished event")
		}
	}
	if result == nil || result.Status == "passed" || result.FailureKind == "" || result.ConfigLink != link {
		t.Fatalf("dropped link result = %+v", result)
	}
	if kinds[result.FailureKind].(float64) != 1 {
		t.Fatalf("failureKinds = %v, want %s:1", kinds, result.FailureKind)
	}
	if snap := ht.Snapshot(); snap.FailureKinds[result.FailureKind] != 1 || snap.Progress["completed"] != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestSupportedProtocols(t *testing.T) {
	got := map[string]string{}
	for _, p := range supportedProtocols() {
		got[p.Scheme] = p.Core
	}
	for _, want := range []string{"vless", "vmess", "trojan", "ss", "hysteria2", "mtproto"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s missing from %v", want, got)
		}
	}
	if got["hysteria2"] != "sing-box" || got["mtproto"] != "mtproto" {
		t.Errorf("cores = %v", got)
	}
}
