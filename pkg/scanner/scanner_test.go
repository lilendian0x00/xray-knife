package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
)

// newTestService builds a scanner whose network calls are replaced by fn.
func newTestService(t *testing.T, cfg ScannerConfig, latency func(ctx context.Context, ip string) *ScanResult) *ScannerService {
	t.Helper()
	if cfg.ThreadCount == 0 {
		cfg.ThreadCount = 4
	}
	s, err := NewScannerService(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	s.latencyFn = latency
	return s
}

func drain(ch <-chan *ScanResult) (n int) {
	for range ch {
		n++
	}
	return n
}

func run(t *testing.T, s *ScannerService, ctx context.Context) error {
	t.Helper()
	ch := make(chan *ScanResult, 4)
	done := make(chan int)
	go func() { done <- drain(ch) }()
	err := s.Run(ctx, ch)
	<-done
	return err
}

func TestNewScannerServiceValidates(t *testing.T) {
	for name, cfg := range map[string]ScannerConfig{
		"zero threads":    {Subnets: []string{"1.1.1.0/24"}},
		"negative sample": {Subnets: []string{"1.1.1.0/24"}, ThreadCount: 1, SamplePerSubnet: -1},
		"bad cidr":        {Subnets: []string{"1.1.1.0/99"}, ThreadCount: 1},
		"bad format":      {Subnets: []string{"1.1.1.0/24"}, ThreadCount: 1, OutputFormat: "xml"},
		"negative top":    {Subnets: []string{"1.1.1.0/24"}, ThreadCount: 1, DoSpeedtest: true, SpeedtestTop: -1, DownloadMB: 1},
		"bad fragment":    {Subnets: []string{"1.1.1.0/24"}, ThreadCount: 1, ConfigLink: "socks://127.0.0.1:1080", FragmentSpec: "tlshello,0,1"},
		"huge sample":     {Subnets: []string{"1.1.1.0/24"}, ThreadCount: 1, SamplePerSubnet: 100_000_000},
		"resume stdout":   {Subnets: []string{"1.1.1.0/24"}, ThreadCount: 1, Resume: true, OutputFile: "-"},
		"endless ipv6":    {Subnets: []string{"2606:4700::/32"}, ThreadCount: 1, MaxIPs: -1},
	} {
		if _, err := NewScannerService(cfg, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A speed test failure must not turn an IP that passed latency into a
// failure: it keeps its latency, stays ranked, and counts as working.
func TestSpeedFailureKeepsLatencyVerdict(t *testing.T) {
	out := filepath.Join(t.TempDir(), "results.csv")
	s := newTestService(t, ScannerConfig{
		Subnets: []string{"192.0.2.0/30"}, OutputFile: out,
		DoSpeedtest: true, SpeedtestTop: 4, DownloadMB: 1,
	}, func(_ context.Context, ip string) *ScanResult {
		return &ScanResult{IP: ip, Latency: 10 * time.Millisecond}
	})
	s.speedFn = func(_ context.Context, ip string) (float64, float64, error) {
		if ip == "192.0.2.1" {
			return 0, 0, errors.New("download: window expired")
		}
		return 50, 10, nil
	}
	if err := run(t, s, context.Background()); err != nil {
		t.Fatal(err)
	}
	var failedSpeed *ScanResult
	for _, r := range s.Results() {
		if r.Error != nil {
			t.Fatalf("%s demoted to failed: %v", r.IP, r.Error)
		}
		if r.IP == "192.0.2.1" {
			failedSpeed = r
		}
	}
	if failedSpeed == nil || failedSpeed.SpeedErr == nil || failedSpeed.Latency != 10*time.Millisecond {
		t.Fatalf("speed failure not recorded separately: %+v", failedSpeed)
	}
	// Reload: the CSV carries the speed error in its own column.
	back, err := LoadResults(out)
	if err != nil || len(back) != 4 {
		t.Fatalf("reload: %d results, %v", len(back), err)
	}
	for _, r := range back {
		if r.Error != nil {
			t.Errorf("reloaded %s as failed", r.IP)
		}
	}
}

// With --speedtest the ranking follows download speed among tested IPs.
func TestSortResultsBySpeed(t *testing.T) {
	rs := []*ScanResult{
		{IP: "a", Latency: 10 * time.Millisecond, DownSpeed: 5},
		{IP: "b", Latency: 12 * time.Millisecond, DownSpeed: 80},
		{IP: "c", Latency: 5 * time.Millisecond},
		{IP: "d", Error: errors.New("x")},
	}
	SortResults(rs, true)
	if got := rs[0].IP + rs[1].IP + rs[2].IP + rs[3].IP; got != "bacd" {
		t.Fatalf("speed ranking = %s, want bacd", got)
	}
	SortResults(rs, false)
	if got := rs[0].IP + rs[1].IP + rs[2].IP + rs[3].IP; got != "cabd" {
		t.Fatalf("latency ranking = %s, want cabd", got)
	}
}

// Ctrl-C mid-scan: finished results are saved, interrupted probes are not
// recorded, and --resume skips exactly the IPs that were tested.
func TestInterruptedScanSavesAndResumes(t *testing.T) {
	out := filepath.Join(t.TempDir(), "results.csv")
	ctx, cancel := context.WithCancel(context.Background())
	var probes atomic.Int32
	s := newTestService(t, ScannerConfig{Subnets: []string{"10.0.0.0/24"}, OutputFile: out, ThreadCount: 2},
		func(ctx context.Context, ip string) *ScanResult {
			if probes.Add(1) > 20 {
				cancel()
				<-ctx.Done()
				return &ScanResult{IP: ip, Error: ctx.Err()}
			}
			return &ScanResult{IP: ip, Latency: time.Millisecond}
		})
	if err := run(t, s, ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	saved, err := LoadResults(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) == 0 || len(saved) > 20 {
		t.Fatalf("saved %d results, want the finished ones only", len(saved))
	}
	for _, r := range saved {
		if r.Error != nil {
			t.Fatalf("interrupted probe recorded as failure: %+v", r)
		}
	}

	var rescanned atomic.Int32
	resumed := newTestService(t, ScannerConfig{Subnets: []string{"10.0.0.0/24"}, OutputFile: out, Resume: true},
		func(_ context.Context, ip string) *ScanResult {
			rescanned.Add(1)
			return &ScanResult{IP: ip, Latency: time.Millisecond}
		})
	if err := run(t, resumed, context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := int(rescanned.Load()), 256-len(saved); got != want {
		t.Fatalf("resume scanned %d IPs, want %d", got, want)
	}
	final, _ := LoadResults(out)
	if len(final) != 256 {
		t.Fatalf("final file has %d results, want 256", len(final))
	}
}

// A panicking probe is confined to its IP.
func TestScanPanicIsConfined(t *testing.T) {
	s := newTestService(t, ScannerConfig{Subnets: []string{"192.0.2.0/29"}}, func(_ context.Context, ip string) *ScanResult {
		if ip == "192.0.2.3" {
			panic("boom")
		}
		return &ScanResult{IP: ip, Latency: time.Millisecond}
	})
	if err := run(t, s, context.Background()); err != nil {
		t.Fatal(err)
	}
	res := s.Results()
	if len(res) != 8 {
		t.Fatalf("%d results, want 8", len(res))
	}
	for _, r := range res {
		if (r.IP == "192.0.2.3") != (r.Error != nil) {
			t.Errorf("%s: err %v", r.IP, r.Error)
		}
	}
}

// Nothing is dropped between workers and the consumer, even when the
// consumer is slower than the scan.
func TestProgressNotDropped(t *testing.T) {
	s := newTestService(t, ScannerConfig{Subnets: []string{"10.1.0.0/24"}, ThreadCount: 32}, func(_ context.Context, ip string) *ScanResult {
		return &ScanResult{IP: ip, Latency: time.Millisecond}
	})
	ch := make(chan *ScanResult)
	done := make(chan int)
	go func() {
		n := 0
		for range ch {
			n++
			time.Sleep(50 * time.Microsecond)
		}
		done <- n
	}()
	if err := s.Run(context.Background(), ch); err != nil {
		t.Fatal(err)
	}
	if n := <-done; n != 256 {
		t.Fatalf("consumer saw %d updates, want 256", n)
	}
}

func TestSaveResultsFormats(t *testing.T) {
	dir := t.TempDir()
	rs := []*ScanResult{{IP: "1.1.1.1", Latency: 20 * time.Millisecond, Colo: "FRA"}, {IP: "1.0.0.1", Error: errors.New("timeout")}}
	for _, format := range []string{"csv", "json", "jsonl"} {
		path := filepath.Join(dir, "r."+format)
		if err := SaveResults(path, format, rs); err != nil {
			t.Fatal(err)
		}
		back, err := LoadResults(path)
		if err != nil || len(back) != 2 {
			t.Fatalf("%s: %d results, %v", format, len(back), err)
		}
		if back[0].Colo != "FRA" || back[0].Latency != 20*time.Millisecond || back[1].Error == nil {
			t.Fatalf("%s round trip: %+v %+v", format, back[0], back[1])
		}
	}
	// A CSV from before the colo/speed_error columns still loads.
	legacy := filepath.Join(dir, "old.csv")
	_ = os.WriteFile(legacy, []byte("ip,latency_ms,download_mbps,upload_mbps,error\n1.1.1.1,15,0,0,\n"), 0644)
	back, err := LoadResults(legacy)
	if err != nil || len(back) != 1 || back[0].Latency != 15*time.Millisecond {
		t.Fatalf("legacy csv: %+v %v", back, err)
	}
}

func TestTraceField(t *testing.T) {
	body := []byte("fl=1\nh=cloudflare.com\nip=1.2.3.4\ncolo=AMS\nwarp=off\n")
	if got := traceField(body, "colo"); got != "AMS" {
		t.Fatalf("colo = %q", got)
	}
	if got := traceField(body, "missing"); got != "" {
		t.Fatalf("missing = %q", got)
	}
}

func TestSetAddressKeepsServerName(t *testing.T) {
	type proto struct{ Address, SNI, Host string }
	p := &proto{Address: "cdn.example.com"}
	if err := setAddress(p, "104.16.1.1"); err != nil {
		t.Fatal(err)
	}
	if p.Address != "104.16.1.1" || p.SNI != "cdn.example.com" || p.Host != "cdn.example.com" {
		t.Fatalf("got %+v", p)
	}
	explicit := &proto{Address: "cdn.example.com", SNI: "front.example.com", Host: "h.example.com"}
	_ = setAddress(explicit, "104.16.1.1")
	if explicit.SNI != "front.example.com" || explicit.Host != "h.example.com" {
		t.Fatalf("explicit names overwritten: %+v", explicit)
	}
	ip := &proto{Address: "1.2.3.4"}
	_ = setAddress(ip, "104.16.1.1")
	if ip.SNI != "" {
		t.Fatalf("an IP address became an SNI: %+v", ip)
	}
	if err := setAddress(struct{}{}, "x"); err == nil || !strings.Contains(err.Error(), "no 'Address'") {
		t.Fatalf("struct without an address field: %v", err)
	}
}

// A scanned config must send the SNI it sent before its address became a
// CDN IP. With an empty SNI, xray takes it from Host and sing-box from the
// address.
func TestSetAddressKeepsCoreSNI(t *testing.T) {
	const link = "vless://11111111-1111-1111-1111-111111111111@cdn.example.com:443?encryption=none&security=tls&type=ws&host=real.example.com&path=%2F#x"
	xc := core.CoreFactory(core.XrayCoreType, false, false)
	xp, err := xc.CreateProtocol(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := xp.Parse(); err != nil {
		t.Fatal(err)
	}
	serverName := func(p protocol.Protocol) string {
		t.Helper()
		out, err := p.(xray.Protocol).BuildOutboundDetourConfig(false)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`"serverName":"([^"]*)"`).FindSubmatch(b)
		if m == nil {
			return ""
		}
		return string(m[1])
	}
	before := serverName(xp)
	if err := setAddress(xp, "104.16.1.1"); err != nil {
		t.Fatal(err)
	}
	if after := serverName(xp); after != before || after != "real.example.com" {
		t.Fatalf("xray SNI %q became %q", before, after)
	}
	if g := xp.ConvertToGeneralConfig(); g.Host != "real.example.com" || g.Address != "104.16.1.1" {
		t.Fatalf("xray config = %+v", g)
	}

	sc := core.CoreFactory(core.SingboxCoreType, false, false)
	sp, err := sc.CreateProtocol(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Parse(); err != nil {
		t.Fatal(err)
	}
	if err := setAddress(sp, "104.16.1.1"); err != nil {
		t.Fatal(err)
	}
	if g := sp.ConvertToGeneralConfig(); g.SNI != "cdn.example.com" || g.Host != "real.example.com" {
		t.Fatalf("sing-box config = %+v", g)
	}
}

// Each scanned IP works on its own copy of the once-parsed config.
func TestCopyProtocolIsIndependent(t *testing.T) {
	c := core.NewAutomaticCore(false, false)
	for _, link := range []string{
		"vless://11111111-1111-1111-1111-111111111111@cdn.example.com:443?encryption=none&security=tls&type=ws&host=real.example.com#x",
		"hysteria2://pass@cdn.example.com:443?sni=real.example.com#h",
	} {
		base, err := c.CreateProtocol(link)
		if err != nil {
			t.Fatal(err)
		}
		if err := base.Parse(); err != nil {
			t.Fatal(err)
		}
		cp, err := copyProtocol(base)
		if err != nil {
			t.Fatal(err)
		}
		if err := setAddress(cp, "104.16.1.1"); err != nil {
			t.Fatal(err)
		}
		if got := base.ConvertToGeneralConfig().Address; got != "cdn.example.com" {
			t.Fatalf("%s: base address changed to %q", link, got)
		}
		if got := cp.ConvertToGeneralConfig().Address; got != "104.16.1.1" {
			t.Fatalf("%s: copy address = %q", link, got)
		}
	}
	if _, err := copyProtocol(nil); err == nil {
		t.Fatal("nil protocol copied")
	}
}

// An IPv6 range is fine with a cap or with sampling.
func TestNewScannerServiceBoundedIPv6(t *testing.T) {
	for name, cfg := range map[string]ScannerConfig{
		"default cap": {Subnets: []string{"2606:4700::/32"}, ThreadCount: 1},
		"sampled":     {Subnets: []string{"2606:4700::/32"}, ThreadCount: 1, MaxIPs: -1, SamplePerSubnet: 1},
		"small v6":    {Subnets: []string{"2606:4700::/120"}, ThreadCount: 1, MaxIPs: -1},
	} {
		if _, err := NewScannerService(cfg, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Stdout gets the results once at the end, never per checkpoint.
func TestStdoutIsWrittenOnce(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	s := newTestService(t, ScannerConfig{Subnets: []string{"192.0.2.0/28"}, ThreadCount: 1, OutputFile: "-", CheckpointInterval: 5 * time.Millisecond},
		func(ctx context.Context, ip string) *ScanResult {
			time.Sleep(10 * time.Millisecond)
			return &ScanResult{IP: ip, Latency: time.Millisecond}
		})
	done := make(chan string)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	runErr := run(t, s, context.Background())
	w.Close()
	os.Stdout = old
	out := <-done
	if runErr != nil {
		t.Fatal(runErr)
	}
	if n := strings.Count(out, "ip,latency_ms"); n != 1 {
		t.Fatalf("stdout got %d headers, want 1", n)
	}
	if n := strings.Count(out, "192.0.2."); n != 16 {
		t.Fatalf("stdout got %d rows, want 16", n)
	}
}

// A checkpoint returns at once (the write happens in the background), a
// second one is skipped while the first is still writing, and the final save
// waits for it.
func TestCheckpointRunsInBackground(t *testing.T) {
	out := filepath.Join(t.TempDir(), "r.csv")
	s := newTestService(t, ScannerConfig{Subnets: []string{"192.0.2.0/30"}, OutputFile: out}, nil)
	for i := 0; i < 50_000; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)
		s.results[ip] = &ScanResult{IP: ip, Latency: time.Duration(i) * time.Microsecond}
	}
	s.dirty = true
	start := time.Now()
	_ = s.checkpoint()
	_ = s.checkpoint() // skipped: the first is still running, or nothing is dirty
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("checkpoint blocked the caller for %v", elapsed)
	}
	if err := s.saveOutput(); err != nil {
		t.Fatal(err)
	}
	back, err := LoadResults(out)
	if err != nil || len(back) != 50_000 {
		t.Fatalf("saved %d results, %v", len(back), err)
	}
	if got := s.checkpointInterval(); got != s.config.CheckpointInterval {
		t.Errorf("interval at 50k results = %v, want the base %v", got, s.config.CheckpointInterval)
	}
	for i := 50_000; i < 600_000; i++ {
		ip := fmt.Sprintf("11.%d.%d.%d", i>>16&255, i>>8&255, i&255)
		s.results[ip] = &ScanResult{IP: ip}
	}
	if got := s.checkpointInterval(); got <= s.config.CheckpointInterval {
		t.Errorf("interval at 600k results = %v, want it scaled up", got)
	}
}
