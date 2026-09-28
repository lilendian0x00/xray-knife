package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// scriptCore is a stubCore whose protocol creation and client construction
// can be scripted per link.
type scriptCore struct {
	stubCore
	create func(link string) (protocol.Protocol, error)
	client func(ctx context.Context) (*http.Client, protocol.Instance, error)
}

func (c scriptCore) CreateProtocol(link string) (protocol.Protocol, error) {
	if c.create != nil {
		return c.create(link)
	}
	return stubProtocol{}, nil
}

func (c scriptCore) MakeHttpClient(ctx context.Context, p protocol.Protocol, d time.Duration) (*http.Client, protocol.Instance, error) {
	if c.client != nil {
		return c.client(ctx)
	}
	return c.stubCore.MakeHttpClient(ctx, p, d)
}

func collect(tm *TestManager, ctx context.Context, links []string) []*Result {
	ch := make(chan *Result, len(links))
	tm.RunTests(ctx, links, ch, nil)
	close(ch)
	var out []*Result
	for r := range ch {
		out = append(out, r)
	}
	return out
}

// One config whose parser panics must not take the rest of the batch with it.
func TestRunTestsSurvivesPanickingConfig(t *testing.T) {
	srv := gradeTestServer(t)
	e := newGradeExaminer(srv.Client(), []EndpointCheck{{URL: srv.URL + "/ok"}}, 1)
	e.Core = scriptCore{
		stubCore: stubCore{client: srv.Client()},
		create: func(link string) (protocol.Protocol, error) {
			if link == "panic://boom" {
				panic("parser exploded")
			}
			return stubProtocol{}, nil
		},
	}
	links := make([]string, 0, 21)
	for i := 0; i < 20; i++ {
		links = append(links, "stub://ok"+string(rune('a'+i)))
	}
	links = append(links, "panic://boom")

	results := collect(NewTestManager(e, 4, false, log.New(io.Discard, "", 0)), context.Background(), links)
	if len(results) != 21 {
		t.Fatalf("got %d results, want 21 (a panic must not cancel the batch)", len(results))
	}
	var broken, passed int
	for _, r := range results {
		switch r.Status {
		case StatusBroken:
			broken++
			if !strings.Contains(r.Reason, "parser exploded") {
				t.Errorf("broken reason = %q, want the panic message", r.Reason)
			}
		case StatusPassed:
			passed++
		}
	}
	if broken != 1 || passed != 20 {
		t.Fatalf("broken=%d passed=%d, want 1/20", broken, passed)
	}
}

// Tests interrupted by cancellation are dropped, never reported as failures.
func TestRunTestsDropsCanceledTests(t *testing.T) {
	var started sync.WaitGroup
	started.Add(8)
	e := newGradeExaminer(nil, nil, 1)
	e.Core = scriptCore{client: func(ctx context.Context) (*http.Client, protocol.Instance, error) {
		started.Done()
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}}
	links := make([]string, 8)
	for i := range links {
		links[i] = "stub://slow" + string(rune('a'+i))
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { started.Wait(); cancel() }()

	results := collect(NewTestManager(e, 8, false, log.New(io.Discard, "", 0)), ctx, links)
	for _, r := range results {
		t.Errorf("canceled test reported as %q: %+v", r.Status, r)
	}
}

func TestNewTestManagerZeroThreadsUsesDefault(t *testing.T) {
	if tm := NewTestManager(nil, 0, false, nil); tm.threadCount != DefaultThreadCount {
		t.Fatalf("threadCount = %d, want %d (0 is unlimited in pond)", tm.threadCount, DefaultThreadCount)
	}
}

func TestBetterResultPrefersSemiPassedOverFailed(t *testing.T) {
	failed := Result{Status: StatusFailed, Delay: -1}
	semi := Result{Status: StatusSemiPassed, Delay: 300}
	passed := Result{Status: StatusPassed, Delay: 900}
	fasterPassed := Result{Status: StatusPassed, Delay: 100}
	cases := []struct {
		cand, best Result
		want       bool
	}{
		{semi, failed, true},
		{failed, semi, false},
		{passed, semi, true},
		{fasterPassed, passed, true},
		{passed, fasterPassed, false},
		{Result{Status: StatusTimeout}, failed, true},
		{failed, Result{Status: StatusFailed, Reason: "first"}, false},
	}
	for i, tc := range cases {
		if got := betterResult(tc.cand, tc.best); got != tc.want {
			t.Errorf("case %d: betterResult(%s, %s) = %v, want %v", i, tc.cand.Status, tc.best.Status, got, tc.want)
		}
	}
}

// A lookup failure on a config that already reached the test URL is a note,
// not a demotion (the txt output keeps only passed configs).
func TestFailedIPLookupDoesNotDemote(t *testing.T) {
	srv := gradeTestServer(t)
	e := newGradeExaminer(srv.Client(), []EndpointCheck{{URL: srv.URL + "/ok"}}, 1)
	e.DoIPInfo = true
	// The dedicated lookup goes to cloudflare.com, which this client cannot
	// reach: its transport only knows the local test server.
	e.Core = stubCore{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "cloudflare.com" {
			return nil, errors.New("lookup blocked")
		}
		return srv.Client().Transport.RoundTrip(r)
	})}}
	r, err := e.ExamineConfig(context.Background(), "stub://config")
	if err != nil || r.Status != StatusPassed {
		t.Fatalf("status = %q, err = %v, want passed", r.Status, err)
	}
	if !strings.Contains(r.Reason, "ip_info_failed") {
		t.Errorf("reason = %q, want the lookup failure noted", r.Reason)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestParseTraceBodyColoAndWarp(t *testing.T) {
	var r Result
	parseTraceBody([]byte("fl=1\nip=1.2.3.4\nloc=DE\ncolo=FRA\nwarp=off\n"), &r)
	if r.RealIPAddr != "1.2.3.4" || r.IpAddrLoc != "DE" || r.Colo != "FRA" || r.Warp != "off" {
		t.Fatalf("parsed %+v", r)
	}
}

// A CSV written before colo/warp existed keeps its header when appended to.
func TestAppendResultsToCSVPreColoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.csv")
	header := legacyCSVHeader + ",rtt_min,rtt_avg,rtt_max,jitter,rtt_samples"
	if err := os.WriteFile(path, []byte(header+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	passed := sampledProbeResult(t)
	passed.Colo = "FRA"
	if err := AppendResultsToCSV(path, []*Result{&passed}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if first := strings.SplitN(string(raw), "\n", 2)[0]; first != header {
		t.Fatalf("header changed to %q", first)
	}
	if strings.Contains(string(raw), "FRA") {
		t.Error("colo leaked into a file without the column")
	}
}

func TestJSONWriters(t *testing.T) {
	dir := t.TempDir()
	passed := sampledProbeResult(t)
	res := []*Result{&passed, {ConfigLink: "vless://dead", Status: StatusFailed, Delay: -1}}

	jsonPath := filepath.Join(dir, "out.json")
	if err := WriteResultsJSON(jsonPath, res); err != nil {
		t.Fatal(err)
	}
	var back []map[string]any
	raw, _ := os.ReadFile(jsonPath)
	if err := json.Unmarshal(raw, &back); err != nil || len(back) != 2 || back[1]["link"] != "vless://dead" {
		t.Fatalf("json array = %s, err %v", raw, err)
	}
	if _, ok := back[0]["rttSamples"]; !ok {
		t.Error("RTT fields missing from JSON output")
	}

	jsonlPath := filepath.Join(dir, "out.jsonl")
	for i := 0; i < 2; i++ {
		if err := AppendResultsToJSONL(jsonlPath, res); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ = os.ReadFile(jsonlPath)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 4 {
		t.Fatalf("jsonl has %d lines, want 4", len(lines))
	}
	for _, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Fatalf("invalid jsonl line %q", l)
		}
	}
}

func TestWriteFileAtomicReplacesAndKeepsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "valid.txt")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	fi, _ := os.Stat(path)
	if string(raw) != "new" || fi.Mode().Perm() != 0600 {
		t.Fatalf("content %q mode %v", raw, fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

func TestNewSpeedTester(t *testing.T) {
	cf, err := NewSpeedTester("https://speed.example.com")
	if err != nil || !cf.CanUpload() || cf.SNI != "speed.example.com" {
		t.Fatalf("origin: %+v, %v", cf, err)
	}
	if got := cf.MakeDownloadHTTPRequest(false, 5).URL.String(); got != "https://speed.example.com/__down?bytes=5" {
		t.Errorf("download url = %s", got)
	}
	plain, err := NewSpeedTester("http://mirror.example.com/100MB.bin")
	if err != nil || plain.CanUpload() {
		t.Fatalf("plain: %+v, %v", plain, err)
	}
	if got := plain.MakeDownloadHTTPRequest(false, 5).URL.String(); got != "http://mirror.example.com/100MB.bin" {
		t.Errorf("plain download url = %s", got)
	}
	for _, bad := range []string{"", "not a url", "ftp://host/file", "http://host"} {
		if _, err := NewSpeedTester(bad); err == nil {
			t.Errorf("NewSpeedTester(%q) accepted", bad)
		}
	}
}

// A plain download URL is read only up to the requested amount, and upload
// is skipped with a note instead of failing.
func TestRunSpeedtestPlainDownloadURL(t *testing.T) {
	srv := speedtestServer(t, 0, http.StatusOK, nil)
	e := &Examiner{DoSpeedtest: true, SpeedtestKbAmount: 10, SpeedtestTimeout: 10}
	st, err := NewSpeedTester(srv.URL + "/__down")
	if err != nil {
		t.Fatal(err)
	}
	e.SpeedTester = st
	r := Result{Status: StatusPassed}
	e.runSpeedtest(context.Background(), latencyBudgetClient(srv, 5*time.Second), &r)
	if r.DownloadSpeed <= 0 {
		t.Errorf("download = %v, reason %q", r.DownloadSpeed, r.Reason)
	}
	if r.UploadSpeed != 0 || !strings.Contains(r.Reason, "speedtest_upload_skipped") {
		t.Errorf("upload = %v, reason %q", r.UploadSpeed, r.Reason)
	}
}

func TestNewExaminerFragment(t *testing.T) {
	e, err := NewExaminer(Options{FragmentSpec: "tlshello,100-200,10-20", Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if e.Fragment.String() != "tlshello,100-200,10-20" {
		t.Fatalf("fragment = %q", e.Fragment.String())
	}
	if _, err := NewExaminer(Options{FragmentSpec: "tlshello,0,1"}); err == nil {
		t.Fatal("invalid fragment accepted")
	}
}

// A body read that fails mid-way is an error, not a silently short latency.
func TestMeasureDelayDetailedBoundsBody(t *testing.T) {
	srv := gradeTestServer(t)
	res, err := MeasureDelayDetailed(context.Background(), srv.Client(), srv.URL+"/ok", "GET")
	if err != nil || res.Code != 200 {
		t.Fatalf("res %+v err %v", res, err)
	}
}
