package http

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gocarina/gocsv"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// probeResultFor grades probeLink through the real examiner, so what gets
// persisted below is what the examiner actually produces.
func probeResultFor(t *testing.T, res protocol.ProbeResult, probeErr error) Result {
	t.Helper()
	p := &stubProber{res: res, err: probeErr}
	e := newProbeExaminer(t, p, nil)
	r, err := e.ExamineConfig(context.Background(), probeLink)
	if probeErr == nil && err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSaveProbeResultToDatabase(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "probe-results.db")); err != nil {
		t.Fatalf("temporary database: %v", err)
	}
	defer func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	}()

	passed := probeResultFor(t, protocol.ProbeResult{
		ConnectTime: 20 * time.Millisecond,
		TTFB:        50 * time.Millisecond,
		Delay:       80 * time.Millisecond,
		Detail:      "faketls, dc2 resPQ ok",
	}, nil)
	failed := probeResultFor(t, protocol.ProbeResult{}, errors.New("read resPQ: EOF (proxy closed connection; wrong secret?)"))

	runID, err := database.CreateHttpTestRun("{}", 2)
	if err != nil {
		t.Fatal(err)
	}
	rp := NewResultProcessor(ResultProcessorOptions{RunID: runID})
	if err := rp.SaveResults(ConfigResults{&passed, &failed}); err != nil {
		t.Fatal(err)
	}

	rows, err := database.GetHttpTestHistory(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("saved %d rows, want 2", len(rows))
	}
	byStatus := map[string]database.HttpTestResult{}
	for _, row := range rows {
		byStatus[row.Status] = row
	}
	ok, found := byStatus["passed"]
	if !found {
		t.Fatalf("no passed row: %+v", rows)
	}
	if ok.ConfigLink != probeLink || ok.DelayMs != 80 || ok.TTFBMs != 50 || ok.ConnectTimeMs != 20 {
		t.Errorf("passed row = %+v", ok)
	}
	if ok.Reason.String != "faketls, dc2 resPQ ok" {
		t.Errorf("reason = %q", ok.Reason.String)
	}
	if ok.DownloadMbps != 0 || ok.UploadMbps != 0 || ok.IPAddress.Valid || ok.IPLocation.Valid {
		t.Errorf("HTTP-only columns must stay empty: %+v", ok)
	}
	bad, found := byStatus["failed"]
	if !found {
		t.Fatalf("no failed row: %+v", rows)
	}
	if bad.DelayMs != -1 || !strings.Contains(bad.Reason.String, "proxy closed connection") {
		t.Errorf("failed row = %+v", bad)
	}
}

func TestProbeResultSerialization(t *testing.T) {
	passed := probeResultFor(t, protocol.ProbeResult{
		ConnectTime: 20 * time.Millisecond,
		TTFB:        50 * time.Millisecond,
		Delay:       80 * time.Millisecond,
		Detail:      "faketls, dc2 resPQ ok",
	}, nil)

	blob, err := json.Marshal(passed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{
		"status":      "passed",
		"reason":      "faketls, dc2 resPQ ok",
		"delay":       float64(80),
		"ttfb":        float64(50),
		"connectTime": float64(20),
		"code":        float64(-1),
		"download":    float64(0),
		"upload":      float64(0),
		"ip":          "null",
		"location":    "null",
		"tls":         "faketls",
	} {
		if decoded[key] != want {
			t.Errorf("json %s = %v, want %v", key, decoded[key], want)
		}
	}
	proto, _ := decoded["protocol"].(map[string]any)
	if proto["protocol"] != "mtproto" {
		t.Errorf("json protocol = %v", decoded["protocol"])
	}

	// CSV uses the same struct tags as the file writer.
	dir := t.TempDir()
	out := filepath.Join(dir, "results.csv")
	rp := NewResultProcessor(ResultProcessorOptions{OutputFile: out, OutputType: "csv"})
	if err := rp.saveCSVResults(ConfigResults{&passed}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var back []*Result
	if err := gocsv.UnmarshalBytes(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 1 {
		t.Fatalf("csv round trip produced %d rows", len(back))
	}
	got := back[0]
	if got.Status != "passed" || got.Reason != "faketls, dc2 resPQ ok" || got.Delay != 80 || got.TTFB != 50 || got.ConnectTime != 20 {
		t.Errorf("csv row = %+v", got)
	}
	if got.HTTPCode != -1 || got.DownloadSpeed != 0 || got.UploadSpeed != 0 || got.RealIPAddr != "null" || got.IpAddrLoc != "null" {
		t.Errorf("csv HTTP-only columns = %+v", got)
	}
}

// legacyCSVHeader is the exact schema shipped before RTT sampling.
const legacyCSVHeader = "link,status,reason,tls,ip,delay,code,download,upload,location,ttfb,connect_time,success,total,endpoints"

// sampledProbeResult grades a three-sample probe through the real examiner.
func sampledProbeResult(t *testing.T) Result {
	t.Helper()
	p := &stubProber{res: protocol.ProbeResult{
		ConnectTime: 20 * time.Millisecond,
		TTFB:        90 * time.Millisecond,
		Delay:       180 * time.Millisecond,
		Detail:      "faketls, dc2 resPQ ok, 3/3 samples",
		RTTs:        rttsOf(100, 200, 300),
	}}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.MaxDelay = 250; e.ProbeSamples = 3 })
	r, err := e.ExamineConfig(context.Background(), probeLink)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const sampledReason = "faketls, dc2 resPQ ok, 3/3 samples; rtt min/avg/max/jitter 100/200/300/82 ms"

func TestSampledProbeResultSerialization(t *testing.T) {
	passed := sampledProbeResult(t)

	blob, err := json.Marshal(passed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{
		"reason":     sampledReason,
		"delay":      float64(180),
		"rttMin":     float64(100),
		"rttAvg":     float64(200),
		"rttMax":     float64(300),
		"jitter":     float64(82),
		"rttSamples": float64(3),
	} {
		if decoded[key] != want {
			t.Errorf("json %s = %v, want %v", key, decoded[key], want)
		}
	}

	out := filepath.Join(t.TempDir(), "results.csv")
	rp := NewResultProcessor(ResultProcessorOptions{OutputFile: out, OutputType: "csv"})
	if err := rp.saveCSVResults(ConfigResults{&passed}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var back []*Result
	if err := gocsv.UnmarshalBytes(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 1 {
		t.Fatalf("csv round trip produced %d rows", len(back))
	}
	got := back[0]
	if got.RTTMin != 100 || got.RTTAvg != 200 || got.RTTMax != 300 || got.Jitter != 82 || got.RTTSamples != 3 {
		t.Errorf("csv rtt columns = %d/%d/%d/%d over %d", got.RTTMin, got.RTTAvg, got.RTTMax, got.Jitter, got.RTTSamples)
	}
	if got.Reason != sampledReason || got.Delay != 180 {
		t.Errorf("csv row = %+v", got)
	}
}

func TestSaveSampledProbeResultToDatabase(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "probe-results.db")); err != nil {
		t.Fatalf("temporary database: %v", err)
	}
	defer func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	}()

	passed := sampledProbeResult(t)
	runID, err := database.CreateHttpTestRun("{}", 1)
	if err != nil {
		t.Fatal(err)
	}
	rp := NewResultProcessor(ResultProcessorOptions{RunID: runID})
	if err := rp.SaveResults(ConfigResults{&passed}); err != nil {
		t.Fatal(err)
	}

	rows, err := database.GetHttpTestHistory(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("saved %d rows, want 1", len(rows))
	}
	if rows[0].Reason.String != sampledReason {
		t.Errorf("reason = %q, want %q", rows[0].Reason.String, sampledReason)
	}
	if rows[0].DelayMs != 180 {
		t.Errorf("delay = %d, want the first-exchange delay", rows[0].DelayMs)
	}
}

// A fresh file gets the current schema, written once across batches.
func TestAppendResultsToCSVNewFile(t *testing.T) {
	passed := sampledProbeResult(t)
	path := filepath.Join(t.TempDir(), "history.csv")

	for i := 0; i < 2; i++ {
		if err := AppendResultsToCSV(path, []*Result{&passed}); err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("file has %d lines, want a header and two rows:\n%s", len(lines), raw)
	}
	if !strings.HasPrefix(lines[0], legacyCSVHeader+",rtt_min,rtt_avg,rtt_max,jitter,rtt_samples") {
		t.Errorf("header = %q", lines[0])
	}
	var back []*Result
	if err := gocsv.UnmarshalBytes(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 {
		t.Fatalf("read back %d rows, want 2", len(back))
	}
	for i, r := range back {
		if r.RTTMax != 300 || r.RTTSamples != 3 || r.Reason != sampledReason {
			t.Errorf("row %d = %+v", i, r)
		}
	}
}

// A file from before RTT sampling keeps its own columns. The statistics still
// reach the user through the reason column.
func TestAppendResultsToCSVLegacyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.csv")
	old := legacyCSVHeader + "\n" +
		"vless://old,passed,,tls,1.2.3.4,120,200,0,0,DE,60,30,1,1,\n"
	if err := os.WriteFile(path, []byte(old), 0644); err != nil {
		t.Fatal(err)
	}

	passed := sampledProbeResult(t)
	for i := 0; i < 2; i++ {
		if err := AppendResultsToCSV(path, []*Result{&passed}); err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if lines[0] != legacyCSVHeader {
		t.Fatalf("header changed to %q", lines[0])
	}
	if len(lines) != 4 {
		t.Fatalf("file has %d lines, want a header and three rows:\n%s", len(lines), raw)
	}

	var back []*Result
	if err := gocsv.UnmarshalBytes(raw, &back); err != nil {
		t.Fatalf("legacy history must stay readable: %v", err)
	}
	if len(back) != 3 {
		t.Fatalf("read back %d rows, want 3", len(back))
	}
	if back[0].ConfigLink != "vless://old" || back[0].Delay != 120 || back[0].IpAddrLoc != "DE" {
		t.Errorf("the original row changed: %+v", back[0])
	}
	for i, r := range back {
		if r.RTTMin != 0 || r.RTTAvg != 0 || r.RTTMax != 0 || r.Jitter != 0 || r.RTTSamples != 0 {
			t.Errorf("row %d has RTT columns the legacy schema cannot hold: %+v", i, r)
		}
	}
	for _, r := range back[1:] {
		if r.Reason != sampledReason || r.Delay != 180 {
			t.Errorf("appended row = %+v", r)
		}
	}
}

func TestAppendResultsToCSVRejectsUnknownHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.csv")
	foreign := "when,what,how\n2026-01-01,something,else\n"
	if err := os.WriteFile(path, []byte(foreign), 0644); err != nil {
		t.Fatal(err)
	}

	passed := sampledProbeResult(t)
	err := AppendResultsToCSV(path, []*Result{&passed})
	if err == nil {
		t.Fatal("appending to a foreign CSV must fail")
	}
	if !strings.Contains(err.Error(), "does not match this version's result columns") {
		t.Errorf("err = %v, want an actionable message", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != foreign {
		t.Errorf("the rejected file was modified:\n%s", raw)
	}
}

// The sorted rewrite runs after streaming, so it must keep the same schema.
func TestRewriteFileSortedKeepsLegacySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.csv")
	if err := os.WriteFile(path, []byte(legacyCSVHeader+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	passed := sampledProbeResult(t)
	if err := AppendResultsToCSV(path, []*Result{&passed}); err != nil {
		t.Fatal(err)
	}
	rp := NewResultProcessor(ResultProcessorOptions{OutputFile: path, OutputType: "csv"})
	rp.RewriteFileSorted(ConfigResults{&passed})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if lines[0] != legacyCSVHeader {
		t.Fatalf("sorting changed the header to %q", lines[0])
	}
	var back []*Result
	if err := gocsv.UnmarshalBytes(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 1 || back[0].Reason != sampledReason {
		t.Fatalf("rows = %+v", back)
	}
}

func TestRewriteFileSortedUsesCurrentSchemaOnNewFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.csv")
	passed := sampledProbeResult(t)
	rp := NewResultProcessor(ResultProcessorOptions{OutputFile: path, OutputType: "csv"})
	rp.RewriteFileSorted(ConfigResults{&passed})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), legacyCSVHeader+",rtt_min,rtt_avg,rtt_max,jitter,rtt_samples") {
		t.Fatalf("header = %q", strings.SplitN(string(raw), "\n", 2)[0])
	}
	var back []*Result
	if err := gocsv.UnmarshalBytes(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 1 || back[0].RTTMax != 300 || back[0].RTTSamples != 3 {
		t.Fatalf("rows = %+v", back)
	}
}

// CLI and web runs store the same rows; canceled tests store none.
func TestResultsToDB(t *testing.T) {
	passed := &Result{ConfigLink: "vless://a", Status: StatusPassed, Delay: 120, DownloadSpeed: 5, RealIPAddr: "null", IpAddrLoc: "DE", TTFB: 40}
	failed := &Result{ConfigLink: "vless://b", Status: StatusFailed, Delay: 900, Reason: "diagnosis: tcp-timeout: x", FailureKind: FailTCPTimeout}
	canceled := &Result{ConfigLink: "vless://c", Status: StatusCanceled, FailureKind: FailCanceled}
	rows := ResultsToDB(7, []*Result{passed, failed, canceled})
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	p, f := rows[0], rows[1]
	if p.RunID != 7 || p.DelayMs != 120 || p.DownloadMbps != 5 || p.IPAddress.Valid || p.IPLocation.String != "DE" || p.TTFBMs != 40 {
		t.Errorf("passed row = %+v", p)
	}
	if f.DelayMs != -1 || f.FailureKind.String != FailTCPTimeout || f.Reason.String != failed.Reason || f.IPLocation.Valid {
		t.Errorf("failed row = %+v", f)
	}
}
