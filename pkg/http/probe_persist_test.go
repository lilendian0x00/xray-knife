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
