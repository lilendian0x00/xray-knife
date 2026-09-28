package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/dpi"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy"
)

const dpiTestLink = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=tls&sni=example.com&type=tcp#t"

func TestBuildDpiOptions(t *testing.T) {
	opts, err := buildDpiOptions(dpiStartRequest{Link: " " + dpiTestLink + " ", Mode: "FULL", Specs: []string{"tlshello,100-200,10-20", " "}, SNIs: []string{"a.example"}, TimeoutMs: 5000})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Link != dpiTestLink || opts.Mode != dpi.ModeFull || len(opts.Specs) != 1 || opts.Timeout != 5*time.Second || len(opts.SNIs) != 1 {
		t.Fatalf("opts = %+v", opts)
	}
	for name, req := range map[string]dpiStartRequest{
		"no link":      {},
		"bad link":     {Link: "nonsense"},
		"mtproto":      {Link: "tg://proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff"},
		"bad mode":     {Link: dpiTestLink, Mode: "turbo"},
		"bad core":     {Link: dpiTestLink, Core: "v2ray"},
		"bad spec":     {Link: dpiTestLink, Specs: []string{"tlshello"}},
		"bad sni":      {Link: dpiTestLink, SNIs: []string{"a b"}},
		"timeout":      {Link: dpiTestLink, TimeoutMs: 120000},
		"attempts":     {Link: dpiTestLink, Attempts: 99},
		"threads":      {Link: dpiTestLink, Threads: -1},
		"stop after":   {Link: dpiTestLink, StopAfter: -1},
		"bad test url": {Link: dpiTestLink, TestURL: "ftp://x"},
	} {
		if _, err := buildDpiOptions(req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDpiRunnerEvents(t *testing.T) {
	hub := newHub()
	c, _, _, _ := hub.Subscribe(0)
	defer hub.Unsubscribe(c)
	d := NewDpiRunner(quietLogger(), hub)
	d.runFn = func(ctx context.Context, opts dpi.Options) (*dpi.Report, error) {
		profiles := []dpi.Profile{{Name: "baseline"}, {Name: "tlshello 100-200 / 10-20ms", Spec: "tlshello,100-200,10-20"}}
		opts.OnStart(profiles)
		opts.OnResult(dpi.Result{Index: 0, Profile: profiles[0], Status: dpi.StatusFail})
		opts.OnResult(dpi.Result{Index: 1, Profile: profiles[1], Status: dpi.StatusPass, MedianDelay: 300})
		best := dpi.Result{Index: 1, Profile: profiles[1], Status: dpi.StatusPass}
		return &dpi.Report{Link: opts.Link, Verdict: dpi.VerdictFragmentHelps, Best: &best, Duration: time.Second}, nil
	}
	opts, err := buildDpiOptions(dpiStartRequest{Link: dpiTestLink})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(opts); err != nil {
		t.Fatal(err)
	}
	waitState(t, d, StateFinished)
	report, results := d.Report()
	if report == nil || report.Verdict != dpi.VerdictFragmentHelps || len(results) != 2 {
		t.Fatalf("report=%+v results=%d", report, len(results))
	}

	var types []string
	var lastStatus map[string]any
	timeout := time.After(2 * time.Second)
	for len(types) < 7 {
		select {
		case ev := <-c.send:
			types = append(types, ev.Type)
			if ev.Type == "dpi_status" {
				var env struct {
					Data map[string]any `json:"data"`
				}
				_ = json.Unmarshal(ev.Data, &env)
				lastStatus = env.Data
			}
		case <-timeout:
			t.Fatalf("events = %v", types)
		}
	}
	want := []string{"dpi_status", "dpi_profiles", "dpi_status", "dpi_result", "dpi_result", "dpi_report", "dpi_status"}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("events = %v, want %v", types, want)
		}
	}
	if lastStatus["state"] != "finished" || lastStatus["total"].(float64) != 2 || lastStatus["done"].(float64) != 2 {
		t.Fatalf("final dpi_status = %v", lastStatus)
	}
}

func TestDpiRunnerStopAndError(t *testing.T) {
	d := NewDpiRunner(quietLogger(), newHub())
	var started sync.WaitGroup
	started.Add(1)
	d.runFn = func(ctx context.Context, opts dpi.Options) (*dpi.Report, error) {
		started.Done()
		<-ctx.Done()
		return &dpi.Report{Verdict: dpi.VerdictCanceled}, nil
	}
	opts, _ := buildDpiOptions(dpiStartRequest{Link: dpiTestLink})
	if err := d.Start(opts); err != nil {
		t.Fatal(err)
	}
	started.Wait()
	if err := d.Start(opts); err == nil {
		t.Fatal("second start while running accepted")
	}
	if err := d.Stop(); err != nil {
		t.Fatal(err)
	}
	if d.Status() != StateIdle {
		t.Fatalf("after stop: %s", d.Status())
	}

	d.runFn = func(ctx context.Context, opts dpi.Options) (*dpi.Report, error) {
		return nil, errors.New("udp protocol")
	}
	if err := d.Start(opts); err != nil {
		t.Fatal(err)
	}
	waitState(t, d, StateError)
	if d.Snapshot().Error != "udp protocol" {
		t.Fatalf("error = %q", d.Snapshot().Error)
	}
}

func TestDpiAPI(t *testing.T) {
	_, ts := newTestServer(t, Options{})
	_, body := login(t, ts, "admin", "s3cret-pass")
	token := body["token"].(string)
	resp, out := doJSON(t, "POST", ts.URL+"/api/v1/dpi/start", token, `{"link":"garbage"}`)
	if resp.StatusCode != http.StatusBadRequest || out["code"] != codeInvalidRequest {
		t.Fatalf("bad link: %d %v", resp.StatusCode, out)
	}
	resp, out = doJSON(t, "POST", ts.URL+"/api/v1/dpi/stop", token, "")
	if resp.StatusCode != http.StatusConflict || out["code"] != codeNotRunning {
		t.Fatalf("stop idle: %d %v", resp.StatusCode, out)
	}
	resp, out = doJSON(t, "GET", ts.URL+"/api/v1/dpi/status", token, "")
	if resp.StatusCode != 200 || out["status"] != "idle" {
		t.Fatalf("status: %d %v", resp.StatusCode, out)
	}
	resp, out = doJSON(t, "GET", ts.URL+"/api/v1/dpi/defaults", token, "")
	if resp.StatusCode != 200 || out["modes"] == nil {
		t.Fatalf("defaults: %d %v", resp.StatusCode, out)
	}
	resp, out = doJSON(t, "POST", ts.URL+"/api/v1/proxy/deadman/confirm", token, "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("deadman confirm while stopped: %d %v", resp.StatusCode, out)
	}
}

func TestProxyRestoreEndpoint(t *testing.T) {
	calls := 0
	prev := restoreFn
	restoreFn = func(force bool) proxy.RestoreReport {
		calls++
		return proxy.RestoreReport{Removed: []string{"kill switch rules"}}
	}
	t.Cleanup(func() { restoreFn = prev })

	_, ts := newTestServer(t, Options{})
	_, body := login(t, ts, "admin", "s3cret-pass")
	resp, out := doJSON(t, "POST", ts.URL+"/api/v1/proxy/restore", body["token"].(string), `{"force":true}`)
	if resp.StatusCode != http.StatusForbidden || out["code"] != "host_modes_disabled" || calls != 0 {
		t.Fatalf("restore without host modes: %d %v calls=%d", resp.StatusCode, out, calls)
	}

	_, ts2 := newTestServer(t, Options{AllowHostModes: true})
	_, body = login(t, ts2, "admin", "s3cret-pass")
	resp, out = doJSON(t, "POST", ts2.URL+"/api/v1/proxy/restore", body["token"].(string), "")
	if resp.StatusCode != 200 || calls != 1 || len(out["removed"].([]any)) != 1 || out["clean"] != false {
		t.Fatalf("restore: %d %v calls=%d", resp.StatusCode, out, calls)
	}
}
