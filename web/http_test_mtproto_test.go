package web

import (
	"io"
	"log"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
)

// Drives the web HTTP-testing flow with an MTProto link aimed at a closed port
// and checks the row the frontend ends up rendering.
func TestWebHttpTestMTProtoLink(t *testing.T) {
	// Never touch the user's real history.
	prevHistory := httpTesterHistoryFile
	httpTesterHistoryFile = filepath.Join(t.TempDir(), "http-results.csv")
	t.Cleanup(func() { httpTesterHistoryFile = prevHistory })

	// A just-released port, so the probe fails at the dial.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()

	link := "tg://proxy?server=127.0.0.1&port=" + port + "&secret=00112233445566778899aabbccddeeff"

	hub := newHub()
	go hub.run()
	runner := NewHttpTestRunner(log.New(io.Discard, "", 0), hub)

	req := pkghttp.HttpTestRequest{
		Links:       []string{link},
		ThreadCount: 1,
		Options: pkghttp.Options{
			MaxDelay: 3000,
			Timeout:  3000,
			Core:     "auto",
		},
	}
	if err := runner.Start(req); err != nil {
		t.Fatal(err)
	}
	// run() ends back at idle, so wait for that rather than the transient
	// "finished" state.
	deadline := time.Now().Add(30 * time.Second)
	for {
		state := runner.Status()
		if state == StateError {
			t.Fatal("http test runner reported an error state")
		}
		if state == StateIdle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("http test did not finish; state = %s", state)
		}
		time.Sleep(20 * time.Millisecond)
	}

	var results []*pkghttp.Result
	if err := loadResultsFromCSV(httpTesterHistoryFile, &results); err != nil {
		t.Fatalf("reading the history the UI loads: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("history has %d rows, want 1", len(results))
	}
	r := results[0]
	if r.ConfigLink != link {
		t.Errorf("link = %q", r.ConfigLink)
	}
	if r.Status != "failed" {
		t.Errorf("status = %q, want failed (a dial failure is not 'broken')", r.Status)
	}
	if !strings.HasPrefix(r.Reason, "dial 127.0.0.1:"+port) {
		t.Errorf("reason = %q, want a dial failure", r.Reason)
	}
	if r.Delay != pkghttp.FailedDelay || r.TTFB != 0 || r.ConnectTime != 0 {
		t.Errorf("timings = delay %d ttfb %d connect %d", r.Delay, r.TTFB, r.ConnectTime)
	}
	if r.DownloadSpeed != 0 || r.UploadSpeed != 0 {
		t.Errorf("speeds must stay unmeasured: %v/%v", r.DownloadSpeed, r.UploadSpeed)
	}
	if r.RealIPAddr != "null" || r.IpAddrLoc != "null" {
		t.Errorf("ip fields = %q/%q, want null", r.RealIPAddr, r.IpAddrLoc)
	}
}
