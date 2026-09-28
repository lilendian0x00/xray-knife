package web

import (
	"encoding/json"
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
	// A completed run stays "finished" until the next start.
	deadline := time.Now().Add(30 * time.Second)
	for {
		state := runner.Status()
		if state == StateError {
			t.Fatal("http test runner reported an error state")
		}
		if state == StateFinished || state == StateIdle {
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

// The UI posts examiner options flat, so probeSamples is a top-level property.
func TestHttpTestRequestCarriesProbeSamples(t *testing.T) {
	body := `{"links":["tg://proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff"],"threadCount":1,"maxDelay":3000,"timeout":3000,"probeSamples":5}`

	var decoded httpTestRequestBody
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ProbeSamples != 5 {
		t.Fatalf("probeSamples = %d, want 5", decoded.ProbeSamples)
	}

	// The runner builds its examiner straight from these options.
	decoded.Options.Logger = log.New(io.Discard, "", 0)
	examiner, err := pkghttp.NewExaminer(decoded.Options)
	if err != nil {
		t.Fatal(err)
	}
	if examiner.ProbeSamples != 5 {
		t.Errorf("examiner ProbeSamples = %d, want 5", examiner.ProbeSamples)
	}
}

// An out-of-range count decodes fine; it is rejected when the examiner is
// built, which Start now does synchronously (see TestHttpTestStartRejects*).
func TestHttpTestRequestRangeFailsInTheRunner(t *testing.T) {
	var decoded httpTestRequestBody
	if err := json.Unmarshal([]byte(`{"links":[],"probeSamples":33}`), &decoded); err != nil {
		t.Fatalf("the handler must not reject this synchronously: %v", err)
	}
	decoded.Options.Logger = log.New(io.Discard, "", 0)
	if _, err := pkghttp.NewExaminer(decoded.Options); err == nil {
		t.Fatal("the runner must reject 33 samples")
	}
}

// What the websocket pushes to the frontend as an http_result.
func TestHttpResultMessageIncludesRTTFields(t *testing.T) {
	result := &pkghttp.Result{
		Status:     "passed",
		Delay:      180,
		RTTMin:     100,
		RTTAvg:     200,
		RTTMax:     300,
		Jitter:     82,
		RTTSamples: 3,
	}
	blob, err := json.Marshal(map[string]interface{}{"type": "http_result", "data": result})
	if err != nil {
		t.Fatal(err)
	}
	var msg struct {
		Type string `json:"type"`
		Data struct {
			RTTMin     int64 `json:"rttMin"`
			RTTAvg     int64 `json:"rttAvg"`
			RTTMax     int64 `json:"rttMax"`
			Jitter     int64 `json:"jitter"`
			RTTSamples int   `json:"rttSamples"`
		} `json:"data"`
	}
	if err := json.Unmarshal(blob, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Type != "http_result" {
		t.Fatalf("type = %q", msg.Type)
	}
	if msg.Data.RTTMin != 100 || msg.Data.RTTAvg != 200 || msg.Data.RTTMax != 300 || msg.Data.Jitter != 82 || msg.Data.RTTSamples != 3 {
		t.Errorf("rtt fields = %+v", msg.Data)
	}
}
