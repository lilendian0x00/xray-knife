package singbox

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type flakyTransport struct {
	calls  int
	failOn int // calls up to this one fail
	err    error
	bodies []string
}

func (f *flakyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls++
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		f.bodies = append(f.bodies, string(b))
	}
	if f.calls <= f.failOn {
		return nil, f.err
	}
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

func TestResetRetry(t *testing.T) {
	changed := errors.New("network changed")

	base := &flakyTransport{failOn: 1, err: changed}
	req, _ := http.NewRequest(http.MethodPost, "http://x/", strings.NewReader("payload"))
	if _, err := (&resetRetry{base: base}).RoundTrip(req); err != nil || base.calls != 2 {
		t.Fatalf("err %v after %d calls, want one retry", err, base.calls)
	}
	if strings.Join(base.bodies, "|") != "payload|payload" {
		t.Fatalf("retried body = %q", base.bodies)
	}

	// Only once, and only for this error.
	base = &flakyTransport{failOn: 5, err: changed}
	req, _ = http.NewRequest(http.MethodGet, "http://x/", nil)
	if _, err := (&resetRetry{base: base}).RoundTrip(req); err == nil || base.calls != 2 {
		t.Fatalf("err %v after %d calls, want failure after two", err, base.calls)
	}
	base = &flakyTransport{failOn: 1, err: errors.New("connection refused")}
	if _, err := (&resetRetry{base: base}).RoundTrip(req); err == nil || base.calls != 1 {
		t.Fatalf("retried an unrelated error (%d calls)", base.calls)
	}

	// A body that cannot be replayed is not retried.
	base = &flakyTransport{failOn: 1, err: changed}
	req, _ = http.NewRequest(http.MethodPost, "http://x/", io.NopCloser(strings.NewReader("once")))
	req.GetBody = nil
	if _, err := (&resetRetry{base: base}).RoundTrip(req); err == nil || base.calls != 1 {
		t.Fatalf("retried a one-shot body (%d calls)", base.calls)
	}
}
