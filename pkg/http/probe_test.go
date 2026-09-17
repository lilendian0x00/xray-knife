package http

import (
	"context"
	"errors"
	"io"
	"log"
	stdhttp "net/http"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// stubProber stands in for an MTProto proxy: scripted Probe outcomes, no network.
type stubProber struct {
	stubProtocol
	res       protocol.ProbeResult
	err       error
	opts      protocol.ProbeOptions // what the examiner passed
	calls     int
	failFirst bool
}

func (s *stubProber) Probe(ctx context.Context, opts protocol.ProbeOptions) (protocol.ProbeResult, error) {
	s.opts = opts
	s.calls++
	if err := ctx.Err(); err != nil {
		return protocol.ProbeResult{}, err
	}
	if s.failFirst && s.calls == 1 {
		return protocol.ProbeResult{}, errors.New("temporary probe failure")
	}
	return s.res, s.err
}

func (s *stubProber) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{Protocol: "mtproto", Address: "1.2.3.4", Port: "443", TLS: "faketls"}
}

type proberCore struct {
	stubCore
	p *stubProber
}

func (c proberCore) CreateProtocol(string) (protocol.Protocol, error) { return c.p, nil }

func (c proberCore) MakeHttpClient(context.Context, protocol.Protocol, time.Duration) (*stdhttp.Client, protocol.Instance, error) {
	return nil, nil, errors.New("unexpected HTTP path for Prober")
}

const probeLink = "tg://proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff"

func newProbeExaminer(t *testing.T, p *stubProber, mutate func(*Examiner)) *Examiner {
	t.Helper()
	e, err := NewExaminer(Options{MaxDelay: 1000, Timeout: 2500, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	e.Core = proberCore{p: p}
	if mutate != nil {
		mutate(e)
	}
	return e
}

func TestExamineConfigUsesProber(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{
		ConnectTime: 20 * time.Millisecond,
		TTFB:        50 * time.Millisecond,
		Delay:       80 * time.Millisecond,
		Detail:      "faketls, dc2 resPQ ok",
	}}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.BindInterface = "eth-test" })

	r, err := e.ExamineConfig(context.Background(), probeLink)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "passed" || r.Delay != 80 || r.ConnectTime != 20 || r.TTFB != 50 || r.Reason != "faketls, dc2 resPQ ok" {
		t.Errorf("result = %+v", r)
	}
	if r.HTTPCode != -1 || r.DownloadSpeed != 0 || r.UploadSpeed != 0 || r.RealIPAddr != "null" || r.IpAddrLoc != "null" {
		t.Errorf("HTTP-only fields must keep their defaults: %+v", r)
	}
	if r.SuccessCount != 1 || r.TotalCount != 1 {
		t.Errorf("counts = %d/%d, want 1/1", r.SuccessCount, r.TotalCount)
	}
	if r.ProtocolInfo.Protocol != "mtproto" || r.TLS != "faketls" || r.ConfigLink != probeLink {
		t.Errorf("protocol info = %+v, tls = %q, link = %q", r.ProtocolInfo, r.TLS, r.ConfigLink)
	}
	if p.opts.Timeout != 2500*time.Millisecond || p.opts.BindInterface != "eth-test" {
		t.Errorf("probe options = %+v", p.opts)
	}
}

func TestExamineConfigProberTimeout(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{Delay: 1500 * time.Millisecond, Detail: "secured, dc2 resPQ ok"}}
	e := newProbeExaminer(t, p, nil) // MaxDelay is 1000 ms

	r, err := e.ExamineConfig(context.Background(), probeLink)
	if err == nil {
		t.Fatal("expected an error for a slow probe")
	}
	if r.Status != "timeout" || r.Reason != "config delay is more than the maximum allowed delay" || r.Delay != 1500 || r.SuccessCount != 0 || r.TotalCount != 1 {
		t.Errorf("result = %+v", r)
	}
}

func TestExamineConfigProberFailure(t *testing.T) {
	probeErr := errors.New("faketls: server digest mismatch (wrong secret or cloak domain answered)")
	p := &stubProber{err: probeErr}
	e := newProbeExaminer(t, p, nil)

	r, err := e.ExamineConfig(context.Background(), probeLink)
	if !errors.Is(err, probeErr) {
		t.Fatalf("err = %v, want the probe error", err)
	}
	if r.Status != "failed" || r.Reason != probeErr.Error() || r.Delay != FailedDelay {
		t.Errorf("result = %+v", r)
	}
}

func TestExamineConfigProberNotesSkippedSpeedtest(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{Delay: 10 * time.Millisecond, Detail: "simple, dc2 resPQ ok"}}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.DoSpeedtest = true; e.DoIPInfo = true })

	r, err := e.ExamineConfig(context.Background(), probeLink)
	if err != nil {
		t.Fatal(err)
	}
	want := "simple, dc2 resPQ ok; speedtest and ip lookup not applicable to mtproto"
	if r.Status != "passed" || r.Reason != want {
		t.Errorf("status = %q reason = %q, want passed / %q", r.Status, r.Reason, want)
	}
}

func TestExamineConfigWithRetriesStopsOnPassedProbe(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{Delay: 30 * time.Millisecond, Detail: "simple, dc2 resPQ ok"}}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.Retries = 2 })
	r, err := e.ExamineConfigWithRetries(context.Background(), probeLink)
	if err != nil || r.Status != "passed" || r.Delay != 30 || p.calls != 1 {
		t.Fatalf("result = %+v, err = %v, calls = %d", r, err, p.calls)
	}
}

func TestExamineConfigWithRetriesRecoversAfterFailure(t *testing.T) {
	p := &stubProber{
		failFirst: true,
		res:       protocol.ProbeResult{Delay: 45 * time.Millisecond, Detail: "secured, dc2 resPQ ok"},
	}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.Retries = 2 })
	r, err := e.ExamineConfigWithRetries(context.Background(), probeLink)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if r.Status != "passed" || r.Delay != 45 || r.Reason != "secured, dc2 resPQ ok" {
		t.Errorf("result = %+v", r)
	}
	// Retries stop at the first pass: one failure plus one success.
	if p.calls != 2 {
		t.Errorf("calls = %d, want 2", p.calls)
	}
}

func TestExamineConfigWithRetriesExhaustsAttempts(t *testing.T) {
	p := &stubProber{err: errors.New("read resPQ: timeout")}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.Retries = 3 })
	r, err := e.ExamineConfigWithRetries(context.Background(), probeLink)
	if err == nil || r.Status != "failed" {
		t.Fatalf("result = %+v, err = %v", r, err)
	}
	if p.calls != 4 { // 1 + Retries
		t.Errorf("calls = %d, want 4", p.calls)
	}
}

func TestExamineConfigWithRetriesStopsOnCanceledContext(t *testing.T) {
	p := &stubProber{err: errors.New("read resPQ: timeout")}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.Retries = 3 })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := e.ExamineConfigWithRetries(ctx, probeLink)
	if err == nil || r.Status != "failed" {
		t.Fatalf("result = %+v, err = %v", r, err)
	}
	if p.calls != 1 {
		t.Errorf("calls = %d, want 1 (no retries after cancellation)", p.calls)
	}
}
