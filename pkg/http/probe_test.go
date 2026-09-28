package http

import (
	"context"
	"errors"
	"fmt"
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
	// A canceled run is not a verdict on the proxy.
	if err == nil || r.Status != StatusCanceled {
		t.Fatalf("result = %+v, err = %v", r, err)
	}
	if p.calls != 1 {
		t.Errorf("calls = %d, want 1 (no retries after cancellation)", p.calls)
	}
}

func rttsOf(ms ...int) []time.Duration {
	out := make([]time.Duration, len(ms))
	for i, v := range ms {
		out[i] = time.Duration(v) * time.Millisecond
	}
	return out
}

// Delay is graded as before. The spread is reported, not judged.
func TestExamineProbeSummarizesSamples(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{
		ConnectTime: 20 * time.Millisecond,
		TTFB:        90 * time.Millisecond,
		Delay:       180 * time.Millisecond,
		Detail:      "secured, dc2 resPQ ok, 3/3 samples",
		RTTs:        rttsOf(100, 200, 300),
	}}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.MaxDelay = 250; e.ProbeSamples = 3 })

	r, err := e.ExamineConfig(context.Background(), probeLink)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "passed" || r.Delay != 180 || r.ConnectTime != 20 || r.TTFB != 90 {
		t.Errorf("result = %+v", r)
	}
	if r.RTTMin != 100 || r.RTTAvg != 200 || r.RTTMax != 300 || r.Jitter != 82 || r.RTTSamples != 3 {
		t.Errorf("rtt fields = %d/%d/%d/%d over %d samples", r.RTTMin, r.RTTAvg, r.RTTMax, r.Jitter, r.RTTSamples)
	}
	want := "secured, dc2 resPQ ok, 3/3 samples; rtt min/avg/max/jitter 100/200/300/82 ms"
	if r.Reason != want {
		t.Errorf("reason = %q, want %q", r.Reason, want)
	}
	if r.HTTPCode != -1 || r.DownloadSpeed != 0 || r.UploadSpeed != 0 || r.RealIPAddr != "null" || r.IpAddrLoc != "null" {
		t.Errorf("HTTP-only fields must keep their defaults: %+v", r)
	}
	if p.opts.Samples != 3 {
		t.Errorf("probe options = %+v, want 3 samples", p.opts)
	}
}

func TestExamineProbeGradesDelayNotRTTs(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{
		Delay:  1500 * time.Millisecond,
		Detail: "secured, dc2 resPQ ok, 2/2 samples",
		RTTs:   rttsOf(10, 12),
	}}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.ProbeSamples = 2 }) // MaxDelay is 1000 ms

	r, err := e.ExamineConfig(context.Background(), probeLink)
	if err == nil {
		t.Fatal("fast samples must not rescue a slow first exchange")
	}
	if r.Status != "timeout" || r.Reason != "config delay is more than the maximum allowed delay" {
		t.Errorf("result = %+v", r)
	}
	if r.RTTMin != 10 || r.RTTAvg != 11 || r.RTTMax != 12 || r.Jitter != 1 || r.RTTSamples != 2 {
		t.Errorf("rtt fields must survive a MaxDelay failure: %+v", r)
	}
}

func TestExamineProbeReasonWithoutSpread(t *testing.T) {
	cases := []struct {
		name   string
		res    protocol.ProbeResult
		want   string
		count  int
		sample int
	}{
		{
			name:   "one requested sample",
			res:    protocol.ProbeResult{Delay: 40 * time.Millisecond, Detail: "simple, dc2 resPQ ok", RTTs: rttsOf(38)},
			want:   "simple, dc2 resPQ ok",
			count:  1,
			sample: 1,
		},
		{
			name:   "sampling stopped early",
			res:    protocol.ProbeResult{Delay: 40 * time.Millisecond, Detail: "simple, dc2 resPQ ok, 1/5 samples", RTTs: rttsOf(38)},
			want:   "simple, dc2 resPQ ok, 1/5 samples",
			count:  1,
			sample: 5,
		},
		{
			name:  "prober reports no RTTs",
			res:   protocol.ProbeResult{Delay: 40 * time.Millisecond, Detail: "simple, dc2 resPQ ok"},
			want:  "simple, dc2 resPQ ok",
			count: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &stubProber{res: tc.res}
			e := newProbeExaminer(t, p, func(e *Examiner) {
				if tc.sample != 0 {
					e.ProbeSamples = tc.sample
				}
			})

			r, err := e.ExamineConfig(context.Background(), probeLink)
			if err != nil {
				t.Fatal(err)
			}
			if r.Status != "passed" || r.Reason != tc.want {
				t.Errorf("status = %q reason = %q, want passed / %q", r.Status, r.Reason, tc.want)
			}
			if r.RTTSamples != tc.count {
				t.Errorf("rtt samples = %d, want %d", r.RTTSamples, tc.count)
			}
			if tc.count == 0 && (r.RTTMin != 0 || r.RTTAvg != 0 || r.RTTMax != 0 || r.Jitter != 0) {
				t.Errorf("rtt fields must stay zero without samples: %+v", r)
			}
		})
	}
}

func TestExamineProbeFailureLeavesRTTFieldsZero(t *testing.T) {
	p := &stubProber{err: errors.New("read resPQ: timeout")}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.ProbeSamples = 5 })

	r, _ := e.ExamineConfig(context.Background(), probeLink)
	if r.Status != "failed" {
		t.Fatalf("result = %+v", r)
	}
	if r.RTTMin != 0 || r.RTTAvg != 0 || r.RTTMax != 0 || r.Jitter != 0 || r.RTTSamples != 0 {
		t.Errorf("rtt fields = %+v, want all zero", r)
	}
}

// The spread note goes before the speedtest note, which stays last.
func TestExamineProbeNoteOrdering(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{
		Delay:  40 * time.Millisecond,
		Detail: "simple, dc2 resPQ ok, 3/3 samples",
		RTTs:   rttsOf(100, 200, 300),
	}}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.ProbeSamples = 3; e.DoSpeedtest = true; e.DoIPInfo = true })

	r, err := e.ExamineConfig(context.Background(), probeLink)
	if err != nil {
		t.Fatal(err)
	}
	want := "simple, dc2 resPQ ok, 3/3 samples; rtt min/avg/max/jitter 100/200/300/82 ms; speedtest and ip lookup not applicable to mtproto"
	if r.Reason != want {
		t.Errorf("reason = %q, want %q", r.Reason, want)
	}
}

// A partial sample count is still a pass, so retries must not re-run it.
func TestExamineConfigWithRetriesAcceptsPartialSampling(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{
		Delay:  30 * time.Millisecond,
		Detail: "simple, dc2 resPQ ok, 1/5 samples",
		RTTs:   rttsOf(28),
	}}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.Retries = 2; e.ProbeSamples = 5 })

	r, err := e.ExamineConfigWithRetries(context.Background(), probeLink)
	if err != nil || r.Status != "passed" || p.calls != 1 {
		t.Fatalf("result = %+v, err = %v, calls = %d", r, err, p.calls)
	}
}

// A struct-literal Examiner skips NewExaminer, so zero must still mean one.
func TestExamineProbeZeroSamplesMeansOne(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{Delay: 30 * time.Millisecond, Detail: "simple, dc2 resPQ ok", RTTs: rttsOf(28)}}
	e := &Examiner{MaxDelay: 1000, Timeout: 1000, Logger: log.New(io.Discard, "", 0)}

	if _, err := e.examineProbe(context.Background(), Result{}, p); err != nil {
		t.Fatal(err)
	}
	if p.opts.Samples != 1 {
		t.Errorf("probe options = %+v, want 1 sample", p.opts)
	}
}

func TestNewExaminerProbeSamples(t *testing.T) {
	cases := []struct {
		in      int
		want    int
		wantErr string
	}{
		{in: 0, want: 1},
		{in: 1, want: 1},
		{in: 32, want: 32},
		{in: -1, wantErr: "examiner: probe samples must be between 1 and 32, got -1"},
		{in: 33, wantErr: "examiner: probe samples must be between 1 and 32, got 33"},
		{in: 256, wantErr: "examiner: probe samples must be between 1 and 32, got 256"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("samples=%d", tc.in), func(t *testing.T) {
			e, err := NewExaminer(Options{ProbeSamples: tc.in, Logger: log.New(io.Discard, "", 0)})
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if e.ProbeSamples != tc.want {
				t.Errorf("ProbeSamples = %d, want %d", e.ProbeSamples, tc.want)
			}
		})
	}
}
