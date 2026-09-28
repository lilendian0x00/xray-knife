package http

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// examineProbe grades a protocol.Prober, which checks reachability itself. It
// keeps the single-endpoint HTTP contract and grades only Delay.
func (e *Examiner) examineProbe(ctx context.Context, r Result, p protocol.Prober) (Result, error) {
	r.TotalCount = 1
	samples := e.ProbeSamples
	if samples == 0 {
		samples = 1 // struct-literal callers skip NewExaminer
	}
	pr, err := p.Probe(ctx, protocol.ProbeOptions{
		Timeout:       time.Duration(e.Timeout) * time.Millisecond,
		BindInterface: e.BindInterface,
		Samples:       samples,
	})
	if err != nil {
		if ctx.Err() != nil {
			return canceledResult(r, ctx)
		}
		r.Status = "failed"
		r.Reason = err.Error()
		return r, err
	}

	r.Delay = pr.Delay.Milliseconds()
	r.ConnectTime = pr.ConnectTime.Milliseconds()
	r.TTFB = pr.TTFB.Milliseconds()
	r.Reason = pr.Detail
	rtt := summarizeRTTs(pr.RTTs)
	r.RTTMin, r.RTTAvg, r.RTTMax, r.Jitter, r.RTTSamples = rtt.Min, rtt.Avg, rtt.Max, rtt.Jitter, rtt.Count
	if r.Delay > int64(e.MaxDelay) {
		r.Status = "timeout"
		r.Reason = "config delay is more than the maximum allowed delay"
		return r, errors.New(r.Reason)
	}
	r.Status = "passed"
	r.SuccessCount = 1
	if rtt.Count > 1 {
		r.appendReason(fmt.Sprintf("rtt min/avg/max/jitter %d/%d/%d/%d ms", rtt.Min, rtt.Avg, rtt.Max, rtt.Jitter))
	}
	if e.DoSpeedtest || e.DoIPInfo {
		// No HTTP path through this proxy: the fields keep their defaults, and
		// the reason says so instead of leaving them unexplained.
		r.appendReason(fmt.Sprintf("speedtest and ip lookup not applicable to %s", r.ProtocolInfo.Protocol))
	}
	return r, nil
}
