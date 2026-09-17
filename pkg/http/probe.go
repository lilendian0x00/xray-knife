package http

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// examineProbe grades a protocol that checks reachability itself instead of
// carrying HTTP (see protocol.Prober). It keeps the single-endpoint HTTP
// contract — passed within MaxDelay, timeout above it, failed on error, same
// error returns — so retries and callers behave identically.
func (e *Examiner) examineProbe(ctx context.Context, r Result, p protocol.Prober) (Result, error) {
	r.TotalCount = 1
	pr, err := p.Probe(ctx, protocol.ProbeOptions{
		Timeout:       time.Duration(e.Timeout) * time.Millisecond,
		BindInterface: e.BindInterface,
	})
	if err != nil {
		r.Status = "failed"
		r.Reason = err.Error()
		return r, err
	}

	r.Delay = pr.Delay.Milliseconds()
	r.ConnectTime = pr.ConnectTime.Milliseconds()
	r.TTFB = pr.TTFB.Milliseconds()
	r.Reason = pr.Detail
	if r.Delay > int64(e.MaxDelay) {
		r.Status = "timeout"
		r.Reason = "config delay is more than the maximum allowed delay"
		return r, errors.New(r.Reason)
	}
	r.Status = "passed"
	r.SuccessCount = 1
	if e.DoSpeedtest || e.DoIPInfo {
		// No HTTP path through this proxy: the fields keep their defaults, and
		// the reason says so instead of leaving them unexplained.
		r.appendReason(fmt.Sprintf("speedtest and ip lookup not applicable to %s", r.ProtocolInfo.Protocol))
	}
	return r, nil
}
