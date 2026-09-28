package http

import (
	"math"
	"time"
)

// RTTSummary aggregates the round trips of one probe, in milliseconds.
type RTTSummary struct {
	Min    int64
	Avg    int64
	Max    int64
	Jitter int64 // population standard deviation
	Count  int
}

// summarizeRTTs works in fractional milliseconds and rounds only at the end, so
// a single 140.9ms sample reports 141.
func summarizeRTTs(rtts []time.Duration) RTTSummary {
	if len(rtts) == 0 {
		return RTTSummary{}
	}
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

	lo, hi, sum := ms(rtts[0]), ms(rtts[0]), 0.0
	for _, rtt := range rtts {
		v := ms(rtt)
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
		sum += v
	}
	mean := sum / float64(len(rtts))

	// Second pass rather than E[x²]-E[x]², which cancels away the variance of
	// large, nearly equal samples.
	var squares float64
	for _, rtt := range rtts {
		d := ms(rtt) - mean
		squares += d * d
	}

	return RTTSummary{
		Min:    int64(math.Round(lo)),
		Avg:    int64(math.Round(mean)),
		Max:    int64(math.Round(hi)),
		Jitter: int64(math.Round(math.Sqrt(squares / float64(len(rtts))))),
		Count:  len(rtts),
	}
}
