package http

import (
	"testing"
	"time"
)

func TestSummarizeRTTs(t *testing.T) {
	ms := func(values ...float64) []time.Duration {
		out := make([]time.Duration, len(values))
		for i, v := range values {
			out[i] = time.Duration(v * float64(time.Millisecond))
		}
		return out
	}

	cases := []struct {
		name string
		in   []time.Duration
		want RTTSummary
	}{
		{name: "nil", in: nil, want: RTTSummary{}},
		{name: "empty", in: []time.Duration{}, want: RTTSummary{}},
		{name: "one sample", in: ms(140), want: RTTSummary{140, 140, 140, 0, 1}},
		{name: "identical samples", in: ms(140, 140, 140), want: RTTSummary{140, 140, 140, 0, 3}},
		{name: "spread", in: ms(100, 200, 300), want: RTTSummary{100, 200, 300, 82, 3}},
		{name: "spread unordered", in: ms(300, 100, 200), want: RTTSummary{100, 200, 300, 82, 3}},
		{name: "half millisecond mean", in: ms(140, 141), want: RTTSummary{140, 141, 141, 1, 2}},
		{name: "fractional single sample", in: ms(140.9), want: RTTSummary{141, 141, 141, 0, 1}},
		{name: "sub millisecond", in: ms(0.3, 0.4, 0.35), want: RTTSummary{0, 0, 0, 0, 3}},
		{name: "rounds up to one", in: ms(0.4, 0.6), want: RTTSummary{0, 1, 1, 0, 2}},
		// A sum-of-squares implementation reports a nonzero jitter here.
		{name: "identical large samples", in: ms(1e8, 1e8, 1e8), want: RTTSummary{1e8, 1e8, 1e8, 0, 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := summarizeRTTs(tc.in)
			if got != tc.want {
				t.Fatalf("summarizeRTTs() = %+v, want %+v", got, tc.want)
			}
			if got.Count != len(tc.in) {
				t.Errorf("Count = %d, want %d", got.Count, len(tc.in))
			}
			if len(tc.in) == 0 {
				return
			}
			if got.Min > got.Avg || got.Avg > got.Max {
				t.Errorf("min/avg/max out of order: %+v", got)
			}
			if got.Jitter < 0 {
				t.Errorf("jitter = %d, want a nonnegative value", got.Jitter)
			}
		})
	}
}
