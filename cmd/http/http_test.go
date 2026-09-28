package http

import (
	"context"
	"fmt"
	"io"
	"log"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
)

// httpProtocol stands in for a config graded over HTTP.
type httpProtocol struct{}

func (httpProtocol) Parse() error       { return nil }
func (httpProtocol) DetailsStr() string { return "" }
func (httpProtocol) GetLink() string    { return "vless://example" }
func (httpProtocol) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{Protocol: "vless"}
}

// proberProtocol stands in for a config that grades itself, like MTProto.
type proberProtocol struct{ httpProtocol }

func (proberProtocol) Probe(context.Context, protocol.ProbeOptions) (protocol.ProbeResult, error) {
	return protocol.ProbeResult{Delay: time.Millisecond}, nil
}

func TestReasonIsWarning(t *testing.T) {
	cases := []struct {
		name string
		res  pkghttp.Result
		want bool
	}{
		{
			name: "http config with a speedtest failure",
			res:  pkghttp.Result{Status: "passed", Reason: "speedtest_download_failed: boom", Protocol: httpProtocol{}},
			want: true,
		},
		{
			name: "http config with nothing to report",
			res:  pkghttp.Result{Status: "passed", Protocol: httpProtocol{}},
			want: false,
		},
		{
			name: "native probe detail is not a warning",
			res:  pkghttp.Result{Status: "passed", Reason: "simple, dc2 resPQ ok; speedtest and ip lookup not applicable to mtproto", Protocol: proberProtocol{}},
			want: false,
		},
		{
			name: "failed configs are reported elsewhere",
			res:  pkghttp.Result{Status: "failed", Reason: "dial 127.0.0.1:9: connection refused", Protocol: proberProtocol{}},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reasonIsWarning(&tc.res); got != tc.want {
				t.Errorf("reasonIsWarning() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProbeSamplesFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{name: "default", want: 1},
		{name: "zero", args: []string{"--probe-samples", "0"}, want: 0},
		{name: "one", args: []string{"--probe-samples", "1"}, want: 1},
		{name: "five", args: []string{"--probe-samples", "5"}, want: 5},
		{name: "maximum", args: []string{"--probe-samples", "32"}, want: 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newHttpCommand()
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			got, err := cmd.Flags().GetInt("probe-samples")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("--probe-samples = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestProbeSamplesFlagRejectsNonIntegers(t *testing.T) {
	for _, bad := range []string{"abc", "2.5", ""} {
		cmd := newHttpCommand()
		if err := cmd.ParseFlags([]string{"--probe-samples", bad}); err == nil {
			t.Errorf("--probe-samples %q was accepted", bad)
		}
	}
}

// Out-of-range counts fail in the examiner, not at flag parsing.
func TestProbeSamplesRangeIsCheckedByExaminer(t *testing.T) {
	for _, samples := range []int{-1, 33, 256} {
		opts := examinerOptions(&Config{CoreType: "auto", ProbeSamples: samples}, nil)
		if opts.ProbeSamples != samples {
			t.Fatalf("options carried %d samples, want %d", opts.ProbeSamples, samples)
		}
		_, err := pkghttp.NewExaminer(opts)
		want := fmt.Sprintf("examiner: probe samples must be between 1 and 32, got %d", samples)
		if err == nil || err.Error() != want {
			t.Errorf("err = %v, want %q", err, want)
		}
	}
}

func TestExaminerOptionsCarryProbeSamples(t *testing.T) {
	config := &Config{CoreType: "auto", MaximumAllowedDelay: 5000, ProbeSamples: 5, SuccessThreshold: 1}
	opts := examinerOptions(config, nil)
	if opts.ProbeSamples != 5 {
		t.Fatalf("ProbeSamples = %d, want 5", opts.ProbeSamples)
	}
	e, err := pkghttp.NewExaminer(opts)
	if err != nil {
		t.Fatal(err)
	}
	if e.ProbeSamples != 5 {
		t.Errorf("examiner ProbeSamples = %d, want 5", e.ProbeSamples)
	}
}

func TestPingProbeOptionsUseOneSample(t *testing.T) {
	e, err := pkghttp.NewExaminer(pkghttp.Options{ProbeSamples: 5, BindInterface: "", Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	opts := pingProbeOptions(e, 2*time.Second)
	if opts.Samples != 1 {
		t.Errorf("ping Samples = %d, want 1", opts.Samples)
	}
	if opts.Timeout != 2*time.Second {
		t.Errorf("ping Timeout = %v", opts.Timeout)
	}
}

func TestProbeSampleLines(t *testing.T) {
	cases := []struct {
		name      string
		res       pkghttp.Result
		requested int
		want      []string
	}{
		{
			name:      "default single sample",
			res:       pkghttp.Result{Status: "passed", RTTSamples: 1, RTTMin: 140, RTTAvg: 140, RTTMax: 140},
			requested: 1,
		},
		{
			name:      "http result",
			res:       pkghttp.Result{Status: "passed"},
			requested: 5,
		},
		{
			name:      "failed probe",
			res:       pkghttp.Result{Status: "failed"},
			requested: 5,
		},
		{
			name:      "stopped early",
			res:       pkghttp.Result{Status: "passed", RTTSamples: 1, RTTMin: 140, RTTAvg: 140, RTTMax: 140},
			requested: 5,
			want:      []string{"Probe samples: 1/5 (sampling stopped early)"},
		},
		{
			name:      "all samples collected",
			res:       pkghttp.Result{Status: "passed", RTTSamples: 5, RTTMin: 140, RTTAvg: 143, RTTMax: 148, Jitter: 3},
			requested: 5,
			want: []string{
				"Probe samples: 5/5",
				"RTT over 5 samples: min/avg/max/jitter = 140/143/148/3 ms",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := probeSampleLines(&tc.res, tc.requested)
			if len(got) != len(tc.want) {
				t.Fatalf("lines = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("line %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
