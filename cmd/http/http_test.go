package http

import (
	"context"
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
