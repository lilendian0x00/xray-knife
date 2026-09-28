package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/netbind"
)

// ProtocolInfo holds basic, serializable information about a protocol.
type ProtocolInfo struct {
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     string `json:"port"`
}

type Result struct {
	ConfigLink    string            `csv:"link" json:"link"`                // vmess://... vless//..., etc
	Protocol      protocol.Protocol `csv:"-" json:"-"`                      // The full protocol object for internal use
	ProtocolInfo  ProtocolInfo      `csv:"-" json:"protocol"`               // Serializable info for the frontend
	Status        string            `csv:"status" json:"status"`            // passed, semi-passed, failed, broken
	Reason        string            `csv:"reason" json:"reason"`            // reason of the error
	TLS           string            `csv:"tls" json:"tls"`                  // none, tls, reality
	RealIPAddr    string            `csv:"ip" json:"ip"`                    // Real ip address (req to cloudflare.com/cdn-cgi/trace)
	Delay         int64             `csv:"delay" json:"delay"`              // millisecond
	HTTPCode      int               `csv:"code" json:"code"`                // HTTP status code of the tested URL
	DownloadSpeed float32           `csv:"download" json:"download"`        // mbps
	UploadSpeed   float32           `csv:"upload" json:"upload"`            // mbps
	IpAddrLoc     string            `csv:"location" json:"location"`        // IP address location
	TTFB          int64             `csv:"ttfb" json:"ttfb"`                // Time to first byte (ms)
	ConnectTime   int64             `csv:"connect_time" json:"connectTime"` // Connection time (ms)
	SuccessCount  int               `csv:"success" json:"successCount"`     // Endpoints that passed (multi-endpoint panel)
	TotalCount    int               `csv:"total" json:"totalCount"`         // Endpoints probed (multi-endpoint panel)
	// EndpointResults is the structured result
	EndpointResults []EndpointResult `csv:"-" json:"endpoints,omitempty"`
	EndpointSummary string           `csv:"endpoints" json:"endpointSummary"`
	// Latency spread over a native probe's samples, in ms. Zero elsewhere
	RTTMin     int64 `csv:"rtt_min" json:"rttMin"`
	RTTAvg     int64 `csv:"rtt_avg" json:"rttAvg"`
	RTTMax     int64 `csv:"rtt_max" json:"rttMax"`
	Jitter     int64 `csv:"jitter" json:"jitter"`
	RTTSamples int   `csv:"rtt_samples" json:"rttSamples"`
	// Exit-side details from the Cloudflare trace. Appended last so CSV files
	// written before they existed keep a prefix-compatible header.
	Colo string `csv:"colo" json:"colo"` // Cloudflare data center that served the trace (e.g. FRA)
	Warp string `csv:"warp" json:"warp"` // WARP state reported by the trace (off/on/plus)
	// FailureKind says why a non-passed config failed (see the Fail*
	// constants): blocked on the way (dns-poisoned, tcp-reset, tls-reset…)
	// versus a dead server or wrong config. Empty for passed results.
	FailureKind string `csv:"failure_kind" json:"failureKind,omitempty"`
}

// appendReason adds a note to Reason, keeping any note already recorded.
func (r *Result) appendReason(reason string) {
	if r.Reason != "" {
		r.Reason += "; "
	}
	r.Reason += reason
}

// EndpointCheck is one destination probed while grading a config. ExpectStatus
// is the exact status required, or 0 to accept any 2xx.
type EndpointCheck struct {
	URL          string `json:"url"`
	Method       string `json:"method"`
	ExpectStatus int    `json:"expectStatus"`
}

// EndpointResult records one panel endpoint's outcome, so callers see which
// destination failed and why, not just the aggregate count.
type EndpointResult struct {
	URL      string `json:"url"`
	Label    string `json:"label"`            // short host label, e.g. "gstatic.com"
	Outcome  string `json:"outcome"`          // ok, slow, bad-status, error
	HTTPCode int    `json:"code"`             // -1 when no response
	Delay    int64  `json:"delay"`            // ms, -1 when no response
	Reason   string `json:"reason,omitempty"` // populated on failure
}

// endpointLabel derives a short, stable label from a URL's host for compact
// per-endpoint summaries (drops scheme, a leading "www.", and any port).
func endpointLabel(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return strings.TrimPrefix(u.Hostname(), "www.")
	}
	// Fall back to a trimmed raw string when the URL does not parse.
	s := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

// summarizeEndpoints renders per-endpoint outcomes as a compact one-line string
// for CSV/log output, e.g. "gstatic.com=ok(408ms); cloudflare.com=slow(2718ms)".
func summarizeEndpoints(results []EndpointResult) string {
	if len(results) == 0 {
		return ""
	}
	parts := make([]string, 0, len(results))
	for _, er := range results {
		switch er.Outcome {
		case "ok":
			parts = append(parts, fmt.Sprintf("%s=ok(%dms)", er.Label, er.Delay))
		case "slow":
			parts = append(parts, fmt.Sprintf("%s=slow(%dms)", er.Label, er.Delay))
		case "bad-status":
			parts = append(parts, fmt.Sprintf("%s=status%d", er.Label, er.HTTPCode))
		default: // error
			parts = append(parts, fmt.Sprintf("%s=error", er.Label))
		}
	}
	return strings.Join(parts, "; ")
}

// statusOK checks a status against an endpoint's expectation. 0 accepts any 2xx,
// otherwise the match is exact, so a captive portal answering 200 is rejected.
func statusOK(code, expect int) bool {
	if expect != 0 {
		return code == expect
	}
	return code >= 200 && code < 300
}

// expectedStatusFor infers a URL's success code when the caller set none.
// generate_204 endpoints must answer 204, everything else accepts any 2xx.
func expectedStatusFor(rawURL string) int {
	if strings.Contains(rawURL, "generate_204") {
		return 204
	}
	return 0
}

// CheckPresets are named, network-diverse endpoint panels. Each spans a distinct
// provider zone, so a config that only reaches one CDN grades as partial.
var CheckPresets = map[string][]EndpointCheck{
	// cloudflare is the single-endpoint default: just the Cloudflare trace URL.
	"cloudflare": {
		{URL: "https://cloudflare.com/cdn-cgi/trace", Method: "GET"},
	},
	// gstatic is a single-endpoint Google reachability probe (expects 204).
	"gstatic": {
		{URL: "https://www.gstatic.com/generate_204", Method: "GET", ExpectStatus: 204},
	},
	"global": {
		{URL: "https://www.gstatic.com/generate_204", Method: "GET", ExpectStatus: 204},
		{URL: "https://cloudflare.com/cdn-cgi/trace", Method: "GET"},
		{URL: "http://www.msftconnecttest.com/connecttest.txt", Method: "GET"},
		{URL: "https://captive.apple.com/hotspot-detect.html", Method: "GET"},
	},
	"google": {
		{URL: "https://www.gstatic.com/generate_204", Method: "GET", ExpectStatus: 204},
		{URL: "https://www.youtube.com/generate_204", Method: "GET", ExpectStatus: 204},
		{URL: "https://play.google.com/generate_204", Method: "GET", ExpectStatus: 204},
	},
	"streaming": {
		{URL: "https://www.youtube.com/generate_204", Method: "GET", ExpectStatus: 204},
		{URL: "https://www.gstatic.com/generate_204", Method: "GET", ExpectStatus: 204},
		{URL: "https://cloudflare.com/cdn-cgi/trace", Method: "GET"},
	},
}

// PresetNames returns the available preset names, sorted, for CLI help and
// validation.
func PresetNames() []string {
	names := make([]string, 0, len(CheckPresets))
	for name := range CheckPresets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type Examiner struct {
	Core core.Core

	// Maximum allowed delay (ms), the pass/fail latency threshold
	MaxDelay uint16
	// Connection timeout (ms) for the HTTP client
	Timeout     uint16
	Verbose     bool
	ShowBody    bool
	InsecureTLS bool

	DoSpeedtest bool
	DoIPInfo    bool

	TestEndpoint           string
	TestEndpointHttpMethod string
	// TestEndpoints, when non-empty, replaces TestEndpoint with a panel graded by
	// how many entries succeed (see SuccessThreshold).
	TestEndpoints     []EndpointCheck
	SuccessThreshold  float64
	SpeedtestKbAmount uint64
	SpeedtestTimeout  uint16
	Retries           uint8

	// BindInterface pins outbound core dials to a specific OS interface.
	// Empty disables binding.
	BindInterface string

	// ProbeSamples is the round trips a native probe measures per test,
	// 1..protocol.MaxProbeSamples. Ignored by the HTTP path.
	ProbeSamples int

	// Fragment is the TLS fragmentation/noise the core applies to the first
	// hop (nil = off). Informational here: it is baked into Core.
	Fragment *fragment.Options

	// SpeedTester is the speed test target; nil uses speed.cloudflare.com.
	SpeedTester *SpeedTester

	// Diagnoser, when set, checks a failed config's server directly (DNS,
	// TCP, TLS ClientHello) to tell blocking from a dead or misconfigured
	// proxy. NewExaminer sets it unless Options.NoDiagnose.
	Diagnoser *Diagnoser

	Logger *log.Logger `json:"-"`
}

// Result statuses. StatusCanceled marks a test the run stopped before it
// could finish; it is never persisted as a verdict on the config.
const (
	StatusPassed     = "passed"
	StatusSemiPassed = "semi-passed"
	StatusFailed     = "failed"
	StatusTimeout    = "timeout"
	StatusBroken     = "broken"
	StatusCanceled   = "canceled"
)

// maxDelayBody caps how much of a latency probe's response body is read.
// Trace and generate_204 bodies are tiny; an unexpected large page must not
// turn a latency test into a download.
const maxDelayBody = 1 << 20

const FailedDelay int64 = -1
const defaultSpeedtestTimeout = 30 * time.Second

type Options struct {
	Core         string    `json:"core"`
	CoreInstance core.Core `json:"-"` // This field should not be part of the JSON payload

	MaxDelay               uint16 `json:"maxDelay"`
	Timeout                uint16 `json:"timeout"` // Separate timeout for HTTP client (0 = use MaxDelay)
	Verbose                bool   `json:"verbose"`
	ShowBody               bool   `json:"showBody"`
	InsecureTLS            bool   `json:"insecureTLS"`
	DoSpeedtest            bool   `json:"speedtest"`
	DoIPInfo               bool   `json:"doIPInfo"`
	TestEndpoint           string `json:"destURL"`
	TestEndpointHttpMethod string `json:"httpMethod"`
	// TestEndpoints, when non-empty, overrides TestEndpoint. SuccessThreshold is
	// the fraction that must pass for a "passed" verdict, 0 meaning all.
	TestEndpoints     []EndpointCheck `json:"testEndpoints,omitempty"`
	SuccessThreshold  float64         `json:"successThreshold,omitempty"`
	SpeedtestKbAmount uint64          `json:"speedtestAmount"`
	SpeedtestTimeout  uint16          `json:"speedtestTimeout,omitempty"`
	Retries           uint8           `json:"retries"`
	BindInterface     string          `json:"bindInterface,omitempty"`
	ProbeSamples      int             `json:"probeSamples,omitempty"`
	// Fragment splits the first hop's TLS handshake (see pkg/core/fragment).
	// FragmentSpec is the "packets,length[,interval]" string form, used when
	// Fragment is nil (handy for JSON clients).
	Fragment     *fragment.Options `json:"fragment,omitempty"`
	FragmentSpec string            `json:"fragmentSpec,omitempty"`
	// SpeedtestURL overrides the speed test target. A bare origin
	// (https://host) must speak Cloudflare's /__down and /__up; a URL with a
	// path is downloaded as a plain file and upload is skipped.
	SpeedtestURL string `json:"speedtestURL,omitempty"`
	// Resolver is used for diagnostics only (never inside the cores):
	// doh://host, https://host/dns-query, or an IP[:port] for plain DNS.
	// Comparing its answers with the system resolver's exposes poisoning.
	Resolver string `json:"resolver,omitempty"`
	// NoDiagnose skips the direct server checks on failed configs; failure
	// kinds then fall back to the raw error class.
	NoDiagnose bool        `json:"noDiagnose,omitempty"`
	Logger     *log.Logger `json:"-"`
}

func NewExaminer(opts Options) (*Examiner, error) {
	// Set defaults first
	e := &Examiner{
		Verbose:                opts.Verbose,
		ShowBody:               opts.ShowBody,
		InsecureTLS:            opts.InsecureTLS,
		DoSpeedtest:            opts.DoSpeedtest,
		DoIPInfo:               opts.DoIPInfo,
		TestEndpoint:           "https://cloudflare.com/cdn-cgi/trace",
		TestEndpointHttpMethod: "GET",
		MaxDelay:               5000,
		SpeedtestKbAmount:      10000,
	}

	// Override from opts if non-zero
	if opts.MaxDelay != 0 {
		e.MaxDelay = opts.MaxDelay
	}
	if opts.SpeedtestKbAmount != 0 {
		e.SpeedtestKbAmount = opts.SpeedtestKbAmount
	}
	e.SpeedtestTimeout = opts.SpeedtestTimeout
	if opts.TestEndpoint != "" {
		e.TestEndpoint = opts.TestEndpoint
	}
	if opts.TestEndpointHttpMethod != "" {
		e.TestEndpointHttpMethod = opts.TestEndpointHttpMethod
	}

	// Set Timeout: use explicit value if provided, otherwise default to MaxDelay
	if opts.Timeout != 0 {
		e.Timeout = opts.Timeout
	} else {
		e.Timeout = e.MaxDelay
	}

	e.TestEndpoints = opts.TestEndpoints
	e.SuccessThreshold = opts.SuccessThreshold
	if e.SuccessThreshold <= 0 {
		e.SuccessThreshold = 1.0
	}

	e.ProbeSamples = opts.ProbeSamples
	if e.ProbeSamples == 0 {
		e.ProbeSamples = 1
	}
	if e.ProbeSamples < 1 || e.ProbeSamples > protocol.MaxProbeSamples {
		return nil, fmt.Errorf("examiner: probe samples must be between 1 and %d, got %d", protocol.MaxProbeSamples, opts.ProbeSamples)
	}

	e.Retries = opts.Retries
	e.BindInterface = opts.BindInterface

	e.Fragment = opts.Fragment.Clone()
	if e.Fragment == nil && strings.TrimSpace(opts.FragmentSpec) != "" {
		f, err := fragment.Parse(opts.FragmentSpec)
		if err != nil {
			return nil, fmt.Errorf("examiner: %w", err)
		}
		e.Fragment = f
	}
	if err := e.Fragment.Validate(); err != nil {
		return nil, fmt.Errorf("examiner: %w", err)
	}

	if opts.SpeedtestURL != "" {
		st, err := NewSpeedTester(opts.SpeedtestURL)
		if err != nil {
			return nil, fmt.Errorf("examiner: %w", err)
		}
		e.SpeedTester = st
	}

	if !opts.NoDiagnose {
		var trusted Resolver
		if strings.TrimSpace(opts.Resolver) != "" {
			r, err := NewResolver(opts.Resolver, opts.BindInterface)
			if err != nil {
				return nil, fmt.Errorf("examiner: %w", err)
			}
			trusted = r
		}
		// Short steps: a dead server already cost the tunnel attempt its
		// full timeout, and this only has to tell the layers apart.
		step := min(time.Duration(e.Timeout)*time.Millisecond, 3*time.Second)
		d, err := NewDiagnoser(trusted, opts.BindInterface, step)
		if err != nil {
			return nil, fmt.Errorf("examiner: %w", err)
		}
		e.Diagnoser = d
	} else if strings.TrimSpace(opts.Resolver) != "" {
		return nil, errors.New("examiner: a resolver needs diagnostics enabled")
	}
	if e.BindInterface != "" {
		if _, err := netbind.New(e.BindInterface); err != nil {
			return nil, fmt.Errorf("examiner: %w", err)
		}
	}

	// Set logger: use provided logger or default to stdout
	if opts.Logger != nil {
		e.Logger = opts.Logger
	} else {
		e.Logger = log.New(os.Stdout, "", 0)
	}

	factoryOpts := core.FactoryOptions{
		InsecureTLS:   e.InsecureTLS,
		Verbose:       e.Verbose,
		BindInterface: e.BindInterface,
		Fragment:      e.Fragment,
	}
	switch opts.Core {
	case "xray":
		e.Core = core.CoreFactoryWith(core.XrayCoreType, factoryOpts)
	case "singbox", "sing-box":
		e.Core = core.CoreFactoryWith(core.SingboxCoreType, factoryOpts)
	case "auto":
		fallthrough
	default:
		e.Core = core.NewAutomaticCoreWith(factoryOpts)
	}

	if e.Core == nil {
		return nil, fmt.Errorf("failed to create core of type: %s", opts.Core)
	}

	return e, nil
}

// parseTraceBody is a helper function to parse the output of a /cdn-cgi/trace request.
func parseTraceBody(body []byte, r *Result) {
	if len(body) == 0 {
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		// Use strings.Cut for a slightly cleaner way to split on the first '='.
		if key, val, found := strings.Cut(line, "="); found {
			switch key {
			case "ip":
				r.RealIPAddr = val
			case "loc":
				r.IpAddrLoc = val
			case "colo":
				r.Colo = val
			case "warp":
				r.Warp = val
			}
		}
	}
}

// checks returns the effective endpoint panel, filling in per-endpoint defaults.
// With no explicit panel it falls back to the single legacy TestEndpoint.
func (e *Examiner) checks() []EndpointCheck {
	src := e.TestEndpoints
	if len(src) == 0 {
		src = []EndpointCheck{{URL: e.TestEndpoint, Method: e.TestEndpointHttpMethod}}
	}
	out := make([]EndpointCheck, 0, len(src))
	for _, c := range src {
		if c.Method == "" {
			c.Method = "GET"
		}
		if c.ExpectStatus == 0 {
			c.ExpectStatus = expectedStatusFor(c.URL)
		}
		out = append(out, c)
	}
	return out
}

// passesThreshold reports whether the success ratio clears the "passed" bar. All
// passing always qualifies, otherwise successes/total must reach threshold.
func passesThreshold(successes, total int, threshold float64) bool {
	if total <= 0 {
		return false
	}
	if successes >= total {
		return true
	}
	return float64(successes)/float64(total)+1e-9 >= threshold
}

// failureInfo is what examine learned that classifying a failure needs.
type failureInfo struct {
	general      *protocol.GeneralConfig
	transportErr error // first error from the tunnel, nil if every endpoint answered
	prober       bool
}

// ExamineConfig tests one config. A result that did not pass carries a
// FailureKind, and, when a direct server check explains the failure, a
// "diagnosis: <kind>: <detail>" note in Reason.
func (e *Examiner) ExamineConfig(ctx context.Context, link string) (Result, error) {
	return e.ExamineParsed(ctx, ParseLink(e.Core, link))
}

// ExamineParsed tests a link parsed by ParseLink/ParseLinks, without parsing
// it again. The parsed protocol must come from a core compatible with e.Core.
func (e *Examiner) ExamineParsed(ctx context.Context, pl *ParsedLink) (Result, error) {
	pl.ensureParsed(e.Core)
	var info failureInfo
	r, err := e.examine(ctx, pl, &info)
	if r.Status != StatusPassed {
		e.classifyFailure(ctx, &r, err, &info)
	}
	return r, err
}

// classifyFailure fills r.FailureKind.
func (e *Examiner) classifyFailure(ctx context.Context, r *Result, err error, info *failureInfo) {
	switch r.Status {
	case StatusCanceled:
		r.FailureKind = FailCanceled
		return
	case StatusBroken:
		r.FailureKind = FailConfig
		return
	case StatusTimeout:
		r.FailureKind = FailSlow
		return
	}
	if info.prober {
		r.FailureKind = proberKind(err)
		return
	}
	if info.transportErr == nil {
		// Every endpoint answered through the tunnel: it works, the answers
		// did not satisfy the panel.
		r.FailureKind = FailHTTPStatus
		for _, er := range r.EndpointResults {
			if er.Outcome == "bad-status" {
				return
			}
		}
		r.FailureKind = FailSlow
		return
	}
	class := classifyError(info.transportErr)
	if e.Diagnoser == nil || info.general == nil || ctx.Err() != nil {
		r.FailureKind = tunnelKind(class, false)
		return
	}
	check := serverCheckFor(*info.general)
	diag := e.Diagnoser.Server(ctx, check)
	switch {
	case diag.Kind == FailCanceled:
		r.FailureKind = tunnelKind(class, false)
	case diag.Kind != "":
		r.FailureKind = diag.Kind
		r.appendReason(diagnosisPrefix + diag.Kind + ": " + diag.Detail)
	default:
		r.FailureKind = tunnelKind(class, !check.UDP)
	}
}

// serverCheckFor describes a config's server for a direct check.
func serverCheckFor(gc protocol.GeneralConfig) ServerCheck {
	tlsSec := strings.ToLower(gc.TLS)
	return ServerCheck{
		Host: gc.Address,
		Port: gc.Port,
		SNI:  gc.SNI,
		TLS:  tlsSec == "tls" || tlsSec == "reality",
		UDP:  isUDPBased(gc),
	}
}

func (e *Examiner) examine(ctx context.Context, pl *ParsedLink, info *failureInfo) (Result, error) {
	r := Result{
		ConfigLink: pl.Link,
		Status:     "passed",
		Delay:      FailedDelay,
		HTTPCode:   -1,
		RealIPAddr: "null",
		IpAddrLoc:  "null",
	}

	if pl.Err != nil || pl.Proto == nil {
		r.Status = "broken"
		r.Reason = "config link is empty"
		if pl.Err != nil {
			r.Reason = pl.Err.Error()
		}
		return r, errors.New(r.Reason)
	}
	proto := pl.Proto

	if e.Verbose {
		e.Logger.Printf("%v%s: %s\n\n", proto.DetailsStr(), color.RedString("Link"), proto.GetLink())
	}

	r.Protocol = proto
	generalConfig := proto.ConvertToGeneralConfig()
	info.general = &generalConfig
	r.ProtocolInfo = ProtocolInfo{
		Remark:   generalConfig.Remark,
		Protocol: generalConfig.Protocol,
		Address:  generalConfig.Address,
		Port:     generalConfig.Port,
	}
	r.TLS = generalConfig.TLS

	// Protocols that cannot carry HTTP (MTProto proxies) grade themselves.
	if prober, ok := proto.(protocol.Prober); ok {
		info.prober = true
		return e.examineProbe(ctx, r, prober)
	}

	client, instance, err := e.Core.MakeHttpClient(ctx, proto, time.Duration(e.Timeout)*time.Millisecond)
	if err != nil {
		if ctx.Err() != nil {
			return canceledResult(r, ctx)
		}
		r.Status = "broken"
		r.Reason = err.Error()
		return r, err
	}
	defer instance.Close()

	// Build the effective endpoint panel. With no explicit panel this is a
	// single entry (the legacy TestEndpoint), preserving prior behavior.
	checks := e.checks()
	r.TotalCount = len(checks)

	var traceBody []byte
	var firstFailReason string
	var firstTransportErr error
	firstRespRecorded := false
	soleWasTimeout := false
	successes := 0
	endpointResults := make([]EndpointResult, 0, len(checks))

	for _, chk := range checks {
		if ctx.Err() != nil {
			break
		}
		er := EndpointResult{URL: chk.URL, Label: endpointLabel(chk.URL), HTTPCode: -1, Delay: -1}

		dr, derr := MeasureDelayDetailed(ctx, client, chk.URL, chk.Method)
		if derr != nil {
			er.Outcome = "error"
			er.Reason = derr.Error()
			endpointResults = append(endpointResults, er)
			if firstFailReason == "" {
				firstFailReason = fmt.Sprintf("%s: %s", chk.URL, derr.Error())
			}
			if firstTransportErr == nil {
				firstTransportErr = derr
			}
			continue
		}

		er.HTTPCode = dr.Code
		er.Delay = dr.Delay

		// The first endpoint that returns a response defines the representative
		// timing reported for the config (used for sorting and display).
		if !firstRespRecorded {
			r.Delay = dr.Delay
			r.HTTPCode = dr.Code
			r.TTFB = dr.TTFB
			r.ConnectTime = dr.ConnectTime
			firstRespRecorded = true
		}
		if e.ShowBody {
			e.Logger.Printf("Response body from %s:\n%s\n", chk.URL, dr.Body)
		}
		if len(dr.Body) > 0 && strings.Contains(chk.URL, "/cdn-cgi/trace") {
			traceBody = dr.Body
		}

		// A slow endpoint and a wrong status are both failures. Record the reason
		// so a fully failed config explains itself.
		switch {
		case dr.Delay > int64(e.MaxDelay):
			er.Outcome = "slow"
			er.Reason = fmt.Sprintf("delay %dms exceeds max %dms", dr.Delay, e.MaxDelay)
			if firstFailReason == "" {
				firstFailReason = fmt.Sprintf("%s: %s", chk.URL, er.Reason)
			}
			soleWasTimeout = true
		case !statusOK(dr.Code, chk.ExpectStatus):
			er.Outcome = "bad-status"
			if chk.ExpectStatus != 0 {
				er.Reason = fmt.Sprintf("unexpected HTTP status %d (want %d)", dr.Code, chk.ExpectStatus)
			} else {
				er.Reason = fmt.Sprintf("unexpected HTTP status %d", dr.Code)
			}
			if firstFailReason == "" {
				firstFailReason = fmt.Sprintf("%s: %s", chk.URL, er.Reason)
			}
			soleWasTimeout = false
		default:
			er.Outcome = "ok"
			successes++
		}
		endpointResults = append(endpointResults, er)
	}
	info.transportErr = firstTransportErr
	r.SuccessCount = successes
	r.EndpointResults = endpointResults
	r.EndpointSummary = summarizeEndpoints(endpointResults)
	total := len(checks)

	// A run stopped mid-panel says nothing about the config: report it as
	// canceled instead of grading the endpoints the cancellation killed.
	if ctx.Err() != nil && !passesThreshold(successes, total, e.SuccessThreshold) {
		return canceledResult(r, ctx)
	}

	// Grade the config from how many panel endpoints passed.
	switch {
	case passesThreshold(successes, total, e.SuccessThreshold):
		r.Status = "passed"
		if total > 1 {
			r.Reason = fmt.Sprintf("%d/%d endpoints reachable", successes, total)
		}
	case successes > 0:
		r.Status = "semi-passed"
		r.Reason = fmt.Sprintf("%d/%d endpoints reachable", successes, total)
	default:
		// Nothing passed. The single-endpoint path keeps its original
		// failed/timeout contract so existing callers behave as before.
		if total == 1 && !firstRespRecorded {
			r.Status = "failed"
			r.Reason = firstFailReason
			return r, firstTransportErr
		}
		if total == 1 && soleWasTimeout {
			r.Status = "timeout"
			r.Reason = "config delay is more than the maximum allowed delay"
			return r, errors.New(r.Reason)
		}
		r.Status = "failed"
		if firstFailReason != "" {
			r.Reason = firstFailReason
		} else {
			r.Reason = "all endpoints failed"
		}
		return r, errors.New(r.Reason)
	}

	if e.DoIPInfo {
		// Reuse a trace body captured during the panel run if one is available.
		if len(traceBody) > 0 {
			parseTraceBody(traceBody, &r)
		} else {
			// Otherwise, make a dedicated request for the IP info. The config
			// already reached the user's own test URL, so a failed lookup is
			// noted in Reason but never demotes the verdict.
			req, reqErr := http.NewRequestWithContext(ctx, "GET", "https://cloudflare.com/cdn-cgi/trace", nil)
			if reqErr != nil {
				r.appendReason("ip_info_failed")
			} else {
				_, ipBody, _, traceErr := CoreHTTPRequestCustom(ctx, client, 10*time.Second, req)
				if traceErr != nil {
					r.appendReason("ip_info_failed")
				} else {
					parseTraceBody(ipBody, &r)
				}
			}
		}
	}

	if e.DoSpeedtest {
		e.runSpeedtest(ctx, client, &r)
	}

	return r, nil
}

// ExamineConfigWithRetries runs ExamineConfig up to 1+Retries times, keeping
// the best result: passed beats semi-passed beats every failure, and among
// equal verdicts the lower delay wins. Broken configs (unparseable, or a core
// that refuses to build them) are not retried: another attempt cannot help.
func (e *Examiner) ExamineConfigWithRetries(ctx context.Context, link string) (Result, error) {
	return e.ExamineParsedWithRetries(ctx, ParseLink(e.Core, link))
}

// ExamineParsedWithRetries is ExamineConfigWithRetries for a parsed link; every
// attempt reuses the one parsed protocol.
func (e *Examiner) ExamineParsedWithRetries(ctx context.Context, pl *ParsedLink) (Result, error) {
	best, err := e.ExamineParsed(ctx, pl)
	if e.Retries == 0 || best.Status == StatusPassed || best.Status == StatusBroken || best.Status == StatusCanceled {
		return best, err
	}

	for i := uint8(0); i < e.Retries; i++ {
		if ctx.Err() != nil {
			break
		}
		res, retryErr := e.ExamineParsed(ctx, pl)
		if res.Status == StatusCanceled {
			break
		}
		if betterResult(res, best) {
			best = res
			err = retryErr
		}
		if best.Status == StatusPassed {
			break
		}
	}
	return best, err
}

// verdictRank orders statuses for picking the best of several attempts.
func verdictRank(status string) int {
	switch status {
	case StatusPassed:
		return 3
	case StatusSemiPassed:
		return 2
	case StatusTimeout:
		return 1
	default:
		return 0
	}
}

// betterResult reports whether candidate should replace best.
func betterResult(candidate, best Result) bool {
	cr, br := verdictRank(candidate.Status), verdictRank(best.Status)
	if cr != br {
		return cr > br
	}
	if cr < 2 {
		return false // equally failed: keep the first explanation
	}
	return candidate.Delay >= 0 && (best.Delay < 0 || candidate.Delay < best.Delay)
}

// canceledResult marks r as stopped by the run rather than judged.
func canceledResult(r Result, ctx context.Context) (Result, error) {
	r.Status = StatusCanceled
	r.Reason = "test canceled before it finished"
	r.Delay = FailedDelay
	return r, ctx.Err()
}

// MeasureDelayResult holds the timing results from MeasureDelay.
type MeasureDelayResult struct {
	Delay       int64
	Code        int
	Body        []byte
	TTFB        int64
	ConnectTime int64
}

func MeasureDelay(ctx context.Context, client *http.Client, dest string, httpMethod string) (int64, int, []byte, error) {
	res, err := MeasureDelayDetailed(ctx, client, dest, httpMethod)
	if err != nil {
		return -1, -1, nil, err
	}
	return res.Delay, res.Code, res.Body, nil
}

func MeasureDelayDetailed(ctx context.Context, client *http.Client, dest string, httpMethod string) (*MeasureDelayResult, error) {
	req, err := http.NewRequestWithContext(ctx, httpMethod, dest, nil)
	if err != nil {
		return nil, err
	}

	// The trace hooks can fire from transport goroutines, so they record into
	// atomics rather than plain variables.
	var connectStart, connectTime, tlsDone, ttfb atomic.Int64
	start := time.Now()
	sinceStart := func() int64 { return time.Since(start).Milliseconds() }

	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) {
			connectStart.Store(time.Now().UnixNano())
		},
		ConnectDone: func(_, _ string, err error) {
			if at := connectStart.Load(); err == nil && at != 0 {
				connectTime.Store(time.Since(time.Unix(0, at)).Milliseconds())
			}
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				tlsDone.Store(sinceStart())
			}
		},
		GotFirstResponseByte: func() {
			ttfb.Store(sinceStart())
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDelayBody))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	delay := time.Since(start).Milliseconds()

	// Cores dial through their own pipes, so net/http's ConnectStart/Done
	// rarely fire. The TLS handshake to the test URL (through the tunnel) is
	// the closest honest stand-in for "time to connect".
	connect := connectTime.Load()
	if connect == 0 {
		connect = tlsDone.Load()
	}

	return &MeasureDelayResult{
		Delay:       delay,
		Code:        resp.StatusCode,
		Body:        b,
		TTFB:        ttfb.Load(),
		ConnectTime: connect,
	}, nil
}

// zeroReader is an io.Reader that endlessly produces zero bytes.
type zeroReader struct{}

func (z zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// countingReader counts bytes read, so a truncated transfer is measured by what
// actually moved rather than what was requested.
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// speedtestTimeout is the per-direction measurement window for a speed test.
func (e *Examiner) speedtestTimeout() time.Duration {
	if e.SpeedtestTimeout == 0 {
		return defaultSpeedtestTimeout
	}
	return time.Duration(e.SpeedtestTimeout) * time.Second
}

// runSpeedtest measures throughput in both directions and records it on r.
func (e *Examiner) runSpeedtest(ctx context.Context, client *http.Client, r *Result) {
	// Do not reuse the caller's client
	stClient := &http.Client{
		Transport:     client.Transport,
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
	}
	amount := e.SpeedtestKbAmount * 1000
	timeout := e.speedtestTimeout()
	tester := e.speedTester()

	if speed, err := MeasureDownload(ctx, stClient, tester, timeout, amount); err != nil {
		r.appendReason(fmt.Sprintf("speedtest_download_failed: %v", err))
	} else {
		r.DownloadSpeed = speed
	}

	if !tester.CanUpload() {
		r.appendReason("speedtest_upload_skipped: plain download URL")
		return
	}
	if speed, err := MeasureUpload(ctx, stClient, tester, timeout, amount); err != nil {
		r.appendReason(fmt.Sprintf("speedtest_upload_failed: %v", err))
	} else {
		r.UploadSpeed = speed
	}
}

// speedTester returns the configured speed test target, or the default.
func (e *Examiner) speedTester() *SpeedTester {
	if e.SpeedTester != nil {
		return e.SpeedTester
	}
	return speedtest
}

// budgetExpired reports whether reqCtx ended because the speed test's own
// per-direction window ran out, as opposed to the caller cancelling the run.
func budgetExpired(reqCtx, parent context.Context) bool {
	return errors.Is(reqCtx.Err(), context.DeadlineExceeded) && parent.Err() == nil
}

// MeasureDownload pulls up to amount bytes from tester and returns Mbps. The
// timeout is a measurement window, so a partial transfer reports its real
// speed instead of 0 (issue #69). Moving nothing at all is still a failure.
// Timing starts at the first response byte, so dial and TLS setup through the
// tunnel are not counted as transfer time.
func MeasureDownload(ctx context.Context, client *http.Client, tester *SpeedTester, timeout time.Duration, amount uint64) (float32, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req := tester.MakeDownloadHTTPRequest(false, amount)
	var firstByte time.Time
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(reqCtx, trace))

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if firstByte.IsZero() {
		// Custom RoundTrippers (the scanner's uTLS transport) fire no trace
		// hooks; response headers in hand is the next best start.
		firstByte = time.Now()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("unexpected status %s", resp.Status)
	}

	// A plain file may be larger than the requested amount: stop there.
	read, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, int64(amount)))
	elapsed := time.Since(firstByte)
	if copyErr != nil && !(read > 0 && budgetExpired(reqCtx, ctx)) {
		return 0, fmt.Errorf("read body after %d bytes: %w", read, copyErr)
	}
	return mbps(read, elapsed)
}

// MeasureUpload pushes up to amount bytes to tester and returns Mbps. Like
// MeasureDownload, running out of the window mid-body is not a failure. The
// count leads what the server received by the in-flight buffers, a small
// overshoot.
func MeasureUpload(ctx context.Context, client *http.Client, tester *SpeedTester, timeout time.Duration, amount uint64) (float32, error) {
	if !tester.CanUpload() {
		return 0, errors.New("upload is not supported by a plain download URL")
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req := tester.MakeUploadHTTPRequest(false, amount)

	// The transport's write loop reads the body, and a retry (GetBody) may
	// start while an abandoned attempt is still being read, so every
	// attempt counts into its own reader and only the latest is measured.
	var counter atomic.Pointer[countingReader]
	newBody := func() io.ReadCloser {
		c := &countingReader{r: io.LimitReader(zeroReader{}, int64(amount))}
		counter.Store(c)
		return io.NopCloser(c)
	}
	sent := func() int64 { return counter.Load().n.Load() }
	req.Body = newBody()
	req.GetBody = func() (io.ReadCloser, error) { return newBody(), nil }

	// The trace hooks fire on transport goroutines (WroteHeaders on the
	// write loop), so they record offsets from requestStart into atomics;
	// 0 means the hook did not fire.
	requestStart := time.Now()
	var bodyAt, responseAt atomic.Int64
	mark := func(v *atomic.Int64) func() {
		return func() { v.Store(max(1, int64(time.Since(requestStart)))) }
	}
	trace := &httptrace.ClientTrace{
		WroteHeaders:         mark(&bodyAt),
		GotFirstResponseByte: mark(&responseAt),
	}
	req = req.WithContext(httptrace.WithClientTrace(reqCtx, trace))

	resp, err := client.Do(req)
	// Custom RoundTrippers fire no trace hooks: fall back to the request's
	// own start and the moment the response arrived.
	bodyStart := requestStart.Add(time.Duration(bodyAt.Load()))
	if err != nil {
		if n := sent(); n > 0 && budgetExpired(reqCtx, ctx) {
			return mbps(n, time.Since(bodyStart))
		}
		return 0, err
	}
	defer resp.Body.Close()
	gotResponse := time.Now()
	if at := responseAt.Load(); at != 0 {
		gotResponse = requestStart.Add(time.Duration(at))
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return mbps(sent(), gotResponse.Sub(bodyStart))
}

// mbps converts a transferred byte count and its duration into megabits/sec.
func mbps(bytes int64, d time.Duration) (float32, error) {
	if bytes <= 0 {
		return 0, errors.New("no bytes transferred")
	}
	if d <= 0 {
		return 0, errors.New("transfer too fast to time")
	}
	return float32(float64(bytes) * 8 / d.Seconds() / 1e6), nil
}

func CoreHTTPRequest(ctx context.Context, client *http.Client, method, dest string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, dest, nil)
	if err != nil {
		return -1, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return -1, nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func CoreHTTPRequestCustom(ctx context.Context, client *http.Client, timeout time.Duration, req *http.Request) (int, []byte, int64, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req = req.WithContext(timeoutCtx)
	resp, err := client.Do(req)
	if err != nil {
		return -1, nil, 0, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, int64(len(b)), nil
}

// SpeedTester is a speed test target. By default it speaks Cloudflare's
// speed API (GET /__down?bytes=N, POST /__up) on SNI. When DownloadURL is set
// the download is a plain GET of that URL and upload is unavailable.
type SpeedTester struct {
	SNI              string
	DownloadEndpoint string
	UploadEndpoint   string
	DebugEndpoint    string
	// DownloadURL, when set, is fetched as a plain file instead of /__down.
	DownloadURL string
}

var speedtest = &SpeedTester{
	SNI:              "speed.cloudflare.com",
	DebugEndpoint:    "/cdn-cgi/trace",
	DownloadEndpoint: "/__down",
	UploadEndpoint:   "/__up",
}

// DefaultSpeedTester returns the default target (speed.cloudflare.com).
func DefaultSpeedTester() *SpeedTester { return speedtest }

// NewSpeedTester builds a target from a URL. A bare https origin
// (https://host[:port]) must implement Cloudflare's /__down and /__up; a URL
// with a path is treated as a plain file to download.
func NewSpeedTester(rawURL string) (*SpeedTester, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid speedtest URL %q", rawURL)
	}
	switch {
	case u.Path == "" || u.Path == "/":
		if u.Scheme != "https" {
			return nil, fmt.Errorf("speedtest origin %q must be https (Cloudflare-compatible /__down and /__up)", rawURL)
		}
		return &SpeedTester{
			SNI:              u.Host,
			DebugEndpoint:    "/cdn-cgi/trace",
			DownloadEndpoint: "/__down",
			UploadEndpoint:   "/__up",
		}, nil
	case u.Scheme == "http" || u.Scheme == "https":
		return &SpeedTester{SNI: u.Host, DownloadURL: u.String()}, nil
	default:
		return nil, fmt.Errorf("speedtest URL %q must be http or https", rawURL)
	}
}

// CanUpload reports whether the target accepts upload tests.
func (c *SpeedTester) CanUpload() bool { return c.DownloadURL == "" }

func (c *SpeedTester) MakeDownloadHTTPRequest(noTLS bool, amount uint64) *http.Request {
	if c.DownloadURL != "" {
		u, _ := url.Parse(c.DownloadURL) // validated by NewSpeedTester
		return &http.Request{Method: "GET", URL: u, Header: make(http.Header), Host: u.Host}
	}
	scheme := "https"
	if noTLS {
		scheme = "http"
	}
	return &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path:     c.DownloadEndpoint,
			RawQuery: fmt.Sprintf("bytes=%d", amount),
			Scheme:   scheme,
			Host:     c.SNI,
		},
		Header: make(http.Header),
		Host:   c.SNI,
	}
}

func (c *SpeedTester) MakeUploadHTTPRequest(noTLS bool, amount uint64) *http.Request {
	scheme := "https"
	if noTLS {
		scheme = "http"
	}
	// Use io.LimitReader to avoid allocating a massive string for the body.
	// This is more memory-efficient and avoids int overflow on 32-bit systems.
	newBody := func() io.ReadCloser {
		return io.NopCloser(io.LimitReader(zeroReader{}, int64(amount)))
	}
	req := &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path:   c.UploadEndpoint,
			Scheme: scheme,
			Host:   c.SNI,
		},
		Header:        make(http.Header),
		Host:          c.SNI,
		Body:          newBody(),
		ContentLength: int64(amount),
		// Without GetBody the transport cannot replay the body on a redirect
		// or a retried idempotent attempt.
		GetBody: func() (io.ReadCloser, error) { return newBody(), nil },
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	return req
}

func (c *SpeedTester) MakeDebugRequest() *http.Request {
	return &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path:   c.DebugEndpoint,
			Scheme: "https",
			Host:   c.SNI,
		},
		Header: make(http.Header),
		Host:   c.SNI,
	}
}
