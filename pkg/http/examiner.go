package http

import (
	"bufio"
	"context"
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
	// Per-endpoint visibility: EndpointResults is the structured breakdown
	// (JSON/web), EndpointSummary is a compact one-line form (CSV/logs).
	EndpointResults []EndpointResult `csv:"-" json:"endpoints,omitempty"`
	EndpointSummary string           `csv:"endpoints" json:"endpointSummary"`
}

// appendReason adds a note to Reason, keeping any note already recorded.
func (r *Result) appendReason(reason string) {
	if r.Reason != "" {
		r.Reason += "; "
	}
	r.Reason += reason
}

// EndpointCheck describes a single destination probed while grading a config.
// ExpectStatus is the exact HTTP status required for the check to count as a
// success; 0 means any 2xx response is accepted.
type EndpointCheck struct {
	URL          string `json:"url"`
	Method       string `json:"method"`
	ExpectStatus int    `json:"expectStatus"`
}

// EndpointResult records the outcome of probing one panel endpoint, so callers
// can see which destination failed and why — not just the aggregate count.
type EndpointResult struct {
	URL      string `json:"url"`
	Label    string `json:"label"`            // short host label, e.g. "gstatic.com"
	Outcome  string `json:"outcome"`          // ok, slow, bad-status, error
	HTTPCode int    `json:"code"`             // -1 when no response
	Delay    int64  `json:"delay"`            // ms; -1 when no response
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

// statusOK reports whether an HTTP status code satisfies an endpoint's
// expectation. When expect is 0, any 2xx code passes; otherwise the code must
// match exactly — so a captive portal answering 200 to a generate_204 probe is
// correctly rejected instead of counted as working.
func statusOK(code, expect int) bool {
	if expect != 0 {
		return code == expect
	}
	return code >= 200 && code < 300
}

// expectedStatusFor infers the success code for a URL when the caller did not
// set one explicitly: generate_204 endpoints must answer 204, everything else
// accepts any 2xx.
func expectedStatusFor(rawURL string) int {
	if strings.Contains(rawURL, "generate_204") {
		return 204
	}
	return 0
}

// CheckPresets are named, network-diverse endpoint panels. Each spans a
// distinct provider/DNS zone, so a config that only reaches one CDN (a common
// failure of Cloudflare-fronted or server-side-DNS-broken proxies) is graded as
// partial rather than fully working.
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

	// Related to automatic core //
	SelectedCore map[string]core.Core
	xrayCore     core.Core
	singboxCore  core.Core
	// =========================== //

	// Maximum allowed delay (in ms) — used as the pass/fail latency threshold
	MaxDelay uint16
	// Connection timeout (in ms) — used for the HTTP client timeout
	Timeout     uint16
	Verbose     bool
	ShowBody    bool
	InsecureTLS bool

	DoSpeedtest bool
	DoIPInfo    bool

	TestEndpoint           string
	TestEndpointHttpMethod string
	// TestEndpoints, when non-empty, replaces the single TestEndpoint with a
	// diverse panel: the config is probed against every entry and graded by how
	// many succeed (see SuccessThreshold).
	TestEndpoints     []EndpointCheck
	SuccessThreshold  float64
	SpeedtestKbAmount uint64
	SpeedtestTimeout  uint16
	Retries           uint8

	// BindInterface pins outbound core dials to a specific OS interface.
	// Empty disables binding.
	BindInterface string

	Logger *log.Logger `json:"-"`
}

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
	// TestEndpoints, when non-empty, enables multi-endpoint grading (overrides
	// the single TestEndpoint). SuccessThreshold is the fraction of endpoints
	// that must pass for a "passed" verdict (0 defaults to 1.0 = all).
	TestEndpoints     []EndpointCheck `json:"testEndpoints,omitempty"`
	SuccessThreshold  float64         `json:"successThreshold,omitempty"`
	SpeedtestKbAmount uint64          `json:"speedtestAmount"`
	SpeedtestTimeout  uint16          `json:"speedtestTimeout,omitempty"`
	Retries           uint8           `json:"retries"`
	BindInterface     string          `json:"bindInterface,omitempty"`
	Logger            *log.Logger     `json:"-"`
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

	e.Retries = opts.Retries
	e.BindInterface = opts.BindInterface
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
			}
		}
	}
}

// checks returns the effective endpoint panel for a test. An explicit panel is
// used as-is (filling in per-endpoint defaults); otherwise it falls back to the
// single legacy TestEndpoint, preserving the original single-URL behavior.
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

// passesThreshold reports whether the success ratio clears the "passed" bar.
// All endpoints passing always qualifies; otherwise successes/total must be at
// least threshold (a small epsilon absorbs float rounding).
func passesThreshold(successes, total int, threshold float64) bool {
	if total <= 0 {
		return false
	}
	if successes >= total {
		return true
	}
	return float64(successes)/float64(total)+1e-9 >= threshold
}

func (e *Examiner) ExamineConfig(ctx context.Context, link string) (Result, error) {
	r := Result{
		ConfigLink: link,
		Status:     "passed",
		Delay:      FailedDelay,
		HTTPCode:   -1,
		RealIPAddr: "null",
		IpAddrLoc:  "null",
	}

	// Remove any spaces from the link
	link = strings.TrimSpace(link)
	if link == "" {
		r.Status = "broken"
		r.Reason = "config link is empty"
		return r, errors.New(r.Reason)
	}

	proto, err := e.Core.CreateProtocol(link)
	if err != nil {
		r.Status = "broken"
		r.Reason = fmt.Sprintf("create protocol: %v", err)
		return r, errors.New(r.Reason)
	}

	if err = proto.Parse(); err != nil {
		r.Status = "broken"
		r.Reason = fmt.Sprintf("parse protocol: %v", err)
		return r, errors.New(r.Reason)
	}

	if e.Verbose {
		e.Logger.Printf("%v%s: %s\n\n", proto.DetailsStr(), color.RedString("Link"), proto.GetLink())
	}

	r.Protocol = proto
	generalConfig := proto.ConvertToGeneralConfig()
	r.ProtocolInfo = ProtocolInfo{
		Remark:   generalConfig.Remark,
		Protocol: generalConfig.Protocol,
		Address:  generalConfig.Address,
		Port:     generalConfig.Port,
	}
	r.TLS = generalConfig.TLS

	// Protocols that cannot carry HTTP (MTProto proxies) grade themselves.
	if prober, ok := proto.(protocol.Prober); ok {
		return e.examineProbe(ctx, r, prober)
	}

	client, instance, err := e.Core.MakeHttpClient(ctx, proto, time.Duration(e.Timeout)*time.Millisecond)
	if err != nil {
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

		// A slow-but-alive endpoint and a wrong status are both failures; record
		// the reason so a fully-failed config explains itself.
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
	r.SuccessCount = successes
	r.EndpointResults = endpointResults
	r.EndpointSummary = summarizeEndpoints(endpointResults)
	total := len(checks)

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
		// Nothing passed. For the single-endpoint path, preserve the original
		// failed/timeout contract (and returned error) so existing callers and
		// the proxy health check behave exactly as before.
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
			// Otherwise, make a dedicated request for the IP info.
			// Use a standard, reliable trace endpoint.
			req, reqErr := http.NewRequestWithContext(ctx, "GET", "https://cloudflare.com/cdn-cgi/trace", nil)
			if reqErr != nil {
				r.appendReason("ip_info_failed")
				r.Status = "semi-passed"
			} else {
				_, ipBody, _, traceErr := CoreHTTPRequestCustom(ctx, client, 10*time.Second, req)
				if traceErr != nil {
					r.appendReason("ip_info_failed")
					r.Status = "semi-passed"
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

// ExamineConfigWithRetries runs ExamineConfig up to 1+Retries times, keeping the best result.
func (e *Examiner) ExamineConfigWithRetries(ctx context.Context, link string) (Result, error) {
	best, err := e.ExamineConfig(ctx, link)
	if e.Retries == 0 || best.Status == "passed" {
		return best, err
	}

	for i := uint8(0); i < e.Retries; i++ {
		if ctx.Err() != nil {
			break
		}
		res, retryErr := e.ExamineConfig(ctx, link)
		// Keep the best result: prefer passed, then lowest delay
		if res.Status == "passed" && (best.Status != "passed" || (res.Delay >= 0 && res.Delay < best.Delay)) {
			best = res
			err = retryErr
		}
		if best.Status == "passed" {
			break
		}
	}
	return best, err
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

	var connectStart time.Time
	var connectTime int64
	var ttfb int64
	start := time.Now()

	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) {
			connectStart = time.Now()
		},
		ConnectDone: func(_, _ string, err error) {
			if err == nil && !connectStart.IsZero() {
				connectTime = time.Since(connectStart).Milliseconds()
			}
		},
		GotFirstResponseByte: func() {
			ttfb = time.Since(start).Milliseconds()
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	delay := time.Since(start).Milliseconds()

	return &MeasureDelayResult{
		Delay:       delay,
		Code:        resp.StatusCode,
		Body:        b,
		TTFB:        ttfb,
		ConnectTime: connectTime,
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

// countingReader wraps an io.Reader and counts the total bytes read from it,
// so a truncated transfer is measured by what actually moved rather than by
// what was requested.
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

	if speed, err := measureDownload(ctx, stClient, timeout, amount); err != nil {
		r.appendReason(fmt.Sprintf("speedtest_download_failed: %v", err))
	} else {
		r.DownloadSpeed = speed
	}

	if speed, err := measureUpload(ctx, stClient, timeout, amount); err != nil {
		r.appendReason(fmt.Sprintf("speedtest_upload_failed: %v", err))
	} else {
		r.UploadSpeed = speed
	}
}

// budgetExpired reports whether reqCtx ended because the speed test's own
// per-direction window ran out, as opposed to the caller cancelling the run.
func budgetExpired(reqCtx, parent context.Context) bool {
	return errors.Is(reqCtx.Err(), context.DeadlineExceeded) && parent.Err() == nil
}

// measureDownload pulls up to amount bytes from the speed test endpoint and
// returns the throughput in Mbps. The timeout is a measurement window, not a
// pass/fail bar: when it runs out mid-transfer the bytes that did arrive are
// measured over the time they took, so a link slower than amount/timeout
// reports its real speed instead of 0 (issue #69). A transfer that moved
// nothing at all is still a failure.
func measureDownload(ctx context.Context, client *http.Client, timeout time.Duration, amount uint64) (float32, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req := speedtest.MakeDownloadHTTPRequest(false, amount)
	firstByte := time.Now()
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(reqCtx, trace))

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("unexpected status %s", resp.Status)
	}

	read, copyErr := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(firstByte)
	if copyErr != nil && !(read > 0 && budgetExpired(reqCtx, ctx)) {
		return 0, fmt.Errorf("read body after %d bytes: %w", read, copyErr)
	}
	return mbps(read, elapsed)
}

// measureUpload pushes up to amount bytes to the speed test endpoint and
// returns the throughput in Mbps. As with measureDownload, running out of the
// window mid-body is not a failure: the bytes handed to the transport so far
// are measured over the window. That count leads what the server has actually
// received by the in-flight socket buffers, which is a small overshoot on a
// multi-second window.
func measureUpload(ctx context.Context, client *http.Client, timeout time.Duration, amount uint64) (float32, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req := speedtest.MakeUploadHTTPRequest(false, amount)

	counter := &countingReader{}
	newBody := func() io.ReadCloser {
		counter.r = io.LimitReader(zeroReader{}, int64(amount))
		counter.n.Store(0)
		return io.NopCloser(counter)
	}
	req.Body = newBody()
	req.GetBody = func() (io.ReadCloser, error) { return newBody(), nil }

	bodyStart, gotResponse := time.Now(), time.Now()
	trace := &httptrace.ClientTrace{
		WroteHeaders:         func() { bodyStart = time.Now() },
		GotFirstResponseByte: func() { gotResponse = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(reqCtx, trace))

	resp, err := client.Do(req)
	if err != nil {
		if sent := counter.n.Load(); sent > 0 && budgetExpired(reqCtx, ctx) {
			return mbps(sent, time.Since(bodyStart))
		}
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return mbps(counter.n.Load(), gotResponse.Sub(bodyStart))
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

type SpeedTester struct {
	SNI              string
	DownloadEndpoint string
	UploadEndpoint   string
	DebugEndpoint    string
}

var speedtest = &SpeedTester{
	SNI:              "speed.cloudflare.com",
	DebugEndpoint:    "/cdn-cgi/trace",
	DownloadEndpoint: "/__down",
	UploadEndpoint:   "/__up",
}

func (c *SpeedTester) MakeDownloadHTTPRequest(noTLS bool, amount uint64) *http.Request {
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
