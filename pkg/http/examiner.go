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
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/lilendian0x00/xray-knife/v9/pkg/core"
	"github.com/lilendian0x00/xray-knife/v9/pkg/core/protocol"
)

// ProtocolInfo holds basic, serializable information about a protocol.
type ProtocolInfo struct {
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     string `json:"port"`
}

type Result struct {
	ConfigLink    string            `csv:"link" json:"link"`         // vmess://... vless//..., etc
	Protocol      protocol.Protocol `csv:"-" json:"-"`               // The full protocol object for internal use
	ProtocolInfo  ProtocolInfo      `csv:"-" json:"protocol"`        // Serializable info for the frontend
	Status        string            `csv:"status" json:"status"`     // passed, semi-passed, failed, broken
	Reason        string            `csv:"reason" json:"reason"`     // reason of the error
	TLS           string            `csv:"tls" json:"tls"`           // none, tls, reality
	RealIPAddr    string            `csv:"ip" json:"ip"`             // Real ip address (req to cloudflare.com/cdn-cgi/trace)
	Delay         int64             `csv:"delay" json:"delay"`       // millisecond
	HTTPCode      int               `csv:"code" json:"code"`         // HTTP status code of the tested URL
	DownloadSpeed float32           `csv:"download" json:"download"`       // mbps
	UploadSpeed   float32           `csv:"upload" json:"upload"`           // mbps
	IpAddrLoc     string            `csv:"location" json:"location"`       // IP address location
	TTFB          int64             `csv:"ttfb" json:"ttfb"`               // Time to first byte (ms)
	ConnectTime   int64             `csv:"connect_time" json:"connectTime"` // Connection time (ms)
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
	Timeout  uint16
	Verbose  bool
	ShowBody bool
	InsecureTLS bool

	DoSpeedtest bool
	DoIPInfo    bool

	TestEndpoint           string
	TestEndpointHttpMethod string
	SpeedtestKbAmount      uint64
	Retries                uint8

	Logger *log.Logger `json:"-"`
}

const FailedDelay int64 = -1

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
	SpeedtestKbAmount      uint64 `json:"speedtestAmount"`
	Retries                uint8  `json:"retries"`
	Logger                 *log.Logger `json:"-"`
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

	e.Retries = opts.Retries

	// Set logger: use provided logger or default to stdout
	if opts.Logger != nil {
		e.Logger = opts.Logger
	} else {
		e.Logger = log.New(os.Stdout, "", 0)
	}

	switch opts.Core {
	case "xray":
		e.Core = core.CoreFactory(core.XrayCoreType, e.InsecureTLS, e.Verbose)
	case "singbox", "sing-box":
		e.Core = core.CoreFactory(core.SingboxCoreType, e.InsecureTLS, e.Verbose)
	case "auto":
		fallthrough
	default:
		e.Core = core.NewAutomaticCore(e.Verbose, e.InsecureTLS)
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

	client, instance, err := e.Core.MakeHttpClient(ctx, proto, time.Duration(e.Timeout)*time.Millisecond)
	if err != nil {
		r.Status = "broken"
		r.Reason = err.Error()
		return r, err
	}
	defer instance.Close()

	delayResult, err := MeasureDelayDetailed(ctx, client, e.TestEndpoint, e.TestEndpointHttpMethod)
	if err != nil {
		r.Status = "failed"
		r.Reason = err.Error()
		return r, err
	}
	if e.ShowBody {
		e.Logger.Printf("Response body: \n%s\n", delayResult.Body)
	}
	r.Delay = delayResult.Delay
	r.HTTPCode = delayResult.Code
	r.TTFB = delayResult.TTFB
	r.ConnectTime = delayResult.ConnectTime
	body := delayResult.Body

	if r.Delay > int64(e.MaxDelay) {
		r.Status = "timeout"
		r.Reason = "config delay is more than the maximum allowed delay"
		return r, errors.New(r.Reason)
	}

	if e.DoIPInfo {
		// If the latency test URL was already the trace endpoint, use its body.
		if strings.Contains(e.TestEndpoint, "/cdn-cgi/trace") {
			parseTraceBody(body, &r)
		} else {
			// Otherwise, make a dedicated request for the IP info.
			// Use a standard, reliable trace endpoint.
			req, reqErr := http.NewRequestWithContext(ctx, "GET", "https://cloudflare.com/cdn-cgi/trace", nil)
			if reqErr != nil {
				if r.Reason != "" {
					r.Reason += "; "
				}
				r.Reason += "ip_info_failed"
				r.Status = "semi-passed"
			} else {
				_, ipBody, _, traceErr := CoreHTTPRequestCustom(ctx, client, 10*time.Second, req)
				if traceErr != nil {
					if r.Reason != "" {
						r.Reason += "; "
					}
					r.Reason += "ip_info_failed"
					r.Status = "semi-passed"
				} else {
					parseTraceBody(ipBody, &r)
				}
			}
		}
	}

	if e.DoSpeedtest {
		downloadStartTime := time.Now()
		_, _, bytesRead, dlErr := CoreHTTPRequestCustom(ctx, client, 20*time.Second, speedtest.MakeDownloadHTTPRequest(false, e.SpeedtestKbAmount*1000))
		if dlErr == nil {
			downloadTime := time.Since(downloadStartTime).Milliseconds()
			// Use actual bytes received for accurate speed calculation
			r.DownloadSpeed = (float32(bytesRead*8) / (float32(downloadTime) / float32(1000.0))) / float32(1000000.0)
		}

		uploadStartTime := time.Now()
		byteAmount := e.SpeedtestKbAmount * 1000
		_, _, _, ulErr := CoreHTTPRequestCustom(ctx, client, 20*time.Second, speedtest.MakeUploadHTTPRequest(false, byteAmount))
		if ulErr == nil {
			uploadTime := time.Since(uploadStartTime).Milliseconds()
			// For upload, use intended byte amount (request body is locally generated)
			r.UploadSpeed = (float32(byteAmount*8) / (float32(uploadTime) / float32(1000.0))) / float32(1000000.0)
		}
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
	bodyReader := io.LimitReader(zeroReader{}, int64(amount))
	req := &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path:   c.UploadEndpoint,
			Scheme: scheme,
			Host:   c.SNI,
		},
		Header:        make(http.Header),
		Host:          c.SNI,
		Body:          io.NopCloser(bodyReader),
		ContentLength: int64(amount),
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
