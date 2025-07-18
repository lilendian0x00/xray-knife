package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v5/pkg/core"
	"github.com/lilendian0x00/xray-knife/v5/pkg/core/protocol"
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
	DownloadSpeed float32           `csv:"download" json:"download"` // mbps
	UploadSpeed   float32           `csv:"upload" json:"upload"`     // mbps
	IpAddrLoc     string            `csv:"location" json:"location"` // IP address location
}

type Examiner struct {
	Core core.Core

	// Related to automatic core //
	SelectedCore map[string]core.Core
	xrayCore     core.Core
	singboxCore  core.Core
	// =========================== //

	// Maximum allowed delay (in ms)
	MaxDelay    uint16
	Verbose     bool
	ShowBody    bool
	InsecureTLS bool

	DoSpeedtest bool
	DoIPInfo    bool

	TestEndpoint           string
	TestEndpointHttpMethod string
	SpeedtestKbAmount      uint32
}

var (
	failedDelay int64 = 99999
)

type Options struct {
	Core         string    `json:"core"`
	CoreInstance core.Core `json:"-"` // This field should not be part of the JSON payload

	MaxDelay               uint16 `json:"maxDelay"`
	Verbose                bool   `json:"verbose"`
	ShowBody               bool   `json:"showBody"`
	InsecureTLS            bool   `json:"insecureTLS"`
	DoSpeedtest            bool   `json:"speedtest"`
	DoIPInfo               bool   `json:"doIPInfo"`
	TestEndpoint           string `json:"destURL"`
	TestEndpointHttpMethod string `json:"httpMethod"`
	SpeedtestKbAmount      uint32 `json:"speedtestAmount"`
}

func NewExaminer(opts Options) (*Examiner, error) {
	e := &Examiner{
		MaxDelay:               opts.MaxDelay,
		Verbose:                opts.Verbose,
		ShowBody:               opts.ShowBody,
		InsecureTLS:            opts.InsecureTLS,
		DoSpeedtest:            opts.DoSpeedtest,
		DoIPInfo:               opts.DoIPInfo,
		TestEndpoint:           "https://cloudflare.com/cdn-cgi/trace",
		TestEndpointHttpMethod: "GET",
		SpeedtestKbAmount:      10000,
	}

	switch opts.Core {
	case "xray":
		e.Core = core.CoreFactory(core.XrayCoreType, e.InsecureTLS, e.Verbose)
	case "singbox":
		e.Core = core.CoreFactory(core.SingboxCoreType, e.InsecureTLS, e.Verbose)
	case "auto":
		fallthrough
	default:
		e.Core = core.NewAutomaticCore(e.InsecureTLS, e.Verbose)
	}

	if e.Core == nil {
		return nil, fmt.Errorf("failed to create core of type: %s", opts.Core)
	}

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
		Delay:      failedDelay,
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
		fmt.Printf("%v%s: %s\n\n", proto.DetailsStr(), color.RedString("Link"), proto.GetLink())
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

	client, instance, err := e.Core.MakeHttpClient(ctx, proto, time.Duration(e.MaxDelay)*time.Millisecond)
	if err != nil {
		r.Status = "broken"
		r.Reason = err.Error()
		return r, err
	}
	defer instance.Close()

	delay, _, body, err := MeasureDelay(ctx, client, e.ShowBody, e.TestEndpoint, e.TestEndpointHttpMethod)
	if err != nil {
		r.Status = "failed"
		r.Reason = err.Error()
		return r, err
	}
	r.Delay = delay

	if uint16(delay) > e.MaxDelay {
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
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://cloudflare.com/cdn-cgi/trace", nil)
			_, ipBody, traceErr := CoreHTTPRequestCustom(ctx, client, 10*time.Second, req)
			if traceErr != nil {
				if r.Reason != "" {
					r.Reason += "; "
				}
				r.Reason += "ip_info_failed"
			} else {
				parseTraceBody(ipBody, &r)
			}
		}
	}

	if e.DoSpeedtest {
		downloadStartTime := time.Now()
		_, _, err := CoreHTTPRequestCustom(ctx, client, time.Duration(20000)*time.Millisecond, speedtest.MakeDownloadHTTPRequest(false, e.SpeedtestKbAmount*1000))
		if err == nil {
			downloadTime := time.Since(downloadStartTime).Milliseconds()
			r.DownloadSpeed = (float32((e.SpeedtestKbAmount*1000)*8) / (float32(downloadTime) / float32(1000.0))) / float32(1000000.0)
		}

		uploadStartTime := time.Now()
		_, _, err = CoreHTTPRequestCustom(ctx, client, time.Duration(20000)*time.Millisecond, speedtest.MakeUploadHTTPRequest(false, e.SpeedtestKbAmount*1000))
		if err == nil {
			uploadTime := time.Since(uploadStartTime).Milliseconds()
			r.UploadSpeed = (float32((e.SpeedtestKbAmount*1000)*8) / (float32(uploadTime) / float32(1000.0))) / float32(1000000.0)
		}
	}

	return r, nil
}

func MeasureDelay(ctx context.Context, client *http.Client, showBody bool, dest string, httpMethod string) (int64, int, []byte, error) {
	start := time.Now()
	code, body, err := CoreHTTPRequest(ctx, client, httpMethod, dest)
	if err != nil {
		return -1, -1, nil, err
	}
	if showBody {
		fmt.Printf("Response body: \n%s\n", body)
	}
	return time.Since(start).Milliseconds(), code, body, nil
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
	req, _ := http.NewRequestWithContext(ctx, method, dest, nil)
	resp, err := client.Do(req)
	if err != nil {
		return -1, nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func CoreHTTPRequestCustom(ctx context.Context, client *http.Client, timeout time.Duration, req *http.Request) (int, []byte, error) {
	req = req.WithContext(ctx)
	client.Timeout = timeout
	resp, err := client.Do(req)
	if err != nil {
		return -1, nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
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

func (c *SpeedTester) MakeDownloadHTTPRequest(noTLS bool, amount uint32) *http.Request {
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

func (c *SpeedTester) MakeUploadHTTPRequest(noTLS bool, amount uint32) *http.Request {
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
