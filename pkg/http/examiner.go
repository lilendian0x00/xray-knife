package http

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/lilendian0x00/xray-knife/v5/pkg/core"
	"github.com/lilendian0x00/xray-knife/v5/pkg/core/protocol"
)

type Result struct {
	ConfigLink    string            `csv:"link" json:"link"` // vmess://... vless//..., etc
	Protocol      protocol.Protocol `csv:"-" json:"-"`
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
	Core         string
	CoreInstance core.Core

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

	if opts.CoreInstance != nil {
		e.Core = opts.CoreInstance
	} else {
		switch opts.Core {
		case "xray":
			e.Core = core.CoreFactory(core.XrayCoreType, e.InsecureTLS, e.Verbose)
			break
		case "singbox":
			e.Core = core.CoreFactory(core.SingboxCoreType, e.InsecureTLS, e.Verbose)
			break
		default:
			e.Core = nil
			e.xrayCore = core.CoreFactory(core.XrayCoreType, e.InsecureTLS, e.Verbose)
			e.singboxCore = core.CoreFactory(core.SingboxCoreType, e.InsecureTLS, e.Verbose)
			e.SelectedCore = map[string]core.Core{
				protocol.VmessIdentifier:       e.xrayCore,
				protocol.VlessIdentifier:       e.xrayCore,
				protocol.ShadowsocksIdentifier: e.xrayCore,
				protocol.TrojanIdentifier:      e.xrayCore,
				protocol.SocksIdentifier:       e.xrayCore,
				protocol.WireguardIdentifier:   e.xrayCore,
				protocol.Hysteria2Identifier:   e.singboxCore,
				"hy2":                          e.singboxCore,
			}
			break
		}
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
		e.TestEndpointHttpMethod = "GET"
	}

	return e, nil
}

func (e *Examiner) ExamineConfig(link string) (Result, error) {
	r := Result{
		ConfigLink: link,
		Status:     "passed",
		Delay:      failedDelay,
		RealIPAddr: "null",
		IpAddrLoc:  "null",
	}

	if link == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Reading config from STDIN:")
		text, _ := reader.ReadString('\n')
		link = text
		fmt.Printf("\n")
	}

	// Remove any spaces from the link
	link = strings.TrimSpace(link)

	var c = e.Core

	// Select core based on config (Automatic Core)
	if c == nil {
		uri, err := url.Parse(link)
		if err != nil {
			return Result{}, errors.New(fmt.Sprintf("Couldn't parse the config: %v", err))
		}

		coreAuto, ok := e.SelectedCore[uri.Scheme]
		if !ok {
			return Result{}, errors.New(fmt.Sprintf("Couldn't parse the config: invalid protocol"))
		}

		c = coreAuto
	}

	proto, err := c.CreateProtocol(link)
	if err != nil {
		r.Status = "broken"
		r.Reason = fmt.Sprintf("create protocol: %v", err)
		return r, errors.New(r.Reason)
	}

	err = proto.Parse()
	if err != nil {
		r.Status = "broken"
		r.Reason = fmt.Sprintf("parse protocol: %v", err)
		return r, errors.New(r.Reason)
	}

	if e.Verbose {
		fmt.Printf("%v%s: %s\n\n", proto.DetailsStr(), color.RedString("Link"), proto.GetLink())
	}

	r.Protocol = proto
	r.TLS = proto.ConvertToGeneralConfig().TLS

	client, instance, err := c.MakeHttpClient(proto, time.Duration(e.MaxDelay)*time.Millisecond)
	if err != nil {
		r.Status = "broken"
		r.Reason = err.Error()
		return r, err
	}
	defer instance.Close()

	var delay int64

	delay, _, err = MeasureDelay(client, e.ShowBody, e.TestEndpoint, e.TestEndpointHttpMethod)
	if err != nil {
		r.Status = "failed"
		r.Reason = err.Error()
		return r, err
	}
	r.Delay = delay

	defer func() {
		if e.DoSpeedtest && r.Status == "passed" && (r.UploadSpeed == 0 || r.DownloadSpeed == 0) {
			r.Status = "semi-passed"
		}
	}()

	if uint16(delay) > e.MaxDelay {
		r.Status = "timeout"
		r.Reason = "config delay is more than the maximum allowed delay"
		return r, errors.New(r.Reason)
	}

	if e.DoIPInfo {
		_, body, err := CoreHTTPRequestCustom(client, time.Duration(10000)*time.Millisecond, speedtest.MakeDebugRequest())
		if err != nil {
			// Do nothing
		} else {
			for _, line := range strings.Split(string(body), "\n") {
				s := strings.SplitN(line, "=", 2)
				if len(s) == 2 {
					if s[0] == "ip" {
						r.RealIPAddr = s[1]
					} else if s[0] == "loc" {
						r.IpAddrLoc = s[1]
						break
					}
				}
			}
		}
	}

	if e.DoSpeedtest {
		downloadStartTime := time.Now()
		_, _, err := CoreHTTPRequestCustom(client, time.Duration(20000)*time.Millisecond, speedtest.MakeDownloadHTTPRequest(false, e.SpeedtestKbAmount*1000))
		if err == nil {
			downloadTime := time.Since(downloadStartTime).Milliseconds()
			r.DownloadSpeed = (float32((e.SpeedtestKbAmount*1000)*8) / (float32(downloadTime) / float32(1000.0))) / float32(1000000.0)
		}

		uploadStartTime := time.Now()
		_, _, err = CoreHTTPRequestCustom(client, time.Duration(20000)*time.Millisecond, speedtest.MakeUploadHTTPRequest(false, e.SpeedtestKbAmount*1000))
		if err == nil {
			uploadTime := time.Since(uploadStartTime).Milliseconds()
			r.UploadSpeed = (float32((e.SpeedtestKbAmount*1000)*8) / (float32(uploadTime) / float32(1000.0))) / float32(1000000.0)
		}
	}

	return r, nil
}

func MeasureDelay(client *http.Client, showBody bool, dest string, httpMethod string) (int64, int, error) {
	start := time.Now()
	code, body, err := CoreHTTPRequest(client, httpMethod, dest)
	if err != nil {
		return -1, -1, err
	}
	if showBody {
		fmt.Printf("Response body: \n%s\n", body)
	}
	return time.Since(start).Milliseconds(), code, nil
}

func CoreHTTPRequest(client *http.Client, method, dest string) (int, []byte, error) {
	req, _ := http.NewRequest(method, dest, nil)
	resp, err := client.Do(req)
	if err != nil {
		return -1, nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func CoreHTTPRequestCustom(client *http.Client, timeout time.Duration, req *http.Request) (int, []byte, error) {
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
	lk := strings.NewReader(strings.Repeat("0", int(amount)))
	rc := io.NopCloser(lk)
	return &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path:   c.UploadEndpoint,
			Scheme: scheme,
			Host:   c.SNI,
		},
		Header: make(http.Header),
		Host:   c.SNI,
		Body:   rc,
	}
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
