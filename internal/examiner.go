package internal

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/lilendian0x00/xray-knife/internal/protocol"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/speedtester/cloudflare"
)

type Result struct {
	ConfigLink    string            `csv:"link"` // vmess://... vless//..., etc
	Protocol      protocol.Protocol `csv:"-"`
	Status        string            `csv:"status"`   // passed, semi-passed, failed
	TLS           string            `csv:"tls"`      // none, tls, reality
	RealIPAddr    string            `csv:"ip"`       // Real ip address (req to cloudflare.com/cdn-cgi/trace)
	Delay         int64             `csv:"delay"`    // millisecond
	DownloadSpeed float32           `csv:"download"` // mbps
	UploadSpeed   float32           `csv:"upload"`   // mbps
	IpAddrLoc     string            `csv:"location"` // IP address location
}

type Examiner struct {
	Core Core

	// Related to automatic core //
	SelectedCore map[string]Core
	xrayCore     Core
	singboxCore  Core
	// =========================== //

	// Maximum allowed delay (in ms)
	MaxDelay uint16
	Verbose  bool
	ShowBody bool

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
	CoreInstance Core

	// Maximum allowed delay (in ms)
	MaxDelay uint16
	Verbose  bool
	ShowBody bool

	DoSpeedtest bool
	DoIPInfo    bool

	TestEndpoint           string
	TestEndpointHttpMethod string
	SpeedtestKbAmount      uint32
}

func NewExaminer(opts Options) (*Examiner, error) {
	e := &Examiner{
		MaxDelay:               10000,
		Verbose:                opts.Verbose,
		ShowBody:               opts.ShowBody,
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
			e.Core = CoreFactory(XrayCoreType)
			break
		case "singbox":
			e.Core = CoreFactory(SingboxCoreType)
			break
		default:
			e.Core = nil
			e.xrayCore = CoreFactory(XrayCoreType)
			e.singboxCore = CoreFactory(SingboxCoreType)
			e.SelectedCore = map[string]Core{
				protocol.VmessIdentifier:       e.singboxCore,
				protocol.VlessIdentifier:       e.singboxCore,
				protocol.ShadowsocksIdentifier: e.singboxCore,
				protocol.TrojanIdentifier:      e.singboxCore,
				protocol.SocksIdentifier:       e.singboxCore,
				protocol.WireguardIdentifier:   e.singboxCore,
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

	// Remove any spaces
	link = strings.TrimSpace(link)

	var core = e.Core

	// Automatic Core
	if core == nil {
		uri, err := url.Parse(link)
		if err != nil {
			return Result{}, errors.New(fmt.Sprintf("Couldn't parse the config: %v", err))
		}

		coreAuto, ok := e.SelectedCore[uri.Scheme]
		if !ok {
			return Result{}, errors.New(fmt.Sprintf("Couldn't parse the config: invalid protocol"))
		}

		core = coreAuto
	}

	proto, err := core.CreateProtocol(link)
	if err != nil {
		return r, errors.New(fmt.Sprintf("Couldn't parse the config: %v", err))
		//os.Exit(1)
	}

	err = proto.Parse()
	if err != nil {
		return r, errors.New(fmt.Sprintf("Couldn't parse the config: %v", err))
	}

	if e.Verbose {
		fmt.Printf("%v\n", proto.DetailsStr())
	}

	r.Protocol = proto
	r.TLS = proto.ConvertToGeneralConfig().TLS

	client, instance, err1 := core.MakeHttpClient(proto)
	if err1 != nil {
		r.Status = "broken"
		return r, nil
	}
	// Close xray conn after testing
	defer instance.Close()

	var delay int64
	var downloadTime int64
	var uploadTime int64

	delay, _, err = MeasureDelay(client, time.Duration(10000)*time.Millisecond, e.ShowBody, e.TestEndpoint, e.TestEndpointHttpMethod)
	if err != nil {
		//customlog.Printf(customlog.Failure, "Config didn't respond!\n\n")
		r.Status = "failed"
		return r, nil
		//os.Exit(1)
	}
	r.Delay = delay

	defer func() {
		if e.DoSpeedtest && r.Status == "passed" && /*r.Delay != failedDelay &&*/ (r.UploadSpeed == 0 || r.DownloadSpeed == 0) {
			r.Status = "semi-passed"
		}
	}()

	if uint16(delay) > e.MaxDelay {
		r.Status = "timeout"
		return r, nil
	}

	if e.DoIPInfo {
		_, body, err := CoreHTTPRequestCustom(client, time.Duration(10000)*time.Millisecond, cloudflare.Speedtest.MakeDebugRequest())
		if err != nil {
			//customlog.Printf(customlog.Failure, "failed getting ip info!\n")
			//return
		} else {
			for _, line := range strings.Split(string(body), "\n") {
				s := strings.SplitN(line, "=", 2)
				if s[0] == "ip" {
					r.RealIPAddr = s[1]
				} else if s[0] == "loc" {
					r.IpAddrLoc = s[1]
					break
				}
			}

		}
	}

	if e.DoSpeedtest {
		downloadStartTime := time.Now()
		_, _, err = CoreHTTPRequestCustom(client, time.Duration(20000)*time.Millisecond, cloudflare.Speedtest.MakeDownloadHTTPRequest(false, e.SpeedtestKbAmount*1000))
		if err != nil {
			//customlog.Printf(customlog.Failure, "Download failed!\n")
			//return
		} else {
			downloadTime = time.Since(downloadStartTime).Milliseconds()
			r.DownloadSpeed = (float32((e.SpeedtestKbAmount*1000)*8) / (float32(downloadTime) / float32(1000.0))) / float32(1000000.0)
			//customlog.Printf(customlog.Success, "Download took: %dms\n", downloadTime)
		}

		uploadStartTime := time.Now()
		_, _, err = CoreHTTPRequestCustom(client, time.Duration(20000)*time.Millisecond, cloudflare.Speedtest.MakeUploadHTTPRequest(false, e.SpeedtestKbAmount*1000))
		if err != nil {
			//customlog.Printf(customlog.Failure, "Upload failed!\n")
			//return
		} else {
			uploadTime = time.Since(uploadStartTime).Milliseconds()
			r.UploadSpeed = (float32((e.SpeedtestKbAmount*1000)*8) / (float32(uploadTime) / float32(1000.0))) / float32(1000000.0)
			//customlog.Printf(customlog.Success, "Upload took: %dms\n", uploadTime)
		}
	}

	//customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", delay)
	//}

	return r, nil
}

func MeasureDelay(client *http.Client, timeout time.Duration, showBody bool, dest string, httpMethod string) (int64, int, error) {
	start := time.Now()
	code, body, err := CoreHTTPRequest(client, timeout, httpMethod, dest)
	if err != nil {
		return -1, -1, err
	}
	//fmt.Printf("%s: %d\n", color.YellowString("Status code"), code)
	if showBody {
		fmt.Printf("Response body: \n%s\n", body)
	}
	return time.Since(start).Milliseconds(), code, nil
}

func CoreHTTPRequest(client *http.Client, timeout time.Duration, method, dest string) (int, []byte, error) {
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
