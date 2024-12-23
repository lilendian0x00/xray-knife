package xray

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v2/speedtester/cloudflare"
)

type Result struct {
	ConfigLink    string   `csv:"link"` // vmess://... vless//..., etc
	Protocol      Protocol `csv:"-"`
	Status        string   `csv:"status"`   // passed, semi-passed, failed
	TLS           string   `csv:"tls"`      // none, tls, reality
	RealIPAddr    string   `csv:"ip"`       // Real ip address (req to cloudflare.com/cdn-cgi/trace)
	Delay         int64    `csv:"delay"`    // millisecond
	DownloadSpeed float32  `csv:"download"` // mbps
	UploadSpeed   float32  `csv:"upload"`   // mbps
	IpAddrLoc     string   `csv:"location"` // IP address location
}

type Examiner struct {
	Xs       *Service
	MaxDelay uint16
	Logs     bool
	ShowBody bool

	DoSpeedtest bool
	DoIPInfo    bool

	TestEndpoint           string
	TestEndpointHttpMethod string
	SpeedtestAmount        uint32
}

var (
	failedDelay int64 = 99999
)

func (e *Examiner) ExamineConfig(link string) (Result, error) {
	r := Result{
		ConfigLink: link,
		Status:     "passed",
		Delay:      failedDelay,
		RealIPAddr: "null",
		IpAddrLoc:  "null",
	}

	parsed, err := ParseXrayConfig(link)
	if err != nil {
		return r, errors.New(fmt.Sprintf("Couldn't parse the config : %v", err))
		//os.Exit(1)
	}

	if e.Logs {
		fmt.Printf("%v\n", parsed.DetailsStr())
	}

	r.Protocol = parsed
	r.TLS = parsed.ConvertToGeneralConfig().TLS

	instance, err1 := e.Xs.MakeXrayInstance(parsed)
	if err1 != nil {
		r.Status = "broken"
		return r, nil
	}
	// Close xray conn after testing
	defer instance.Close()

	var delay int64
	var downloadTime int64
	var uploadTime int64

	delay, _, err = MeasureDelay(instance, time.Duration(10000)*time.Millisecond, e.ShowBody, e.TestEndpoint, e.TestEndpointHttpMethod)
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
		_, body, err := CoreHTTPRequestCustom(instance, time.Duration(10000)*time.Millisecond, cloudflare.Speedtest.MakeDebugRequest())
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
		_, _, err = CoreHTTPRequestCustom(instance, time.Duration(20000)*time.Millisecond, cloudflare.Speedtest.MakeDownloadHTTPRequest(false, e.SpeedtestAmount*1000))
		if err != nil {
			//customlog.Printf(customlog.Failure, "Download failed!\n")
			//return
		} else {
			downloadTime = time.Since(downloadStartTime).Milliseconds()
			r.DownloadSpeed = (float32((e.SpeedtestAmount*1000)*8) / (float32(downloadTime) / float32(1000.0))) / float32(1000000.0)
			//customlog.Printf(customlog.Success, "Download took: %dms\n", downloadTime)
		}

		uploadStartTime := time.Now()
		_, _, err = CoreHTTPRequestCustom(instance, time.Duration(20000)*time.Millisecond, cloudflare.Speedtest.MakeUploadHTTPRequest(false, e.SpeedtestAmount*1000))
		if err != nil {
			//customlog.Printf(customlog.Failure, "Upload failed!\n")
			//return
		} else {
			uploadTime = time.Since(uploadStartTime).Milliseconds()
			r.UploadSpeed = (float32((e.SpeedtestAmount*1000)*8) / (float32(uploadTime) / float32(1000.0))) / float32(1000000.0)
			//customlog.Printf(customlog.Success, "Upload took: %dms\n", uploadTime)
		}
	}

	//customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", delay)
	//}

	return r, nil
}
