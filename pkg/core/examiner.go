package core

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v5/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v5/speedtester/cloudflare"
	"github.com/lilendian0x00/xray-knife/v5/utils"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"
)

type Result struct {
	ConfigLink    string            `csv:"link"` // vmess://... vless//..., etc
	Protocol      protocol.Protocol `csv:"-"`
	Status        string            `csv:"status"`   // passed, semi-passed, failed, broken
	Reason        string            `csv:"reason"`   // reason of the error
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
	CoreInstance Core

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
			e.Core = CoreFactory(XrayCoreType, e.InsecureTLS, e.Verbose)
			break
		case "singbox":
			e.Core = CoreFactory(SingboxCoreType, e.InsecureTLS, e.Verbose)
			break
		default:
			e.Core = nil
			e.xrayCore = CoreFactory(XrayCoreType, e.InsecureTLS, e.Verbose)
			e.singboxCore = CoreFactory(SingboxCoreType, e.InsecureTLS, e.Verbose)
			e.SelectedCore = map[string]Core{
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

	var core = e.Core

	// Select core based on config (Automatic Core)
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
		fmt.Printf("%v%s: %s\n\n", proto.DetailsStr(), color.RedString("Link"), proto.GetLink())
	}

	r.Protocol = proto
	r.TLS = proto.ConvertToGeneralConfig().TLS

	client, instance, err := core.MakeHttpClient(proto, time.Duration(e.MaxDelay)*time.Millisecond)
	if err != nil {
		r.Status = "broken"
		r.Reason = err.Error()
		return r, err
	}
	// Close xray conn after testing
	defer instance.Close()

	var delay int64
	var downloadTime int64
	var uploadTime int64

	delay, _, err = MeasureDelay(client, e.ShowBody, e.TestEndpoint, e.TestEndpointHttpMethod)
	if err != nil {
		//customlog.Printf(customlog.Failure, "Config didn't respond!\n\n")
		r.Status = "failed"
		r.Reason = err.Error()
		return r, err
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
		return r, errors.New("timeout")
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

func MeasureDelay(client *http.Client, showBody bool, dest string, httpMethod string) (int64, int, error) {
	start := time.Now()
	code, body, err := CoreHTTPRequest(client, httpMethod, dest)
	if err != nil {
		return -1, -1, err
	}
	//fmt.Printf("%s: %d\n", color.YellowString("Status code"), code)
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

// ConfigResults represents a slice of test results
type ConfigResults []*Result

// ResultProcessor handles the processing and storage of test results
type ResultProcessor struct {
	validConfigs   []string
	validConfigsMu sync.Mutex
	outputFile     string
	outputType     string
	sorted         bool
}

type ResultProcessorOptions struct {
	OutputFile string
	OutputType string
	Sorted     bool
}

// NewResultProcessor creates a new ResultProcessor instance
func NewResultProcessor(opts ResultProcessorOptions) *ResultProcessor {
	return &ResultProcessor{
		validConfigs: make([]string, 0),
		outputFile:   opts.OutputFile,
		outputType:   opts.OutputType,
		sorted:       opts.Sorted,
	}
}

// Sort interface implementation for ConfigResults
func (cr ConfigResults) Len() int { return len(cr) }
func (cr ConfigResults) Less(i, j int) bool {
	return cr[i].Delay < cr[j].Delay &&
		cr[i].DownloadSpeed >= cr[j].DownloadSpeed &&
		cr[i].UploadSpeed >= cr[j].UploadSpeed
}
func (cr ConfigResults) Swap(i, j int) { cr[i], cr[j] = cr[j], cr[i] }

// TestManager handles the concurrent testing of configurations
type TestManager struct {
	examiner    *Examiner
	processor   *ResultProcessor
	threadCount uint16
	verbose     bool
}

// NewTestManager creates a new TestManager instance
func NewTestManager(examiner *Examiner, processor *ResultProcessor, threadCount uint16, verbose bool) *TestManager {
	return &TestManager{
		examiner:    examiner,
		processor:   processor,
		threadCount: threadCount,
		verbose:     verbose,
	}
}

// TestConfigs tests multiple configurations concurrently
func (tm *TestManager) TestConfigs(links []string, printSuccess bool) ConfigResults {
	semaphore := make(chan int, tm.threadCount)
	var wg sync.WaitGroup
	var results ConfigResults

	for i := range links {
		semaphore <- 1
		wg.Add(1)
		go tm.testSingleConfig(links[i], i, &results, semaphore, &wg, printSuccess)
	}

	wg.Wait()
	close(semaphore)
	return results
}

// testSingleConfig tests a single configuration
func (tm *TestManager) testSingleConfig(link string, index int, results *ConfigResults, semaphore chan int, wg *sync.WaitGroup, printSuccess bool) {
	defer func() {
		<-semaphore
		wg.Done()
	}()

	res, err := tm.examiner.ExamineConfig(link)
	if err != nil {
		if tm.verbose {
			customlog.Printf(customlog.Failure, "Error: %s - broken config: %s\n", err.Error(), link)
		}
		return
	}

	if res.Status == "passed" && printSuccess {
		tm.printSuccessDetails(index, res)
	}

	if tm.processor.outputType == "csv" || res.Status == "passed" {
		tm.processor.validConfigsMu.Lock()
		*results = append(*results, &res)
		tm.processor.validConfigsMu.Unlock()
	}
}

// printSuccessDetails prints the details of a successful test
func (tm *TestManager) printSuccessDetails(index int, res Result) {
	d := color.New(color.FgCyan, color.Bold)
	d.Printf("Config Number: %d\n", index+1)
	fmt.Printf("%v%s: %s\n", res.Protocol.DetailsStr(), color.RedString("Link"), res.Protocol.GetLink())
	customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", res.Delay)
}

// SaveResults saves the test results to a file
func (rp *ResultProcessor) SaveResults(results ConfigResults) error {
	if rp.sorted {
		sort.Sort(results)
	}

	switch rp.outputType {
	case "txt":
		return rp.saveTxtResults(results)
	case "csv":
		return rp.saveCSVResults(results)
	default:
		return fmt.Errorf("unsupported output type: %s", rp.outputType)
	}
}

// saveTxtResults saves results in text format
func (rp *ResultProcessor) saveTxtResults(results ConfigResults) error {
	for _, v := range results {
		if v.Status == "passed" {
			rp.validConfigs = append(rp.validConfigs, v.ConfigLink)
		}
	}

	content := strings.Join(rp.validConfigs, "\n\n")
	if err := utils.WriteIntoFile(rp.outputFile, []byte(content)); err != nil {
		return fmt.Errorf("failed to save configs: %v", err)
	}

	customlog.Printf(customlog.Finished, "A total of %d working configurations have been saved to %s\n",
		len(rp.validConfigs), rp.outputFile)
	return nil
}

// saveCSVResults saves results in CSV format
func (rp *ResultProcessor) saveCSVResults(results ConfigResults) error {
	// Ensure the file has a .csv extension
	base := strings.TrimSuffix(rp.outputFile, filepath.Ext(rp.outputFile))
	csvFile := base + ".csv"

	out, err := gocsv.MarshalString(&results)
	if err != nil {
		return fmt.Errorf("failed to marshal CSV: %v", err)
	}

	if err := utils.WriteIntoFile(csvFile, []byte(out)); err != nil {
		return fmt.Errorf("failed to save configs: %v", err)
	}

	for _, v := range results {
		if v.Status == "passed" {
			rp.validConfigs = append(rp.validConfigs, v.ConfigLink)
		}
	}

	customlog.Printf(customlog.Finished, "A total of %d configurations have been saved to %s\n",
		len(rp.validConfigs), csvFile)
	return nil
}
