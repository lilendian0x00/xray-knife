package scanner

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/lilendian0x00/xray-knife/v5/pkg/core"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v5/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v5/utils"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"
	utls "github.com/refraction-networking/utls"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
)

// zeroReader is an io.Reader that endlessly produces zero bytes.
type zeroReader struct{}

func (z zeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// ScannerConfig holds all configuration for a scan.
type ScannerConfig struct {
	Subnets              []string
	ThreadCount          int
	ShuffleIPs           bool
	ShuffleSubnets       bool
	DoSpeedtest          bool
	RequestTimeout       int
	ShowTraceBody        bool
	Verbose              bool
	OutputFile           string
	RetryCount           int
	OnlySpeedtestResults bool
	DownloadMB           int
	UploadMB             int
	SpeedtestTop         int
	SpeedtestConcurrency int
	SpeedtestTimeout     int
	ConfigLink           string
	InsecureTLS          bool
	Resume               bool
}

// ScannerService is the main engine for scanning.
type ScannerService struct {
	config          ScannerConfig
	logger          *log.Logger
	xrayCore        core.Core
	singboxCore     core.Core
	selectedCoreMap map[string]core.Core
	initialResults  []*ScanResult
	scannedIPs      map[string]bool
}

// ScanResult represents the outcome of scanning a single IP.
type ScanResult struct {
	IP        string        `csv:"ip" json:"ip"`
	Latency   time.Duration `csv:"-" json:"-"`
	LatencyMS int64         `csv:"latency_ms" json:"latency_ms"`
	DownSpeed float64       `csv:"download_mbps" json:"download_mbps"`
	UpSpeed   float64       `csv:"upload_mbps" json:"upload_mbps"`
	Error     error         `csv:"-" json:"-"`
	ErrorStr  string        `csv:"error,omitempty" json:"error,omitempty"`
	mu        sync.Mutex    `csv:"-" json:"-"`
}

// PrepareForMarshal populates the marshal-friendly fields before serialization.
func (r *ScanResult) PrepareForMarshal() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.LatencyMS = r.Latency.Milliseconds()
	if r.Error != nil {
		r.ErrorStr = r.Error.Error()
	} else {
		r.ErrorStr = ""
	}
}

// NewScannerService creates a new, configured scanner service.
func NewScannerService(config ScannerConfig, logger *log.Logger) (*ScannerService, error) {
	s := &ScannerService{
		config:     config,
		logger:     logger,
		scannedIPs: make(map[string]bool),
	}

	if s.config.Resume {
		resumedResults, err := LoadResultsForResume(s.config.OutputFile)
		if err != nil {
			s.logger.Printf("Could not resume from %s: %v. Starting fresh.", s.config.OutputFile, err)
		} else if len(resumedResults) > 0 {
			s.initialResults = resumedResults
			for _, r := range resumedResults {
				s.scannedIPs[r.IP] = true
			}
			s.logger.Printf("Resumed %d results from %s", len(s.initialResults), s.config.OutputFile)
		}
	} else {
		// If not resuming, we clear the file.
		err := os.Remove(s.config.OutputFile)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to clear previous results file %s: %w", s.config.OutputFile, err)
		}
	}

	if s.config.ConfigLink != "" {
		s.xrayCore = core.CoreFactory(core.XrayCoreType, s.config.InsecureTLS, s.config.Verbose)
		s.singboxCore = core.CoreFactory(core.SingboxCoreType, s.config.InsecureTLS, s.config.Verbose)
		s.selectedCoreMap = map[string]core.Core{
			protocol.VmessIdentifier: s.xrayCore, protocol.VlessIdentifier: s.xrayCore,
			protocol.ShadowsocksIdentifier: s.xrayCore, protocol.TrojanIdentifier: s.xrayCore,
			protocol.SocksIdentifier: s.xrayCore, protocol.WireguardIdentifier: s.xrayCore,
			protocol.Hysteria2Identifier: s.singboxCore, "hy2": s.singboxCore,
		}
	}

	return s, nil
}

// Run starts the scan and sends results to progressChan. It blocks until complete or context is cancelled.
func (s *ScannerService) Run(ctx context.Context, progressChan chan<- *ScanResult) error {
	defer close(progressChan)

	workerResultsChan := make(chan *ScanResult, s.config.ThreadCount)

	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go s.resultProcessor(ctx, &writerWg, workerResultsChan, progressChan)

	// --- Latency Scan Phase ---
	if err := s.runLatencyScan(ctx, workerResultsChan); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logger.Printf("Latency scan failed: %v", err)
			return err
		}
		s.logger.Println("Latency scan cancelled.")
	} else {
		s.logger.Println("Latency scan phase finished.")
	}

	// --- Speed Test Phase ---
	if s.config.DoSpeedtest && ctx.Err() == nil {
		s.logger.Println("Waiting for result writer before starting speed test...")
		time.Sleep(saveInterval + 1*time.Second) // Give the writer a moment to finish its last batch.

		if err := s.runSpeedTest(ctx, workerResultsChan); err != nil {
			if !errors.Is(err, context.Canceled) {
				s.logger.Printf("Speed test failed: %v", err)
				return err
			}
			s.logger.Println("Speed test cancelled.")
		} else {
			s.logger.Println("Speed test phase finished.")
		}
	}

	close(workerResultsChan)
	writerWg.Wait()
	s.logger.Println("Scan process completed.")
	return nil
}

func (s *ScannerService) runLatencyScan(ctx context.Context, workerResultsChan chan<- *ScanResult) error {
	s.logger.Printf("Phase 1: Scanning for latency with %d threads...", s.config.ThreadCount)
	pool := pond.NewPool(s.config.ThreadCount)
	defer pool.Stop()

	var hasIPs bool
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	if s.config.ShuffleSubnets {
		r.Shuffle(len(s.config.Subnets), func(i, j int) {
			s.config.Subnets[i], s.config.Subnets[j] = s.config.Subnets[j], s.config.Subnets[i]
		})
	}

	for _, cidr := range s.config.Subnets {
		select {
		case <-ctx.Done():
			return context.Canceled
		default:
		}

		if s.config.ShuffleIPs {
			listIP, err := utils.CIDRtoListIP(cidr)
			if err != nil {
				s.logger.Printf("Error processing CIDR %s: %v", cidr, err)
				continue
			}
			if len(listIP) > 0 {
				hasIPs = true
			}
			r.Shuffle(len(listIP), func(i, j int) { listIP[i], listIP[j] = listIP[j], listIP[i] })
			for _, ip := range listIP {
				if _, exists := s.scannedIPs[ip]; exists {
					continue
				}
				pool.Submit(func(ip string) func() {
					return func() {
						if ctx.Err() == nil {
							workerResultsChan <- s.scanIPForLatency(ctx, ip)
						}
					}
				}(ip))
			}
		} else {
			ip, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				s.logger.Printf("Error parsing CIDR %s: %v", cidr, err)
				continue
			}
			for currentIP := ip.Mask(ipnet.Mask); ipnet.Contains(currentIP); inc(currentIP) {
				if !hasIPs {
					hasIPs = true
				}
				ipToScan := make(net.IP, len(currentIP))
				copy(ipToScan, currentIP)
				ipStr := ipToScan.String()
				if _, exists := s.scannedIPs[ipStr]; exists {
					continue
				}
				pool.Submit(func(ip string) func() {
					return func() {
						if ctx.Err() == nil {
							workerResultsChan <- s.scanIPForLatency(ctx, ip)
						}
					}
				}(ipStr))
			}
		}
	}

	if !hasIPs && len(s.initialResults) == 0 {
		return errors.New("scanner failed: no scannable IPs detected")
	}

	pool.StopAndWait()
	return nil
}

func (s *ScannerService) runSpeedTest(ctx context.Context, workerResultsChan chan<- *ScanResult) error {
	allResults, err := LoadResultsForResume(s.config.OutputFile)
	if err != nil {
		return fmt.Errorf("could not load results for speed test phase: %w", err)
	}

	var successfulLatencyResults []*ScanResult
	for _, r := range allResults {
		if r.Error == nil {
			successfulLatencyResults = append(successfulLatencyResults, r)
		}
	}

	if len(successfulLatencyResults) == 0 {
		s.logger.Println("No successful latency results to speed test.")
		return nil
	}

	sort.Slice(successfulLatencyResults, func(i, j int) bool {
		return successfulLatencyResults[i].Latency < successfulLatencyResults[j].Latency
	})

	numToTest := s.config.SpeedtestTop
	if len(successfulLatencyResults) < numToTest {
		numToTest = len(successfulLatencyResults)
	}
	topResults := successfulLatencyResults[:numToTest]
	s.logger.Printf("Phase 2: Performing speed tests on the top %d IPs (with %d concurrent tests, %ds timeout each)...", len(topResults), s.config.SpeedtestConcurrency, s.config.SpeedtestTimeout)

	speedTestPool := pond.NewPool(s.config.SpeedtestConcurrency)
	defer speedTestPool.Stop()

	for _, result := range topResults {
		if result.DownSpeed > 0 || result.UpSpeed > 0 {
			continue // Already tested
		}
		speedTestPool.Submit(func(res *ScanResult) func() {
			return func() {
				if ctx.Err() != nil {
					return
				}
				timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(s.config.SpeedtestTimeout)*time.Second)
				defer cancel()
				downSpeed, upSpeed, err := s.measureSpeed(timeoutCtx, res.IP)
				res.mu.Lock()
				res.DownSpeed = downSpeed
				res.UpSpeed = upSpeed
				res.Error = err
				res.mu.Unlock()
				workerResultsChan <- res
			}
		}(result))
	}

	speedTestPool.StopAndWait()
	return nil
}

func (s *ScannerService) resultProcessor(ctx context.Context, wg *sync.WaitGroup, workerResultsChan <-chan *ScanResult, uiProgressChan chan<- *ScanResult) {
	defer wg.Done()
	batch := make([]*ScanResult, 0, saveBatchSize)
	ticker := time.NewTicker(saveInterval)
	defer ticker.Stop()

	save := func() {
		if len(batch) == 0 {
			return
		}
		for _, res := range batch {
			res.PrepareForMarshal()
		}
		if err := appendResultsToCSV(s.config.OutputFile, batch); err != nil {
			s.logger.Printf("Real-time save failed: %v", err)
		} else if s.config.Verbose {
			s.logger.Printf("Progress for %d new results saved to %s", len(batch), s.config.OutputFile)
		}
		batch = make([]*ScanResult, 0, saveBatchSize) // Reset batch
	}

	for {
		select {
		case <-ctx.Done():
			s.logger.Println("Result processor shutting down due to context cancellation.")
			save()
			return
		case result, ok := <-workerResultsChan:
			if !ok {
				save()
				s.logger.Println("Result processor finished.")
				return
			}
			result.PrepareForMarshal()
			if uiProgressChan != nil {
				select {
				case uiProgressChan <- result:
				case <-ctx.Done():
				}
			}

			batch = append(batch, result)
			if len(batch) >= saveBatchSize {
				save()
			}
		case <-ticker.C:
			save()
		}
	}
}

func (s *ScannerService) createDialerWithRetry(ip string, retries int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout: time.Duration(s.config.RequestTimeout) * time.Millisecond,
		}
		targetAddr := fmt.Sprintf("%s:%d", ip, 443)
		var lastErr error

		for i := 0; i <= retries; i++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if s.config.Verbose && i > 0 {
				s.logger.Printf("Retrying connection to %s (attempt %d/%d)...", ip, i+1, retries+1)
			}
			conn, err := dialer.DialContext(ctx, network, targetAddr)
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if i < retries {
				time.Sleep(200 * time.Millisecond)
			}
		}
		return nil, fmt.Errorf("all %d connection attempts to %s failed, last error: %w", retries+1, ip, lastErr)
	}
}

func (s *ScannerService) scanIPForLatency(ctx context.Context, ip string) *ScanResult {
	result := &ScanResult{IP: ip}
	var client *http.Client
	var instance protocol.Instance
	var err error

	req, err := http.NewRequestWithContext(ctx, "GET", cloudflareTraceURL, nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to create request: %w", err)
		return result
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	if s.config.ConfigLink != "" {
		client, instance, err = s.createClientFromConfig(ip, time.Duration(s.config.RequestTimeout)*time.Millisecond)
		if err != nil {
			result.Error = fmt.Errorf("failed creating client from config for latency test: %w", err)
			return result
		}
		defer instance.Close()
	} else {
		transport := NewBypassJA3Transport(utls.HelloChrome_Auto)
		transport.DialContext = s.createDialerWithRetry(ip, s.config.RetryCount)
		client = &http.Client{
			Transport: transport,
			Timeout:   time.Duration(s.config.RequestTimeout) * time.Millisecond,
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("latency test failed: %w", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = fmt.Errorf("bad status code: %d", resp.StatusCode)
		return result
	}

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		result.Error = fmt.Errorf("failed to read body: %w", err)
		return result
	}
	result.Latency = time.Since(start)
	return result
}

func (s *ScannerService) measureSpeed(ctx context.Context, ip string) (downSpeed, upSpeed float64, err error) {
	downloadBytesTotal := int64(s.config.DownloadMB) * 1024 * 1024
	uploadBytesTotal := int64(s.config.UploadMB) * 1024 * 1024
	var client *http.Client
	var instance protocol.Instance

	if s.config.ConfigLink != "" {
		client, instance, err = s.createClientFromConfig(ip, time.Duration(s.config.SpeedtestTimeout)*time.Second)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to create speedtest client from config: %w", err)
		}
		defer instance.Close()
	} else {
		transport := NewBypassJA3Transport(utls.HelloChrome_Auto)
		transport.DialContext = s.createDialerWithRetry(ip, s.config.RetryCount)
		client = &http.Client{Transport: transport}
	}

	// Download
	downURL := fmt.Sprintf("https://%s/__down?bytes=%d", cloudflareSpeedTestURL, downloadBytesTotal)
	reqDown, err := http.NewRequestWithContext(ctx, "GET", downURL, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create download request: %w", err)
	}
	reqDown.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	startDown := time.Now()
	respDown, err := client.Do(reqDown)
	if err != nil {
		return 0, 0, fmt.Errorf("download test failed: %w", err)
	}
	defer respDown.Body.Close()
	if respDown.StatusCode < 200 || respDown.StatusCode >= 300 {
		return 0, 0, fmt.Errorf("download status: %s", respDown.Status)
	}
	written, err := io.Copy(io.Discard, respDown.Body)
	if err != nil {
		return 0, 0, fmt.Errorf("download stream copy: %w", err)
	}
	downDuration := time.Since(startDown).Seconds()
	if downDuration > 0 {
		downSpeed = (float64(written) * 8) / (downDuration * 1e6)
	}

	if ctx.Err() != nil {
		return downSpeed, 0, context.Canceled
	}

	// Upload
	upURL := fmt.Sprintf("https://%s/__up", cloudflareSpeedTestURL)

	// Use a memory-efficient reader instead of a massive byte slice
	bodyReader := io.LimitReader(zeroReader{}, uploadBytesTotal)
	reqUp, err := http.NewRequestWithContext(ctx, "POST", upURL, bodyReader)
	if err != nil {
		return downSpeed, 0, fmt.Errorf("failed to create upload request: %w", err)
	}

	// Explicitly set ContentLength as it's not automatically inferred from io.LimitReader
	reqUp.ContentLength = uploadBytesTotal
	reqUp.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")
	reqUp.Header.Set("Content-Type", "application/octet-stream")

	startUp := time.Now()
	respUp, err := client.Do(reqUp)
	if err != nil {
		return downSpeed, 0, fmt.Errorf("upload test failed: %w", err)
	}
	defer respUp.Body.Close()
	io.Copy(io.Discard, respUp.Body)
	if respUp.StatusCode < 200 || respUp.StatusCode >= 300 {
		return downSpeed, 0, fmt.Errorf("upload status: %s", respUp.Status)
	}
	upDuration := time.Since(startUp).Seconds()
	if upDuration > 0 {
		upSpeed = (float64(uploadBytesTotal) * 8) / (upDuration * 1e6)
	}
	return downSpeed, upSpeed, nil
}

func (s *ScannerService) createClientFromConfig(ip string, timeout time.Duration) (*http.Client, protocol.Instance, error) {
	uri, err := url.Parse(s.config.ConfigLink)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse config link for core selection: %w", err)
	}
	selectedCore, ok := s.selectedCoreMap[uri.Scheme]
	if !ok {
		return nil, nil, fmt.Errorf("unsupported protocol scheme for auto core: %s", uri.Scheme)
	}
	proto, errProto := selectedCore.CreateProtocol(s.config.ConfigLink)
	if errProto != nil {
		return nil, nil, fmt.Errorf("failed to create protocol: %w", errProto)
	}
	if err = proto.Parse(); err != nil {
		return nil, nil, fmt.Errorf("failed to parse protocol: %w", err)
	}
	if err = setAddress(proto, ip); err != nil {
		return nil, nil, fmt.Errorf("failed to set IP on protocol: %w", err)
	}
	return selectedCore.MakeHttpClient(proto, timeout)
}

// CLI-specific implementation below

var (
	cliConfig ScannerConfig
)

var CFscannerCmd = &cobra.Command{
	Use:   "cfscanner",
	Short: "Cloudflare's edge IP scanner with latency/speed tests and real-time resume.",
	Long:  `...`, // unchanged
	Run: func(cmd *cobra.Command, args []string) {
		var subnets []string
		if _, err := os.Stat(cliConfig.Subnets[0]); err == nil {
			subnets = utils.ParseFileByNewline(cliConfig.Subnets[0])
		} else {
			subnets = strings.Split(cliConfig.Subnets[0], ",")
		}
		cliConfig.Subnets = subnets

		service, err := NewScannerService(cliConfig, log.New(os.Stdout, "", 0))
		if err != nil {
			customlog.Printf(customlog.Failure, "Failed to create scanner: %v\n", err)
			return
		}

		progressChan := make(chan *ScanResult, cliConfig.ThreadCount)
		var finalResults []*ScanResult
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for res := range progressChan {
				if res.Error != nil {
					if cliConfig.Verbose {
						customlog.Printf(customlog.Warning, "IP %s failed test: %v\n", res.IP, res.Error)
					}
				} else if res.DownSpeed > 0 || res.UpSpeed > 0 {
					customlog.Printf(customlog.Success, "SPEEDTEST: %-20s | %-10v | %-15.2f | %-15.2f\n", res.IP, res.Latency.Round(time.Millisecond), res.DownSpeed, res.UpSpeed)
				} else {
					customlog.Printf(customlog.Success, "LATENCY:   %-20s | %-10v\n", res.IP, res.Latency.Round(time.Millisecond))
				}
				finalResults = append(finalResults, res)
			}
		}()

		if err := service.Run(context.Background(), progressChan); err != nil {
			customlog.Printf(customlog.Failure, "Scan encountered an error: %v\n", err)
		}
		wg.Wait()

		printResultsToConsole(finalResults, cliConfig.DoSpeedtest, cliConfig.OnlySpeedtestResults)
		customlog.Printf(customlog.Success, "Scan finished. Final results saved to %s\n", cliConfig.OutputFile)
	},
}

func init() {
	CFscannerCmd.Flags().StringSliceVarP(&cliConfig.Subnets, "subnets", "s", nil, "Subnet(s) or file containing subnets (e.g., \"1.1.1.1/24,2.2.2.2/16\")")
	CFscannerCmd.Flags().IntVarP(&cliConfig.ThreadCount, "threads", "t", 100, "Count of threads for latency scan")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.DoSpeedtest, "speedtest", "p", false, "Measure download/upload speed on the fastest IPs")
	CFscannerCmd.Flags().IntVarP(&cliConfig.SpeedtestTop, "speedtest-top", "c", 10, "Number of fastest IPs to select for speed testing")
	CFscannerCmd.Flags().IntVar(&cliConfig.SpeedtestConcurrency, "speedtest-concurrency", 4, "Number of concurrent speed tests to run")
	CFscannerCmd.Flags().IntVar(&cliConfig.SpeedtestTimeout, "speedtest-timeout", 30, "Total timeout in seconds for one IP's speed test")
	CFscannerCmd.Flags().IntVarP(&cliConfig.RequestTimeout, "timeout", "u", 5000, "Individual request timeout (in ms)")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.ShowTraceBody, "body", "b", false, "Show trace body output")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.Verbose, "verbose", "v", false, "Show verbose output with detailed errors")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.ShuffleSubnets, "shuffle-subnet", "e", false, "Shuffle list of Subnets")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.ShuffleIPs, "shuffle-ip", "i", false, "Shuffle list of IPs")
	CFscannerCmd.Flags().StringVarP(&cliConfig.OutputFile, "output", "o", "results.csv", "Output file to save sorted results (in CSV format)")
	CFscannerCmd.Flags().IntVarP(&cliConfig.RetryCount, "retry", "r", 1, "Number of times to retry TCP connection on failure")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.OnlySpeedtestResults, "only-speedtest", "k", false, "Only display results that have successful speedtest data")
	CFscannerCmd.Flags().IntVarP(&cliConfig.DownloadMB, "download-mb", "d", 20, "Custom amount of data to download for speedtest (in MB)")
	CFscannerCmd.Flags().IntVarP(&cliConfig.UploadMB, "upload-mb", "m", 10, "Custom amount of data to upload for speedtest (in MB)")
	CFscannerCmd.Flags().StringVarP(&cliConfig.ConfigLink, "config", "C", "", "Use a config link as a proxy to test IPs")
	CFscannerCmd.Flags().BoolVarP(&cliConfig.InsecureTLS, "insecure", "E", false, "Allow insecure TLS connections for the proxy config")
	CFscannerCmd.Flags().BoolVar(&cliConfig.Resume, "resume", false, "Resume scan from output file")

	_ = CFscannerCmd.MarkFlagRequired("subnets")
}

const (
	saveBatchSize          = 500
	saveInterval           = 5 * time.Second
	cloudflareTraceURL     = "https://cloudflare.com/cdn-cgi/trace"
	cloudflareSpeedTestURL = "speed.cloudflare.com"
)

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func printResultsToConsole(results []*ScanResult, doSpeedtest, onlySpeedtestResults bool) {
	var successfulResults, finalResults []*ScanResult
	for _, r := range results {
		if r.Error == nil {
			successfulResults = append(successfulResults, r)
		}
	}

	if len(successfulResults) == 0 {
		customlog.Printf(customlog.Warning, "No successful IPs found to display.\n")
		return
	}

	if doSpeedtest && onlySpeedtestResults {
		for _, r := range successfulResults {
			if r.DownSpeed > 0 || r.UpSpeed > 0 {
				finalResults = append(finalResults, r)
			}
		}
	} else {
		finalResults = successfulResults
	}

	if len(finalResults) == 0 {
		customlog.Printf(customlog.Warning, "No results to display after filtering.\n")
		return
	}

	sort.Slice(finalResults, func(i, j int) bool {
		if doSpeedtest {
			if finalResults[i].Latency != finalResults[j].Latency {
				return finalResults[i].Latency < finalResults[j].Latency
			}
			return finalResults[i].DownSpeed > finalResults[j].DownSpeed
		}
		return finalResults[i].Latency < finalResults[j].Latency
	})

	var header string
	var outputLines []string
	if doSpeedtest {
		header = fmt.Sprintf("%-20s | %-10s | %-15s | %-15s", "IP", "Latency", "Downlink (Mbps)", "Uplink (Mbps)")
	} else {
		header = fmt.Sprintf("%-20s | %-10s", "IP", "Latency")
	}
	outputLines = append(outputLines, header)
	for _, result := range finalResults {
		outputLines = append(outputLines, formatResultLine(*result, doSpeedtest))
	}
	customlog.Println(customlog.GetColor(customlog.None, "\n--- Sorted Results ---\n"))
	customlog.Println(customlog.GetColor(customlog.Success, strings.Join(outputLines, "\n")))
	customlog.Println(customlog.GetColor(customlog.None, "\n--------------------\n"))
}

func formatResultLine(result ScanResult, speedtestEnabled bool) string {
	if speedtestEnabled {
		return fmt.Sprintf("%-20s | %-10v | %-15.2f | %-15.2f", result.IP, result.Latency.Round(time.Millisecond), result.DownSpeed, result.UpSpeed)
	}
	return fmt.Sprintf("%-20s | %-10v", result.IP, result.Latency.Round(time.Millisecond))
}

func LoadResultsForResume(filePath string) ([]*ScanResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No history is not an error
		}
		return nil, err
	}
	defer file.Close()

	var results []*ScanResult
	if err := gocsv.UnmarshalFile(file, &results); err != nil {
		if err.Error() == "EOF" { // Handle empty file gracefully
			return nil, nil
		}
		return nil, fmt.Errorf("failed to parse resume file (must be CSV): %w", err)
	}

	// Re-hydrate the non-serialized fields
	for _, r := range results {
		r.Latency = time.Duration(r.LatencyMS) * time.Millisecond
		if r.ErrorStr != "" {
			r.Error = errors.New(r.ErrorStr)
		}
	}
	return results, nil
}

// appendResultsToCSV appends a batch of results to the CSV file.
func appendResultsToCSV(filePath string, batch []*ScanResult) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Create a buffered writer for efficiency
	bufWriter := bufio.NewWriter(file)

	// Create the standard csv.Writer
	csvWriter := csv.NewWriter(bufWriter)

	if info.Size() == 0 {
		// If the file is new, marshal the batch with headers
		err = gocsv.MarshalCSV(batch, csvWriter)
	} else {
		// If the file exists, marshal without headers to append
		err = gocsv.MarshalCSVWithoutHeaders(batch, csvWriter)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal and append results to CSV: %w", err)
	}

	// Flush the CSV writer (to the buffer) and then the buffered writer (to the file)
	csvWriter.Flush()
	return bufWriter.Flush()
}

type BypassJA3Transport struct {
	tr1         http.Transport
	tr2         http2.Transport
	mu          sync.RWMutex
	clientHello utls.ClientHelloID
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewBypassJA3Transport(helloID utls.ClientHelloID) *BypassJA3Transport {
	return &BypassJA3Transport{
		clientHello: helloID,
		tr2: http2.Transport{
			AllowHTTP: true,
		},
	}
}

func (b *BypassJA3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Scheme {
	case "https":
		return b.httpsRoundTrip(req)
	case "http":
		b.tr1.DialContext = b.DialContext
		return b.tr1.RoundTrip(req)
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", req.URL.Scheme)
	}
}

func (b *BypassJA3Transport) httpsRoundTrip(req *http.Request) (*http.Response, error) {
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	hostname := req.URL.Hostname()

	dialer := b.DialContext
	if dialer == nil {
		dialer = (&net.Dialer{}).DialContext
	}

	conn, err := dialer(req.Context(), "tcp", fmt.Sprintf("%s:%s", hostname, port))
	if err != nil {
		return nil, fmt.Errorf("custom dial failed: %w", err)
	}

	tlsConn, err := b.tlsConnect(req.Context(), conn, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls connect failed: %w", err)
	}

	if deadline, ok := req.Context().Deadline(); ok {
		tlsConn.SetDeadline(deadline)
	}

	httpVersion := tlsConn.ConnectionState().NegotiatedProtocol
	switch httpVersion {
	case "h2":
		t2 := b.tr2
		t2.DialTLS = nil
		clientConn, err := t2.NewClientConn(tlsConn)
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("failed to create http2 client connection: %w", err)
		}
		return clientConn.RoundTrip(req)
	case "http/1.1", "":
		if err := req.Write(tlsConn); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("failed to write http1 request: %w", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}
		return resp, nil
	default:
		tlsConn.Close()
		return nil, fmt.Errorf("unsupported http version: %s", httpVersion)
	}
}

func (b *BypassJA3Transport) getTLSConfig(req *http.Request) *utls.Config {
	return &utls.Config{
		ServerName:         req.URL.Host,
		InsecureSkipVerify: false,
		NextProtos:         []string{"h2", "http/1.1"},
	}
}

func (b *BypassJA3Transport) tlsConnect(ctx context.Context, conn net.Conn, req *http.Request) (*utls.UConn, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	tlsConfig := b.getTLSConfig(req)
	tlsConn := utls.UClient(conn, tlsConfig, b.clientHello)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

func setAddress(p interface{}, newAddr string) error {
	val := reflect.ValueOf(p)

	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return fmt.Errorf("provided interface is not a struct or a pointer to a struct")
	}

	addressField := val.FieldByName("Address")
	if addressField.IsValid() {
		if !addressField.CanSet() {
			return fmt.Errorf("'Address' field is not settable")
		}
		if addressField.Kind() != reflect.String {
			return fmt.Errorf("'Address' field is not a string")
		}
		addressField.SetString(newAddr)
		return nil
	}

	endpointField := val.FieldByName("Endpoint")
	if endpointField.IsValid() {
		if !endpointField.CanSet() {
			return fmt.Errorf("'Endpoint' field is not settable")
		}
		if endpointField.Kind() != reflect.String {
			return fmt.Errorf("'Endpoint' field is not a string")
		}

		currentEndpoint := endpointField.String()
		_, port, err := net.SplitHostPort(currentEndpoint)
		if err != nil {
			return fmt.Errorf("could not split host:port from endpoint '%s': %w", currentEndpoint, err)
		}
		newEndpoint := net.JoinHostPort(newAddr, port)
		endpointField.SetString(newEndpoint)
		return nil
	}

	return fmt.Errorf("struct has no 'Address' or 'Endpoint' field")
}
