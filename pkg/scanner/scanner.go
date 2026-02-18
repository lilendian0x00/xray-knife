package scanner

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v9/database"
	"github.com/lilendian0x00/xray-knife/v9/pkg/core"
	"github.com/lilendian0x00/xray-knife/v9/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v9/utils"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// zeroReader is an io.Reader that endlessly produces zero bytes.
type zeroReader struct{}

func (z zeroReader) Read(p []byte) (n int, err error) {
	return len(p), nil
}

// countingReader wraps an io.Reader and counts the total bytes read.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (n int, err error) {
	n, err = c.r.Read(p)
	c.n += int64(n)
	return
}

// ScannerConfig holds all configuration for a scan.
type ScannerConfig struct {
	Subnets              []string `json:"subnets"`
	ThreadCount          int      `json:"threadCount"`
	ShuffleIPs           bool     `json:"shuffleIPs"`
	ShuffleSubnets       bool     `json:"shuffleSubnets"`
	DoSpeedtest          bool     `json:"doSpeedtest"`
	RequestTimeout       int      `json:"timeout"`
	ShowTraceBody        bool     `json:"showTraceBody"`
	Verbose              bool     `json:"verbose"`
	OutputFile           string   `json:"outputFile"`
	RetryCount           int      `json:"retry"`
	OnlySpeedtestResults bool     `json:"onlySpeedtestResults"`
	DownloadMB           int      `json:"downloadMB"`
	UploadMB             int      `json:"uploadMB"`
	SpeedtestTop         int      `json:"speedtestTop"`
	SpeedtestConcurrency int      `json:"speedtestConcurrency"`
	SpeedtestTimeout     int      `json:"speedtestTimeout"`
	ConfigLink           string   `json:"configLink"`
	InsecureTLS          bool     `json:"insecureTLS"`
	Resume               bool     `json:"resume"`
	SaveToDB             bool     `json:"saveToDB"`
	OnIPScannedCallback  func()  `json:"-"` // Instance-scoped callback for progress reporting
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

// notifyIPScanned calls the instance callback if set, otherwise falls back to the global.
func (s *ScannerService) notifyIPScanned() {
	if s.config.OnIPScannedCallback != nil {
		s.config.OnIPScannedCallback()
	} else if OnIPScanned != nil {
		OnIPScanned()
	}
}

// ScanResult holds the outcome for a single scanned IP.
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

// NewScannerService builds a scanner service from the given config, resuming previous results if asked.
func NewScannerService(config ScannerConfig, logger *log.Logger) (*ScannerService, error) {
	s := &ScannerService{
		config:     config,
		logger:     logger,
		scannedIPs: make(map[string]bool),
	}

	if s.config.Resume {
		if s.config.SaveToDB {
			dbResults, err := database.GetCfScanResults()
			if err != nil {
				s.logger.Printf("Could not resume from database: %v. Starting fresh.", err)
			} else if len(dbResults) > 0 {
				s.initialResults = make([]*ScanResult, 0, len(dbResults))
				for ip, dbRes := range dbResults {
					s.scannedIPs[ip] = true
					res := &ScanResult{
						IP:        dbRes.IP,
						Latency:   time.Duration(dbRes.LatencyMs.Int64) * time.Millisecond,
						LatencyMS: dbRes.LatencyMs.Int64,
						DownSpeed: dbRes.DownloadMbps.Float64,
						UpSpeed:   dbRes.UploadMbps.Float64,
					}
					if dbRes.Error.Valid && dbRes.Error.String != "" {
						res.Error = errors.New(dbRes.Error.String)
						res.ErrorStr = dbRes.Error.String
					}
					s.initialResults = append(s.initialResults, res)
				}
				s.logger.Printf("Resumed %d results from the database.", len(s.initialResults))
			}
		} else {
			csvResults, err := LoadResultsFromCSV(s.config.OutputFile)
			if err != nil {
				s.logger.Printf("Could not resume from file %s: %v. Starting fresh.", s.config.OutputFile, err)
			} else if len(csvResults) > 0 {
				s.initialResults = csvResults
				for _, res := range csvResults {
					s.scannedIPs[res.IP] = true
				}
				s.logger.Printf("Resumed %d results from %s.", len(s.initialResults), s.config.OutputFile)
			}
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

// Run scans all IPs, sending results to progressChan. Blocks until done or ctx is canceled.
func (s *ScannerService) Run(ctx context.Context, progressChan chan<- *ScanResult) error {
	defer close(progressChan)

	workerResultsChan := make(chan *ScanResult, s.config.ThreadCount*2)

	runResultsMap := make(map[string]*ScanResult)
	var mapMu sync.Mutex
	var writerWg sync.WaitGroup
	writerWg.Add(1)

	// This goroutine consumes results from workers, saves them to DB, and forwards them to the UI.
	go func() {
		defer writerWg.Done()
		batch := make([]*ScanResult, 0, saveBatchSize)
		ticker := time.NewTicker(saveInterval)
		defer ticker.Stop()

		saveToDB := func() {
			if !s.config.SaveToDB || len(batch) == 0 {
				return
			}
			dbBatch := make([]database.CfScanResult, 0, len(batch))
			for _, res := range batch {
				res.PrepareForMarshal()
				dbRes := database.CfScanResult{
					IP:    res.IP,
					Error: sql.NullString{String: res.ErrorStr, Valid: res.ErrorStr != ""},
				}
				if res.Error == nil {
					dbRes.LatencyMs = sql.NullInt64{Int64: res.LatencyMS, Valid: true}
					if res.DownSpeed > 0 {
						dbRes.DownloadMbps = sql.NullFloat64{Float64: res.DownSpeed, Valid: true}
					}
					if res.UpSpeed > 0 {
						dbRes.UploadMbps = sql.NullFloat64{Float64: res.UpSpeed, Valid: true}
					}
				}
				dbBatch = append(dbBatch, dbRes)
			}

			if err := database.UpsertCfScanResultsBatch(dbBatch); err != nil {
				s.logger.Printf("Real-time DB save failed: %v", err)
			}
			batch = make([]*ScanResult, 0, saveBatchSize)
		}

		for {
			select {
			case <-ctx.Done():
				saveToDB()
				return
			case result, ok := <-workerResultsChan:
				if !ok {
					saveToDB()
					return
				}
				mapMu.Lock()
				runResultsMap[result.IP] = result
				mapMu.Unlock()
				batch = append(batch, result)

				// Forward progress to the UI/CLI channel
				select {
				case progressChan <- result:
				case <-ctx.Done():
				default:
					s.logger.Printf("UI progress channel full, dropping update for IP %s", result.IP)
				}

				if len(batch) >= saveBatchSize {
					saveToDB()
				}
			case <-ticker.C:
				saveToDB()
			}
		}
	}()

	// Latency Scan Phase
	if err := s.runLatencyScan(ctx, workerResultsChan); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logger.Printf("Latency scan failed: %v", err)
		}
		s.logger.Println("Latency scan cancelled.")
	} else {
		s.logger.Println("Latency scan phase finished.")
	}

	// Speed Test Phase
	if s.config.DoSpeedtest && ctx.Err() == nil {
		mapMu.Lock()
		resultsCopy := make([]*ScanResult, len(runResultsMap))
		i := 0
		for _, r := range runResultsMap {
			resultsCopy[i] = r
			i++
		}
		mapMu.Unlock()

		if err := s.runSpeedTest(ctx, resultsCopy, workerResultsChan); err != nil {
			if !errors.Is(err, context.Canceled) {
				s.logger.Printf("Speed test failed: %v", err)
			}
			s.logger.Println("Speed test cancelled.")
		}
		s.logger.Println("Speed test phase finished.")
	}

	close(workerResultsChan)
	writerWg.Wait()

	// Final Result Processing and Saving
	finalCombinedResults := runResultsMap
	if s.config.Resume {
		for _, initialResult := range s.initialResults {
			if _, exists := finalCombinedResults[initialResult.IP]; !exists {
				finalCombinedResults[initialResult.IP] = initialResult
			}
		}
	}

	var finalResultsSlice []*ScanResult
	for _, result := range finalCombinedResults {
		result.PrepareForMarshal()
		finalResultsSlice = append(finalResultsSlice, result)
	}

	sort.Slice(finalResultsSlice, func(i, j int) bool {
		r_i, r_j := finalResultsSlice[i], finalResultsSlice[j]
		if r_i.Error != nil && r_j.Error == nil {
			return false
		}
		if r_i.Error == nil && r_j.Error != nil {
			return true
		}
		if r_i.Error != nil && r_j.Error != nil {
			return r_i.IP < r_j.IP
		}
		if s.config.DoSpeedtest {
			if r_i.Latency != r_j.Latency {
				return r_i.Latency < r_j.Latency
			}
			return r_i.DownSpeed > r_j.DownSpeed
		}
		return r_i.Latency < r_j.Latency
	})

	if err := saveResultsToCSV(s.config.OutputFile, finalResultsSlice); err != nil {
		s.logger.Printf("Error saving final results to CSV: %v", err)
		return err
	}

	s.logger.Println("Scan process completed.")
	return nil
}

// OnIPScanned is a deprecated global hook for progress reporting.
// Prefer using ScannerConfig.OnIPScannedCallback instead.
var OnIPScanned func()

func (s *ScannerService) runLatencyScan(ctx context.Context, workerResultsChan chan<- *ScanResult) error {
	s.logger.Printf("Phase 1: Scanning for latency with %d threads...", s.config.ThreadCount)
	pool := pond.NewPool(s.config.ThreadCount)
	defer pool.Stop()

	group := pool.NewGroupContext(ctx)

	var hasIPs bool
	if s.config.ShuffleSubnets {
		rand.Shuffle(len(s.config.Subnets), func(i, j int) {
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
			rand.Shuffle(len(listIP), func(i, j int) { listIP[i], listIP[j] = listIP[j], listIP[i] })
			for _, ip := range listIP {
				if _, exists := s.scannedIPs[ip]; exists {
					s.notifyIPScanned()
					continue
				}
				ipToScan := ip
				group.Submit(func() {
					defer s.notifyIPScanned()
					res := s.scanIPForLatency(group.Context(), ipToScan)
					select {
					case workerResultsChan <- res:
					case <-group.Context().Done():
					}
				})
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
					s.notifyIPScanned()
					continue
				}
				group.Submit(func() {
					defer s.notifyIPScanned()
					res := s.scanIPForLatency(group.Context(), ipStr)
					select {
					case workerResultsChan <- res:
					case <-group.Context().Done():
					}
				})
			}
		}
	}

	if !hasIPs && len(s.initialResults) == 0 {
		return errors.New("scanner failed: no scannable IPs detected")
	}

	return group.Wait()
}

func (s *ScannerService) runSpeedTest(ctx context.Context, allResults []*ScanResult, workerResultsChan chan<- *ScanResult) error {
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
	group := speedTestPool.NewGroupContext(ctx)

	for _, result := range topResults {
		result.mu.Lock()
		alreadyTested := result.DownSpeed > 0 || result.UpSpeed > 0
		result.mu.Unlock()
		if alreadyTested {
			continue // Already tested
		}
		resToTest := result
		group.Submit(func() {
			timeoutCtx, cancel := context.WithTimeout(group.Context(), time.Duration(s.config.SpeedtestTimeout)*time.Second)
			defer cancel()
			downSpeed, upSpeed, err := s.measureSpeed(timeoutCtx, resToTest.IP)
			resToTest.mu.Lock()
			resToTest.DownSpeed = downSpeed
			resToTest.UpSpeed = upSpeed
			resToTest.Error = err
			resToTest.mu.Unlock()

			select {
			case workerResultsChan <- resToTest:
			case <-group.Context().Done():
			}
		})
	}

	return group.Wait()
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

	// Read the body to properly account for the whole request time.
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		result.Error = fmt.Errorf("failed to read body: %w", readErr)
		return result
	}
	result.Latency = time.Since(start)

	if s.config.ShowTraceBody {
		s.logger.Printf("Trace body for %s:\n%s", ip, string(body))
	}

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
		client = &http.Client{
			Transport: transport,
			Timeout:   time.Duration(s.config.SpeedtestTimeout) * time.Second,
		}
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

	// Use a memory-efficient counting reader instead of a massive byte slice
	upCounter := &countingReader{r: io.LimitReader(zeroReader{}, uploadBytesTotal)}
	reqUp, err := http.NewRequestWithContext(ctx, "POST", upURL, upCounter)
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
	if _, drainErr := io.Copy(io.Discard, respUp.Body); drainErr != nil {
		return downSpeed, 0, fmt.Errorf("upload response drain: %w", drainErr)
	}
	if respUp.StatusCode < 200 || respUp.StatusCode >= 300 {
		return downSpeed, 0, fmt.Errorf("upload status: %s", respUp.Status)
	}
	upDuration := time.Since(startUp).Seconds()
	if upDuration > 0 {
		upSpeed = (float64(upCounter.n) * 8) / (upDuration * 1e6)
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
	return selectedCore.MakeHttpClient(context.Background(), proto, timeout)
}

const (
	saveBatchSize          = 50
	saveInterval           = 3 * time.Second
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

func LoadResultsFromCSV(filePath string) ([]*ScanResult, error) {
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

// saveResultsToCSV overwrites a file with the given results.
func saveResultsToCSV(filePath string, results []*ScanResult) error {
	if len(results) == 0 {
		return nil // Don't create an empty file
	}
	for _, r := range results {
		r.PrepareForMarshal()
	}
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create/truncate file for saving: %w", err)
	}
	defer file.Close()

	return gocsv.MarshalFile(&results, file)
}

// connClosingBody also closes the underlying conn on Close() because
// BypassJA3Transport manages connections outside of http.Transport's pool.
type connClosingBody struct {
	io.ReadCloser
	conn net.Conn
}

func (c *connClosingBody) Close() error {
	err := c.ReadCloser.Close()
	c.conn.Close()
	return err
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
		resp, err := clientConn.RoundTrip(req)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}
		resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: tlsConn}
		return resp, nil
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
		resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: tlsConn}
		return resp, nil
	default:
		tlsConn.Close()
		return nil, fmt.Errorf("unsupported http version: %s", httpVersion)
	}
}

func (b *BypassJA3Transport) getTLSConfig(req *http.Request) *utls.Config {
	return &utls.Config{
		ServerName:         req.URL.Hostname(),
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
