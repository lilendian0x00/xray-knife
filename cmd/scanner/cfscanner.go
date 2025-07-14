package scanner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/lilendian0x00/xray-knife/v5/pkg/core/protocol"
	"io"
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
	"github.com/lilendian0x00/xray-knife/v5/pkg"
	"github.com/lilendian0x00/xray-knife/v5/utils"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"
	utls "github.com/refraction-networking/utls"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
)

// Configuration for the real-time saver
const (
	saveBatchSize = 500
	saveInterval  = 5 * time.Second
)

var (
	subnets              string
	threadCount          int
	shuffleIPs           bool
	shuffleSubnets       bool
	doSpeedtest          bool
	requestTimeout       int
	ShowTraceBody        bool
	Verbose              bool
	outputFile           string
	retryCount           int
	onlySpeedtestResults bool
	downloadMB           int
	uploadMB             int
	speedtestTop         int
	speedtestConcurrency int
	speedtestTimeout     int
	configLink           string
	insecureTLS          bool
	resume               bool
	resumeFile           string

	xrayCore        pkg.Core
	singboxCore     pkg.Core
	selectedCoreMap map[string]pkg.Core
)

type ScanResult struct {
	IP        string        `csv:"ip"`
	Latency   time.Duration `csv:"-"`
	LatencyMS int64         `csv:"latency_ms"`
	DownSpeed float64       `csv:"download_mbps"`
	UpSpeed   float64       `csv:"upload_mbps"`
	Error     error         `csv:"-"`
	ErrorStr  string        `csv:"error,omitempty"`
	mu        sync.Mutex
}

// resultWriter is a dedicated goroutine that listens for new results on a channel
// and saves them to disk in batches
func resultWriter(wg *sync.WaitGroup, resultsChan <-chan *ScanResult, initialResults []*ScanResult, filePath string) {
	defer wg.Done()

	allResults := make(map[string]*ScanResult)
	for _, r := range initialResults {
		allResults[r.IP] = r
	}

	batch := make([]*ScanResult, 0, saveBatchSize)
	ticker := time.NewTicker(saveInterval)
	defer ticker.Stop()

	save := func() {
		if len(batch) == 0 {
			return
		}
		for _, res := range batch {
			// Lock the result while reading its data to prevent a data race with a speed test worker.
			res.mu.Lock()
			// Update the master list with the latest data for this IP.
			allResults[res.IP] = res
			res.mu.Unlock()
		}

		resultsToSave := make([]*ScanResult, 0, len(allResults))
		for _, r := range allResults {
			resultsToSave = append(resultsToSave, r)
		}

		if err := saveResultsToCSV(filePath, resultsToSave); err != nil {
			customlog.Printf(customlog.Failure, "Real-time save failed: %v\n", err)
		} else if Verbose {
			customlog.Printf(customlog.Info, "Progress for %d new results saved to %s\n", len(batch), filePath)
		}
		batch = make([]*ScanResult, 0, saveBatchSize)
	}

	for {
		select {
		case result, ok := <-resultsChan:
			if !ok {
				save()
				return
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

const (
	cloudflareTraceURL     = "https://cloudflare.com/cdn-cgi/trace"
	cloudflareSpeedTestURL = "speed.cloudflare.com"
)

var CFscannerCmd = &cobra.Command{
	Use:   "cfscanner",
	Short: "Cloudflare's edge IP scanner with latency/speed tests and real-time resume.",
	Long: `Scans Cloudflare IPs with real-time progress saving for maximum durability.

The scanner saves progress to the output CSV file periodically. If the scan is interrupted
at any time (even during the latency test), you can use the --resume flag to continue
from almost exactly where you left off, minimizing lost work.

Phase 1 (Latency Scan):
Quickly tests latency of all IPs. Progress is saved in batches, so an interruption only
loses the most recent, unsaved results.

Phase 2 (Speed Test):
Performs a full speed test on the fastest IPs. This phase can also be resumed seamlessly.`,
	Run: func(cmd *cobra.Command, args []string) {
		initialResults := []*ScanResult{}
		scannedIPs := make(map[string]bool)

		if resume {
			resumedResults, err := loadResultsForResume(resumeFile)
			if err != nil {
				customlog.Printf(customlog.Warning, "Could not resume from %s: %v. Starting fresh.\n", resumeFile, err)
			} else if len(resumedResults) > 0 {
				initialResults = resumedResults
				for _, r := range resumedResults {
					scannedIPs[r.IP] = true
				}
				customlog.Printf(customlog.Info, "Resumed %d results from %s\n", len(initialResults), resumeFile)
			}
		} else {
			// For a fresh scan, remove the old results file.
			// Ignore a "not found" error, as that's an expected state.
			err := os.Remove(outputFile)
			if err != nil && !os.IsNotExist(err) {
				// If another error occurred (e.g., permissions), we should stop.
				customlog.Printf(customlog.Failure, "Failed to clear previous results file %s: %v\n", outputFile, err)
				return
			}
		}

		resultsChan := make(chan *ScanResult, threadCount)
		var writerWg sync.WaitGroup
		writerWg.Add(1)
		go resultWriter(&writerWg, resultsChan, initialResults, outputFile)

		if configLink != "" {
			customlog.Printf(customlog.Info, "Using config link to test IPs: %s\n", configLink)
			xrayCore = pkg.CoreFactory(pkg.XrayCoreType, insecureTLS, Verbose)
			singboxCore = pkg.CoreFactory(pkg.SingboxCoreType, insecureTLS, Verbose)
			selectedCoreMap = map[string]pkg.Core{
				protocol.VmessIdentifier: xrayCore, protocol.VlessIdentifier: xrayCore,
				protocol.ShadowsocksIdentifier: xrayCore, protocol.TrojanIdentifier: xrayCore,
				protocol.SocksIdentifier: xrayCore, protocol.WireguardIdentifier: xrayCore,
				protocol.Hysteria2Identifier: singboxCore, "hy2": singboxCore,
			}
		}

		var cidrs []string
		if _, err := os.Stat(subnets); err == nil {
			cidrs = utils.ParseFileByNewline(subnets)
		} else {
			cidrs = strings.Split(subnets, ",")
		}
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		if shuffleSubnets {
			r.Shuffle(len(cidrs), func(i, j int) { cidrs[i], cidrs[j] = cidrs[j], cidrs[i] })
		}

		customlog.Printf(customlog.Info, "Phase 1: Scanning for latency with %d threads...\n", threadCount)
		pool := pond.NewPool(threadCount)
		var hasIPs bool

		for _, cidr := range cidrs {
			if shuffleIPs {
				listIP, err := utils.CIDRtoListIP(cidr)
				if err != nil {
					customlog.Printf(customlog.Failure, "Error processing CIDR %s: %v\n", cidr, err)
					continue
				}
				if len(listIP) > 0 {
					hasIPs = true
				}
				r.Shuffle(len(listIP), func(i, j int) { listIP[i], listIP[j] = listIP[j], listIP[i] })
				for _, ip := range listIP {
					if _, exists := scannedIPs[ip]; exists {
						continue
					}
					pool.Submit(func(ip string) func() { return func() { resultsChan <- scanIPForLatency(ip, configLink) } }(ip))
				}
			} else {
				ip, ipnet, err := net.ParseCIDR(cidr)
				if err != nil {
					customlog.Printf(customlog.Failure, "Error parsing CIDR %s: %v\n", cidr, err)
					continue
				}
				for currentIP := ip.Mask(ipnet.Mask); ipnet.Contains(currentIP); inc(currentIP) {
					if !hasIPs {
						hasIPs = true
					}
					ipToScan := make(net.IP, len(currentIP))
					copy(ipToScan, currentIP)
					ipStr := ipToScan.String()
					if _, exists := scannedIPs[ipStr]; exists {
						continue
					}
					pool.Submit(func(ip string) func() { return func() { resultsChan <- scanIPForLatency(ip, configLink) } }(ipStr))
				}
			}
		}

		if !hasIPs && len(initialResults) == 0 {
			customlog.Printf(customlog.Failure, "Scanner failed! => No scannable IPs detected.\n")
			close(resultsChan)
			writerWg.Wait()
			return
		}
		pool.StopAndWait()
		customlog.Printf(customlog.Success, "Latency scan phase finished.\n")

		// To get the candidates for the speed test, we first ensure all latency results are written to disk,
		// then we read the file back. This makes the file the single source of truth and simplifies the logic.
		close(resultsChan)
		writerWg.Wait() // Wait for the writer to perform its final save of latency results.

		if doSpeedtest {
			// Now, read the complete state from the file.
			allResults, err := loadResultsForResume(outputFile)
			if err != nil {
				customlog.Printf(customlog.Failure, "Could not load results for speed test phase: %v\n", err)
				return
			}

			// Filter for only successful latency tests.
			var successfulLatencyResults []*ScanResult
			for _, r := range allResults {
				if r.Error == nil {
					successfulLatencyResults = append(successfulLatencyResults, r)
				}
			}

			if len(successfulLatencyResults) > 0 {
				sort.Slice(successfulLatencyResults, func(i, j int) bool {
					return successfulLatencyResults[i].Latency < successfulLatencyResults[j].Latency
				})

				numToTest := speedtestTop
				if len(successfulLatencyResults) < speedtestTop {
					numToTest = len(successfulLatencyResults)
				}
				topResults := successfulLatencyResults[:numToTest]

				customlog.Printf(customlog.Info, "Phase 2: Performing speed tests on the top %d IPs (with %d concurrent tests, %ds timeout each)...\n", len(topResults), speedtestConcurrency, speedtestTimeout)

				// We need a new writer for the speed test results.
				speedTestResultsChan := make(chan *ScanResult, speedtestConcurrency)
				writerWg.Add(1)
				go resultWriter(&writerWg, speedTestResultsChan, allResults, outputFile)

				speedTestPool := pond.NewPool(speedtestConcurrency)
				for _, result := range topResults {
					if result.DownSpeed > 0 || result.UpSpeed > 0 {
						continue
					}
					speedTestPool.Submit(func(res *ScanResult) func() {
						return func() {
							ctx, cancel := context.WithTimeout(context.Background(), time.Duration(speedtestTimeout)*time.Second)
							defer cancel()

							downSpeed, upSpeed, err := measureSpeed(ctx, res.IP, configLink)

							// Lock the result struct before updating it to prevent the resultWriter
							// from reading it while it's in an inconsistent state.
							res.mu.Lock()
							res.DownSpeed = downSpeed
							res.UpSpeed = upSpeed
							res.Error = err
							res.mu.Unlock()

							if err == nil {
								customlog.Printf(customlog.Success, "SPEEDTEST: %-20s | %-10v | %-15.2f | %-15.2f\n", res.IP, res.Latency.Round(time.Millisecond), downSpeed, upSpeed)
							} else if os.IsTimeout(err) || errors.Is(err, context.DeadlineExceeded) {
								customlog.Printf(customlog.Warning, "IP %s failed speed test: Timeout exceeded\n", res.IP)
							} else if Verbose {
								customlog.Printf(customlog.Warning, "IP %s failed speed test: %v\n", res.IP, err)
							}

							speedTestResultsChan <- res
						}
					}(result))
				}
				speedTestPool.StopAndWait()
				customlog.Printf(customlog.Success, "Speed test phase finished.\n")

				close(speedTestResultsChan)
				writerWg.Wait() // Wait for the final speed test save.
			}
		}

		// Load final, complete data for printing to console.
		finalSortedResults, err := loadResultsForResume(outputFile)
		if err != nil {
			customlog.Printf(customlog.Failure, "Could not load final results for display: %v\n", err)
		} else {
			printResultsToConsole(finalSortedResults)
		}

		customlog.Printf(customlog.Success, "Scan finished. Final results saved to %s\n", outputFile)
	},
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func createDialerWithRetry(ip string, retries int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout: time.Duration(requestTimeout) * time.Millisecond,
		}
		targetAddr := fmt.Sprintf("%s:%d", ip, 443)
		var lastErr error

		for i := 0; i <= retries; i++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if Verbose && i > 0 {
				customlog.Printf(customlog.Info, "Retrying connection to %s (attempt %d/%d)...\n", ip, i+1, retries+1)
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

func scanIPForLatency(ip, baseConfigLink string) *ScanResult {
	result := &ScanResult{IP: ip}
	var client *http.Client
	var instance protocol.Instance
	var err error

	if baseConfigLink != "" {
		client, instance, err = createClientFromConfig(ip, baseConfigLink, time.Duration(requestTimeout)*time.Millisecond)
		if err != nil {
			result.Error = fmt.Errorf("failed creating client from config for latency test: %w", err)
			return result
		}
		defer instance.Close()
	} else {
		transport := NewBypassJA3Transport(utls.HelloChrome_Auto)
		transport.DialContext = createDialerWithRetry(ip, retryCount)
		client = &http.Client{
			Transport: transport,
			Timeout:   time.Duration(requestTimeout) * time.Millisecond,
		}
	}

	req, err := http.NewRequest("GET", cloudflareTraceURL, nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to create request: %w", err)
		return result
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

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

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Errorf("failed to read body: %w", err)
		return result
	}
	result.Latency = time.Since(start)

	if ShowTraceBody {
		fmt.Println(string(bodyBytes))
	}

	customlog.Printf(customlog.Success, "LATENCY:   %-20s | %-10v\n", ip, result.Latency.Round(time.Millisecond))
	return result
}

func measureSpeed(ctx context.Context, ip, baseConfigLink string) (downSpeed float64, upSpeed float64, err error) {
	downloadBytesTotal := int64(downloadMB * 1024 * 1024)
	uploadBytesTotal := int64(uploadMB * 1024 * 1024)
	var client *http.Client
	var instance protocol.Instance

	if baseConfigLink != "" {
		client, instance, err = createClientFromConfig(ip, baseConfigLink, time.Duration(speedtestTimeout)*time.Second)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to create speedtest client from config: %w", err)
		}
		defer instance.Close()
	} else {
		transport := NewBypassJA3Transport(utls.HelloChrome_Auto)
		transport.DialContext = createDialerWithRetry(ip, retryCount)
		client = &http.Client{Transport: transport}
	}

	downURL := fmt.Sprintf("https://%s/__down?bytes=%d", cloudflareSpeedTestURL, downloadBytesTotal)
	reqDown, err := http.NewRequestWithContext(ctx, "GET", downURL, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create download request: %w", err)
	}
	reqDown.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	startDown := time.Now()
	respDown, err := client.Do(reqDown)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
			return 0, 0, errors.New("speed test timed out during download")
		}
		return 0, 0, fmt.Errorf("download test failed: %w", err)
	}
	defer respDown.Body.Close()

	if respDown.StatusCode < 200 || respDown.StatusCode >= 300 {
		return 0, 0, fmt.Errorf("download test received status: %s", respDown.Status)
	}

	written, err := io.Copy(io.Discard, respDown.Body)
	if err != nil {
		return 0, 0, fmt.Errorf("failed while reading download stream: %w", err)
	}
	downDuration := time.Since(startDown).Seconds()
	if downDuration > 0 {
		downSpeed = (float64(written) * 8) / (downDuration * 1e6)
	}

	if ctx.Err() != nil {
		return downSpeed, 0, errors.New("operation cancelled before upload")
	}

	upURL := fmt.Sprintf("https://%s/__up", cloudflareSpeedTestURL)
	reqUp, err := http.NewRequestWithContext(ctx, "POST", upURL, bytes.NewReader(make([]byte, uploadBytesTotal)))
	if err != nil {
		return downSpeed, 0, fmt.Errorf("failed to create upload request: %w", err)
	}
	reqUp.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")
	reqUp.Header.Set("Content-Type", "application/octet-stream")

	startUp := time.Now()
	respUp, err := client.Do(reqUp)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return downSpeed, 0, errors.New("speed test timed out during upload")
		}
		return downSpeed, 0, fmt.Errorf("upload test failed: %w", err)
	}
	defer respUp.Body.Close()
	io.Copy(io.Discard, respUp.Body)

	if respUp.StatusCode < 200 || respUp.StatusCode >= 300 {
		return downSpeed, 0, fmt.Errorf("upload test received status: %s", respUp.Status)
	}
	upDuration := time.Since(startUp).Seconds()
	if upDuration > 0 {
		upSpeed = (float64(uploadBytesTotal) * 8) / (upDuration * 1e6)
	}

	return downSpeed, upSpeed, nil
}

func formatResultLine(result ScanResult, speedtestEnabled bool) string {
	if speedtestEnabled {
		return fmt.Sprintf("%-20s | %-10v | %-15.2f | %-15.2f", result.IP, result.Latency.Round(time.Millisecond), result.DownSpeed, result.UpSpeed)
	}
	return fmt.Sprintf("%-20s | %-10v", result.IP, result.Latency.Round(time.Millisecond))
}

func printResultsToConsole(results []*ScanResult) {
	if len(results) == 0 {
		customlog.Printf(customlog.Warning, "No results to display.\n")
		return
	}

	// Create a new slice containing only successful results for display purposes.
	var successfulResults []*ScanResult
	for _, r := range results {
		if r.Error == nil {
			successfulResults = append(successfulResults, r)
		}
	}

	if len(successfulResults) == 0 {
		customlog.Printf(customlog.Warning, "No successful IPs found to display.\n")
		return
	}

	var finalResults []*ScanResult
	// Now, filter the successful results further if only-speedtest is enabled
	if doSpeedtest && onlySpeedtestResults {
		customlog.Printf(customlog.Info, "Filtering results to include only those with successful speed tests...\n")
		for _, r := range successfulResults { // Use the pre-filtered successful results
			if r.DownSpeed > 0 || r.UpSpeed > 0 {
				finalResults = append(finalResults, r)
			}
		}
		customlog.Printf(customlog.Info, "Filtered from %d to %d results.\n", len(successfulResults), len(finalResults))
	} else {
		finalResults = successfulResults // Use all successful results
	}

	if len(finalResults) == 0 {
		customlog.Printf(customlog.Warning, "No results to display after filtering.\n")
		return
	}

	sort.Slice(finalResults, func(i, j int) bool {
		if doSpeedtest {
			// Sort by latency first, then by speed
			if finalResults[i].Latency != finalResults[j].Latency {
				return finalResults[i].Latency < finalResults[j].Latency
			}
			if finalResults[i].DownSpeed != finalResults[j].DownSpeed {
				return finalResults[i].DownSpeed > finalResults[j].DownSpeed
			}
			return finalResults[i].UpSpeed > finalResults[j].UpSpeed
		}
		// Default sort by latency only
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
		// Pass a copy of the struct to the formatting function to be safe.
		outputLines = append(outputLines, formatResultLine(*result, doSpeedtest))
	}
	finalOutput := strings.Join(outputLines, "\n")
	customlog.Println(customlog.GetColor(customlog.None, "\n--- Sorted Results ---\n"))
	customlog.Println(customlog.GetColor(customlog.Success, finalOutput))
	customlog.Println(customlog.GetColor(customlog.None, "\n--------------------\n"))
}

func loadResultsForResume(filePath string) ([]*ScanResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var results []*ScanResult
	if err := gocsv.UnmarshalFile(file, &results); err != nil {
		return nil, fmt.Errorf("failed to parse resume file (must be CSV): %w", err)
	}

	for _, r := range results {
		r.Latency = time.Duration(r.LatencyMS) * time.Millisecond
		if r.ErrorStr != "" {
			r.Error = errors.New(r.ErrorStr)
		}
	}
	return results, nil
}

func saveResultsToCSV(filePath string, results []*ScanResult) error {
	// This function is now only called from the single resultWriter goroutine,
	// so the mutex is no longer needed here.
	for _, r := range results {
		r.mu.Lock()
		r.LatencyMS = r.Latency.Milliseconds()
		if r.Error != nil {
			r.ErrorStr = r.Error.Error()
		} else {
			r.ErrorStr = "" // Ensure error string is empty on success
		}
		r.mu.Unlock()
	}

	// Sort the results before saving to ensure the CSV is always ordered.
	sort.Slice(results, func(i, j int) bool {
		resI := results[i]
		resJ := results[j]

		// Results with errors go to the bottom.
		iHasError := resI.Error != nil || resI.ErrorStr != ""
		jHasError := resJ.Error != nil || resJ.ErrorStr != ""

		if iHasError && !jHasError {
			return false // i (error) comes after j (success)
		}
		if !iHasError && jHasError {
			return true // i (success) comes before j (error)
		}
		// If both have errors, sort by IP to have a stable order
		if iHasError && jHasError {
			return resI.IP < resJ.IP
		}

		// If both are successful, sort by performance.
		if doSpeedtest {
			// Sort by latency first, then by speed
			if resI.Latency != resJ.Latency {
				return resI.Latency < resJ.Latency
			}
			if resI.DownSpeed != resJ.DownSpeed {
				return resI.DownSpeed > resJ.DownSpeed
			}
			return resI.UpSpeed > resJ.UpSpeed
		}
		// Default sort by latency only
		return resI.Latency < resJ.Latency
	})

	tempFilePath := filePath + ".tmp"
	file, err := os.Create(tempFilePath)
	if err != nil {
		return fmt.Errorf("could not create temporary file: %w", err)
	}

	err = gocsv.MarshalFile(&results, file)
	file.Close()
	if err != nil {
		os.Remove(tempFilePath)
		return fmt.Errorf("could not marshal results to CSV: %w", err)
	}

	return os.Rename(tempFilePath, filePath)
}

func init() {
	CFscannerCmd.Flags().StringVarP(&subnets, "subnets", "s", "", "Subnet or file containing subnets (e.g., \"1.1.1.1/24,2.2.2.2/16\")")
	CFscannerCmd.Flags().IntVarP(&threadCount, "threads", "t", 100, "Count of threads for latency scan")
	CFscannerCmd.Flags().BoolVarP(&doSpeedtest, "speedtest", "p", false, "Measure download/upload speed on the fastest IPs")
	CFscannerCmd.Flags().IntVarP(&speedtestTop, "speedtest-top", "c", 1000000, "Number of fastest IPs to select for speed testing")
	CFscannerCmd.Flags().IntVarP(&speedtestConcurrency, "speedtest-concurrency", "", 4, "Number of concurrent speed tests to run (to avoid saturating bandwidth)")
	CFscannerCmd.Flags().IntVarP(&speedtestTimeout, "speedtest-timeout", "", 30, "Total timeout in seconds for one IP's speed test (download + upload)")
	CFscannerCmd.Flags().IntVarP(&requestTimeout, "timeout", "u", 5000, "Individual request timeout (in ms)")
	CFscannerCmd.Flags().BoolVarP(&ShowTraceBody, "body", "b", false, "Show trace body output")
	CFscannerCmd.Flags().BoolVarP(&Verbose, "verbose", "v", false, "Show verbose output with detailed errors")
	CFscannerCmd.Flags().BoolVarP(&shuffleSubnets, "shuffle-subnet", "e", false, "Shuffle list of Subnets")
	CFscannerCmd.Flags().BoolVarP(&shuffleIPs, "shuffle-ip", "i", false, "Shuffle list of IPs")
	CFscannerCmd.Flags().StringVarP(&outputFile, "output", "o", "results.csv", "Output file to save sorted results (in CSV format)")
	CFscannerCmd.Flags().IntVarP(&retryCount, "retry", "r", 1, "Number of times to retry TCP connection on failure")
	CFscannerCmd.Flags().BoolVarP(&onlySpeedtestResults, "only-speedtest", "k", false, "Only display results that have successful speedtest data")
	CFscannerCmd.Flags().IntVarP(&downloadMB, "download-mb", "d", 20, "Custom amount of data to download for speedtest (in MB)")
	CFscannerCmd.Flags().IntVarP(&uploadMB, "upload-mb", "m", 10, "Custom amount of data to upload for speedtest (in MB)")
	CFscannerCmd.Flags().StringVarP(&configLink, "config", "C", "", "Use a config link as a proxy to test IPs")
	CFscannerCmd.Flags().BoolVarP(&insecureTLS, "insecure", "E", false, "Allow insecure TLS connections for the proxy config")
	CFscannerCmd.Flags().StringVar(&resumeFile, "resume-file", "results.csv", "Resume scan file")
	CFscannerCmd.Flags().BoolVar(&resume, "resume", false, "Resume scan")

	_ = CFscannerCmd.MarkFlagRequired("subnets")
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

func createClientFromConfig(ip, baseConfigLink string, timeout time.Duration) (*http.Client, protocol.Instance, error) {
	uri, err := url.Parse(baseConfigLink)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse config link for core selection: %w", err)
	}
	selectedCore, ok := selectedCoreMap[uri.Scheme]
	if !ok {
		return nil, nil, fmt.Errorf("unsupported protocol scheme for auto core: %s", uri.Scheme)
	}
	proto, errProto := selectedCore.CreateProtocol(baseConfigLink)
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
