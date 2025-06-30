package scanner

import (
	"bytes"
	"context"
	"errors" // Import the errors package
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"

	"github.com/alitto/pond/v2"
	"github.com/lilendian0x00/xray-knife/v5/utils"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"

	"github.com/spf13/cobra"
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
	liveOutputFile       string
	onlySpeedtestResults bool
	downloadMB           int
	uploadMB             int
	speedtestTop         int
	speedtestConcurrency int
	speedtestTimeout     int
)

// ScanResult holds the result of a scan for a single IP.
type ScanResult struct {
	IP        string
	Latency   time.Duration
	DownSpeed float64 // in Mbps
	UpSpeed   float64 // in Mbps
	Error     error
}

const (
	cloudflareTraceURL     = "https://cloudflare.com/cdn-cgi/trace"
	cloudflareSpeedTestURL = "speed.cloudflare.com"
	tLSHandshakeTimeout    = 15 * time.Second
)

// CFscannerCmd represents the cfscanner command
var CFscannerCmd = &cobra.Command{
	Use:   "cfscanner",
	Short: "Cloudflare's edge IP scanner (delay, downlink, uplink)",
	Long: `Scans Cloudflare IPs in two phases for efficiency and accuracy.

Phase 1 (Latency Scan):
It uses a high number of threads (-t) to quickly test the latency of all IPs in the given subnets.

Phase 2 (Speed Test):
If --speedtest is enabled, it takes the fastest IPs (-c) and performs a full speed test on them.
This phase is controlled by two settings:
- --speedtest-concurrency: Limits how many tests run at once to avoid saturating your network.
- --speedtest-timeout: Sets a strict time limit for each IP's entire speed test.

Example: xray-knife scan cfscanner -s "104.16.124.0/24" -t 100 -p -c 10 -sc 4 -st 45 -o results.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		// ... (setup code remains the same) ...
		var cidrs []string
		var results []*ScanResult // Use slice of pointers for easier in-place updates
		var resultsMutex sync.Mutex
		var hasIPs bool // Used to check if any scannable IPs were found

		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		if _, err := os.Stat(subnets); err == nil {
			cidrs = utils.ParseFileByNewline(subnets)
		} else {
			cidrs = strings.Split(subnets, ",")
		}

		if shuffleSubnets {
			r.Shuffle(len(cidrs), func(i, j int) { cidrs[i], cidrs[j] = cidrs[j], cidrs[i] })
		}

		var liveFile *os.File
		if liveOutputFile != "" {
			var err error
			liveFile, err = os.OpenFile(liveOutputFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				customlog.Printf(customlog.Failure, "Could not open live output file %s: %v. Continuing without live saving.\n", liveOutputFile, err)
				liveFile = nil
			} else {
				defer liveFile.Close()
				header := fmt.Sprintf("%-20s | %-10s", "IP", "Latency")
				if _, err := fmt.Fprintln(liveFile, header); err != nil {
					customlog.Printf(customlog.Failure, "Failed to write header to live output file: %v\n", err)
				} else {
					customlog.Printf(customlog.Info, "Saving live latency results to %s\n", liveOutputFile)
				}
			}
		}

		customlog.Printf(customlog.Info, "Phase 1: Scanning for latency from %d subnets with %d threads...\n", len(cidrs), threadCount)
		if shuffleIPs {
			customlog.Printf(customlog.Warning, "IP shuffling is enabled. This may use more memory for large subnets.\n")
		}

		handleLatencyResult := func(result *ScanResult) {
			if result.Error != nil {
				return
			}
			resultsMutex.Lock()
			defer resultsMutex.Unlock()
			results = append(results, result)
			if liveFile != nil {
				line := formatResult(*result)
				if _, err := fmt.Fprintln(liveFile, line); err != nil {
					customlog.Printf(customlog.Warning, "Failed to write live result for IP %s: %v\n", result.IP, err)
				}
			}
		}

		pool := pond.NewPool(threadCount)

		// Phase 1: Latency Scanning (remains the same)
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
					pool.Submit(func(ip string) func() { return func() { handleLatencyResult(scanIPForLatency(ip)) } }(ip))
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
					pool.Submit(func(ip string) func() { return func() { handleLatencyResult(scanIPForLatency(ip)) } }(ipToScan.String()))
				}
			}
		}

		if !hasIPs {
			customlog.Printf(customlog.Failure, "Scanner failed! => No IP detected in the provided subnets\n")
			return
		}
		pool.StopAndWait()

		customlog.Printf(customlog.Success, "Latency scan finished. Found %d responsive IPs.\n", len(results))

		// Phase 2: Speed Test on Top IPs
		if doSpeedtest && len(results) > 0 {
			customlog.Printf(customlog.Info, "Sorting latency results to select the best IPs for speed testing...\n")
			sort.Slice(results, func(i, j int) bool {
				return results[i].Latency < results[j].Latency
			})

			numToTest := speedtestTop
			if len(results) < speedtestTop {
				numToTest = len(results)
			}
			topResults := results[:numToTest]

			customlog.Printf(customlog.Info, "Phase 2: Performing speed tests on the top %d IPs (with %d concurrent tests, %ds timeout each)...\n", len(topResults), speedtestConcurrency, speedtestTimeout)
			speedTestPool := pond.NewPool(speedtestConcurrency)
			for _, result := range topResults {
				speedTestPool.Submit(func(res *ScanResult) func() {
					return func() {
						// *** KEY CHANGE: Create a context with the specified timeout for the speed test ***
						ctx, cancel := context.WithTimeout(context.Background(), time.Duration(speedtestTimeout)*time.Second)
						defer cancel() // Ensure context resources are released

						// Pass the context to the measureSpeed function
						downSpeed, upSpeed, err := measureSpeed(ctx, res.IP)
						if err != nil {
							customlog.Printf(customlog.Warning, "IP %s failed speed test: %v\n", res.IP, err)
						}
						res.DownSpeed = downSpeed
						res.UpSpeed = upSpeed
						customlog.Printf(customlog.Success, "SPEEDTEST: %-20s | %-10v | %-15.2f | %-15.2f\n", res.IP, res.Latency.Round(time.Millisecond), downSpeed, upSpeed)
					}
				}(result))
			}
			speedTestPool.StopAndWait()
			customlog.Printf(customlog.Success, "Speed test phase finished.\n")
		}

		// ... (Final sorting and printing remains the same) ...
		customlog.Printf(customlog.Info, "Sorting %d final results...\n", len(results))
		sort.Slice(results, func(i, j int) bool {
			if doSpeedtest {
				if results[i].Latency != results[j].Latency {
					return results[i].Latency < results[j].Latency
				}
				if results[i].DownSpeed != results[j].DownSpeed {
					return results[i].DownSpeed > results[j].DownSpeed
				}
				return results[i].UpSpeed > results[j].UpSpeed
			}
			return results[i].Latency < results[j].Latency
		})
		finalResults := make([]ScanResult, len(results))
		for i, r := range results {
			finalResults[i] = *r
		}
		printAndSaveResults(finalResults)
		customlog.Printf(customlog.Success, "Scan finished.\n")
	},
}

// ... (inc, createDialerWithRetry, scanIPForLatency functions remain the same) ...
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
		dialer := &net.Dialer{}
		targetAddr := fmt.Sprintf("%s:%d", ip, 443)
		var lastErr error
		for i := 0; i < retries; i++ {
			if Verbose && i > 0 {
				customlog.Printf(customlog.Info, "Retrying connection to %s (attempt %d/%d)...\n", ip, i+1, retries)
			}
			conn, err := dialer.DialContext(ctx, network, targetAddr)
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if i < retries-1 {
				time.Sleep(200 * time.Millisecond)
			}
		}
		return nil, fmt.Errorf("all %d connection attempts to %s failed, last error: %w", retries, ip, lastErr)
	}
}
func scanIPForLatency(ip string) *ScanResult {
	result := &ScanResult{IP: ip}
	start := time.Now()
	c := req.C().SetTimeout(time.Duration(requestTimeout) * time.Millisecond).SetTLSHandshakeTimeout(tLSHandshakeTimeout).SetTLSFingerprintChrome().ImpersonateChrome()
	c.Transport.SetDial(createDialerWithRetry(ip, retryCount))
	r := c.R().EnableCloseConnection()
	res, err := r.Get(cloudflareTraceURL)
	if err != nil || !res.IsSuccessState() {
		if Verbose {
			fmt.Println("LATENCY TEST FAILED:", err)
		}
		result.Error = fmt.Errorf("latency test failed: %v", err)
		return result
	}
	if ShowTraceBody {
		fmt.Println(res)
	}
	result.Latency = time.Since(start)
	customlog.Printf(customlog.Success, "LATENCY:   %-20s | %-10v\n", ip, result.Latency.Round(time.Millisecond))
	c.CloseIdleConnections()
	return result
}

// measureSpeed performs download and upload tests and returns speeds in Mbps.
// *** KEY CHANGE: It now accepts a context to enforce a total timeout. ***
func measureSpeed(ctx context.Context, ip string) (downSpeed float64, upSpeed float64, err error) {
	downloadBytesTotal := downloadMB * 1024 * 1024
	uploadBytesTotal := uploadMB * 1024 * 1024

	c := req.C().SetTLSFingerprintChrome().ImpersonateChrome().SetTLSHandshakeTimeout(tLSHandshakeTimeout)
	c.Transport.SetDial(createDialerWithRetry(ip, retryCount))

	// Download test
	downURL := fmt.Sprintf("https://%s/__down?bytes=%d", cloudflareSpeedTestURL, downloadBytesTotal)
	startDown := time.Now()
	// *** KEY CHANGE: Use the passed-in context for the request. ***
	resDown, err := c.R().SetContext(ctx).Get(downURL)
	if err != nil {
		if Verbose {
			fmt.Println("DOWNLOAD FAILED:", err)
		}
		// Check if the error was due to the context's deadline being exceeded.
		if errors.Is(err, context.DeadlineExceeded) {
			return 0, 0, errors.New("speed test timed out")
		}
		return 0, 0, fmt.Errorf("download test failed: %w", err)
	}
	if !resDown.IsSuccessState() {
		return 0, 0, fmt.Errorf("download test failed with status: %s", resDown.Status)
	}
	downDuration := time.Since(startDown).Seconds()
	downSpeed = (float64(len(resDown.String())) * 8) / (downDuration * 1e6)

	// Upload test
	upURL := fmt.Sprintf("https://%s/__up", cloudflareSpeedTestURL)
	uploadData := make([]byte, uploadBytesTotal)
	startUp := time.Now()
	// *** KEY CHANGE: Use the passed-in context for the request. ***
	resUp, err := c.R().SetContext(ctx).SetBody(bytes.NewReader(uploadData)).Post(upURL)
	if err != nil {
		if Verbose {
			fmt.Println("UPLOAD FAILED:", err)
		}
		// Check for timeout here as well.
		if errors.Is(err, context.DeadlineExceeded) {
			return downSpeed, 0, errors.New("speed test timed out")
		}
		return downSpeed, 0, fmt.Errorf("upload test failed: %w", err)
	}
	if !resUp.IsSuccessState() {
		return downSpeed, 0, fmt.Errorf("upload test failed with status: %s", resUp.Status)
	}
	upDuration := time.Since(startUp).Seconds()
	upSpeed = (float64(uploadBytesTotal) * 8) / (upDuration * 1e6)

	return downSpeed, upSpeed, nil
}

// ... (formatResult and printAndSaveResults functions remain the same) ...
func formatResult(result ScanResult) string {
	if doSpeedtest && (result.DownSpeed > 0 || result.UpSpeed > 0) {
		return fmt.Sprintf("%-20s | %-10v | %-15.2f | %-15.2f", result.IP, result.Latency.Round(time.Millisecond), result.DownSpeed, result.UpSpeed)
	}
	return fmt.Sprintf("%-20s | %-10v", result.IP, result.Latency.Round(time.Millisecond))
}
func printAndSaveResults(results []ScanResult) {
	var finalResults []ScanResult
	if doSpeedtest && onlySpeedtestResults {
		customlog.Printf(customlog.Info, "Filtering results to include only those with successful speed tests...\n")
		for _, r := range results {
			if r.DownSpeed > 0 || r.UpSpeed > 0 {
				finalResults = append(finalResults, r)
			}
		}
		customlog.Printf(customlog.Info, "Filtered from %d to %d results.\n", len(results), len(finalResults))
	} else {
		finalResults = results
	}
	if len(finalResults) == 0 {
		customlog.Printf(customlog.Warning, "No results to display or save.\n")
		return
	}
	var header string
	var outputLines []string
	if doSpeedtest {
		header = fmt.Sprintf("%-20s | %-10s | %-15s | %-15s", "IP", "Latency", "Downlink (Mbps)", "Uplink (Mbps)")
	} else {
		header = fmt.Sprintf("%-20s | %-10s", "IP", "Latency")
	}
	outputLines = append(outputLines, header)
	for _, result := range finalResults {
		outputLines = append(outputLines, formatResult(result))
	}
	finalOutput := strings.Join(outputLines, "\n")
	customlog.Println(customlog.GetColor(customlog.None, "\n--- Sorted Results ---\n"))
	customlog.Println(customlog.GetColor(customlog.Success, finalOutput))
	customlog.Println(customlog.GetColor(customlog.None, "\n--------------------\n"))
	if len(finalResults) > 0 {
		err := os.WriteFile(outputFile, []byte(finalOutput), 0644)
		if err != nil {
			customlog.Printf(customlog.Failure, "Failed to save results to %s: %v\n", outputFile, err)
		} else {
			customlog.Printf(customlog.Success, "Results successfully saved to %s\n", outputFile)
		}
	}
}

func init() {
	CFscannerCmd.Flags().StringVarP(&subnets, "subnets", "s", "", "Subnet or file containing subnets (e.g., \"1.1.1.1/24,2.2.2.2/16\")")
	CFscannerCmd.Flags().IntVarP(&threadCount, "threads", "t", 100, "Count of threads for latency scan")
	CFscannerCmd.Flags().BoolVarP(&doSpeedtest, "speedtest", "p", false, "Measure download/upload speed on the fastest IPs")
	CFscannerCmd.Flags().IntVarP(&speedtestTop, "speedtest-top", "c", 100000, "Number of fastest IPs to select for speed testing")
	CFscannerCmd.Flags().IntVarP(&speedtestConcurrency, "speedtest-concurrency", "", 1, "Number of concurrent speed tests to run (to avoid saturating bandwidth)")
	CFscannerCmd.Flags().IntVarP(&speedtestTimeout, "speedtest-timeout", "", 20, "Total timeout in seconds for one IP's speed test (download + upload)")
	CFscannerCmd.Flags().IntVarP(&requestTimeout, "timeout", "u", 10000, "Individual request timeout (in ms)")
	CFscannerCmd.Flags().BoolVarP(&ShowTraceBody, "body", "b", false, "Show trace body output")
	CFscannerCmd.Flags().BoolVarP(&Verbose, "verbose", "v", false, "Show verbose output")
	CFscannerCmd.Flags().BoolVarP(&shuffleSubnets, "shuffle-subnet", "e", false, "Shuffle list of Subnets")
	CFscannerCmd.Flags().BoolVarP(&shuffleIPs, "shuffle-ip", "i", false, "Shuffle list of IPs")
	CFscannerCmd.Flags().StringVarP(&outputFile, "output", "o", "results.txt", "Output file to save sorted results")
	CFscannerCmd.Flags().IntVarP(&retryCount, "retry", "r", 1, "Number of times to retry TCP connection on failure")
	CFscannerCmd.Flags().StringVarP(&liveOutputFile, "live-output", "l", "", "Live output file to save results as they are found (unsorted)")
	CFscannerCmd.Flags().BoolVarP(&onlySpeedtestResults, "only-speedtest", "k", false, "Only save results that have successful speedtest data (download or upload)")
	CFscannerCmd.Flags().IntVarP(&downloadMB, "download-mb", "d", 25, "Custom amount of data to download for speedtest (in MB)")
	CFscannerCmd.Flags().IntVarP(&uploadMB, "upload-mb", "m", 1, "Custom amount of data to upload for speedtest (in MB)")

	_ = CFscannerCmd.MarkFlagRequired("subnets")
}
