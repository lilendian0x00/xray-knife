package scan

import (
	"bytes"
	"context"
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
	// Cloudflare's trace endpoint. Lightweight and good for latency tests.
	cloudflareTraceURL = "https://cloudflare.com/cdn-cgi/trace"
	// Cloudflare's speedtest endpoint.
	cloudflareSpeedTestURL = "speed.cloudflare.com"
	// Timeout for requests
	tLSHandshakeTimeout = 15 * time.Second
)

// CFscannerCmd represents the cfscanner command
var CFscannerCmd = &cobra.Command{
	Use:   "cfscanner",
	Short: "Cloudflare's edge IP scanner (delay, downlink, uplink)",
	Long: `Scans Cloudflare IPs for latency and optional speed tests, then sorts and saves the results.
You can provide subnets as a comma-separated string or a path to a file containing one subnet per line.
Example: xray-knife scan cfscanner -s "104.16.124.0/24" -t 50 -p -o results.txt -l live.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		var cidrs []string
		var results []ScanResult
		var resultsMutex sync.Mutex
		var hasIPs bool // Used to check if any scannable IPs were found

		// Use a seeded random source for shuffling
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		if _, err := os.Stat(subnets); err == nil {
			cidrs = utils.ParseFileByNewline(subnets)
		} else {
			cidrs = strings.Split(subnets, ",")
		}

		if shuffleSubnets {
			r.Shuffle(len(cidrs), func(i, j int) { cidrs[i], cidrs[j] = cidrs[j], cidrs[i] })
		}

		// live file handling
		var liveFile *os.File
		if liveOutputFile != "" {
			var err error
			// Open the file, creating it if it doesn't exist and truncating it if it does.
			liveFile, err = os.OpenFile(liveOutputFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				customlog.Printf(customlog.Failure, "Could not open live output file %s: %v. Continuing without live saving.\n", liveOutputFile, err)
				liveFile = nil // Ensure it's nil on error
			} else {
				defer liveFile.Close()
				// Write header to the live file
				var header string
				if doSpeedtest {
					header = fmt.Sprintf("%-20s | %-10s | %-15s | %-15s", "IP", "Latency", "Downlink (Mbps)", "Uplink (Mbps)")
				} else {
					header = fmt.Sprintf("%-20s | %-10s", "IP", "Latency")
				}
				if _, err := fmt.Fprintln(liveFile, header); err != nil {
					customlog.Printf(customlog.Failure, "Failed to write header to live output file: %v\n", err)
				} else {
					customlog.Printf(customlog.Info, "Saving live results to %s\n", liveOutputFile)
				}
			}
		}

		// The log message is changed to reflect that we no longer know the total IP count upfront
		// without incurring a memory cost.
		customlog.Printf(customlog.Info, "Scanning IPs from %d subnets with %d threads...\n", len(cidrs), threadCount)
		if shuffleIPs {
			customlog.Printf(customlog.Warning, "IP shuffling is enabled. This may use more memory for large subnets, but memory will be freed after each subnet is processed.\n")
		}

		// Define a handler for scan results to reduce code duplication.
		handleResult := func(result ScanResult) {
			if result.Error != nil {
				return
			}

			resultsMutex.Lock()
			defer resultsMutex.Unlock()

			results = append(results, result)

			// Live saving logic
			if liveFile != nil {
				// Apply the --only-speedtest filter to live results as well.
				// We write the line if:
				// 1. Filtering is NOT enabled.
				// 2. Filtering IS enabled AND the result passes the filter.
				shouldWrite := true
				if doSpeedtest && onlySpeedtestResults {
					if result.DownSpeed <= 0 && result.UpSpeed <= 0 {
						shouldWrite = false // Don't write if filter is on and speeds are zero
					}
				}

				if shouldWrite {
					line := formatResult(result)
					if _, err := fmt.Fprintln(liveFile, line); err != nil {
						customlog.Printf(customlog.Warning, "Failed to write live result for IP %s: %v\n", result.IP, err)
					}
				}
			}
		}

		// Create a worker pool
		pool := pond.NewPool(threadCount)

		// Define a function to submit a job to the pool.
		submitJob := func(ip string) {
			pool.Submit(func() {
				result := scanIP(ip)
				handleResult(result)
			})
		}

		// Process subnets one by one to avoid aggregating all IPs in memory.
		for _, cidr := range cidrs {
			// If shuffling IPs is requested, we must generate the list for the current CIDR.
			// This is a compromise: it uses memory, but only for one subnet at a time.
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
					submitJob(ip) // Use the new submitJob function
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
					// Create a copy of the IP for the closure, as inc() modifies the loop variable in place.
					ipToScan := make(net.IP, len(currentIP))
					copy(ipToScan, currentIP)
					submitJob(ipToScan.String()) // Use the new submitJob function
				}
			}
		}

		// Replaces the check for `len(totalIPs) <= 0`
		if !hasIPs {
			customlog.Printf(customlog.Failure, "Scanner failed! => No IP detected in the provided subnets\n")
			return
		}

		// Stop the pool and wait for all submitted tasks to complete
		pool.StopAndWait()

		customlog.Printf(customlog.Info, "Sorting %d successful results...\n", len(results))

		// Sort the results
		sort.Slice(results, func(i, j int) bool {
			// If speed test is enabled, sort by latency, then down speed, then up speed
			if doSpeedtest {
				if results[i].Latency != results[j].Latency {
					return results[i].Latency < results[j].Latency
				}
				if results[i].DownSpeed != results[j].DownSpeed {
					return results[i].DownSpeed > results[j].DownSpeed // Higher is better
				}
				return results[i].UpSpeed > results[j].UpSpeed // Higher is better
			}
			// Otherwise, just sort by latency
			return results[i].Latency < results[j].Latency
		})

		// Print and save the sorted results
		printAndSaveResults(results)

		customlog.Printf(customlog.Success, "Scan finished.\n")
	},
}

// inc increments an IP address (supports both IPv4 and IPv6).
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// createDialerWithRetry creates a custom dial function that retries a TCP connection.
func createDialerWithRetry(ip string, retries int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		// Override IP
		targetAddr := fmt.Sprintf("%s:%d", ip, 443)
		var lastErr error

		// Attempt loop
		for i := 0; i < retries; i++ {
			if Verbose && i > 0 {
				customlog.Printf(customlog.Info, "Retrying connection to %s (attempt %d/%d)...\n", ip, i+1, retries)
			}
			conn, err := dialer.DialContext(ctx, network, targetAddr)
			if err == nil {
				// Success
				return conn, nil
			}
			lastErr = err
			// Add a small delay before the next attempt to avoid hammering
			if i < retries-1 {
				time.Sleep(200 * time.Millisecond)
			}
		}
		// All retries failed, return the last error
		return nil, fmt.Errorf("all %d connection attempts to %s failed, last error: %w", retries, ip, lastErr)
	}
}

// scanIP performs latency and optional speed tests on a single IP address and returns a ScanResult.
func scanIP(ip string) ScanResult {
	result := ScanResult{IP: ip}
	start := time.Now()

	c := req.C().SetTimeout(time.Duration(requestTimeout) * time.Millisecond).SetTLSHandshakeTimeout(tLSHandshakeTimeout).SetTLSFingerprintChrome().ImpersonateChrome()

	// Use the custom dialer with retry logic
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

	if !doSpeedtest {
		customlog.Printf(customlog.Success, "%-20s | %-10v\n", ip, result.Latency.Round(time.Millisecond))
		return result
	}
	c.CloseIdleConnections()

	// Speed Test (if enabled)
	downSpeed, upSpeed, err := measureSpeed(ip)
	if err != nil {
		// We still have a valid latency, so we can consider this a partial success
		// Log the warning and return the result with speeds as 0
		customlog.Printf(customlog.Warning, "IP %s failed speed test: %v\n", ip, err)
		// We can still add it to results, but with 0 speeds
	}

	result.DownSpeed = downSpeed
	result.UpSpeed = upSpeed
	customlog.Printf(customlog.Success, "%-20s | %-10v | %-15.2f | %-15.2f\n", ip, result.Latency.Round(time.Millisecond), downSpeed, upSpeed)
	return result
}

// measureSpeed performs download and upload tests and returns speeds in Mbps.
func measureSpeed(ip string) (downSpeed float64, upSpeed float64, err error) {
	// Calculate bytes from MB flags
	downloadBytesTotal := downloadMB * 1024 * 1024
	uploadBytesTotal := uploadMB * 1024 * 1024

	// Create a single client for both download and upload tests
	c := req.C().SetTLSFingerprintChrome().ImpersonateChrome().SetTLSHandshakeTimeout(tLSHandshakeTimeout)

	// Custom dialer with retry logic
	c.Transport.SetDial(createDialerWithRetry(ip, retryCount))

	// Download test
	downURL := fmt.Sprintf("https://%s/__down?bytes=%d", cloudflareSpeedTestURL, downloadBytesTotal)
	startDown := time.Now()

	resDown, err := c.R().SetContext(context.Background()).Get(downURL)
	if err != nil || !resDown.IsSuccessState() {
		if Verbose {
			fmt.Println("DOWNLOAD FAILED:", err)
		}
		return 0, 0, fmt.Errorf("download test failed: %v", err)
	}
	downDuration := time.Since(startDown).Seconds()
	// Speed (Mbps) = (bytes * 8) / (seconds * 1_000_000)
	downSpeed = (float64(len(resDown.String())) * 8) / (downDuration * 1e6)

	// Upload test
	upURL := fmt.Sprintf("https://%s/__up", cloudflareSpeedTestURL)
	uploadData := make([]byte, uploadBytesTotal)
	startUp := time.Now()

	resUp, err := c.R().SetContext(context.Background()).SetBody(bytes.NewReader(uploadData)).Post(upURL)
	if err != nil || !resUp.IsSuccessState() {
		if Verbose {
			fmt.Println("UPLOAD FAILED:", err)
		}
		return downSpeed, 0, fmt.Errorf("upload test failed: %v", err)
	}
	upDuration := time.Since(startUp).Seconds()
	upSpeed = (float64(uploadBytesTotal) * 8) / (upDuration * 1e6)

	return downSpeed, upSpeed, nil
}

// formatResult formats a single ScanResult into a string for consistent output.
func formatResult(result ScanResult) string {
	if doSpeedtest {
		return fmt.Sprintf("%-20s | %-10v | %-15.2f | %-15.2f", result.IP, result.Latency.Round(time.Millisecond), result.DownSpeed, result.UpSpeed)
	}
	return fmt.Sprintf("%-20s | %-10v", result.IP, result.Latency.Round(time.Millisecond))
}

// printAndSaveResults prints the results to the console and saves them to a file if specified.
func printAndSaveResults(results []ScanResult) {
	// Filter results if the flag is set
	var finalResults []ScanResult
	if doSpeedtest && onlySpeedtestResults {
		customlog.Printf(customlog.Info, "Filtering results to include only those with successful speed tests...\n")
		for _, r := range results {
			// A successful speedtest means at least one of the speeds is greater than 0.
			if r.DownSpeed > 0 || r.UpSpeed > 0 {
				finalResults = append(finalResults, r)
			}
		}
		customlog.Printf(customlog.Info, "Filtered from %d to %d results.\n", len(results), len(finalResults))
	} else {
		finalResults = results
	}

	// Guard against empty results after filtering
	if len(finalResults) == 0 {
		customlog.Printf(customlog.Warning, "No results to display or save.\n")
		return
	}

	var header string
	var outputLines []string

	// Prepare header
	if doSpeedtest {
		header = fmt.Sprintf("%-20s | %-10s | %-15s | %-15s", "IP", "Latency", "Downlink (Mbps)", "Uplink (Mbps)")
	} else {
		header = fmt.Sprintf("%-20s | %-10s", "IP", "Latency")
	}

	outputLines = append(outputLines, header)

	// Prepare result lines using the helper function
	for _, result := range finalResults {
		outputLines = append(outputLines, formatResult(result))
	}

	// Join all lines with a newline
	finalOutput := strings.Join(outputLines, "\n")

	// Print to console
	customlog.Println(customlog.GetColor(customlog.None, "\n--- Sorted Results ---\n"))
	customlog.Println(customlog.GetColor(customlog.Success, finalOutput))
	customlog.Println(customlog.GetColor(customlog.None, "\n--------------------\n"))

	// Save to file
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
	CFscannerCmd.Flags().IntVarP(&threadCount, "threads", "t", 50, "Count of threads")
	CFscannerCmd.Flags().BoolVarP(&doSpeedtest, "speedtest", "p", false, "Measure download/upload speed")
	CFscannerCmd.Flags().IntVarP(&requestTimeout, "timeout", "u", 10000, "Request timeout")
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
