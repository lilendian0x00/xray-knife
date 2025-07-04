package scanner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/lilendian0x00/xray-knife/v5/utils"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"
	utls "github.com/refraction-networking/utls"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
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
				line := formatResult(*result, false)
				if _, err := fmt.Fprintln(liveFile, line); err != nil {
					customlog.Printf(customlog.Warning, "Failed to write live result for IP %s: %v\n", result.IP, err)
				}
			}
		}

		pool := pond.NewPool(threadCount)

		// Phase 1: Latency Scanning
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
						// The context is still useful for cancellation, especially in the dialer and TLS handshake.
						ctx, cancel := context.WithTimeout(context.Background(), time.Duration(speedtestTimeout)*time.Second)
						defer cancel()

						downSpeed, upSpeed, err := measureSpeed(ctx, res.IP)
						if err != nil {
							if os.IsTimeout(err) || errors.Is(err, context.DeadlineExceeded) {
								customlog.Printf(customlog.Warning, "IP %s failed speed test: Timeout exceeded\n", res.IP)
							} else {
								customlog.Printf(customlog.Warning, "IP %s failed speed test: %v\n", res.IP, err)
							}
						}
						res.DownSpeed = downSpeed
						res.UpSpeed = upSpeed
						// Only print success if the test actually ran and produced some result
						if downSpeed > 0 || upSpeed > 0 {
							customlog.Printf(customlog.Success, "SPEEDTEST: %-20s | %-10v | %-15.2f | %-15.2f\n", res.IP, res.Latency.Round(time.Millisecond), downSpeed, upSpeed)
						}
					}
				}(result))
			}
			speedTestPool.StopAndWait()
			customlog.Printf(customlog.Success, "Speed test phase finished.\n")
		}

		customlog.Printf(customlog.Info, "Sorting %d final results...\n", len(results))
		sort.Slice(results, func(i, j int) bool {
			if doSpeedtest {
				// Sort by latency first, then by speed
				if results[i].Latency != results[j].Latency {
					return results[i].Latency < results[j].Latency
				}
				if results[i].DownSpeed != results[j].DownSpeed {
					return results[i].DownSpeed > results[j].DownSpeed
				}
				return results[i].UpSpeed > results[j].UpSpeed
			}
			// Default sort by latency only
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

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// createDialerWithRetry creates a dialer that connects to a specific IP, ignoring the address passed to it.
func createDialerWithRetry(ip string, retries int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout: time.Duration(requestTimeout) * time.Millisecond, // Use the request timeout for dialing
		}
		targetAddr := fmt.Sprintf("%s:%d", ip, 443)
		var lastErr error

		for i := 0; i <= retries; i++ {
			// Check if context has been cancelled before retrying
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if Verbose && i > 0 {
				customlog.Printf(customlog.Info, "Retrying connection to %s (attempt %d/%d)...\n", ip, i+1, retries+1)
			}
			conn, err := dialer.DialContext(ctx, network, targetAddr)
			if err == nil {
				return conn, nil // Success
			}
			lastErr = err
			// Don't sleep on the last attempt
			if i < retries {
				time.Sleep(200 * time.Millisecond)
			}
		}
		return nil, fmt.Errorf("all %d connection attempts to %s failed, last error: %w", retries+1, ip, lastErr)
	}
}

func scanIPForLatency(ip string) *ScanResult {
	result := &ScanResult{IP: ip}

	transport := NewBypassJA3Transport(utls.HelloChrome_Auto)
	transport.DialContext = createDialerWithRetry(ip, retryCount)

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(requestTimeout) * time.Millisecond,
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
		if Verbose {
			customlog.Printf(customlog.Warning, "Verbose (IP: %s): Latency test raw error: %v\n", ip, err)
		}
		result.Error = fmt.Errorf("latency test failed: %w", err)
		return result
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Errorf("failed to read body: %w", err)
		return result
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = fmt.Errorf("bad status code: %d", resp.StatusCode)
		return result
	}

	result.Latency = time.Since(start)

	if ShowTraceBody {
		fmt.Println(string(bodyBytes))
	}

	customlog.Printf(customlog.Success, "LATENCY:   %-20s | %-10v\n", ip, result.Latency.Round(time.Millisecond))
	return result
}

func measureSpeed(ctx context.Context, ip string) (downSpeed float64, upSpeed float64, err error) {
	downloadBytesTotal := int64(downloadMB * 1024 * 1024)
	uploadBytesTotal := int64(uploadMB * 1024 * 1024)

	transport := NewBypassJA3Transport(utls.HelloChrome_Auto)
	transport.DialContext = createDialerWithRetry(ip, retryCount)

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(speedtestTimeout) * time.Second,
	}

	// --- Download test ---
	downURL := fmt.Sprintf("https://%s/__down?bytes=%d", cloudflareSpeedTestURL, downloadBytesTotal)
	// We still create the request with the context, as it's used by the dialer and TLS handshake.
	reqDown, err := http.NewRequestWithContext(ctx, "GET", downURL, nil)
	if err != nil {
		if Verbose {
			customlog.Printf(customlog.Warning, "Verbose (IP: %s): Failed to create download request: %v\n", ip, err)
		}
		return 0, 0, fmt.Errorf("failed to create download request: %w", err)
	}
	reqDown.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	startDown := time.Now()
	respDown, err := client.Do(reqDown)
	if err != nil {
		if Verbose {
			customlog.Printf(customlog.Warning, "Verbose (IP: %s): Download request execution failed: %v\n", ip, err)
		}
		// The client timeout will manifest as a context.DeadlineExceeded error.
		if errors.Is(err, context.DeadlineExceeded) {
			return 0, 0, errors.New("speed test timed out during download")
		}
		return 0, 0, fmt.Errorf("download test failed: %w", err)
	}
	defer respDown.Body.Close()

	if respDown.StatusCode < 200 || respDown.StatusCode >= 300 {
		if Verbose {
			bodyBytes, _ := io.ReadAll(respDown.Body)
			customlog.Printf(customlog.Warning, "Verbose (IP: %s): Download test received bad status '%s'. Body: %s\n", ip, respDown.Status, string(bodyBytes))
		}
		return 0, 0, fmt.Errorf("download test received status: %s", respDown.Status)
	}

	written, err := io.Copy(io.Discard, respDown.Body)
	if err != nil {
		if Verbose {
			customlog.Printf(customlog.Warning, "Verbose (IP: %s): Failed reading download stream after %d bytes: %v\n", ip, written, err)
		}
		// An error here could also be due to the client timeout firing during the copy.
		return 0, 0, fmt.Errorf("failed while reading download stream: %w", err)
	}
	downDuration := time.Since(startDown).Seconds()

	if downDuration > 0 {
		downSpeed = (float64(written) * 8) / (downDuration * 1e6)
	}

	// Check if context was cancelled (e.g., by CTRL+C), even if the client timeout didn't fire.
	if ctx.Err() != nil {
		return downSpeed, 0, errors.New("operation cancelled before upload")
	}

	// --- Upload test ---
	upURL := fmt.Sprintf("https://%s/__up", cloudflareSpeedTestURL)
	uploadData := make([]byte, uploadBytesTotal)
	reqUp, err := http.NewRequestWithContext(ctx, "POST", upURL, bytes.NewReader(uploadData))
	if err != nil {
		if Verbose {
			customlog.Printf(customlog.Warning, "Verbose (IP: %s): Failed to create upload request: %v\n", ip, err)
		}
		return downSpeed, 0, fmt.Errorf("failed to create upload request: %w", err)
	}
	reqUp.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")
	reqUp.Header.Set("Content-Type", "application/octet-stream")

	startUp := time.Now()
	respUp, err := client.Do(reqUp)
	if err != nil {
		if Verbose {
			customlog.Printf(customlog.Warning, "Verbose (IP: %s): Upload request execution failed: %v\n", ip, err)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return downSpeed, 0, errors.New("speed test timed out during upload")
		}
		return downSpeed, 0, fmt.Errorf("upload test failed: %w", err)
	}
	defer respUp.Body.Close()
	io.Copy(io.Discard, respUp.Body)

	if respUp.StatusCode < 200 || respUp.StatusCode >= 300 {
		if Verbose {
			bodyBytes, _ := io.ReadAll(respUp.Body)
			customlog.Printf(customlog.Warning, "Verbose (IP: %s): Upload test received bad status '%s'. Body: %s\n", ip, respUp.Status, string(bodyBytes))
		}
		return downSpeed, 0, fmt.Errorf("upload test received status: %s", respUp.Status)
	}
	upDuration := time.Since(startUp).Seconds()

	if upDuration > 0 {
		upSpeed = (float64(uploadBytesTotal) * 8) / (upDuration * 1e6)
	}

	return downSpeed, upSpeed, nil
}

func formatResult(result ScanResult, speedtestEnabled bool) string {
	if speedtestEnabled {
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
		outputLines = append(outputLines, formatResult(result, doSpeedtest))
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
	CFscannerCmd.Flags().IntVarP(&speedtestTop, "speedtest-top", "c", 1000000, "Number of fastest IPs to select for speed testing")
	CFscannerCmd.Flags().IntVarP(&speedtestConcurrency, "speedtest-concurrency", "", 4, "Number of concurrent speed tests to run (to avoid saturating bandwidth)")
	CFscannerCmd.Flags().IntVarP(&speedtestTimeout, "speedtest-timeout", "", 30, "Total timeout in seconds for one IP's speed test (download + upload)")
	CFscannerCmd.Flags().IntVarP(&requestTimeout, "timeout", "u", 5000, "Individual request timeout (in ms)")
	CFscannerCmd.Flags().BoolVarP(&ShowTraceBody, "body", "b", false, "Show trace body output")
	CFscannerCmd.Flags().BoolVarP(&Verbose, "verbose", "v", false, "Show verbose output with detailed errors")
	CFscannerCmd.Flags().BoolVarP(&shuffleSubnets, "shuffle-subnet", "e", false, "Shuffle list of Subnets")
	CFscannerCmd.Flags().BoolVarP(&shuffleIPs, "shuffle-ip", "i", false, "Shuffle list of IPs")
	CFscannerCmd.Flags().StringVarP(&outputFile, "output", "o", "results.txt", "Output file to save sorted results")
	CFscannerCmd.Flags().IntVarP(&retryCount, "retry", "r", 1, "Number of times to retry TCP connection on failure")
	CFscannerCmd.Flags().StringVarP(&liveOutputFile, "live-output", "l", "", "Live output file to save results as they are found (unsorted)")
	CFscannerCmd.Flags().BoolVarP(&onlySpeedtestResults, "only-speedtest", "k", false, "Only save results that have successful speedtest data (download or upload)")
	CFscannerCmd.Flags().IntVarP(&downloadMB, "download-mb", "d", 20, "Custom amount of data to download for speedtest (in MB)")
	CFscannerCmd.Flags().IntVarP(&uploadMB, "upload-mb", "m", 10, "Custom amount of data to upload for speedtest (in MB)")

	_ = CFscannerCmd.MarkFlagRequired("subnets")
}

// BypassJA3Transport is an http.RoundTripper that allows for custom TLS ClientHello.
type BypassJA3Transport struct {
	tr1         http.Transport
	tr2         http2.Transport
	mu          sync.RWMutex
	clientHello utls.ClientHelloID
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewBypassJA3Transport creates a new BypassJA3Transport with the specified ClientHello.
func NewBypassJA3Transport(helloID utls.ClientHelloID) *BypassJA3Transport {
	return &BypassJA3Transport{
		clientHello: helloID,
		tr2: http2.Transport{
			AllowHTTP: true,
		},
	}
}

// RoundTrip executes a single HTTP transaction.
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

// httpsRoundTrip handles the custom HTTPS logic.
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
		// SetDeadline applies to all future I/O operations.
		tlsConn.SetDeadline(deadline)
		defer tlsConn.SetDeadline(time.Time{})
	}

	httpVersion := tlsConn.ConnectionState().NegotiatedProtocol
	switch httpVersion {
	case "h2":
		// The http2.Transport is more robust and handles contexts correctly,
		// so it doesn't need the same manual deadline management.
		t2 := b.tr2
		t2.DialTLS = nil // We've already dialed.
		clientConn, err := t2.NewClientConn(tlsConn)
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("failed to create http2 client connection: %w", err)
		}
		return clientConn.RoundTrip(req)
	case "http/1.1", "":
		if err := req.Write(tlsConn); err != nil {
			tlsConn.Close() // Close connection on write error
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

// getTLSConfig creates a uTLS config for the connection.
func (b *BypassJA3Transport) getTLSConfig(req *http.Request) *utls.Config {
	return &utls.Config{
		ServerName:         req.URL.Host,
		InsecureSkipVerify: true, // We are connecting to an IP, so we can't verify the hostname.
		NextProtos:         []string{"h2", "http/1.1"},
	}
}

// tlsConnect establishes the TLS connection using uTLS.
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
