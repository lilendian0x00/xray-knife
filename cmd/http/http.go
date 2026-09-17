package http

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
	"github.com/lilendian0x00/xray-knife/v11/utils"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
)

// HttpCmd is the http subcommand.
var HttpCmd = newHttpCommand()

// Config holds all command configuration options
type Config struct {
	ConfigLink      string
	ConfigLinksFile string
	ThreadCount     uint16
	CoreType        string
	DestURL         string
	HTTPMethod      string
	ShowBody        bool
	InsecureTLS     bool
	Verbose         bool

	// Multi-endpoint "reachability panel": test each config against several
	// diverse destinations and grade it by how many succeed, instead of
	// trusting a single URL. CheckPreset selects a built-in panel; TestURLs is
	// a custom comma-separated list (overrides the preset and --url).
	CheckPreset      string
	TestURLs         string
	SuccessThreshold float64

	// DB flags
	FromDB         bool
	Limit          int
	SubscriptionID int64
	Protocol       string

	// File Output Flags
	OutputFile        string
	OutputType        string
	SortedByRealDelay bool

	SaveToDB            bool
	Speedtest           bool
	GetIPInfo           bool
	SpeedtestAmount     uint64
	SpeedtestTimeout    uint16
	MaximumAllowedDelay uint16
	Timeout             uint16
	Retries             uint16
	Ping                bool
	PingInterval        uint16
	BindInterface       string

	// SemanticDedup collapses links that describe the same connection (not just
	// exact-string duplicates) before testing.
	SemanticDedup bool

	// Prescan flags: a fast TCP reachability pass that drops dead endpoints
	// before the expensive full test.
	Prescan        bool
	PrescanTimeout uint16
	PrescanWorkers uint16

	// MaxPassed stops the batch test once N configs have passed (0 = test all).
	MaxPassed uint16
}

func validateConfig(cfg *Config) error {
	validCores := map[string]bool{"auto": true, "xray": true, "singbox": true}
	if !validCores[cfg.CoreType] {
		return fmt.Errorf("invalid core type. Available cores: (auto, xray, singbox)")
	}

	if cfg.OutputFile != "" {
		validOutputTypes := map[string]bool{"csv": true, "txt": true}
		if !validOutputTypes[cfg.OutputType] {
			return fmt.Errorf("bad output format. Allowed formats: txt, csv")
		}
		if cfg.OutputType == "csv" {
			base := strings.TrimSuffix(cfg.OutputFile, filepath.Ext(cfg.OutputFile))
			cfg.OutputFile = base + ".csv"
		}
	}

	if cfg.SuccessThreshold <= 0 || cfg.SuccessThreshold > 1 {
		return fmt.Errorf("--url-success-threshold must be within (0, 1], got %g", cfg.SuccessThreshold)
	}
	if cfg.CheckPreset != "" {
		if _, ok := pkghttp.CheckPresets[cfg.CheckPreset]; !ok {
			return fmt.Errorf("unknown --check-preset %q; available: %s", cfg.CheckPreset, strings.Join(pkghttp.PresetNames(), ", "))
		}
	}

	if cfg.Ping {
		if cfg.ConfigLinksFile != "" || cfg.FromDB {
			return fmt.Errorf("--ping flag cannot be used with --file or --from-db flags")
		}
		if cfg.ConfigLink == "" {
			// This is now fine, as we will read from stdin if it's empty.
		}
		if cfg.Speedtest {
			customlog.Printf(customlog.Warning, "--speedtest is disabled in ping mode.\n")
			cfg.Speedtest = false
		}
	}
	return nil
}

// buildEndpointPanel resolves the multi-endpoint test panel from the flags, or
// returns nil to keep the legacy single-URL behavior. A custom --test-urls list
// takes precedence over a named --check-preset.
func buildEndpointPanel(config *Config) ([]pkghttp.EndpointCheck, error) {
	if strings.TrimSpace(config.TestURLs) != "" {
		var panel []pkghttp.EndpointCheck
		for _, raw := range strings.Split(config.TestURLs, ",") {
			u := strings.TrimSpace(raw)
			if u == "" {
				continue
			}
			panel = append(panel, pkghttp.EndpointCheck{URL: u, Method: config.HTTPMethod})
		}
		if len(panel) == 0 {
			return nil, fmt.Errorf("--test-urls was set but contained no valid URLs")
		}
		return panel, nil
	}
	if config.CheckPreset != "" {
		return pkghttp.CheckPresets[config.CheckPreset], nil
	}
	return nil, nil
}

func newHttpCommand() *cobra.Command {
	config := &Config{}

	cmd := &cobra.Command{
		Use:   "http",
		Short: "Test proxy configurations for latency, speed, and IP info using HTTP requests.",
		Long: `Tests one or more proxy configurations. 
By default, if no flag is provided, it will wait for a single config link from standard input.
Use --from-db to test configs from the database library.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateConfig(config); err != nil {
				return err
			}

			panel, err := buildEndpointPanel(config)
			if err != nil {
				return err
			}

			examiner, err := pkghttp.NewExaminer(pkghttp.Options{
				Core:                   config.CoreType,
				MaxDelay:               config.MaximumAllowedDelay,
				Timeout:                config.Timeout,
				Retries:                uint8(config.Retries),
				Verbose:                config.Verbose,
				ShowBody:               config.ShowBody,
				InsecureTLS:            config.InsecureTLS,
				DoSpeedtest:            config.Speedtest,
				DoIPInfo:               config.GetIPInfo,
				TestEndpoint:           config.DestURL,
				TestEndpointHttpMethod: config.HTTPMethod,
				TestEndpoints:          panel,
				SuccessThreshold:       config.SuccessThreshold,
				SpeedtestKbAmount:      config.SpeedtestAmount,
				SpeedtestTimeout:       config.SpeedtestTimeout,
				BindInterface:          config.BindInterface,
			})
			if err != nil {
				return fmt.Errorf("failed to create examiner: %w", err)
			}

			// Determine source of configs for batch testing
			var links []string
			if config.FromDB {
				var err error
				customlog.Printf(customlog.Processing, "Fetching config links from the database...\n")
				links, err = database.GetConfigsFromDB(config.SubscriptionID, config.Protocol, config.Limit)
				if err != nil {
					return err
				}
				if len(links) == 0 {
					customlog.Printf(customlog.Warning, "No matching config links found in the database.\n")
					return nil
				}
				customlog.Printf(customlog.Success, "Found %d config links to test.\n", len(links))
			} else if config.ConfigLinksFile != "" {
				links = utils.ParseFileByNewline(config.ConfigLinksFile)
			}

			// If we have links for a batch test, run it.
			if len(links) > 0 {
				return handleMultipleConfigs(examiner, config, links)
			}

			// Handle single config modes (ping or one-shot test from flag/stdin).
			if config.ConfigLink == "" {
				customlog.Printf(customlog.Info, "Please enter a config link and press Enter:\n")
				reader := bufio.NewReader(os.Stdin)
				text, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %w", err)
				}
				config.ConfigLink = strings.TrimSpace(text)
				if config.ConfigLink == "" {
					return fmt.Errorf("no config link provided")
				}
			}

			if config.Ping {
				return handlePingMode(examiner, config)
			} else {
				handleSingleConfig(examiner, config)
				return nil
			}
		},
	}

	addFlags(cmd, config)
	return cmd
}

// handlePingMode runs a continuous ping loop until the user hits Ctrl+C.
func handlePingMode(examiner *pkghttp.Examiner, config *Config) error {
	pinger, err := examiner.Core.CreateProtocol(config.ConfigLink)
	if err != nil {
		return fmt.Errorf("failed to create protocol for ping: %w", err)
	}
	if err := pinger.Parse(); err != nil {
		return fmt.Errorf("failed to parse protocol for ping: %w", err)
	}

	generalConfig := pinger.ConvertToGeneralConfig()
	customlog.Printf(customlog.Info, "Pinging %s with a %dms interval. Press Ctrl+C to stop.\n\n", generalConfig.Address, config.PingInterval)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	timeout := time.Duration(config.Timeout) * time.Millisecond
	if timeout == 0 {
		timeout = time.Duration(config.MaximumAllowedDelay) * time.Millisecond
	}

	// measure performs one ping and returns its latency in milliseconds.
	var measure func() (int64, error)
	if prober, ok := pinger.(protocol.Prober); ok {
		// Protocols without an HTTP path (MTProto) probe natively on every tick.
		opts := protocol.ProbeOptions{Timeout: timeout, BindInterface: examiner.BindInterface}
		measure = func() (int64, error) {
			res, err := prober.Probe(ctx, opts)
			if err != nil {
				return 0, err
			}
			return res.Delay.Milliseconds(), nil
		}
	} else {
		// Create HTTP client and instance ONCE before the ticker loop
		client, instance, err := examiner.Core.MakeHttpClient(ctx, pinger, timeout)
		if err != nil {
			return fmt.Errorf("failed to create HTTP client: %w", err)
		}
		defer instance.Close()
		measure = func() (int64, error) {
			delay, _, _, err := pkghttp.MeasureDelay(ctx, client, config.DestURL, config.HTTPMethod)
			return delay, err
		}
	}

	ticker := time.NewTicker(time.Duration(config.PingInterval) * time.Millisecond)
	defer ticker.Stop()

	var sent, received int
	var totalLatency, minLatency, maxLatency int64
	minLatency = -1

	defer func() {
		fmt.Println()
		customlog.Printf(customlog.Info, "--- %s ping statistics ---\n", generalConfig.Address)
		loss := 0.0
		if sent > 0 {
			loss = (float64(sent-received) / float64(sent)) * 100
		}
		fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss\n", sent, received, loss)

		if received > 0 {
			avgLatency := totalLatency / int64(received)
			fmt.Printf("rtt min/avg/max = %d/%d/%d ms\n", minLatency, avgLatency, maxLatency)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			sent++
			delay, err := measure()
			if err != nil {
				customlog.Printf(customlog.Failure, "Request failed: %v\n", err)
			} else {
				received++
				totalLatency += delay
				if minLatency == -1 || delay < minLatency {
					minLatency = delay
				}
				if delay > maxLatency {
					maxLatency = delay
				}
				customlog.Printf(customlog.Success, "Reply from %s: time=%dms\n", generalConfig.Address, delay)
			}
		}
	}
}

// handleMultipleConfigs runs a batch test with a progress bar and saves results.
func handleMultipleConfigs(examiner *pkghttp.Examiner, config *Config, links []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Deduplicate links before testing. Semantic dedup subsumes exact-string
	// dedup (identical strings map to the same connection identity), so use one
	// or the other.
	var dupsRemoved int
	if config.SemanticDedup {
		links, dupsRemoved = pkghttp.SemanticDeduplicateLinks(examiner.Core, links)
		if dupsRemoved > 0 {
			customlog.Printf(customlog.Info, "Semantic dedup removed %d duplicate config link(s) (same connection). Testing %d unique configs.\n", dupsRemoved, len(links))
		}
	} else {
		links, dupsRemoved = pkghttp.DeduplicateLinks(links)
		if dupsRemoved > 0 {
			customlog.Printf(customlog.Info, "Removed %d duplicate config link(s). Testing %d unique configs.\n", dupsRemoved, len(links))
		}
	}

	// Optional TCP pre-check: cheaply drop unreachable endpoints before the
	// full test, which spins up a whole core instance per config.
	if config.Prescan {
		var preBar *progressbar.ProgressBar
		pre, err := pkghttp.RunPrescan(ctx, examiner.Core, links,
			pkghttp.PrescanOptions{
				Workers:       int(config.PrescanWorkers),
				Timeout:       time.Duration(config.PrescanTimeout) * time.Millisecond,
				BindInterface: config.BindInterface,
			},
			func(uniqueEndpoints int) {
				customlog.Printf(customlog.Processing, "Pre-scanning %d unique endpoint(s) via TCP (timeout %dms)...\n", uniqueEndpoints, config.PrescanTimeout)
				preBar = progressbar.NewOptions(uniqueEndpoints,
					progressbar.OptionSetWriter(os.Stderr),
					progressbar.OptionEnableColorCodes(true),
					progressbar.OptionShowCount(),
					progressbar.OptionSetDescription("[cyan]Pre-scanning endpoints[reset]"),
					progressbar.OptionClearOnFinish(),
				)
			},
			func() {
				if preBar != nil {
					_ = preBar.Add(1)
				}
			},
		)
		if err != nil {
			return fmt.Errorf("prescan failed: %w", err)
		}
		if preBar != nil {
			_ = preBar.Finish()
			fmt.Fprintln(os.Stderr)
		}
		customlog.Printf(customlog.Success,
			"Pre-scan complete: %d reachable, %d filtered out, %d kept without probing (UDP/unparseable).\n",
			pre.TCPReachable, pre.FilteredOut, pre.Bypassed)

		// Abort cleanly if the user interrupted during the pre-scan.
		if ctx.Err() != nil {
			return nil
		}

		links = pre.Reachable
		if len(links) == 0 {
			customlog.Printf(customlog.Warning, "No reachable configs after pre-scan; nothing to test.\n")
			return nil
		}
	}

	panel, err := buildEndpointPanel(config)
	if err != nil {
		return err
	}

	printConfiguration(config, len(links), panel)

	// Create a test run entry in the database
	opts := pkghttp.Options{
		Core:                   config.CoreType,
		MaxDelay:               config.MaximumAllowedDelay,
		Timeout:                config.Timeout,
		Retries:                uint8(config.Retries),
		Verbose:                config.Verbose,
		ShowBody:               config.ShowBody,
		InsecureTLS:            config.InsecureTLS,
		DoSpeedtest:            config.Speedtest,
		DoIPInfo:               config.GetIPInfo,
		TestEndpoint:           config.DestURL,
		TestEndpointHttpMethod: config.HTTPMethod,
		TestEndpoints:          panel,
		SuccessThreshold:       config.SuccessThreshold,
		SpeedtestKbAmount:      config.SpeedtestAmount,
		SpeedtestTimeout:       config.SpeedtestTimeout,
		BindInterface:          config.BindInterface,
	}
	optsJson, err := json.Marshal(opts)
	if err != nil {
		return fmt.Errorf("failed to marshal test options to JSON: %w", err)
	}

	var runID int64
	if config.SaveToDB {
		runID, err = database.CreateHttpTestRun(string(optsJson), len(links))
		if err != nil {
			return fmt.Errorf("failed to create database entry for test run: %w", err)
		}
		customlog.Printf(customlog.Info, "Created test run with ID: %d. Results will be saved to the database.\n", runID)
	}

	// Setup the result processor with the new runID and file options
	processor := pkghttp.NewResultProcessor(
		pkghttp.ResultProcessorOptions{
			RunID:      runID,
			OutputFile: config.OutputFile,
			OutputType: config.OutputType,
			Sorted:     config.SortedByRealDelay,
		},
	)

	// Clear the output file before streaming so we start fresh
	if config.OutputFile != "" {
		os.Remove(config.OutputFile)
	}

	// Derive a cancelable context so --max-passed can stop the pool early.
	testCtx, cancelTests := context.WithCancel(ctx)
	defer cancelTests()

	// Run the tests with progress bar
	testManager := pkghttp.NewTestManager(examiner, config.ThreadCount, config.Verbose, nil)
	resultsChan := make(chan *pkghttp.Result, config.ThreadCount)
	var results pkghttp.ConfigResults
	var passedCount int32
	var collectorWg sync.WaitGroup

	bar := progressbar.NewOptions(len(links),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetDescription("[cyan]Testing configs (0 passed)[reset]"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	// Stream results to file in batches as they arrive
	const saveBatchSize = 50
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		batch := make([]*pkghttp.Result, 0, saveBatchSize)
		flushBatch := func() {
			if len(batch) == 0 {
				return
			}
			if config.OutputFile != "" {
				var err error
				switch config.OutputType {
				case "csv":
					err = pkghttp.AppendResultsToCSV(config.OutputFile, batch)
				case "txt":
					err = pkghttp.AppendResultsToTxt(config.OutputFile, batch)
				}
				if err != nil {
					customlog.Printf(customlog.Failure, "Failed to stream results to file: %v\n", err)
				}
			}
			batch = make([]*pkghttp.Result, 0, saveBatchSize)
		}
		for res := range resultsChan {
			if res.Status == "passed" {
				newCount := atomic.AddInt32(&passedCount, 1)
				// Early exit: once enough configs pass, cancel the pool so the
				// remaining (mostly dead, full-timeout) tasks drain immediately.
				if config.MaxPassed > 0 && newCount >= int32(config.MaxPassed) {
					cancelTests()
				}
			}
			results = append(results, res)
			batch = append(batch, res)
			if len(batch) >= saveBatchSize {
				flushBatch()
			}
		}
		flushBatch()
	}()

	testManager.RunTests(testCtx, links, resultsChan, func() {
		bar.Describe(fmt.Sprintf("[cyan]Testing configs (%d passed)[reset]", atomic.LoadInt32(&passedCount)))
		bar.Add(1)
	})
	close(resultsChan)
	collectorWg.Wait()
	bar.Finish()
	fmt.Fprintln(os.Stderr)

	if config.MaxPassed > 0 && atomic.LoadInt32(&passedCount) >= int32(config.MaxPassed) {
		customlog.Printf(customlog.Info, "Reached --max-passed=%d; stopped early without testing every config.\n", config.MaxPassed)
	}

	// If sorted output was requested, rewrite the file sorted
	if config.SortedByRealDelay && config.OutputFile != "" {
		processor.RewriteFileSorted(results)
	}

	// Save to DB and print summary (file already written via streaming)
	return processor.SaveResults(results)
}

// printEndpointBreakdown shows the per-endpoint outcome of a multi-endpoint
// test so the user can see exactly which destination failed and why.
func printEndpointBreakdown(res *pkghttp.Result) {
	if len(res.EndpointResults) == 0 {
		return
	}
	fmt.Printf("\n%s (%d/%d passed):\n", color.RedString("Endpoint checks"), res.SuccessCount, res.TotalCount)
	for _, er := range res.EndpointResults {
		if er.Outcome == "ok" {
			fmt.Printf("  %s %-26s %dms\n", color.GreenString("✓"), er.Label, er.Delay)
		} else {
			reason := er.Reason
			if reason == "" {
				reason = er.Outcome
			}
			fmt.Printf("  %s %-26s %s\n", color.RedString("✗"), er.Label, reason)
		}
	}
	fmt.Println()
}

func handleSingleConfig(examiner *pkghttp.Examiner, config *Config) {
	examiner.Verbose = true
	res, err := examiner.ExamineConfig(context.Background(), config.ConfigLink)

	// Print the per-endpoint breakdown first: it is populated even on failure
	// and explains exactly which endpoint(s) failed.
	printEndpointBreakdown(&res)

	if err != nil {
		customlog.Printf(customlog.Failure, "%v\n", err)
		return
	}

	if res.Status != "passed" {
		customlog.Printf(customlog.Failure, "%s: %s\n", res.Status, res.Reason)
	}

	if res.Delay >= 0 {
		customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", res.Delay)
	}
	if config.Speedtest {
		customlog.Printf(customlog.Success, "Download: %f mbps (requested %dKB)\n",
			res.DownloadSpeed, config.SpeedtestAmount)
		customlog.Printf(customlog.Success, "Upload: %f mbps (requested %dKB)\n",
			res.UploadSpeed, config.SpeedtestAmount)
	}
	if reasonIsWarning(&res) {
		customlog.Printf(customlog.Warning, "%s\n", res.Reason)
	}
}

// reasonIsWarning reports whether a passed config's reason describes a problem
// worth flagging, such as a speedtest or ip-info failure that would otherwise
// leave a silent 0. Natively probed protocols (MTProto) put their success
// detail in Reason, so warning about it would cry wolf on a healthy config.
func reasonIsWarning(res *pkghttp.Result) bool {
	if res.Status != "passed" || res.Reason == "" {
		return false
	}
	_, native := res.Protocol.(protocol.Prober)
	return !native
}

// printConfiguration prints the current configuration
func printConfiguration(config *Config, totalConfigs int, panel []pkghttp.EndpointCheck) {
	fmt.Printf("%s: %d\n%s: %d\n%s: %dms\n%s: %t\n%s: %t\n%s: %t\n",
		color.RedString("Total configs"), totalConfigs,
		color.RedString("Thread count"), config.ThreadCount,
		color.RedString("Maximum delay"), config.MaximumAllowedDelay,
		color.RedString("Speed test"), config.Speedtest,
		color.RedString("IP info"), config.GetIPInfo,
		color.RedString("Insecure TLS"), config.InsecureTLS,
	)
	if len(panel) > 0 {
		urls := make([]string, len(panel))
		for i, c := range panel {
			urls[i] = c.URL
		}
		fmt.Printf("%s: %s\n", color.RedString("Test panel"), strings.Join(urls, ", "))
		fmt.Printf("%s: %.0f%% of %d endpoint(s)\n", color.RedString("Pass threshold"), config.SuccessThreshold*100, len(panel))
	} else {
		fmt.Printf("%s: %s\n", color.RedString("Test url"), config.DestURL)
	}
	if config.OutputFile != "" {
		fmt.Printf("%s: %s\n", color.RedString("Output file"), config.OutputFile)
	}
	fmt.Println()
}

func addFlags(cmd *cobra.Command, config *Config) {
	flags := cmd.Flags()

	// Input flags
	flags.StringVarP(&config.ConfigLink, "config", "c", "", "The xray config link")
	flags.StringVarP(&config.ConfigLinksFile, "file", "f", "", "Read config links from a file")

	// Core flags
	flags.Uint16VarP(&config.ThreadCount, "threads", "t", 50, "Number of threads")
	flags.Uint16Var(&config.ThreadCount, "thread", 50, "Deprecated alias for --threads")
	_ = flags.MarkDeprecated("thread", "use --threads")
	flags.StringVarP(&config.CoreType, "core", "z", "auto", "Core type (auto, singbox, xray)")
	flags.StringVarP(&config.DestURL, "url", "u", "https://cloudflare.com/cdn-cgi/trace", "The url to test config (single-endpoint mode)")
	flags.StringVarP(&config.HTTPMethod, "method", "m", "GET", "Http method")

	// Multi-endpoint reachability panel (grades configs by how many diverse
	// destinations they can actually reach, not just one CDN).
	flags.StringVar(&config.CheckPreset, "check-preset", "", fmt.Sprintf("Test each config against a diverse endpoint panel instead of one URL. Presets: %s", strings.Join(pkghttp.PresetNames(), ", ")))
	flags.StringVar(&config.TestURLs, "test-urls", "", "Comma-separated URLs to test each config against (overrides --check-preset and --url). generate_204 URLs require a 204 response.")
	flags.Float64Var(&config.SuccessThreshold, "url-success-threshold", 1.0, "Fraction of panel endpoints that must succeed for a 'passed' grade (e.g. 0.75). Above 0 but below it grades 'semi-passed'.")
	flags.BoolVarP(&config.ShowBody, "body", "b", false, "Show response body")
	flags.Uint16VarP(&config.MaximumAllowedDelay, "mdelay", "d", 5000, "Maximum allowed delay (ms)")
	flags.BoolVarP(&config.InsecureTLS, "insecure", "e", false, "Insecure tls connection (fake SNI)")
	flags.Uint16Var(&config.Timeout, "timeout", 0, "HTTP client timeout in ms (0 = use mdelay value)")
	flags.Uint16Var(&config.Retries, "retries", 0, "Number of retries for failed proxy tests")

	// Speedtest flags
	flags.BoolVarP(&config.Speedtest, "speedtest", "S", false, "Speed test with speed.cloudflare.com")
	flags.Uint64Var(&config.SpeedtestAmount, "amount", 10000, "Download and upload amount (KB). A transfer that outlives --speedtest-timeout is measured on what moved within the window.")
	flags.Uint16Var(&config.SpeedtestTimeout, "speedtest-timeout", 30, "Measurement window for each speedtest direction (seconds). Slow links report the throughput reached within it instead of 0.")

	flags.BoolVar(&config.GetIPInfo, "rip", true, "Receive real IP (csv)")
	flags.BoolVarP(&config.Verbose, "verbose", "v", false, "Verbose")

	flags.BoolVar(&config.Ping, "ping", false, "Enable continuous HTTP ping mode for a single config")
	flags.Uint16Var(&config.PingInterval, "interval", 1000, "Interval between pings in milliseconds (ms)")

	flags.StringVar(&config.BindInterface, "bind", "", "Bind outbound dials to a specific OS interface (e.g. eth0). Linux: needs CAP_NET_RAW.")

	// Dedup / prescan / early-exit flags (batch mode only)
	flags.BoolVar(&config.SemanticDedup, "dedup-semantic", true, "Deduplicate by connection identity (protocol/address/port/credential/transport/TLS) instead of exact link text; drops re-skinned duplicates. Use --dedup-semantic=false for exact-string dedup only")
	flags.BoolVar(&config.Prescan, "prescan", false, "TCP pre-check: drop unreachable endpoints before the full test (much faster on large lists)")
	flags.Uint16Var(&config.PrescanTimeout, "prescan-timeout", 2000, "TCP dial timeout for --prescan (ms)")
	flags.Uint16Var(&config.PrescanWorkers, "prescan-workers", 512, "Concurrent TCP dials for --prescan")
	flags.Uint16Var(&config.MaxPassed, "max-passed", 0, "Stop the batch test after N configs pass (0 = test all). Ideal for large lists.")

	// DB flags
	flags.BoolVar(&config.FromDB, "from-db", false, "Test configs from the database")
	flags.IntVar(&config.Limit, "limit", 0, "Limit the number of configs to test from the DB (0 for all)")
	flags.Int64Var(&config.SubscriptionID, "sub-id", 0, "Filter configs by subscription ID from the DB")
	flags.StringVar(&config.Protocol, "protocol", "", "Filter configs by protocol (vmess, vless, etc.) from the DB")

	// Output Flags
	flags.StringVarP(&config.OutputFile, "out", "o", "valid.txt", "Output file for valid/all config links")
	flags.StringVarP(&config.OutputType, "type", "x", "txt", "Output type for file (csv, txt)")
	flags.BoolVar(&config.SortedByRealDelay, "sort", true, "Sort config links by their delay (fast to slow) in file output")
	flags.BoolVar(&config.SaveToDB, "save-db", false, "Save test results to the database")

	cmd.MarkFlagsMutuallyExclusive("file", "config", "from-db")
}
