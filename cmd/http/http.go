package http

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
	"github.com/lilendian0x00/xray-knife/v11/utils"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
)

// HttpCmd is the http subcommand.
var HttpCmd = newHttpCommand()

// Config holds all command configuration options
type Config struct {
	ConfigLink      string
	ConfigLinksFile string
	// Stdin reads a batch of config links from standard input.
	Stdin       bool
	ThreadCount uint16
	CoreType    string
	DestURL     string
	HTTPMethod  string
	ShowBody    bool
	InsecureTLS bool
	Verbose     bool

	// Reachability panel: grade each config by how many diverse destinations it
	// reaches. CheckPreset picks a built-in panel, TestURLs is a custom list.
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
	SpeedtestURL        string
	MaximumAllowedDelay uint16
	Timeout             uint16
	Retries             uint16
	Ping                bool
	PingInterval        uint16
	BindInterface       string

	// ProbeSamples is the round trips MTProto measures per test.
	ProbeSamples int

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

	// FragmentSpec and NoiseSpecs configure TLS fragmentation / UDP noise on
	// each config's first hop; Fragment is the parsed result.
	FragmentSpec string
	NoiseSpecs   []string
	Fragment     *fragment.Options

	// Diagnose checks failed configs' servers directly to tell blocking from
	// a dead server; Resolver is the trusted DNS those checks compare against.
	Diagnose bool
	Resolver string
}

// outputTypes are the accepted --type values.
var outputTypes = map[string]bool{"csv": true, "txt": true, "json": true, "jsonl": true}

func validateConfig(cfg *Config) error {
	validCores := map[string]bool{"auto": true, "xray": true, "singbox": true}
	if !validCores[cfg.CoreType] {
		return fmt.Errorf("invalid core type. Available cores: (auto, xray, singbox)")
	}

	if cfg.ThreadCount < 1 {
		return fmt.Errorf("--threads must be at least 1")
	}

	if cfg.OutputFile != "" {
		if !outputTypes[cfg.OutputType] {
			return fmt.Errorf("bad output format. Allowed formats: txt, csv, json, jsonl")
		}
		if cfg.OutputType != "txt" && cfg.OutputFile != "-" {
			base := strings.TrimSuffix(cfg.OutputFile, filepath.Ext(cfg.OutputFile))
			cfg.OutputFile = base + "." + cfg.OutputType
		}
	}

	frag, err := fragment.Build(cfg.FragmentSpec, cfg.NoiseSpecs)
	if err != nil {
		return err
	}
	cfg.Fragment = frag

	if cfg.SuccessThreshold <= 0 || cfg.SuccessThreshold > 1 {
		return fmt.Errorf("--url-success-threshold must be within (0, 1], got %g", cfg.SuccessThreshold)
	}
	if cfg.CheckPreset != "" {
		if _, ok := pkghttp.CheckPresets[cfg.CheckPreset]; !ok {
			return fmt.Errorf("unknown --check-preset %q; available: %s", cfg.CheckPreset, strings.Join(pkghttp.PresetNames(), ", "))
		}
	}

	if cfg.Ping {
		if cfg.ConfigLinksFile != "" || cfg.FromDB || cfg.Stdin {
			return fmt.Errorf("--ping flag cannot be used with --file, --stdin or --from-db flags")
		}
		if cfg.PingInterval == 0 {
			return fmt.Errorf("--interval must be at least 1ms")
		}
		if cfg.Speedtest {
			customlog.Printf(customlog.Warning, "--speedtest is disabled in ping mode.\n")
			cfg.Speedtest = false
		}
	}
	return nil
}

// buildEndpointPanel resolves the test panel from the flags, or nil to keep the
// single-URL behavior. A custom --test-urls beats a named --check-preset.
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

// examinerOptions is shared by the single-shot and batch paths so a flag cannot
// reach one and miss the other.
func examinerOptions(config *Config, panel []pkghttp.EndpointCheck) pkghttp.Options {
	return pkghttp.Options{
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
		ProbeSamples:           config.ProbeSamples,
		Fragment:               config.Fragment,
		SpeedtestURL:           config.SpeedtestURL,
		Resolver:               config.Resolver,
		NoDiagnose:             !config.Diagnose,
	}
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
				return exitcode.New(exitcode.Usage, err)
			}

			panel, err := buildEndpointPanel(config)
			if err != nil {
				return exitcode.New(exitcode.Usage, err)
			}

			examiner, err := pkghttp.NewExaminer(examinerOptions(config, panel))
			if err != nil {
				return exitcode.New(exitcode.Usage, fmt.Errorf("failed to create examiner: %w", err))
			}
			// The root command cancels this context on the first Ctrl-C.
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			// From here on a failure is about the configs or the network, not
			// the command line: skip the usage dump.
			cmd.SilenceUsage = true

			// Determine source of configs for batch testing
			var links []string
			switch {
			case config.FromDB:
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
			case config.ConfigLinksFile != "":
				// A missing or empty file is an error, never a silent fallback
				// to the single-link prompt.
				if links, err = utils.ReadLinks(config.ConfigLinksFile); err != nil {
					return err
				}
			case config.Stdin:
				if links, err = utils.ReadLinksFrom(os.Stdin); err != nil {
					return fmt.Errorf("failed to read links from stdin: %w", err)
				}
				if len(links) == 0 {
					return fmt.Errorf("no config links on stdin")
				}
			}

			// If we have links for a batch test, run it.
			if len(links) > 0 {
				return handleMultipleConfigs(ctx, examiner, config, links)
			}

			// Handle single config modes (ping or one-shot test from flag/stdin).
			if config.ConfigLink == "" {
				customlog.Printf(customlog.Info, "Please enter a config link and press Enter:\n")
				reader := bufio.NewReader(os.Stdin)
				text, err := reader.ReadString('\n')
				if err != nil && strings.TrimSpace(text) == "" {
					return fmt.Errorf("failed to read from stdin: %w", err)
				}
				config.ConfigLink = strings.TrimSpace(text)
				if config.ConfigLink == "" {
					return fmt.Errorf("no config link provided")
				}
			}

			if config.Ping {
				return handlePingMode(ctx, examiner, config)
			}
			return handleSingleConfig(ctx, examiner, config)
		},
	}

	addFlags(cmd, config)
	registerCompletions(cmd)
	return cmd
}

// knownProtocols are the protocol names stored in the configs table
// (mirrors cmd/subs), offered for --protocol completion.
var knownProtocols = []string{"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria2", "hysteria", "tuic", "anytls", "ssh", "mtproto"}

func registerCompletions(cmd *cobra.Command) {
	fixed := func(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return values, cobra.ShellCompDirectiveNoFileComp
		}
	}
	_ = cmd.RegisterFlagCompletionFunc("core", fixed("auto", "xray", "singbox"))
	_ = cmd.RegisterFlagCompletionFunc("check-preset", fixed(pkghttp.PresetNames()...))
	_ = cmd.RegisterFlagCompletionFunc("protocol", fixed(knownProtocols...))
	_ = cmd.RegisterFlagCompletionFunc("type", fixed("txt", "csv", "json", "jsonl"))
}

// handlePingMode runs a continuous ping loop until the user hits Ctrl+C.
func handlePingMode(ctx context.Context, examiner *pkghttp.Examiner, config *Config) error {
	pinger, err := examiner.Core.CreateProtocol(config.ConfigLink)
	if err != nil {
		return fmt.Errorf("failed to create protocol for ping: %w", err)
	}
	if err := pinger.Parse(); err != nil {
		return fmt.Errorf("failed to parse protocol for ping: %w", err)
	}

	generalConfig := pinger.ConvertToGeneralConfig()
	customlog.Printf(customlog.Info, "Pinging %s with a %dms interval. Press Ctrl+C to stop.\n\n", generalConfig.Address, config.PingInterval)

	timeout := time.Duration(config.Timeout) * time.Millisecond
	if timeout == 0 {
		timeout = time.Duration(config.MaximumAllowedDelay) * time.Millisecond
	}

	// measure performs one ping and returns its latency in milliseconds.
	var measure func() (int64, error)
	if prober, ok := pinger.(protocol.Prober); ok {
		// Protocols without an HTTP path (MTProto) probe natively on every tick.
		opts := pingProbeOptions(examiner, timeout)
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

// pingProbeOptions keeps ping at one sample per tick. Its loop already repeats
// and keeps its own statistics.
func pingProbeOptions(examiner *pkghttp.Examiner, timeout time.Duration) protocol.ProbeOptions {
	return protocol.ProbeOptions{Timeout: timeout, BindInterface: examiner.BindInterface, Samples: 1}
}

// handleMultipleConfigs runs a batch test with a progress bar and saves results.
func handleMultipleConfigs(ctx context.Context, examiner *pkghttp.Examiner, config *Config, links []string) error {
	// Deduplicate before testing. Semantic dedup subsumes exact-string dedup, so
	// use one or the other.
	// Each link is parsed once here; dedup, the prescan and the test reuse it.
	var dupsRemoved int
	var parsed []*pkghttp.ParsedLink
	if config.SemanticDedup {
		// Exact copies go first, so they are not even parsed.
		var exact int
		links, exact = pkghttp.DeduplicateLinks(links)
		parsed, dupsRemoved = pkghttp.SemanticDeduplicateParsed(pkghttp.ParseLinks(examiner.Core, links))
		dupsRemoved += exact
		if dupsRemoved > 0 {
			customlog.Printf(customlog.Info, "Semantic dedup removed %d duplicate config link(s) (same connection). Testing %d unique configs.\n", dupsRemoved, len(parsed))
		}
	} else {
		links, dupsRemoved = pkghttp.DeduplicateLinks(links)
		if dupsRemoved > 0 {
			customlog.Printf(customlog.Info, "Removed %d duplicate config link(s). Testing %d unique configs.\n", dupsRemoved, len(links))
		}
		parsed = pkghttp.ParseLinks(examiner.Core, links)
	}
	links = nil // from here on the parsed links are the source of truth

	// Optional TCP pre-check: cheaply drop unreachable endpoints before the
	// full test, which spins up a whole core instance per config.
	// Links the pre-scan drops are reported as failed results with the reason,
	// not silently lost.
	var dropped pkghttp.ConfigResults
	if config.Prescan {
		var preBar *progressbar.ProgressBar
		pre, err := pkghttp.RunPrescanParsed(ctx, parsed,
			pkghttp.PrescanOptions{
				Workers:       int(config.PrescanWorkers),
				Timeout:       time.Duration(config.PrescanTimeout) * time.Millisecond,
				BindInterface: config.BindInterface,
				Resolver:      trustedResolver(examiner),
			},
			func(uniqueEndpoints int) {
				customlog.Printf(customlog.Processing, "Pre-scanning %d unique endpoint(s) via TCP (timeout %dms)...\n", uniqueEndpoints, config.PrescanTimeout)
				preBar = progressbar.NewOptions(uniqueEndpoints, append(barOptions(),
					progressbar.OptionShowCount(),
					progressbar.OptionSetDescription(barColor("cyan", "Pre-scanning endpoints")),
					progressbar.OptionClearOnFinish(),
				)...)
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
			if customlog.ProgressEnabled() {
				fmt.Fprintln(os.Stderr)
			}
		}
		customlog.Printf(customlog.Success,
			"Pre-scan complete: %d reachable, %d filtered out, %d kept without probing (UDP/unparseable).\n",
			pre.TCPReachable, pre.FilteredOut, pre.Bypassed)

		// Abort cleanly if the user interrupted during the pre-scan.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		dropped = pre.DroppedResults()
		if summary := pkghttp.FailureSummary(dropped); summary != "" {
			customlog.Printf(customlog.Info, "Pre-scan: %s\n", summary)
		}
		parsed = pre.ReachableParsed
		if len(parsed) == 0 {
			customlog.Printf(customlog.Warning, "No reachable configs after pre-scan; nothing to test.\n")
		}
	}

	panel, err := buildEndpointPanel(config)
	if err != nil {
		return err
	}

	printConfiguration(config, len(parsed), panel)

	// Create a test run entry in the database
	opts := examinerOptions(config, panel)
	optsJson, err := json.Marshal(opts)
	if err != nil {
		return fmt.Errorf("failed to marshal test options to JSON: %w", err)
	}

	var runID int64
	if config.SaveToDB {
		runID, err = database.CreateHttpTestRun(string(optsJson), len(parsed)+len(dropped))
		if err != nil {
			return fmt.Errorf("failed to create database entry for test run: %w", err)
		}
		customlog.Printf(customlog.Info, "Created test run with ID: %d. Results will be saved to the database.\n", runID)
		// Mark the run finished however it ends (done, interrupted, failed).
		defer func() {
			if err := database.FinishHttpTestRun(runID); err != nil {
				customlog.Printf(customlog.Warning, "Could not mark test run %d finished: %v\n", runID, err)
			}
		}()
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

	// Stream into a side file and only replace the output at the end, so an
	// earlier result file survives until this run has something to replace
	// it with (including when it is interrupted).
	out := newOutputStream(config.OutputFile, config.OutputType)
	if err := out.reset(); err != nil {
		return err
	}
	if err := out.append(dropped); err != nil {
		customlog.Printf(customlog.Failure, "Failed to stream results to file: %v\n", err)
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

	bar := progressbar.NewOptions(len(parsed), append(barOptions(),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetDescription(barColor("cyan", "Testing configs (0 passed)")),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        barColor("green", "="),
			SaucerHead:    barColor("green", ">"),
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)...)

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
			if err := out.append(batch); err != nil {
				customlog.Printf(customlog.Failure, "Failed to stream results to file: %v\n", err)
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
			// The batch never needs the parsed protocol again; dropping it keeps
			// memory flat on huge lists (ProtocolInfo still describes it).
			res.Protocol = nil
			results = append(results, res)
			batch = append(batch, res)
			if len(batch) >= saveBatchSize {
				flushBatch()
			}
		}
		flushBatch()
	}()

	testManager.RunParsed(testCtx, parsed, resultsChan, func() {
		bar.Describe(barColor("cyan", fmt.Sprintf("Testing configs (%d passed)", atomic.LoadInt32(&passedCount))))
		bar.Add(1)
	})
	close(resultsChan)
	collectorWg.Wait()
	bar.Finish()
	if customlog.ProgressEnabled() {
		fmt.Fprintln(os.Stderr)
	}
	results = append(results, dropped...)

	if config.MaxPassed > 0 && atomic.LoadInt32(&passedCount) >= int32(config.MaxPassed) {
		customlog.Printf(customlog.Info, "Reached --max-passed=%d; stopped early without testing every config.\n", config.MaxPassed)
	}
	interrupted := ctx.Err() != nil
	if interrupted {
		customlog.Printf(customlog.Warning, "Interrupted: keeping the %d result(s) finished so far.\n", len(results))
	}

	if err := out.finish(results, config.SortedByRealDelay); err != nil {
		customlog.Printf(customlog.Failure, "Failed to write %s: %v\n", config.OutputFile, err)
	}

	// Save to DB and print summary (file already written via streaming)
	if err := processor.SaveResults(results); err != nil {
		return err
	}
	if interrupted {
		return ctx.Err()
	}
	if passed := atomic.LoadInt32(&passedCount); passed == 0 {
		return exitcode.New(exitcode.NothingPassed, fmt.Errorf("0 of %d configs passed", len(results)))
	}
	return nil
}

// trustedResolver is the --resolver the examiner compares system DNS with.
func trustedResolver(e *pkghttp.Examiner) pkghttp.Resolver {
	if e.Diagnoser == nil {
		return nil
	}
	return e.Diagnoser.Trusted
}

// outputStream streams batch results into a side file and swaps it in over
// the real output at the end, so the previous output is never truncated
// before there is a replacement.
type outputStream struct {
	path    string // final output; "" disables file output
	partial string // streaming target
	format  string
}

func newOutputStream(path, format string) *outputStream {
	o := &outputStream{path: path, format: format}
	if path != "" && path != "-" {
		o.partial = path + ".partial"
	}
	return o
}

// reset removes a stale side file from an earlier crashed run.
func (o *outputStream) reset() error {
	if o.partial == "" {
		return nil
	}
	if err := os.Remove(o.partial); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to clear %s: %w", o.partial, err)
	}
	return nil
}

func (o *outputStream) append(batch []*pkghttp.Result) error {
	if o.partial == "" {
		return nil
	}
	switch o.format {
	case "csv":
		return pkghttp.AppendResultsToCSV(o.partial, batch)
	case "txt":
		return pkghttp.AppendResultsToTxt(o.partial, batch)
	case "jsonl":
		return pkghttp.AppendResultsToJSONL(o.partial, batch)
	}
	return nil // json is written whole at the end
}

// finish writes the final file. Sorting (or a format that cannot stream)
// rewrites from the in-memory results; otherwise the side file is renamed.
func (o *outputStream) finish(results pkghttp.ConfigResults, sorted bool) error {
	if o.path == "" {
		return nil
	}
	if len(results) == 0 {
		// Nothing to replace the previous output with: keep it.
		if o.partial != "" {
			_ = os.Remove(o.partial)
		}
		return nil
	}
	if o.path == "-" {
		pkghttp.NewResultProcessor(pkghttp.ResultProcessorOptions{OutputFile: "-", OutputType: o.format}).RewriteFileSorted(results)
		return nil
	}
	switch {
	case sorted:
		// Rewrite onto a fresh side file so the current schema is used, not
		// whatever header an older output file had.
		_ = os.Remove(o.partial)
		pkghttp.NewResultProcessor(pkghttp.ResultProcessorOptions{OutputFile: o.partial, DisplayName: o.path, OutputType: o.format}).RewriteFileSorted(results)
	case o.format == "json":
		if err := pkghttp.WriteResultsJSON(o.partial, results); err != nil {
			return err
		}
	}
	if _, err := os.Stat(o.partial); os.IsNotExist(err) {
		// txt streams only passed configs: an all-failed run still leaves a
		// (now empty) output rather than a stale one.
		return pkghttp.WriteFileAtomic(o.path, nil)
	}
	return os.Rename(o.partial, o.path)
}

// barOptions are the progress bar options shared by every bar: hidden when
// progress output is off (stderr not a terminal, XRAY_KNIFE_NO_PROGRESS), so
// logs and CI don't fill with redraws.
func barOptions() []progressbar.Option {
	return []progressbar.Option{
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionEnableColorCodes(customlog.ColorEnabled(os.Stderr)),
		progressbar.OptionSetVisibility(customlog.ProgressEnabled()),
	}
}

// barColor wraps s in a progressbar color tag when colors are on.
func barColor(color, s string) string {
	if !customlog.ColorEnabled(os.Stderr) {
		return s
	}
	return "[" + color + "]" + s + "[reset]"
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

// handleSingleConfig tests one config and returns an error unless it passed,
// so scripts can rely on the exit code.
func handleSingleConfig(ctx context.Context, examiner *pkghttp.Examiner, config *Config) error {
	examiner.Verbose = true
	res, err := examiner.ExamineConfig(ctx, config.ConfigLink)

	// Print the per-endpoint breakdown first: it is populated even on failure
	// and explains exactly which endpoint(s) failed.
	printEndpointBreakdown(&res)

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		customlog.Printf(customlog.Failure, "%v\n", err)
		printFailureKind(&res)
		return singleConfigError(res)
	}

	if res.Status != "passed" {
		customlog.Printf(customlog.Failure, "%s: %s\n", res.Status, res.Reason)
		printFailureKind(&res)
	}

	if res.Delay >= 0 {
		customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", res.Delay)
	}
	for _, line := range probeSampleLines(&res, config.ProbeSamples) {
		customlog.Printf(customlog.Success, "%s\n", line)
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
	if res.Status != "passed" {
		return singleConfigError(res)
	}
	return nil
}

// printFailureKind names why the config failed, in the words the batch
// summary and list-results use.
func printFailureKind(res *pkghttp.Result) {
	if res.FailureKind != "" {
		customlog.Printf(customlog.Info, "Failure kind: %s\n", res.FailureKind)
	}
}

// singleConfigError is the command's error for a config that did not pass:
// exit code 3 when the test ran and the config failed it, 1 when the config
// could not even be tested (unparseable link, core refused to build it).
func singleConfigError(res pkghttp.Result) error {
	msg := "config test failed"
	if res.Status != "" {
		msg = "config " + res.Status
	}
	if res.FailureKind != "" {
		msg += " (" + res.FailureKind + ")"
	}
	if res.Status == pkghttp.StatusBroken || res.Status == "" {
		return exitcode.New(exitcode.Error, errors.New(msg))
	}
	return exitcode.New(exitcode.NothingPassed, errors.New(msg))
}

// probeSampleLines summarizes a native probe's samples for one config. HTTP
// results, failures and single-sample runs have nothing to add.
func probeSampleLines(res *pkghttp.Result, requested int) []string {
	if requested <= 1 || res.Status != "passed" || res.RTTSamples == 0 {
		return nil
	}
	count := fmt.Sprintf("Probe samples: %d/%d", res.RTTSamples, requested)
	if res.RTTSamples < requested {
		count += " (sampling stopped early)"
	}
	lines := []string{count}
	if res.RTTSamples > 1 {
		lines = append(lines, fmt.Sprintf("RTT over %d samples: min/avg/max/jitter = %d/%d/%d/%d ms",
			res.RTTSamples, res.RTTMin, res.RTTAvg, res.RTTMax, res.Jitter))
	}
	return lines
}

// reasonIsWarning reports whether a passed config's reason is worth flagging,
// such as a speedtest failure. Native probes put success detail in Reason.
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
	if config.ProbeSamples > 1 {
		fmt.Printf("%s: %d\n", color.RedString("Probe samples"), config.ProbeSamples)
	}
	if config.Fragment.FragmentsTCP() {
		fmt.Printf("%s: %s\n", color.RedString("Fragment"), config.Fragment.String())
	}
	if config.Fragment != nil && len(config.Fragment.Noises) > 0 {
		n := len(config.Fragment.Noises)
		fmt.Printf("%s: %d packet(s)\n", color.RedString("Noise"), n)
	}
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
	flags.StringVarP(&config.ConfigLinksFile, "file", "f", "", "Read config links from a file, one per line (\"-\" reads stdin). Blank lines and # comments are skipped")
	flags.BoolVarP(&config.Stdin, "stdin", "i", false, "Read a batch of config links from standard input")

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
	flags.StringVar(&config.SpeedtestURL, "speedtest-url", "", "Speed test target: an https origin speaking Cloudflare's /__down and /__up, or a file URL to download (upload skipped). Default speed.cloudflare.com")

	// DPI evasion on the first hop
	flags.StringVar(&config.FragmentSpec, "fragment", "", "Split the TLS ClientHello to evade SNI filtering, as packets,length[,interval] (e.g. tlshello,100-200,10-20). \"off\" disables")
	flags.StringArrayVar(&config.NoiseSpecs, "noise", nil, "Send UDP noise before traffic (xray), as type:packet[:delay] (e.g. rand:10-20:10-16). Repeatable")

	// Failure diagnostics
	flags.BoolVar(&config.Diagnose, "diagnose", true, "Check failed configs' servers directly (DNS, TCP, TLS ClientHello) to tell blocking (dns-poisoned, tcp-reset, tls-reset...) from a dead server or wrong config")
	flags.StringVar(&config.Resolver, "resolver", "", "Trusted DNS for diagnostics and --prescan, compared with the system resolver to detect poisoning: doh://host, https://host/dns-query, or IP[:port]. Cores keep their own DNS")

	flags.BoolVar(&config.GetIPInfo, "rip", true, "Receive real IP (csv)")
	flags.BoolVarP(&config.Verbose, "verbose", "v", false, "Verbose")

	flags.BoolVar(&config.Ping, "ping", false, "Enable continuous HTTP ping mode for a single config")
	flags.Uint16Var(&config.PingInterval, "interval", 1000, "Interval between pings in milliseconds (ms)")

	flags.StringVar(&config.BindInterface, "bind", "", "Bind outbound dials to a specific OS interface (e.g. eth0). Linux: needs CAP_NET_RAW.")
	flags.IntVar(&config.ProbeSamples, "probe-samples", 1, fmt.Sprintf("Round trips to measure for natively probed protocols such as MTProto, 1-%d (0 means 1). All samples share one connection and one --timeout budget, so a slow proxy may report fewer. HTTP testing is unaffected; --ping uses one sample per tick.", protocol.MaxProbeSamples))

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
	flags.StringVarP(&config.OutputFile, "out", "o", "valid.txt", "Output file for valid/all config links (\"-\" writes stdout)")
	flags.StringVarP(&config.OutputType, "type", "x", "txt", "Output type for file: txt (passed links), csv, json or jsonl (all results)")
	flags.BoolVar(&config.SortedByRealDelay, "sort", true, "Sort config links by their delay (fast to slow) in file output")
	flags.BoolVar(&config.SaveToDB, "save-db", false, "Save test results to the database")

	cmd.MarkFlagsMutuallyExclusive("file", "config", "from-db", "stdin")
}
