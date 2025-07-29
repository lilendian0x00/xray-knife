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
	"syscall"
	"time"

	"github.com/lilendian0x00/xray-knife/v7/database"
	pkghttp "github.com/lilendian0x00/xray-knife/v7/pkg/http"
	"github.com/lilendian0x00/xray-knife/v7/utils"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// HttpCmd represents the http command
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

	// DB flags
	FromDB         bool
	Limit          int
	SubscriptionID int64
	Protocol       string

	// File Output Flags
	OutputFile        string
	OutputType        string
	SortedByRealDelay bool

	Speedtest           bool
	GetIPInfo           bool
	SpeedtestAmount     uint32
	MaximumAllowedDelay uint16
	Ping                bool
	PingInterval        uint16
}

// validateConfig validates the configuration options
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

// newHttpCommand creates and returns the HTTP command
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

			examiner, err := pkghttp.NewExaminer(pkghttp.Options{
				Core:                   config.CoreType,
				MaxDelay:               config.MaximumAllowedDelay,
				Verbose:                config.Verbose,
				ShowBody:               config.ShowBody,
				InsecureTLS:            config.InsecureTLS,
				DoSpeedtest:            config.Speedtest,
				DoIPInfo:               config.GetIPInfo,
				TestEndpoint:           config.DestURL,
				TestEndpointHttpMethod: config.HTTPMethod,
				SpeedtestKbAmount:      config.SpeedtestAmount,
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

// handlePingMode handles the continuous HTTP test.
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
			client, instance, err := examiner.Core.MakeHttpClient(context.Background(), pinger, time.Duration(config.MaximumAllowedDelay)*time.Millisecond)
			if err != nil {
				customlog.Printf(customlog.Failure, "Failed to create HTTP client: %v\n", err)
				if instance != nil {
					instance.Close()
				}
				continue
			}

			delay, _, _, err := pkghttp.MeasureDelay(context.Background(), client, false, config.DestURL, config.HTTPMethod)
			if instance != nil {
				instance.Close()
			}

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

// handleMultipleConfigs handles testing multiple configurations
func handleMultipleConfigs(examiner *pkghttp.Examiner, config *Config, links []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	printConfiguration(config, len(links))

	// Create a test run entry in the database
	opts := pkghttp.Options{
		Core:                   config.CoreType,
		MaxDelay:               config.MaximumAllowedDelay,
		Verbose:                config.Verbose,
		ShowBody:               config.ShowBody,
		InsecureTLS:            config.InsecureTLS,
		DoSpeedtest:            config.Speedtest,
		DoIPInfo:               config.GetIPInfo,
		TestEndpoint:           config.DestURL,
		TestEndpointHttpMethod: config.HTTPMethod,
		SpeedtestKbAmount:      config.SpeedtestAmount,
	}
	optsJson, err := json.Marshal(opts)
	if err != nil {
		return fmt.Errorf("failed to marshal test options to JSON: %w", err)
	}

	runID, err := database.CreateHttpTestRun(string(optsJson), len(links))
	if err != nil {
		return fmt.Errorf("failed to create database entry for test run: %w", err)
	}
	customlog.Printf(customlog.Info, "Created test run with ID: %d. Results will be saved to the database.\n", runID)

	// Setup the result processor with the new runID and file options
	processor := pkghttp.NewResultProcessor(
		pkghttp.ResultProcessorOptions{
			RunID:      runID,
			OutputFile: config.OutputFile,
			OutputType: config.OutputType,
			Sorted:     config.SortedByRealDelay,
		},
	)

	// Run the tests as before
	testManager := pkghttp.NewTestManager(examiner, config.ThreadCount, config.Verbose, nil)
	resultsChan := make(chan *pkghttp.Result, len(links))
	var results pkghttp.ConfigResults
	var collectorWg sync.WaitGroup

	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		var counter int
		for res := range resultsChan {
			if res.Status == "passed" {
				printSuccessDetails(counter, *res)
				counter++
			}
			results = append(results, res)
		}
	}()

	testManager.RunTests(ctx, links, resultsChan, func() {})
	close(resultsChan)
	collectorWg.Wait()

	// Save results to both DB and file if specified
	return processor.SaveResults(results)
}

// handleSingleConfig handles testing a single configuration
func handleSingleConfig(examiner *pkghttp.Examiner, config *Config) {
	examiner.Verbose = true
	res, err := examiner.ExamineConfig(context.Background(), config.ConfigLink)
	if err != nil {
		customlog.Printf(customlog.Failure, "%v\n", err)
		return
	}

	if res.Status != "passed" {
		customlog.Printf(customlog.Failure, "%s: %s\n", res.Status, res.Reason)
	}

	customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", res.Delay)
	if config.Speedtest {
		customlog.Printf(customlog.Success, "Downloaded %dKB - Speed: %f mbps\n",
			config.SpeedtestAmount, res.DownloadSpeed)
		customlog.Printf(customlog.Success, "Uploaded %dKB - Speed: %f mbps\n",
			config.SpeedtestAmount, res.UploadSpeed)
	}
}

// printSuccessDetails prints the details of a successful test for the CLI
func printSuccessDetails(index int, res pkghttp.Result) {
	d := color.New(color.FgCyan, color.Bold)
	d.Printf("Config Number: %d\n", index+1)
	fmt.Printf("%v%s: %s\n", res.Protocol.DetailsStr(), color.RedString("Link"), res.Protocol.GetLink())
	customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", res.Delay)
}

// printConfiguration prints the current configuration
func printConfiguration(config *Config, totalConfigs int) {
	fmt.Printf("%s: %d\n%s: %d\n%s: %dms\n%s: %t\n%s: %s\n%s: %t\n%s: %t\n",
		color.RedString("Total configs"), totalConfigs,
		color.RedString("Thread count"), config.ThreadCount,
		color.RedString("Maximum delay"), config.MaximumAllowedDelay,
		color.RedString("Speed test"), config.Speedtest,
		color.RedString("Test url"), config.DestURL,
		color.RedString("IP info"), config.GetIPInfo,
		color.RedString("Insecure TLS"), config.InsecureTLS,
	)
	if config.OutputFile != "" {
		fmt.Printf("%s: %s\n", color.RedString("Output file"), config.OutputFile)
	}
	fmt.Println()
}

// addFlags adds all command-line flags to the command
func addFlags(cmd *cobra.Command, config *Config) {
	flags := cmd.Flags()

	// Input flags
	flags.StringVarP(&config.ConfigLink, "config", "c", "", "The xray config link")
	flags.StringVarP(&config.ConfigLinksFile, "file", "f", "", "Read config links from a file")

	// Core flags
	flags.Uint16VarP(&config.ThreadCount, "thread", "t", 50, "Number of threads")
	flags.StringVarP(&config.CoreType, "core", "z", "auto", "Core type (auto, singbox, xray)")
	flags.StringVarP(&config.DestURL, "url", "u", "https://cloudflare.com/cdn-cgi/trace", "The url to test config")
	flags.StringVarP(&config.HTTPMethod, "method", "m", "GET", "Http method")
	flags.BoolVarP(&config.ShowBody, "body", "b", false, "Show response body")
	flags.Uint16VarP(&config.MaximumAllowedDelay, "mdelay", "d", 5000, "Maximum allowed delay (ms)")
	flags.BoolVarP(&config.InsecureTLS, "insecure", "e", false, "Insecure tls connection (fake SNI)")

	// Speedtest flags
	flags.BoolVarP(&config.Speedtest, "speedtest", "p", false, "Speed test with speed.cloudflare.com")
	flags.Uint32VarP(&config.SpeedtestAmount, "amount", "a", 10000, "Download and upload amount (Kbps)")

	flags.BoolVarP(&config.GetIPInfo, "rip", "r", true, "Receive real IP (csv)")
	flags.BoolVarP(&config.Verbose, "verbose", "v", false, "Verbose")

	flags.BoolVar(&config.Ping, "ping", false, "Enable continuous HTTP ping mode for a single config")
	flags.Uint16Var(&config.PingInterval, "interval", 1000, "Interval between pings in milliseconds (ms)")

	// DB flags
	flags.BoolVar(&config.FromDB, "from-db", false, "Test configs from the database")
	flags.IntVar(&config.Limit, "limit", 0, "Limit the number of configs to test from the DB (0 for all)")
	flags.Int64Var(&config.SubscriptionID, "sub-id", 0, "Filter configs by subscription ID from the DB")
	flags.StringVar(&config.Protocol, "protocol", "", "Filter configs by protocol (vmess, vless, etc.) from the DB")

	// Output Flags
	flags.StringVarP(&config.OutputFile, "out", "o", "valid.txt", "Output file for valid/all config links")
	flags.StringVarP(&config.OutputType, "type", "x", "txt", "Output type for file (csv, txt)")
	flags.BoolVarP(&config.SortedByRealDelay, "sort", "s", true, "Sort config links by their delay (fast to slow) in file output")

	cmd.MarkFlagsMutuallyExclusive("file", "config", "from-db")
}
