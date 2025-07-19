package http

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	pkghttp "github.com/lilendian0x00/xray-knife/v6/pkg/http"
	"github.com/lilendian0x00/xray-knife/v6/utils"
	"github.com/lilendian0x00/xray-knife/v6/utils/customlog"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// HttpCmd represents the http command
var HttpCmd = newHttpCommand()

// Config holds all command configuration options
type Config struct {
	ConfigLink          string
	ConfigLinksFile     string
	OutputFile          string
	OutputType          string
	ThreadCount         uint16
	CoreType            string
	DestURL             string
	HTTPMethod          string
	ShowBody            bool
	InsecureTLS         bool
	Verbose             bool
	SortedByRealDelay   bool
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

	validOutputTypes := map[string]bool{"csv": true, "txt": true}
	if !validOutputTypes[cfg.OutputType] {
		return fmt.Errorf("bad output format. Allowed formats: txt, csv")
	}

	if cfg.OutputType == "csv" {
		base := strings.TrimSuffix(cfg.OutputFile, filepath.Ext(cfg.OutputFile))
		cfg.OutputFile = base + ".csv"
	}

	if cfg.Ping {
		if cfg.ConfigLinksFile != "" {
			return fmt.Errorf("--ping flag cannot be used with --file flag")
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
By default, if no --config or --file flag is provided, it will wait for a single config link from standard input.`,
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

			// 1. File mode has highest precedence (after validation).
			if config.ConfigLinksFile != "" {
				return handleMultipleConfigs(examiner, config)
			}

			// 2. Handle single config modes (ping or one-shot test).
			// If config link is not provided via flag, read from stdin.
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

			// By this point, config.ConfigLink is populated.
			// Now decide between ping mode or single test mode.
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
			if received > 0 {
				avgLatency := totalLatency / int64(received)
				fmt.Printf("rtt min/avg/max = %d/%d/%d ms\n", minLatency, avgLatency, maxLatency)
			}
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
			instance.Close()

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
func handleMultipleConfigs(examiner *pkghttp.Examiner, config *Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	links := utils.ParseFileByNewline(config.ConfigLinksFile)
	printConfiguration(config, len(links))

	if config.Speedtest && config.OutputType != "csv" {
		customlog.Printf(customlog.Processing, "Speedtest is enabled, switching to CSV output!\n\n")
		config.OutputType = "csv"
		base := strings.TrimSuffix(config.OutputFile, filepath.Ext(config.OutputFile))
		config.OutputFile = base + ".csv"
	}

	processor := pkghttp.NewResultProcessor(
		pkghttp.ResultProcessorOptions{
			OutputFile: config.OutputFile,
			OutputType: config.OutputType,
			Sorted:     config.SortedByRealDelay,
		},
	)

	testManager := pkghttp.NewTestManager(examiner, config.ThreadCount, config.Verbose, nil)

	resultsChan := make(chan *pkghttp.Result, len(links))
	var results pkghttp.ConfigResults
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		var counter int
		defer collectorWg.Done()
		for res := range resultsChan {
			// Print success details as soon as a result is received.
			if res.Status == "passed" {
				printSuccessDetails(counter, *res)
				counter++
			}
			results = append(results, res)
		}
	}()

	testManager.RunTests(ctx, links, resultsChan, func() {

	})
	close(resultsChan)
	collectorWg.Wait()

	for i, res := range results {
		if res.Status == "passed" {
			printSuccessDetails(i, *res)
		}
	}

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
	fmt.Printf("%s: %d\n%s: %d\n%s: %dms\n%s: %t\n%s: %s\n%s: %t\n%s: %t\n%s: %s\n%s: %t\n\n",
		color.RedString("Total configs"), totalConfigs,
		color.RedString("Thread count"), config.ThreadCount,
		color.RedString("Maximum delay"), config.MaximumAllowedDelay,
		color.RedString("Speed test"), config.Speedtest,
		color.RedString("Test url"), config.DestURL,
		color.RedString("IP info"), config.GetIPInfo,
		color.RedString("Insecure TLS"), config.InsecureTLS,
		color.RedString("Output type"), config.OutputType,
		color.RedString("Verbose"), config.Verbose)
}

// addFlags adds all command-line flags to the command
func addFlags(cmd *cobra.Command, config *Config) {
	flags := cmd.Flags()
	flags.StringVarP(&config.ConfigLink, "config", "c", "", "The xray config link")
	flags.StringVarP(&config.ConfigLinksFile, "file", "f", "", "Read config links from a file")
	flags.Uint16VarP(&config.ThreadCount, "thread", "t", 5, "Number of threads to be used for checking links from file")
	flags.StringVarP(&config.CoreType, "core", "z", "auto", "Core type (auto, singbox, xray)")
	flags.StringVarP(&config.DestURL, "url", "u", "https://cloudflare.com/cdn-cgi/trace", "The url to test config")
	flags.StringVarP(&config.HTTPMethod, "method", "m", "GET", "Http method")
	flags.BoolVarP(&config.ShowBody, "body", "b", false, "Show response body")
	flags.Uint16VarP(&config.MaximumAllowedDelay, "mdelay", "d", 10000, "Maximum allowed delay (ms)")
	flags.BoolVarP(&config.InsecureTLS, "insecure", "e", false, "Insecure tls connection (fake SNI)")
	flags.BoolVarP(&config.Speedtest, "speedtest", "p", false, "Speed test with speed.cloudflare.com")
	flags.BoolVarP(&config.GetIPInfo, "rip", "r", false, "Send request to XXXX/cdn-cgi/trace to receive config's IP details")
	flags.Uint32VarP(&config.SpeedtestAmount, "amount", "a", 10000, "Download and upload amount (KB)")
	flags.BoolVarP(&config.Verbose, "verbose", "v", false, "Verbose")
	flags.StringVarP(&config.OutputType, "type", "x", "txt", "Output type (csv, txt)")
	flags.StringVarP(&config.OutputFile, "out", "o", "valid.txt", "Output file for valid config links")
	flags.BoolVarP(&config.SortedByRealDelay, "sort", "s", true, "Sort config links by their delay (fast to slow)")
	flags.BoolVar(&config.Ping, "ping", false, "Enable continuous HTTP ping mode for a single config")
	flags.Uint16Var(&config.PingInterval, "interval", 1000, "Interval between pings in milliseconds (ms)")
	cmd.MarkFlagsMutuallyExclusive("file", "config")
}
