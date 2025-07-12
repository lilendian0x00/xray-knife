package http

import (
	"fmt"
	"path/filepath"
	"strings"

	pkghttp "github.com/lilendian0x00/xray-knife/v5/pkg/http"
	"github.com/lilendian0x00/xray-knife/v5/utils"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"

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

	return nil
}

// newHttpCommand creates and returns the HTTP command
func newHttpCommand() *cobra.Command {
	config := &Config{}

	cmd := &cobra.Command{
		Use:   "http",
		Short: "Test proxy configurations for latency, speed, and IP info using HTTP requests.",
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

			if config.ConfigLinksFile != "" {
				return handleMultipleConfigs(examiner, config)
			}
			handleSingleConfig(examiner, config)
			return nil
		},
	}

	addFlags(cmd, config)
	return cmd
}

// handleMultipleConfigs handles testing multiple configurations
func handleMultipleConfigs(examiner *pkghttp.Examiner, config *Config) error {
	links := utils.ParseFileByNewline(config.ConfigLinksFile)
	printConfiguration(config, len(links))

	if config.Speedtest && config.OutputType != "csv" {
		customlog.Printf(customlog.Processing, "Speedtest is enabled, switching to CSV output!\n\n")
		config.OutputType = "csv"
	}

	processor := pkghttp.NewResultProcessor(pkghttp.ResultProcessorOptions{
		OutputFile: config.OutputFile,
		OutputType: config.OutputType,
		Sorted:     config.SortedByRealDelay,
	})

	testManager := pkghttp.NewTestManager(examiner, processor, config.ThreadCount, config.Verbose)
	results := testManager.TestConfigs(links, true)

	return processor.SaveResults(results)
}

// handleSingleConfig handles testing a single configuration
func handleSingleConfig(examiner *pkghttp.Examiner, config *Config) {
	examiner.Verbose = true
	res, err := examiner.ExamineConfig(config.ConfigLink)
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
}
