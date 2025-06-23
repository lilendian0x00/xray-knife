package net

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/lilendian0x00/xray-knife/v3/pkg"
	"github.com/lilendian0x00/xray-knife/v3/utils"
	"github.com/lilendian0x00/xray-knife/v3/utils/customlog"

	"github.com/fatih/color"
	"github.com/gocarina/gocsv"
	"github.com/spf13/cobra"
)

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

// ConfigResults represents a slice of test results
type ConfigResults []*pkg.Result

// ResultProcessor handles the processing and storage of test results
type ResultProcessor struct {
	validConfigs   []string
	validConfigsMu sync.Mutex
	config         *Config
}

// NewResultProcessor creates a new ResultProcessor instance
func NewResultProcessor(config *Config) *ResultProcessor {
	return &ResultProcessor{
		validConfigs: make([]string, 0),
		config:       config,
	}
}

// Sort interface implementation for ConfigResults
func (cr ConfigResults) Len() int { return len(cr) }
func (cr ConfigResults) Less(i, j int) bool {
	return cr[i].Delay < cr[j].Delay &&
		cr[i].DownloadSpeed >= cr[j].DownloadSpeed &&
		cr[i].UploadSpeed >= cr[j].UploadSpeed
}
func (cr ConfigResults) Swap(i, j int) { cr[i], cr[j] = cr[j], cr[i] }

// TestManager handles the concurrent testing of configurations
type TestManager struct {
	examiner    *pkg.Examiner
	processor   *ResultProcessor
	threadCount uint16
	verbose     bool
}

// NewTestManager creates a new TestManager instance
func NewTestManager(examiner *pkg.Examiner, processor *ResultProcessor, threadCount uint16, verbose bool) *TestManager {
	return &TestManager{
		examiner:    examiner,
		processor:   processor,
		threadCount: threadCount,
		verbose:     verbose,
	}
}

// TestConfigs tests multiple configurations concurrently
func (tm *TestManager) TestConfigs(links []string) ConfigResults {
	semaphore := make(chan int, tm.threadCount)
	var wg sync.WaitGroup
	var results ConfigResults

	for i := range links {
		semaphore <- 1
		wg.Add(1)
		go tm.testSingleConfig(links[i], i, &results, semaphore, &wg)
	}

	wg.Wait()
	close(semaphore)
	return results
}

// testSingleConfig tests a single configuration
func (tm *TestManager) testSingleConfig(link string, index int, results *ConfigResults, semaphore chan int, wg *sync.WaitGroup) {
	defer func() {
		<-semaphore
		wg.Done()
	}()

	res, err := tm.examiner.ExamineConfig(link)
	if err != nil {
		if tm.verbose {
			customlog.Printf(customlog.Failure, "Error: %s - broken config: %s\n", err.Error(), link)
		}
		return
	}

	if res.Status == "passed" {
		tm.printSuccessDetails(index, res)
	}

	if tm.processor.config.OutputType == "csv" || res.Status == "passed" {
		tm.processor.validConfigsMu.Lock()
		*results = append(*results, &res)
		tm.processor.validConfigsMu.Unlock()
	}
}

// printSuccessDetails prints the details of a successful test
func (tm *TestManager) printSuccessDetails(index int, res pkg.Result) {
	d := color.New(color.FgCyan, color.Bold)
	d.Printf("Config Number: %d\n", index+1)
	fmt.Printf("%v%s: %s\n", res.Protocol.DetailsStr(), color.RedString("Link"), res.Protocol.GetLink())
	customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", res.Delay)
}

// SaveResults saves the test results to a file
func (rp *ResultProcessor) SaveResults(results ConfigResults) error {
	if rp.config.SortedByRealDelay {
		sort.Sort(results)
	}

	switch rp.config.OutputType {
	case "txt":
		return rp.saveTxtResults(results)
	case "csv":
		return rp.saveCSVResults(results)
	default:
		return fmt.Errorf("unsupported output type: %s", rp.config.OutputType)
	}
}

// saveTxtResults saves results in text format
func (rp *ResultProcessor) saveTxtResults(results ConfigResults) error {
	for _, v := range results {
		if v.Status == "passed" {
			rp.validConfigs = append(rp.validConfigs, v.ConfigLink)
		}
	}

	content := strings.Join(rp.validConfigs, "\n\n")
	if err := utils.WriteIntoFile(rp.config.OutputFile, []byte(content)); err != nil {
		return fmt.Errorf("failed to save configs: %v", err)
	}

	customlog.Printf(customlog.Finished, "A total of %d working configurations have been saved to %s\n",
		len(rp.validConfigs), rp.config.OutputFile)
	return nil
}

// saveCSVResults saves results in CSV format
func (rp *ResultProcessor) saveCSVResults(results ConfigResults) error {
	out, err := gocsv.MarshalString(&results)
	if err != nil {
		return fmt.Errorf("failed to marshal CSV: %v", err)
	}

	if err := utils.WriteIntoFile(rp.config.OutputFile, []byte(out)); err != nil {
		return fmt.Errorf("failed to save configs: %v", err)
	}

	for _, v := range results {
		if v.Status == "passed" {
			rp.validConfigs = append(rp.validConfigs, v.ConfigLink)
		}
	}

	customlog.Printf(customlog.Finished, "A total of %d configurations have been saved to %s\n",
		len(rp.validConfigs), rp.config.OutputFile)
	return nil
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

// NewHTTPCommand creates and returns the HTTP command
func NewHTTPCommand() *cobra.Command {
	config := &Config{}

	cmd := &cobra.Command{
		Use:   "http",
		Short: "Examine config[s] real delay using http request",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the values of the flags
			if err := validateConfig(config); err != nil {
				return err
			}

			// Instantiate a Examiner
			examiner, err := pkg.NewExaminer(pkg.Options{
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
				customlog.Printf(customlog.Failure, "failed to create examiner: %v", err)
				return nil
				//fmt.Errorf("failed to create examiner: %v", err)
			}

			// Instantiate a Result Processor
			processor := NewResultProcessor(config)

			// Multiple or Single config
			if config.ConfigLinksFile != "" {
				err = handleMultipleConfigs(examiner, config, processor)
				if err != nil {
					customlog.Printf(customlog.Failure, "%v", err)
				}
				return nil
			}
			handleSingleConfig(examiner, config)
			return nil
		},
	}

	// Add command flags
	addFlags(cmd, config)
	return cmd
}

// handleMultipleConfigs handles testing multiple configurations
func handleMultipleConfigs(examiner *pkg.Examiner, config *Config, processor *ResultProcessor) error {
	links := utils.ParseFileByNewline(config.ConfigLinksFile)
	printConfiguration(config, len(links))

	if config.Speedtest && config.OutputType != "csv" {
		customlog.Printf(customlog.Processing, "Speedtest is enabled, switching to CSV output!\n\n")
		config.OutputType = "csv"
	}

	testManager := NewTestManager(examiner, processor, config.ThreadCount, config.Verbose)
	results := testManager.TestConfigs(links)

	return processor.SaveResults(results)
}

// handleSingleConfig handles testing a single configuration
func handleSingleConfig(examiner *pkg.Examiner, config *Config) {
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
