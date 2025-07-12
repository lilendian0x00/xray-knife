package http

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v5/utils"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"
)

// ConfigResults represents a slice of test results
type ConfigResults []*Result

// ResultProcessor handles the processing and storage of test results
type ResultProcessor struct {
	validConfigs   []string
	validConfigsMu sync.Mutex
	outputFile     string
	outputType     string
	sorted         bool
}

type ResultProcessorOptions struct {
	OutputFile string
	OutputType string
	Sorted     bool
}

// NewResultProcessor creates a new ResultProcessor instance
func NewResultProcessor(opts ResultProcessorOptions) *ResultProcessor {
	return &ResultProcessor{
		validConfigs: make([]string, 0),
		outputFile:   opts.OutputFile,
		outputType:   opts.OutputType,
		sorted:       opts.Sorted,
	}
}

// Sort interface implementation for ConfigResults
func (cr ConfigResults) Len() int { return len(cr) }
func (cr ConfigResults) Less(i, j int) bool {
	// A more robust sorting: prioritize lower latency, then higher download, then higher upload.
	if cr[i].Delay != cr[j].Delay {
		return cr[i].Delay < cr[j].Delay
	}
	if cr[i].DownloadSpeed != cr[j].DownloadSpeed {
		return cr[i].DownloadSpeed > cr[j].DownloadSpeed
	}
	return cr[i].UploadSpeed > cr[j].UploadSpeed
}
func (cr ConfigResults) Swap(i, j int) { cr[i], cr[j] = cr[j], cr[i] }

// TestManager handles the concurrent testing of configurations
type TestManager struct {
	examiner    *Examiner
	processor   *ResultProcessor
	threadCount uint16
	verbose     bool
}

// NewTestManager creates a new TestManager instance
func NewTestManager(examiner *Examiner, processor *ResultProcessor, threadCount uint16, verbose bool) *TestManager {
	return &TestManager{
		examiner:    examiner,
		processor:   processor,
		threadCount: threadCount,
		verbose:     verbose,
	}
}

// TestConfigs tests multiple configurations concurrently
func (tm *TestManager) TestConfigs(links []string, printSuccess bool) ConfigResults {
	semaphore := make(chan int, tm.threadCount)
	var wg sync.WaitGroup
	results := make(ConfigResults, 0)
	var resultsMu sync.Mutex

	for i := range links {
		semaphore <- 1
		wg.Add(1)
		go tm.testSingleConfig(links[i], i, &results, &resultsMu, semaphore, &wg, printSuccess)
	}

	wg.Wait()
	close(semaphore)
	return results
}

// testSingleConfig tests a single configuration
func (tm *TestManager) testSingleConfig(link string, index int, results *ConfigResults, resultsMu *sync.Mutex, semaphore chan int, wg *sync.WaitGroup, printSuccess bool) {
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

	if res.Status == "passed" && printSuccess {
		tm.printSuccessDetails(index, res)
	}

	if tm.processor.outputType == "csv" || res.Status == "passed" {
		resultsMu.Lock()
		*results = append(*results, &res)
		resultsMu.Unlock()
	}
}

// printSuccessDetails prints the details of a successful test
func (tm *TestManager) printSuccessDetails(index int, res Result) {
	d := color.New(color.FgCyan, color.Bold)
	d.Printf("Config Number: %d\n", index+1)
	fmt.Printf("%v%s: %s\n", res.Protocol.DetailsStr(), color.RedString("Link"), res.Protocol.GetLink())
	customlog.Printf(customlog.Success, "Real Delay: %dms\n\n", res.Delay)
}

// SaveResults saves the test results to a file
func (rp *ResultProcessor) SaveResults(results ConfigResults) error {
	if rp.sorted {
		sort.Sort(results)
	}

	switch rp.outputType {
	case "txt":
		return rp.saveTxtResults(results)
	case "csv":
		return rp.saveCSVResults(results)
	default:
		return fmt.Errorf("unsupported output type: %s", rp.outputType)
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
	if err := utils.WriteIntoFile(rp.outputFile, []byte(content)); err != nil {
		return fmt.Errorf("failed to save configs: %v", err)
	}

	customlog.Printf(customlog.Finished, "A total of %d working configurations have been saved to %s\n",
		len(rp.validConfigs), rp.outputFile)
	return nil
}

// saveCSVResults saves results in CSV format
func (rp *ResultProcessor) saveCSVResults(results ConfigResults) error {
	// Ensure the file has a .csv extension
	base := strings.TrimSuffix(rp.outputFile, filepath.Ext(rp.outputFile))
	csvFile := base + ".csv"

	out, err := gocsv.MarshalString(&results)
	if err != nil {
		return fmt.Errorf("failed to marshal CSV: %v", err)
	}

	if err := utils.WriteIntoFile(csvFile, []byte(out)); err != nil {
		return fmt.Errorf("failed to save configs: %v", err)
	}

	passedCount := 0
	for _, v := range results {
		if v.Status == "passed" {
			passedCount++
		}
	}

	customlog.Printf(customlog.Finished, "A total of %d configurations (with %d working) have been saved to %s\n",
		len(results), passedCount, csvFile)
	return nil
}
