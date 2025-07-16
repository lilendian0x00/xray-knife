package http

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v5/utils"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"
)

// HttpTestRequest encapsulates all parameters for an HTTP test job.
type HttpTestRequest struct {
	Links       []string `json:"links"`
	ThreadCount uint16   `json:"threadCount"`
	Options
}

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
	logger      *log.Logger // Optional logger for web UI
	threadCount uint16
	verbose     bool
}

// NewTestManager creates a new TestManager instance
func NewTestManager(examiner *Examiner, threadCount uint16, verbose bool, logger *log.Logger) *TestManager {
	return &TestManager{
		examiner:    examiner,
		threadCount: threadCount,
		verbose:     verbose,
		logger:      logger,
	}
}

// RunTests tests multiple configurations concurrently. This is a BLOCKING call.
// It sends each result to the provided channel as it becomes available.
// The caller is responsible for consuming from the channel. This function does NOT close the channel.
func (tm *TestManager) RunTests(ctx context.Context, links []string, resultsChan chan<- *Result) {
	semaphore := make(chan int, tm.threadCount)
	var wg sync.WaitGroup

	for i, link := range links {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(link string, index int) {
			semaphore <- 1
			defer func() {
				<-semaphore
				wg.Done()
			}()

			select {
			case <-ctx.Done():
				return
			default:
			}

			res, err := tm.examiner.ExamineConfig(ctx, link)
			if err != nil {
				logMsg := fmt.Sprintf("[-] Error: %s - broken config: %s\n", err.Error(), link)
				if tm.logger != nil {
					tm.logger.Print(logMsg)
				} else if tm.verbose {
					customlog.Printf(customlog.Failure, "Error: %s - broken config: %s\n", err.Error(), link)
				}
			}

			// Check context before sending result, to avoid panic on closed channel
			select {
			case resultsChan <- &res:
				if res.Status == "passed" && tm.logger != nil {
					logMsg := fmt.Sprintf("[+] SUCCESS | %s | Delay: %dms\n", res.ConfigLink, res.Delay)
					tm.logger.Print(logMsg)
				}
			case <-ctx.Done():
				// Don't send, just return
				return
			}
		}(link, i)
	}

	// Wait for all workers to finish, or for the context to be cancelled
	waitChan := make(chan struct{})
	go func() { wg.Wait(); close(waitChan) }()
	select {
	case <-waitChan: // All workers finished
	case <-ctx.Done(): // Context was cancelled
	}
}

//// TestConfigs tests multiple configurations concurrently
//func (tm *TestManager) TestConfigs(links []string) ConfigResults {
//	semaphore := make(chan int, tm.threadCount)
//	var wg sync.WaitGroup
//	results := make(ConfigResults, 0)
//	var resultsMu sync.Mutex
//
//	for i := range links {
//		semaphore <- 1
//		wg.Add(1)
//		go tm.testSingleConfig(links[i], i, &results, &resultsMu, semaphore, &wg)
//	}
//
//	wg.Wait()
//	close(semaphore)
//	return results
//}

//// testSingleConfig tests a single configuration
//func (tm *TestManager) testSingleConfig(link string, index int, results *ConfigResults, resultsMu *sync.Mutex, semaphore chan int, wg *sync.WaitGroup) {
//	defer func() {
//		<-semaphore
//		wg.Done()
//	}()
//
//	res, err := tm.examiner.ExamineConfig(link)
//	if err != nil {
//		logMsg := fmt.Sprintf("[-] Error: %s - broken config: %s\n", err.Error(), link)
//		if tm.logger != nil {
//			tm.logger.Print(logMsg)
//		} else if tm.verbose {
//			customlog.Printf(customlog.Failure, "Error: %s - broken config: %s\n", err.Error(), link)
//		}
//		return
//	}
//
//	if res.Status == "passed" && tm.logger != nil {
//		logMsg := fmt.Sprintf("[+] SUCCESS | %s | Delay: %dms\n", res.ConfigLink, res.Delay)
//		tm.logger.Print(logMsg)
//	}
//
//	if tm.processor.outputType == "csv" || res.Status == "passed" {
//		resultsMu.Lock()
//		*results = append(*results, &res)
//		resultsMu.Unlock()
//	}
//}

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
	// Ensure the file has a .csv extension. gocsv does not add it automatically.
	csvFile := rp.outputFile
	if !strings.HasSuffix(csvFile, ".csv") {
		csvFile += ".csv"
	}

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
