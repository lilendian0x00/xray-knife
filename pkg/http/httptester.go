// pkg/http/httptester.go
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

// RunTests tests multiple configurations concurrently.
// It accepts an optional onProgress callback which is fired after each test.
func (tm *TestManager) RunTests(ctx context.Context, links []string, resultsChan chan<- *Result, onProgress func()) {
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
				if onProgress != nil {
					onProgress() // Call the progress callback on completion
				}
			}()

			if ctx.Err() != nil {
				return
			}

			res, err := tm.examiner.ExamineConfig(ctx, link)
			if err != nil && !strings.Contains(err.Error(), "context canceled") {
				logMsg := fmt.Sprintf("[-] Error: %s - broken config: %s\n", err.Error(), link)
				if tm.logger != nil {
					tm.logger.Print(logMsg)
				} else if tm.verbose {
					customlog.Printf(customlog.Failure, "Error: %s - broken config: %s\n", err.Error(), link)
				}
			}

			select {
			case resultsChan <- &res:
				if res.Status == "passed" && tm.logger != nil {
					logMsg := fmt.Sprintf("[+] SUCCESS | %s | Delay: %dms\n", res.ConfigLink, res.Delay)
					tm.logger.Print(logMsg)
				}
			case <-ctx.Done():
				return
			}
		}(link, i)
	}

	wg.Wait()
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
