package http

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v7/database"
	"github.com/lilendian0x00/xray-knife/v7/utils"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"
	"log"
	"sort"
	"strings"
	"sync"
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
	runID      int64
	outputFile string
	outputType string
	sorted     bool
}

type ResultProcessorOptions struct {
	RunID      int64
	OutputFile string
	OutputType string
	Sorted     bool
}

// NewResultProcessor creates a new ResultProcessor instance
func NewResultProcessor(opts ResultProcessorOptions) *ResultProcessor {
	return &ResultProcessor{
		runID:      opts.RunID,
		outputFile: opts.OutputFile,
		outputType: opts.OutputType,
		sorted:     opts.Sorted,
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

// SaveResults saves results first to the DB, then optionally to a file.
func (rp *ResultProcessor) SaveResults(results ConfigResults) error {
	passedCount := 0
	for _, res := range results {
		if res.Status == "passed" {
			passedCount++
		}
	}

	// Save to the database if a runID is available.
	if rp.runID > 0 {
		dbResults := make([]database.HttpTestResult, 0, len(results))
		for _, res := range results {
			dbRes := database.HttpTestResult{
				RunID:        rp.runID,
				ConfigLink:   res.ConfigLink,
				Status:       res.Status,
				Reason:       sql.NullString{String: res.Reason, Valid: res.Reason != ""},
				DelayMs:      -1, // Default for non-passed tests
				DownloadMbps: 0,
				UploadMbps:   0,
			}

			if res.Status == "passed" {
				dbRes.DelayMs = res.Delay
				dbRes.DownloadMbps = float64(res.DownloadSpeed)
				dbRes.UploadMbps = float64(res.UploadSpeed)
				dbRes.IPAddress = sql.NullString{String: res.RealIPAddr, Valid: res.RealIPAddr != "" && res.RealIPAddr != "null"}
				dbRes.IPLocation = sql.NullString{String: res.IpAddrLoc, Valid: res.IpAddrLoc != "" && res.IpAddrLoc != "null"}
			}
			dbResults = append(dbResults, dbRes)
		}

		if len(dbResults) > 0 {
			if err := database.InsertHttpTestResultsBatch(rp.runID, dbResults); err != nil {
				return fmt.Errorf("failed to save results to database: %w", err)
			}
		}
		customlog.Printf(customlog.Finished, "Test run finished. A total of %d working configs (out of %d) saved to the database.\n", passedCount, len(results))
	} else {
		customlog.Printf(customlog.Finished, "Test run finished. Found %d working configs (out of %d).\n", passedCount, len(results))
	}

	// If an output file is specified, save to it as well.
	if rp.outputFile != "" {
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

	return nil
}

// saveTxtResults saves results in text format (private helper method)
func (rp *ResultProcessor) saveTxtResults(results ConfigResults) error {
	var validConfigs []string
	for _, v := range results {
		if v.Status == "passed" {
			validConfigs = append(validConfigs, v.ConfigLink)
		}
	}

	content := strings.Join(validConfigs, "\n\n")
	if err := utils.WriteIntoFile(rp.outputFile, []byte(content)); err != nil {
		return fmt.Errorf("failed to save TXT results: %w", err)
	}

	customlog.Printf(customlog.Finished, "%d working configurations have also been saved to %s\n",
		len(validConfigs), rp.outputFile)
	return nil
}

// saveCSVResults saves results in CSV format (private helper method)
func (rp *ResultProcessor) saveCSVResults(results ConfigResults) error {
	out, err := gocsv.MarshalString(&results)
	if err != nil {
		return fmt.Errorf("failed to marshal CSV: %w", err)
	}

	if err := utils.WriteIntoFile(rp.outputFile, []byte(out)); err != nil {
		return fmt.Errorf("failed to save CSV results: %w", err)
	}

	customlog.Printf(customlog.Finished, "Full test results for %d configurations have also been saved to %s\n",
		len(results), rp.outputFile)
	return nil
}
