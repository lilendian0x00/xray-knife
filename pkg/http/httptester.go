package http

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/alitto/pond/v2"
	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v7/database"
	"github.com/lilendian0x00/xray-knife/v7/utils"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"
)

// HttpTestRequest encapsulates all parameters for an HTTP test job.
type HttpTestRequest struct {
	Links       []string `json:"links"`
	ThreadCount uint16   `json:"threadCount"`
	SaveToDB    bool     `json:"saveToDB"`
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
	// Treat negative delay (failed) as infinity so failed results sort last.
	di, dj := cr[i].Delay, cr[j].Delay
	if di < 0 {
		di = math.MaxInt64
	}
	if dj < 0 {
		dj = math.MaxInt64
	}
	if di != dj {
		return di < dj
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

// RunTests tests multiple configurations concurrently using a worker pool.
// It accepts an optional onProgress callback which is fired after each test.
func (tm *TestManager) RunTests(ctx context.Context, links []string, resultsChan chan<- *Result, onProgress func()) {
	pool := pond.NewPool(int(tm.threadCount))
	defer pool.Stop()
	group := pool.NewGroupContext(ctx)

	for _, link := range links {
		linkToTest := link
		group.Submit(func() {
			res, err := tm.examiner.ExamineConfigWithRetries(group.Context(), linkToTest)
			if err != nil && !strings.Contains(err.Error(), "context canceled") {
				logMsg := fmt.Sprintf("[-] Error: %s - broken config: %s\n", err.Error(), linkToTest)
				if tm.logger != nil {
					tm.logger.Print(logMsg)
				} else if tm.verbose {
					customlog.Printf(customlog.Failure, "Error: %s - broken config: %s\n", err.Error(), linkToTest)
				}
			}

			select {
			case resultsChan <- &res:
				if res.Status == "passed" && tm.logger != nil {
					logMsg := fmt.Sprintf("[+] SUCCESS | %s | Delay: %dms\n", res.ConfigLink, res.Delay)
					tm.logger.Print(logMsg)
				}
			case <-group.Context().Done():
			}

			if onProgress != nil {
				onProgress()
			}
		})
	}

	group.Wait()
}

// SaveResults saves results to the DB and prints a summary.
// File output is expected to be handled via streaming (AppendResultsToCSV/Txt) by the caller.
// If file streaming was not done by the caller, this will also write the file.
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

			if res.Status == "passed" || res.Status == "semi-passed" {
				dbRes.DelayMs = res.Delay
				dbRes.DownloadMbps = float64(res.DownloadSpeed)
				dbRes.UploadMbps = float64(res.UploadSpeed)
				dbRes.IPAddress = sql.NullString{String: res.RealIPAddr, Valid: res.RealIPAddr != "" && res.RealIPAddr != "null"}
				dbRes.IPLocation = sql.NullString{String: res.IpAddrLoc, Valid: res.IpAddrLoc != "" && res.IpAddrLoc != "null"}
				dbRes.TTFBMs = res.TTFB
				dbRes.ConnectTimeMs = res.ConnectTime
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

	if rp.outputFile != "" {
		customlog.Printf(customlog.Finished, "Results have been saved to %s\n", rp.outputFile)
	}

	return nil
}

// RewriteFileSorted overwrites the output file with results sorted by delay.
func (rp *ResultProcessor) RewriteFileSorted(results ConfigResults) {
	if rp.outputFile == "" {
		return
	}
	sorted := make(ConfigResults, len(results))
	copy(sorted, results)
	sort.Sort(sorted)

	switch rp.outputType {
	case "csv":
		rp.saveCSVResults(sorted)
	case "txt":
		rp.saveTxtResults(sorted)
	}
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

// DeduplicateLinks removes duplicate links and returns the unique list and the number of duplicates removed.
func DeduplicateLinks(links []string) ([]string, int) {
	seen := make(map[string]struct{}, len(links))
	unique := make([]string, 0, len(links))
	for _, link := range links {
		trimmed := strings.TrimSpace(link)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; !exists {
			seen[trimmed] = struct{}{}
			unique = append(unique, trimmed)
		}
	}
	return unique, len(links) - len(unique)
}

// AppendResultsToCSV appends a batch of results to a CSV file, writing headers only if the file is empty/new.
func AppendResultsToCSV(filePath string, batch []*Result) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	bufWriter := bufio.NewWriter(file)
	csvWriter := csv.NewWriter(bufWriter)

	if info.Size() == 0 {
		err = gocsv.MarshalCSV(batch, csvWriter)
	} else {
		err = gocsv.MarshalCSVWithoutHeaders(batch, csvWriter)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal and append results to CSV: %w", err)
	}

	csvWriter.Flush()
	return bufWriter.Flush()
}

// AppendResultsToTxt appends passed config links to a text file.
func AppendResultsToTxt(filePath string, batch []*Result) error {
	var validConfigs []string
	for _, v := range batch {
		if v.Status == "passed" {
			validConfigs = append(validConfigs, v.ConfigLink)
		}
	}
	if len(validConfigs) == 0 {
		return nil
	}

	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	content := strings.Join(validConfigs, "\n\n")
	// Add separator if file already has content
	if info.Size() > 0 {
		content = "\n\n" + content
	}
	_, err = file.WriteString(content)
	return err
}
