package http

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/alitto/pond/v2"
	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
)

type HttpTestRequest struct {
	Links       []string `json:"links"`
	ThreadCount uint16   `json:"threadCount"`
	SaveToDB    bool     `json:"saveToDB"`
	Options
}

// ConfigResults is a sortable slice of results
type ConfigResults []*Result

// ResultProcessor saves test results to files and DB
type ResultProcessor struct {
	runID       int64
	outputFile  string
	displayName string
	outputType  string
	sorted      bool
}

type ResultProcessorOptions struct {
	RunID      int64
	OutputFile string
	// DisplayName is the file name shown in messages when OutputFile is a
	// temporary path that will be renamed (defaults to OutputFile).
	DisplayName string
	OutputType  string
	Sorted      bool
}

func NewResultProcessor(opts ResultProcessorOptions) *ResultProcessor {
	display := opts.DisplayName
	if display == "" {
		display = opts.OutputFile
	}
	return &ResultProcessor{
		runID:       opts.RunID,
		outputFile:  opts.OutputFile,
		displayName: display,
		outputType:  opts.OutputType,
		sorted:      opts.Sorted,
	}
}

// sort.Interface for ConfigResults
func (cr ConfigResults) Len() int { return len(cr) }
func (cr ConfigResults) Less(i, j int) bool {
	// delay=-1 means failed, so treat it as infinity and sort to the end
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

// TestManager runs configs through the examiner concurrently
type TestManager struct {
	examiner    *Examiner
	logger      *log.Logger // Optional logger for web UI
	threadCount uint16
	verbose     bool
}

// DefaultThreadCount is the concurrency a TestManager uses when asked for 0.
// pond treats 0 as unlimited, which would start one core per config at once.
const DefaultThreadCount = 50

func NewTestManager(examiner *Examiner, threadCount uint16, verbose bool, logger *log.Logger) *TestManager {
	if threadCount == 0 {
		threadCount = DefaultThreadCount
	}
	return &TestManager{
		examiner:    examiner,
		threadCount: threadCount,
		verbose:     verbose,
		logger:      logger,
	}
}

// newResult is the zero verdict ExamineConfig starts from.
func newResult(link string) Result {
	return Result{
		ConfigLink: link,
		Delay:      FailedDelay,
		HTTPCode:   -1,
		RealIPAddr: "null",
		IpAddrLoc:  "null",
	}
}

// RunTests tests multiple configurations concurrently using a worker pool.
// It accepts an optional onProgress callback which is fired after each test.
//
// A config whose test panics is reported as "broken" with the panic message
// instead of aborting the batch. Tests the run cancels before they finish are
// dropped rather than reported as failures.
func (tm *TestManager) RunTests(ctx context.Context, links []string, resultsChan chan<- *Result, onProgress func()) {
	// Each worker parses its own link, as before: nothing is held up front.
	tm.RunParsed(ctx, unparsedLinks(links), resultsChan, onProgress)
}

// RunParsed is RunTests for links already parsed by ParseLinks (and possibly
// deduplicated or prescanned with them). Each link's parsed protocol is
// released once its test finishes; the result keeps its own reference.
func (tm *TestManager) RunParsed(ctx context.Context, links []*ParsedLink, resultsChan chan<- *Result, onProgress func()) {
	pool := pond.NewPool(int(tm.threadCount))
	defer pool.Stop()
	group := pool.NewGroupContext(ctx)

	for _, pl := range links {
		if ctx.Err() != nil {
			break
		}
		linkToTest := pl
		group.Submit(func() {
			defer linkToTest.release()
			if onProgress != nil {
				defer onProgress()
			}
			// Canceled run: skip the expensive examine so the pool drains instead
			// of spinning up a core instance per remaining config.
			if group.Context().Err() != nil {
				return
			}
			res, err := tm.examineSafely(group.Context(), linkToTest)
			if res.Status == StatusCanceled {
				return
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				logMsg := fmt.Sprintf("[-] Error: %s - broken config: %s\n", err.Error(), linkToTest.Link)
				if tm.logger != nil {
					tm.logger.Print(logMsg)
				} else if tm.verbose {
					customlog.Printf(customlog.Failure, "Error: %s - broken config: %s\n", err.Error(), linkToTest.Link)
				}
			}

			if !deliver(group.Context(), resultsChan, &res) {
				return
			}
			if res.Status == StatusPassed && tm.logger != nil {
				logMsg := fmt.Sprintf("[+] SUCCESS | %s | Delay: %dms\n", res.ConfigLink, res.Delay)
				tm.logger.Print(logMsg)
			}
		})
	}

	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		msg := fmt.Sprintf("test pool stopped early: %v", err)
		if tm.logger != nil {
			tm.logger.Print("[-] " + msg + "\n")
		} else {
			customlog.Printf(customlog.Failure, "%s\n", msg)
		}
	}
}

// deliver sends res unless the run is over. A result that finished just as
// the run was canceled is still delivered if the consumer has room, so a
// config that passed is not lost to a coin flip between the two cases.
func deliver(ctx context.Context, resultsChan chan<- *Result, res *Result) bool {
	if ctx.Err() == nil {
		select {
		case resultsChan <- res:
			return true
		case <-ctx.Done():
		}
	}
	if res.Status != StatusPassed && res.Status != StatusSemiPassed {
		return false
	}
	select {
	case resultsChan <- res:
		return true
	default:
		return false
	}
}

// examineSafely runs one test, turning a panic anywhere below (parsers, core
// builders) into a "broken" result for that config alone.
func (tm *TestManager) examineSafely(ctx context.Context, pl *ParsedLink) (res Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			res = newResult(pl.Link)
			res.Status = StatusBroken
			res.Reason = fmt.Sprintf("internal error while testing: %v", p)
			err = errors.New(res.Reason)
		}
	}()
	return tm.examiner.ExamineParsedWithRetries(ctx, pl)
}

// ResultsToDB maps results to the rows of run runID. Canceled results are
// not a verdict on their config and are left out.
func ResultsToDB(runID int64, results []*Result) []database.HttpTestResult {
	rows := make([]database.HttpTestResult, 0, len(results))
	for _, res := range results {
		if res.Status == StatusCanceled {
			continue
		}
		row := database.HttpTestResult{
			RunID:       runID,
			ConfigLink:  res.ConfigLink,
			Status:      res.Status,
			Reason:      sql.NullString{String: res.Reason, Valid: res.Reason != ""},
			FailureKind: sql.NullString{String: res.FailureKind, Valid: res.FailureKind != ""},
			DelayMs:     -1, // Default for non-passed tests
		}
		if res.Status == StatusPassed || res.Status == StatusSemiPassed {
			row.DelayMs = res.Delay
			row.DownloadMbps = float64(res.DownloadSpeed)
			row.UploadMbps = float64(res.UploadSpeed)
			row.IPAddress = sql.NullString{String: res.RealIPAddr, Valid: res.RealIPAddr != "" && res.RealIPAddr != "null"}
			row.IPLocation = sql.NullString{String: res.IpAddrLoc, Valid: res.IpAddrLoc != "" && res.IpAddrLoc != "null"}
			row.TTFBMs = res.TTFB
			row.ConnectTimeMs = res.ConnectTime
		}
		rows = append(rows, row)
	}
	return rows
}

// SaveResults saves to the DB and prints a summary. Callers normally stream file
// output themselves, otherwise this writes the file too.
func (rp *ResultProcessor) SaveResults(results ConfigResults) error {
	passedCount := 0
	for _, res := range results {
		if res.Status == "passed" {
			passedCount++
		}
	}

	// Save to the database if a runID is available.
	if rp.runID > 0 {
		dbResults := ResultsToDB(rp.runID, results)
		if len(dbResults) > 0 {
			if err := database.InsertHttpTestResultsBatch(rp.runID, dbResults); err != nil {
				return fmt.Errorf("failed to save results to database: %w", err)
			}
		}
		customlog.Printf(customlog.Finished, "Test run finished. A total of %d working configs (out of %d) saved to the database.\n", passedCount, len(results))
	} else {
		customlog.Printf(customlog.Finished, "Test run finished. Found %d working configs (out of %d).\n", passedCount, len(results))
	}
	if summary := FailureSummary(results); summary != "" {
		customlog.Printf(customlog.Info, "%s\n", summary)
	}

	if rp.outputFile != "" {
		customlog.Printf(customlog.Finished, "Results have been saved to %s\n", rp.outputFile)
	}

	return nil
}

// RewriteFileSorted overwrites the output file with results sorted by delay.
// The file is replaced atomically, so an interruption leaves the old content.
func (rp *ResultProcessor) RewriteFileSorted(results ConfigResults) {
	if rp.outputFile == "" {
		return
	}
	sorted := make(ConfigResults, len(results))
	copy(sorted, results)
	sort.Sort(sorted)

	var err error
	switch rp.outputType {
	case "csv":
		err = rp.saveCSVResults(sorted)
	case "txt":
		err = rp.saveTxtResults(sorted)
	case "json":
		err = WriteResultsJSON(rp.outputFile, sorted)
	case "jsonl":
		err = rp.saveJSONLResults(sorted)
	}
	if err != nil {
		customlog.Printf(customlog.Failure, "%v\n", err)
	}
}

func (rp *ResultProcessor) saveTxtResults(results ConfigResults) error {
	var validConfigs []string
	for _, v := range results {
		if v.Status == "passed" {
			validConfigs = append(validConfigs, v.ConfigLink)
		}
	}

	content := strings.Join(validConfigs, "\n\n")
	if err := WriteFileAtomic(rp.outputFile, []byte(content)); err != nil {
		return fmt.Errorf("failed to save TXT results: %w", err)
	}

	customlog.Printf(customlog.Finished, "%d working configurations have also been saved to %s\n",
		len(validConfigs), rp.displayName)
	return nil
}

func (rp *ResultProcessor) saveCSVResults(results ConfigResults) error {
	// Rewriting sorted must not reshape the file. The streaming writer may have
	// appended to a history file that predates the RTT columns.
	header, rows, _, err := resultCSVRecords(rp.outputFile, results)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	w := csv.NewWriter(&out)
	if header != nil {
		_ = w.Write(header)
		_ = w.WriteAll(rows)
	}
	if err := w.Error(); err != nil {
		return fmt.Errorf("failed to marshal CSV: %w", err)
	}

	if err := WriteFileAtomic(rp.outputFile, out.Bytes()); err != nil {
		return fmt.Errorf("failed to save CSV results: %w", err)
	}

	customlog.Printf(customlog.Finished, "Full test results for %d configurations have also been saved to %s\n",
		len(results), rp.displayName)
	return nil
}

func (rp *ResultProcessor) saveJSONLResults(results ConfigResults) error {
	var out bytes.Buffer
	if err := encodeJSONL(&out, results); err != nil {
		return err
	}
	if err := WriteFileAtomic(rp.outputFile, out.Bytes()); err != nil {
		return fmt.Errorf("failed to save JSONL results: %w", err)
	}
	customlog.Printf(customlog.Finished, "Full test results for %d configurations have also been saved to %s\n",
		len(results), rp.displayName)
	return nil
}

// WriteResultsJSON writes results as one indented JSON array, atomically.
func WriteResultsJSON(filePath string, results []*Result) error {
	if results == nil {
		results = []*Result{}
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results to JSON: %w", err)
	}
	if err := WriteFileAtomic(filePath, append(data, '\n')); err != nil {
		return fmt.Errorf("failed to save JSON results: %w", err)
	}
	return nil
}

// AppendResultsToJSONL appends one JSON object per result.
func AppendResultsToJSONL(filePath string, batch []*Result) error {
	if len(batch) == 0 {
		return nil
	}
	var out bytes.Buffer
	if err := encodeJSONL(&out, batch); err != nil {
		return err
	}
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %w", err)
	}
	if _, err := file.Write(out.Bytes()); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func encodeJSONL(w io.Writer, results []*Result) error {
	enc := json.NewEncoder(w)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("failed to marshal result to JSON: %w", err)
		}
	}
	return nil
}

// WriteFileAtomic replaces path with data via a temp file and rename, so a
// crash or Ctrl-C mid-write never leaves a truncated file. "-" writes stdout.
func WriteFileAtomic(path string, data []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	mode := os.FileMode(0644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	_ = os.Chmod(tmpName, mode)
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// DeduplicateLinks strips duplicates from links, returning the unique list and how many were removed.
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

// SemanticDeduplicateLinks keeps the first link for each connection fingerprint.
// Unparseable links use exact text so the tester can still report them.
// Callers that go on to test the links should use ParseLinks and
// SemanticDeduplicateParsed instead, which parse each link only once.
func SemanticDeduplicateLinks(c core.Core, links []string) ([]string, int) {
	unique, removed := SemanticDeduplicateParsed(ParseLinks(c, links))
	return LinksOf(unique), removed
}

// optionalCSVColumns came after the first released result schema (RTT
// sampling, then the trace colo/warp fields, then failure_kind). A file written without some of
// them stays readable and appendable in its own shape.
var optionalCSVColumns = []string{"rtt_min", "rtt_avg", "rtt_max", "jitter", "rtt_samples", "colo", "warp", "failure_kind"}

// AppendResultsToCSV appends a batch, writing the header only for a new file.
// An existing file keeps its own schema. An unrecognized header is rejected.
func AppendResultsToCSV(filePath string, batch []*Result) error {
	header, rows, onDisk, err := resultCSVRecords(filePath, batch)
	if err != nil {
		return err
	}
	if header == nil {
		return nil
	}

	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %w", err)
	}
	defer file.Close()

	bufWriter := bufio.NewWriter(file)
	csvWriter := csv.NewWriter(bufWriter)
	if !onDisk {
		if err := csvWriter.Write(header); err != nil {
			return fmt.Errorf("failed to write the CSV header: %w", err)
		}
	}
	if err := csvWriter.WriteAll(rows); err != nil {
		return fmt.Errorf("failed to append results to CSV: %w", err)
	}
	return bufWriter.Flush()
}

// resultCSVRecords marshals a batch into the schema filePath already uses.
// onDisk reports whether the file already carries the returned header.
func resultCSVRecords(filePath string, batch []*Result) (header []string, rows [][]string, onDisk bool, err error) {
	out, err := gocsv.MarshalString(&batch)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to marshal results to CSV: %w", err)
	}
	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to re-read marshalled results: %w", err)
	}
	if len(records) == 0 {
		return nil, nil, false, nil
	}
	header, rows = records[0], records[1:]

	existing, err := readCSVHeader(filePath)
	if err != nil {
		return nil, nil, false, err
	}
	if existing == nil {
		return header, rows, false, nil
	}
	if rows, err = projectCSVRows(header, existing, rows); err != nil {
		return nil, nil, false, fmt.Errorf("%s: %w", filePath, err)
	}
	return existing, rows, true, nil
}

// readCSVHeader returns an existing file's header, or nil when there is none.
func readCSVHeader(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer file.Close()

	header, err := csv.NewReader(file).Read()
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read the CSV header of %s: %w", filePath, err)
	}
	return header, nil
}

// projectCSVRows reshapes marshalled rows to the header a file already uses:
// the current schema minus any of the later optional columns, in order.
func projectCSVRows(header, existing []string, rows [][]string) ([][]string, error) {
	if slices.Equal(header, existing) {
		return rows, nil
	}
	present := make(map[string]bool, len(existing))
	for _, name := range existing {
		present[name] = true
	}
	kept := make([]string, 0, len(header))
	for _, name := range header {
		switch {
		case present[name]:
			kept = append(kept, name)
		case !slices.Contains(optionalCSVColumns, name):
			kept = nil // a required column is missing: not one of our schemas
		}
		if kept == nil {
			break
		}
	}
	if !slices.Equal(existing, kept) {
		return nil, fmt.Errorf("CSV header %q does not match this version's result columns; write to a new file or remove it",
			strings.Join(existing, ","))
	}

	column := make(map[string]int, len(header))
	for i, name := range header {
		column[name] = i
	}
	projected := make([][]string, len(rows))
	for i, row := range rows {
		out := make([]string, len(existing))
		for j, name := range existing {
			out[j] = row[column[name]]
		}
		projected[i] = out
	}
	return projected, nil
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
