package scanner

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
	"github.com/lilendian0x00/xray-knife/v11/pkg/netbind"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// ScannerConfig holds all configuration for a scan.
type ScannerConfig struct {
	Subnets              []string `json:"subnets"`
	ThreadCount          int      `json:"threadCount"`
	ShuffleIPs           bool     `json:"shuffleIPs"`
	ShuffleSubnets       bool     `json:"shuffleSubnets"`
	DoSpeedtest          bool     `json:"doSpeedtest"`
	RequestTimeout       int      `json:"timeout"`
	ShowTraceBody        bool     `json:"showTraceBody"`
	Verbose              bool     `json:"verbose"`
	OutputFile           string   `json:"outputFile"`
	RetryCount           int      `json:"retry"`
	OnlySpeedtestResults bool     `json:"onlySpeedtestResults"`
	DownloadMB           int      `json:"downloadMB"`
	UploadMB             int      `json:"uploadMB"`
	SpeedtestTop         int      `json:"speedtestTop"`
	SpeedtestConcurrency int      `json:"speedtestConcurrency"`
	// SpeedtestTimeout is the measurement window, in seconds, for each
	// direction of one IP's speed test.
	SpeedtestTimeout int    `json:"speedtestTimeout"`
	ConfigLink       string `json:"configLink"`
	InsecureTLS      bool   `json:"insecureTLS"`
	Resume           bool   `json:"resume"`
	SaveToDB         bool   `json:"saveToDB"`
	// Port is the TCP port to probe on each scanned IP. Defaults to 443
	// when zero. Cloudflare's edge accepts TLS on alternate ports
	// (2053, 2083, 2087, 2096, 8443) which is useful when 443 is blocked.
	Port int `json:"port"`
	// BindInterface pins outbound dials (both raw and core-based) to a
	// specific OS interface. Empty disables binding.
	BindInterface string `json:"bindInterface,omitempty"`

	// SamplePerSubnet tests this many random IPs from every /24 (IPv4) or
	// /48 (IPv6) block instead of every address. 0 scans everything.
	SamplePerSubnet int `json:"samplePerSubnet,omitempty"`
	// MaxIPs caps the addresses one scan visits: 0 means DefaultMaxIPs,
	// negative means no cap.
	MaxIPs int `json:"maxIPs,omitempty"`
	// SpeedtestURL overrides speed.cloudflare.com (see pkg/http.NewSpeedTester).
	SpeedtestURL string `json:"speedtestURL,omitempty"`
	// Fragment (or its string form FragmentSpec) splits the TLS handshake of
	// ConfigLink's first hop. Ignored without a ConfigLink.
	Fragment     *fragment.Options `json:"fragment,omitempty"`
	FragmentSpec string            `json:"fragmentSpec,omitempty"`
	// OutputFormat is the OutputFile format: "csv" (default), "json" or "jsonl".
	OutputFormat string `json:"outputFormat,omitempty"`
	// CheckpointInterval is how often partial results are flushed to
	// OutputFile while scanning; zero uses 30s.
	CheckpointInterval time.Duration `json:"-"`

	OnIPScannedCallback func() `json:"-"` // Instance-scoped callback for progress reporting
}

// scanPort returns the configured port, falling back to 443.
func (c *ScannerConfig) scanPort() int {
	if c.Port <= 0 || c.Port > 65535 {
		return 443
	}
	return c.Port
}

// MaxSamplePerSubnet bounds SamplePerSubnet: more than this per /24 or /48
// is no longer sampling.
const MaxSamplePerSubnet = 65536

// Defaults applied by NewScannerService to zero-valued fields.
const (
	defaultRequestTimeoutMS     = 5000
	defaultSpeedtestTop         = 10
	defaultSpeedtestConcurrency = 4
	defaultSpeedtestTimeoutSec  = 30
	defaultCheckpointInterval   = 30 * time.Second
)

// validate normalizes defaults and rejects values that would misbehave
// (pond treats 0 workers as unlimited and panics on negative ones).
func (c *ScannerConfig) validate() error {
	if c.ThreadCount < 1 {
		return fmt.Errorf("thread count must be at least 1, got %d", c.ThreadCount)
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = defaultRequestTimeoutMS
	}
	if c.RetryCount < 0 {
		return fmt.Errorf("retry count must not be negative, got %d", c.RetryCount)
	}
	if c.Port < 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d, must be 1..65535", c.Port)
	}
	if c.SamplePerSubnet < 0 || c.SamplePerSubnet > MaxSamplePerSubnet {
		return fmt.Errorf("sample per subnet must be between 0 and %d, got %d", MaxSamplePerSubnet, c.SamplePerSubnet)
	}
	if c.Resume && c.OutputFile == "-" && !c.SaveToDB {
		return errors.New("cannot resume from stdout: write results to a file (or use the database) to resume")
	}
	switch strings.ToLower(c.OutputFormat) {
	case "", "csv":
		c.OutputFormat = "csv"
	case "json", "jsonl":
		c.OutputFormat = strings.ToLower(c.OutputFormat)
	default:
		return fmt.Errorf("unknown output format %q (csv, json, jsonl)", c.OutputFormat)
	}
	if c.CheckpointInterval <= 0 {
		c.CheckpointInterval = defaultCheckpointInterval
	}
	if !c.DoSpeedtest {
		return nil
	}
	if c.SpeedtestTop < 0 || c.SpeedtestConcurrency < 0 || c.DownloadMB < 0 || c.UploadMB < 0 || c.SpeedtestTimeout < 0 {
		return errors.New("speed test settings must not be negative")
	}
	if c.SpeedtestTop == 0 {
		c.SpeedtestTop = defaultSpeedtestTop
	}
	if c.SpeedtestConcurrency == 0 {
		c.SpeedtestConcurrency = defaultSpeedtestConcurrency
	}
	if c.SpeedtestTimeout == 0 {
		c.SpeedtestTimeout = defaultSpeedtestTimeoutSec
	}
	if c.DownloadMB == 0 && c.UploadMB == 0 {
		return errors.New("speed test needs a download or upload amount")
	}
	return nil
}

// ScannerService is the main engine for scanning.
type ScannerService struct {
	config      ScannerConfig
	logger      *log.Logger
	core        core.Core         // nil without a ConfigLink
	baseProto   protocol.Protocol // ConfigLink parsed once; each scanned IP gets a copy
	plan        *ipPlan
	speedTester *pkghttp.SpeedTester
	binder      *netbind.Binder // nil when not configured
	scannedIPs  map[string]bool // resumed IPs, skipped by the latency phase
	resumed     int

	// results holds the canonical record per IP (resumed and new). Workers
	// update entries under mu and hand out copies, so no consumer ever
	// shares memory with a record that is still changing.
	mu      sync.Mutex
	results map[string]*ScanResult
	dirty   bool

	// Checkpoints are written off the writer goroutine; at most one runs.
	checkpointing atomic.Bool
	checkpointWG  sync.WaitGroup

	// Test seams: nil uses the real network measurements.
	latencyFn func(ctx context.Context, ip string) *ScanResult
	speedFn   func(ctx context.Context, ip string) (down, up float64, err error)
}

// notifyIPScanned calls the instance callback if set, otherwise falls back to the global.
func (s *ScannerService) notifyIPScanned() {
	if s.config.OnIPScannedCallback != nil {
		s.config.OnIPScannedCallback()
	} else if OnIPScanned != nil {
		OnIPScanned()
	}
}

// ScanResult holds the outcome for a single scanned IP. Error is the latency
// verdict; SpeedErr only says the speed test (run on IPs that passed) failed.
type ScanResult struct {
	IP          string        `csv:"ip" json:"ip"`
	Latency     time.Duration `csv:"-" json:"-"`
	LatencyMS   int64         `csv:"latency_ms" json:"latency_ms"`
	DownSpeed   float64       `csv:"download_mbps" json:"download_mbps"`
	UpSpeed     float64       `csv:"upload_mbps" json:"upload_mbps"`
	Colo        string        `csv:"colo" json:"colo,omitempty"` // Cloudflare data center, from the trace
	Error       error         `csv:"-" json:"-"`
	ErrorStr    string        `csv:"error,omitempty" json:"error,omitempty"`
	SpeedErr    error         `csv:"-" json:"-"`
	SpeedErrStr string        `csv:"speed_error,omitempty" json:"speed_error,omitempty"`
}

// PrepareForMarshal populates the marshal-friendly fields before serialization.
// Call it on a copy handed out by the scanner, never on a shared record.
func (r *ScanResult) PrepareForMarshal() {
	r.LatencyMS = r.Latency.Milliseconds()
	r.ErrorStr = ""
	if r.Error != nil {
		r.ErrorStr = r.Error.Error()
	}
	r.SpeedErrStr = ""
	if r.SpeedErr != nil {
		r.SpeedErrStr = r.SpeedErr.Error()
	}
}

// HasSpeed reports whether a speed test moved data in either direction.
func (r *ScanResult) HasSpeed() bool { return r.DownSpeed > 0 || r.UpSpeed > 0 }

// snapshot returns a marshal-ready copy of r.
func (r *ScanResult) snapshot() *ScanResult {
	c := *r
	c.PrepareForMarshal()
	return &c
}

// NewScannerService builds a scanner service from the given config, resuming previous results if asked.
func NewScannerService(config ScannerConfig, logger *log.Logger) (*ScannerService, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("cfscanner: %w", err)
	}
	prefixes, err := ParsePrefixes(config.Subnets)
	if err != nil {
		return nil, fmt.Errorf("cfscanner: %w", err)
	}
	binder, err := netbind.New(config.BindInterface)
	if err != nil {
		return nil, fmt.Errorf("cfscanner: %w", err)
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	if config.ShuffleSubnets {
		rand.Shuffle(len(prefixes), func(i, j int) { prefixes[i], prefixes[j] = prefixes[j], prefixes[i] })
	}
	maxIPs := uint64(DefaultMaxIPs)
	switch {
	case config.MaxIPs > 0:
		maxIPs = uint64(config.MaxIPs)
	case config.MaxIPs < 0:
		maxIPs = 0
	}
	s := &ScannerService{
		config:     config,
		logger:     logger,
		scannedIPs: make(map[string]bool),
		results:    make(map[string]*ScanResult),
		binder:     binder,
		plan: &ipPlan{
			prefixes: prefixes,
			sample:   config.SamplePerSubnet,
			shuffle:  config.ShuffleIPs,
			maxIPs:   maxIPs,
			rng:      rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
		},
		speedTester: pkghttp.DefaultSpeedTester(),
	}
	if p, bad := s.plan.unboundedIPv6(); bad {
		return nil, fmt.Errorf("cfscanner: IPv6 prefix %s is too large to scan every address with no --max-ips cap; use --sample-per-subnet N or set a cap", p)
	}
	if config.SpeedtestURL != "" {
		if s.speedTester, err = pkghttp.NewSpeedTester(config.SpeedtestURL); err != nil {
			return nil, fmt.Errorf("cfscanner: %w", err)
		}
	}

	if s.config.ConfigLink != "" {
		if err := s.setupConfigCore(); err != nil {
			return nil, fmt.Errorf("cfscanner: %w", err)
		}
	}

	if s.config.Resume {
		s.resume()
	}
	return s, nil
}

// setupConfigCore builds the core used to reach each IP through ConfigLink
// and checks the link once up front instead of failing on every IP.
func (s *ScannerService) setupConfigCore() error {
	link := strings.TrimSpace(s.config.ConfigLink)
	frag := s.config.Fragment.Clone()
	if frag == nil && strings.TrimSpace(s.config.FragmentSpec) != "" {
		var err error
		if frag, err = fragment.Parse(s.config.FragmentSpec); err != nil {
			return err
		}
	}
	if err := frag.Validate(); err != nil {
		return err
	}
	s.core = core.NewAutomaticCoreWith(core.FactoryOptions{
		InsecureTLS:   s.config.InsecureTLS,
		Verbose:       s.config.Verbose,
		BindInterface: s.config.BindInterface,
		Fragment:      frag,
	})
	proto, err := core.CreateRelayProtocol(s.core, link)
	if errors.Is(err, mtproto.ErrNotProxyable) {
		return errors.New("unsupported protocol scheme for the scanner: MTProto proxies only relay Telegram traffic")
	}
	if err != nil {
		return fmt.Errorf("unsupported config link: %w", err)
	}
	if err := proto.Parse(); err != nil {
		return fmt.Errorf("failed to parse config link: %w", err)
	}
	if _, err := copyProtocol(proto); err != nil {
		return fmt.Errorf("unsupported config link: %w", err)
	}
	s.baseProto = proto
	return nil
}

// copyProtocol returns a shallow copy of a parsed protocol, so each scanned
// IP gets its own address without parsing the link again. Only string
// fields are changed on the copy (setAddress); the reference fields it
// shares with the original are read-only after Parse.
func copyProtocol(p protocol.Protocol) (protocol.Protocol, error) {
	v := reflect.ValueOf(p)
	if v.Kind() != reflect.Ptr || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("cannot copy protocol %T", p)
	}
	c := reflect.New(v.Elem().Type())
	c.Elem().Set(v.Elem())
	return c.Interface().(protocol.Protocol), nil
}

// resume loads earlier results so their IPs are not scanned again.
func (s *ScannerService) resume() {
	var loaded []*ScanResult
	if s.config.SaveToDB {
		dbResults, err := database.GetCfScanResults()
		if err != nil {
			s.logger.Printf("Could not resume from database: %v. Starting fresh.", err)
			return
		}
		for _, dbRes := range dbResults {
			res := &ScanResult{
				IP:        dbRes.IP,
				Latency:   time.Duration(dbRes.LatencyMs.Int64) * time.Millisecond,
				DownSpeed: dbRes.DownloadMbps.Float64,
				UpSpeed:   dbRes.UploadMbps.Float64,
			}
			if dbRes.Error.Valid && dbRes.Error.String != "" {
				res.Error = errors.New(dbRes.Error.String)
			}
			loaded = append(loaded, res)
		}
	} else {
		var err error
		loaded, err = LoadResults(s.config.OutputFile)
		if err != nil {
			s.logger.Printf("Could not resume from file %s: %v. Starting fresh.", s.config.OutputFile, err)
			return
		}
	}
	for _, res := range loaded {
		s.scannedIPs[res.IP] = true
		s.results[res.IP] = res
	}
	s.resumed = len(loaded)
	if s.resumed > 0 {
		s.logger.Printf("Resumed %d results.", s.resumed)
	}
}

// PlannedIPs is how many addresses the latency phase will visit, including
// resumed ones it skips (saturated at the maximum int).
func (s *ScannerService) PlannedIPs() int {
	total := s.plan.Total()
	if total > uint64(int(^uint(0)>>1)) {
		return int(^uint(0) >> 1)
	}
	return int(total)
}

// Results returns a copy of every result (resumed and new), sorted best first.
func (s *ScannerService) Results() []*ScanResult {
	s.mu.Lock()
	out := make([]*ScanResult, 0, len(s.results))
	for _, r := range s.results {
		out = append(out, r.snapshot())
	}
	s.mu.Unlock()
	SortResults(out, s.config.DoSpeedtest)
	return out
}

// record stores res as the canonical result for its IP and returns a copy
// for consumers.
func (s *ScannerService) record(res *ScanResult) *ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[res.IP] = res
	s.dirty = true
	return res.snapshot()
}

// Run scans all IPs, sending results to progressChan. Blocks until done or
// ctx is canceled. Results are checkpointed to OutputFile while scanning and
// saved once more at the end, including when ctx is canceled; in that case
// Run returns ctx.Err() after saving.
func (s *ScannerService) Run(ctx context.Context, progressChan chan<- *ScanResult) error {
	defer close(progressChan)

	if s.plan.Capped() {
		s.logger.Printf("Scan capped at %d IPs; use --sample-per-subnet to spread tests or --max-ips to change the cap.", s.plan.Total())
	}

	// Workers send copies here; the writer persists and forwards them. The
	// writer runs until the channel closes (never on ctx.Done), so nothing
	// a worker finished is lost to a cancellation race.
	updates := make(chan *ScanResult, s.config.ThreadCount*2)
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		s.writer(updates, progressChan)
	}()

	latencyErr := s.runLatencyScan(ctx, updates)
	switch {
	case latencyErr == nil:
		s.logger.Println("Latency scan phase finished.")
	case errors.Is(latencyErr, context.Canceled) || errors.Is(latencyErr, context.DeadlineExceeded):
		s.logger.Println("Latency scan cancelled.")
	default:
		s.logger.Printf("Latency scan failed: %v", latencyErr)
	}

	if s.config.DoSpeedtest && ctx.Err() == nil {
		if err := s.runSpeedTest(ctx, updates); err != nil && ctx.Err() == nil {
			s.logger.Printf("Speed test failed: %v", err)
		} else if ctx.Err() != nil {
			s.logger.Println("Speed test cancelled.")
		} else {
			s.logger.Println("Speed test phase finished.")
		}
	}

	close(updates)
	writerWg.Wait()

	if err := s.saveOutput(); err != nil {
		s.logger.Printf("Error saving final results: %v", err)
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if latencyErr != nil {
		return latencyErr
	}
	s.logger.Println("Scan process completed.")
	return nil
}

// writer persists updates to the DB in batches, checkpoints the output file,
// and forwards every update to the consumer.
func (s *ScannerService) writer(updates <-chan *ScanResult, progressChan chan<- *ScanResult) {
	batch := make([]*ScanResult, 0, saveBatchSize)
	dbTicker := time.NewTicker(saveInterval)
	defer dbTicker.Stop()
	checkpoint := time.NewTimer(s.checkpointInterval())
	defer checkpoint.Stop()

	saveToDB := func() {
		if !s.config.SaveToDB || len(batch) == 0 {
			return
		}
		dbBatch := make([]database.CfScanResult, 0, len(batch))
		for _, res := range batch {
			dbRes := database.CfScanResult{
				IP:    res.IP,
				Error: sql.NullString{String: res.ErrorStr, Valid: res.ErrorStr != ""},
			}
			if res.Error == nil {
				dbRes.LatencyMs = sql.NullInt64{Int64: res.LatencyMS, Valid: true}
				if res.DownSpeed > 0 {
					dbRes.DownloadMbps = sql.NullFloat64{Float64: res.DownSpeed, Valid: true}
				}
				if res.UpSpeed > 0 {
					dbRes.UploadMbps = sql.NullFloat64{Float64: res.UpSpeed, Valid: true}
				}
			}
			dbBatch = append(dbBatch, dbRes)
		}
		if err := database.UpsertCfScanResultsBatch(dbBatch); err != nil {
			s.logger.Printf("Real-time DB save failed: %v", err)
		}
		batch = make([]*ScanResult, 0, saveBatchSize)
	}

	for {
		select {
		case res, ok := <-updates:
			if !ok {
				saveToDB()
				return
			}
			batch = append(batch, res)
			if len(batch) >= saveBatchSize {
				saveToDB()
			}
			progressChan <- res
		case <-dbTicker.C:
			saveToDB()
		case <-checkpoint.C:
			_ = s.checkpoint()
			checkpoint.Reset(s.checkpointInterval())
		}
	}
}

// checkpointInterval grows with the result count: a checkpoint rewrites every
// result, so a million-IP scan should not spend its time re-serializing.
func (s *ScannerService) checkpointInterval() time.Duration {
	s.mu.Lock()
	n := len(s.results)
	s.mu.Unlock()
	d := s.config.CheckpointInterval * time.Duration(1+n/250_000)
	return min(d, 10*time.Minute)
}

// checkpoint starts writing the results to the output file in the background
// if anything changed, unless the previous checkpoint is still being written.
// Only the copy happens under the lock; sorting and serializing do not hold
// up the workers. Stdout gets the results once, at the end, not per checkpoint.
func (s *ScannerService) checkpoint() error {
	if s.config.OutputFile == "" || s.config.OutputFile == "-" {
		return nil
	}
	if !s.checkpointing.CompareAndSwap(false, true) {
		return nil
	}
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		s.checkpointing.Store(false)
		return nil
	}
	snap := make([]*ScanResult, 0, len(s.results))
	for _, r := range s.results {
		c := *r
		snap = append(snap, &c)
	}
	s.dirty = false
	s.mu.Unlock()

	s.checkpointWG.Add(1)
	go func() {
		defer s.checkpointWG.Done()
		defer s.checkpointing.Store(false)
		SortResults(snap, s.config.DoSpeedtest)
		if err := SaveResults(s.config.OutputFile, s.config.OutputFormat, snap); err != nil {
			if s.logger != nil {
				s.logger.Printf("Checkpoint save failed: %v", err)
			}
			s.mu.Lock()
			s.dirty = true
			s.mu.Unlock()
		}
	}()
	return nil
}

// saveOutput writes every result to OutputFile (atomically for files), after
// any checkpoint still in flight, so the final write is the one that stays.
func (s *ScannerService) saveOutput() error {
	s.checkpointWG.Wait()
	if s.config.OutputFile == "" {
		return nil
	}
	results := s.Results()
	s.mu.Lock()
	s.dirty = false
	s.mu.Unlock()
	if len(results) == 0 {
		return nil // don't create (or wipe a previous file with) an empty one
	}
	return SaveResults(s.config.OutputFile, s.config.OutputFormat, results)
}

// OnIPScanned is a deprecated global hook for progress reporting.
// Prefer using ScannerConfig.OnIPScannedCallback instead.
var OnIPScanned func()

func (s *ScannerService) runLatencyScan(ctx context.Context, updates chan<- *ScanResult) error {
	s.logger.Printf("Phase 1: Scanning for latency with %d threads...", s.config.ThreadCount)
	// A bounded queue: the planner blocks instead of materializing millions
	// of pending tasks.
	pool := pond.NewPool(s.config.ThreadCount, pond.WithQueueSize(s.config.ThreadCount*2))
	defer pool.Stop()
	group := pool.NewGroupContext(ctx)
	gctx := group.Context()

	visited := 0
	planErr := s.plan.Each(gctx, func(addr netip.Addr) bool {
		visited++
		ip := addr.String()
		if s.scannedIPs[ip] {
			s.notifyIPScanned()
			return true
		}
		group.Submit(func() {
			defer s.notifyIPScanned()
			if gctx.Err() != nil {
				return
			}
			res := s.scanLatencySafely(gctx, ip)
			// A probe killed by cancellation says nothing about the IP. Not
			// recording it keeps --resume from skipping an untested address.
			if res.Error != nil && gctx.Err() != nil {
				return
			}
			updates <- s.record(res)
		})
		return true
	})
	waitErr := group.Wait()

	if visited == 0 && s.resumed == 0 {
		return errors.New("scanner failed: no scannable IPs detected")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if planErr != nil {
		return planErr
	}
	return waitErr
}

// scanLatencySafely confines a panic to the IP that caused it.
func (s *ScannerService) scanLatencySafely(ctx context.Context, ip string) (res *ScanResult) {
	defer func() {
		if p := recover(); p != nil {
			res = &ScanResult{IP: ip, Error: fmt.Errorf("internal error while scanning: %v", p)}
		}
	}()
	if s.latencyFn != nil {
		return s.latencyFn(ctx, ip)
	}
	return s.scanIPForLatency(ctx, ip)
}

// speedCandidates returns the fastest-latency IPs (resumed ones included)
// that still lack speed data, at most SpeedtestTop of them.
func (s *ScannerService) speedCandidates() []*ScanResult {
	s.mu.Lock()
	var ok []*ScanResult
	for _, r := range s.results {
		if r.Error == nil {
			ok = append(ok, r)
		}
	}
	s.mu.Unlock()
	sort.Slice(ok, func(i, j int) bool {
		if ok[i].Latency != ok[j].Latency {
			return ok[i].Latency < ok[j].Latency
		}
		return ok[i].IP < ok[j].IP
	})
	if len(ok) > s.config.SpeedtestTop {
		ok = ok[:s.config.SpeedtestTop]
	}
	out := ok[:0]
	for _, r := range ok {
		s.mu.Lock()
		tested := r.HasSpeed() || r.SpeedErr != nil
		s.mu.Unlock()
		if !tested {
			out = append(out, r)
		}
	}
	return out
}

func (s *ScannerService) runSpeedTest(ctx context.Context, updates chan<- *ScanResult) error {
	candidates := s.speedCandidates()
	if len(candidates) == 0 {
		s.logger.Println("No successful latency results to speed test.")
		return nil
	}
	s.logger.Printf("Phase 2: Performing speed tests on the top %d IPs (with %d concurrent tests, %ds window per direction)...",
		len(candidates), s.config.SpeedtestConcurrency, s.config.SpeedtestTimeout)

	speedTestPool := pond.NewPool(s.config.SpeedtestConcurrency)
	defer speedTestPool.Stop()
	group := speedTestPool.NewGroupContext(ctx)
	gctx := group.Context()

	for _, candidate := range candidates {
		ip := candidate.IP
		group.Submit(func() {
			down, up, err := s.measureSpeedSafely(gctx, ip)
			if gctx.Err() != nil && down == 0 && up == 0 {
				return // canceled before anything was measured
			}
			s.mu.Lock()
			res := s.results[ip]
			res.DownSpeed, res.UpSpeed, res.SpeedErr = down, up, err
			s.dirty = true
			snap := res.snapshot()
			s.mu.Unlock()
			updates <- snap
		})
	}
	return group.Wait()
}

func (s *ScannerService) measureSpeedSafely(ctx context.Context, ip string) (down, up float64, err error) {
	defer func() {
		if p := recover(); p != nil {
			down, up, err = 0, 0, fmt.Errorf("internal error during speed test: %v", p)
		}
	}()
	if s.speedFn != nil {
		return s.speedFn(ctx, ip)
	}
	return s.measureSpeed(ctx, ip)
}

// dialStats accumulates time a dial spent on failed attempts and retry
// pauses, which is subtracted from the measured latency.
type dialStats struct {
	mu     sync.Mutex
	wasted time.Duration
}

func (d *dialStats) add(t time.Duration) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.wasted += t
	d.mu.Unlock()
}

func (d *dialStats) get() time.Duration {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.wasted
}

// createDialerWithRetry dials ip (ignoring the requested address) with up to
// retries extra attempts. Each attempt gets a share of the request timeout,
// so a retry can still fit after a timeout, and the pause between attempts
// honours ctx.
func (s *ScannerService) createDialerWithRetry(ip string, retries int, stats *dialStats) func(ctx context.Context, network, addr string) (net.Conn, error) {
	port := s.config.scanPort()
	perAttempt := time.Duration(s.config.RequestTimeout) * time.Millisecond / time.Duration(retries+1)
	if perAttempt < 500*time.Millisecond {
		perAttempt = 500 * time.Millisecond
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: perAttempt}
		s.binder.ApplyDialer(dialer)
		targetAddr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		var lastErr error

		for i := 0; i <= retries; i++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if s.config.Verbose && i > 0 {
				s.logger.Printf("Retrying connection to %s (attempt %d/%d)...", targetAddr, i+1, retries+1)
			}
			attemptStart := time.Now()
			conn, err := dialer.DialContext(ctx, network, targetAddr)
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if i < retries {
				pause := time.NewTimer(200 * time.Millisecond)
				select {
				case <-ctx.Done():
					pause.Stop()
					return nil, ctx.Err()
				case <-pause.C:
				}
			}
			stats.add(time.Since(attemptStart))
		}
		return nil, fmt.Errorf("all %d connection attempts to %s failed, last error: %w", retries+1, targetAddr, lastErr)
	}
}

// directClient reaches Cloudflare hosts through ip with a Chrome TLS
// fingerprint. timeout 0 leaves the request bounded by its context only.
func (s *ScannerService) directClient(ip string, timeout time.Duration, stats *dialStats) *http.Client {
	transport := NewBypassJA3Transport(utls.HelloChrome_Auto)
	transport.DialContext = s.createDialerWithRetry(ip, s.config.RetryCount, stats)
	return &http.Client{Transport: transport, Timeout: timeout}
}

func (s *ScannerService) scanIPForLatency(ctx context.Context, ip string) *ScanResult {
	result := &ScanResult{IP: ip}
	var client *http.Client
	stats := &dialStats{}

	req, err := http.NewRequestWithContext(ctx, "GET", cloudflareTraceURL, nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to create request: %w", err)
		return result
	}
	req.Header.Set("User-Agent", userAgent)

	if s.config.ConfigLink != "" {
		var instance protocol.Instance
		client, instance, err = s.createClientFromConfig(ctx, ip, time.Duration(s.config.RequestTimeout)*time.Millisecond)
		if err != nil {
			result.Error = fmt.Errorf("failed creating client from config for latency test: %w", err)
			return result
		}
		defer instance.Close()
	} else {
		client = s.directClient(ip, time.Duration(s.config.RequestTimeout)*time.Millisecond, stats)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Errorf("latency test failed: %w", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = fmt.Errorf("bad status code: %d", resp.StatusCode)
		return result
	}

	// Read the body to properly account for the whole request time.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if readErr != nil {
		result.Error = fmt.Errorf("failed to read body: %w", readErr)
		return result
	}
	// Failed dial attempts and retry pauses are not the IP's latency.
	result.Latency = max(time.Since(start)-stats.get(), 0)
	result.Colo = traceField(body, "colo")

	if s.config.ShowTraceBody {
		s.logger.Printf("Trace body for %s:\n%s", ip, string(body))
	}

	return result
}

// traceField extracts key=value from a /cdn-cgi/trace body.
func traceField(body []byte, key string) string {
	for line := range bytes.SplitSeq(body, []byte("\n")) {
		if k, v, ok := bytes.Cut(bytes.TrimSpace(line), []byte("=")); ok && string(k) == key {
			return string(v)
		}
	}
	return ""
}

// measureSpeed runs the download then the upload test against ip, each in
// its own SpeedtestTimeout window, with pkg/http's semantics: timing starts
// once data flows (dial and TLS are excluded) and a transfer cut short by
// the window is measured on what moved, not reported as a failure.
func (s *ScannerService) measureSpeed(ctx context.Context, ip string) (downSpeed, upSpeed float64, err error) {
	window := time.Duration(s.config.SpeedtestTimeout) * time.Second
	var client *http.Client

	if s.config.ConfigLink != "" {
		c, instance, err := s.createClientFromConfig(ctx, ip, window)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to create speedtest client from config: %w", err)
		}
		defer instance.Close()
		// The core's client carries a latency-sized Timeout; the window is
		// enforced per direction by the measurement instead.
		client = &http.Client{Transport: c.Transport}
	} else {
		client = s.directClient(ip, 0, nil)
	}

	var errs []string
	if s.config.DownloadMB > 0 {
		d, derr := pkghttp.MeasureDownload(ctx, client, s.speedTester, window, uint64(s.config.DownloadMB)*1_000_000)
		if derr != nil {
			errs = append(errs, "download: "+derr.Error())
		}
		downSpeed = float64(d)
	}
	if s.config.UploadMB > 0 && ctx.Err() == nil {
		if !s.speedTester.CanUpload() {
			errs = append(errs, "upload: skipped for a plain download URL")
		} else {
			u, uerr := pkghttp.MeasureUpload(ctx, client, s.speedTester, window, uint64(s.config.UploadMB)*1_000_000)
			if uerr != nil {
				errs = append(errs, "upload: "+uerr.Error())
			}
			upSpeed = float64(u)
		}
	}
	if len(errs) > 0 {
		err = errors.New(strings.Join(errs, "; "))
	}
	return downSpeed, upSpeed, err
}

func (s *ScannerService) createClientFromConfig(ctx context.Context, ip string, timeout time.Duration) (*http.Client, protocol.Instance, error) {
	if s.core == nil || s.baseProto == nil {
		return nil, nil, errors.New("scanner has no config link")
	}
	proto, err := copyProtocol(s.baseProto)
	if err != nil {
		return nil, nil, err
	}
	if err = setAddress(proto, ip); err != nil {
		return nil, nil, fmt.Errorf("failed to set IP on protocol: %w", err)
	}
	return s.core.MakeHttpClient(ctx, proto, timeout)
}

const (
	saveBatchSize      = 50
	saveInterval       = 3 * time.Second
	cloudflareTraceURL = "https://cloudflare.com/cdn-cgi/trace"
	userAgent          = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
)

// SortResults orders results best first: working IPs before failed ones.
// With bySpeed, IPs that have speed data lead, fastest download first, so a
// speed test actually changes the ranking; otherwise, and among the rest,
// lower latency wins.
func SortResults(results []*ScanResult, bySpeed bool) {
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if (a.Error == nil) != (b.Error == nil) {
			return a.Error == nil
		}
		if a.Error != nil {
			return a.IP < b.IP
		}
		if bySpeed {
			if as, bs := a.HasSpeed(), b.HasSpeed(); as != bs {
				return as
			} else if as && a.DownSpeed != b.DownSpeed {
				return a.DownSpeed > b.DownSpeed
			}
		}
		if a.Latency != b.Latency {
			return a.Latency < b.Latency
		}
		return a.IP < b.IP
	})
}

// LoadResultsFromCSV reads results written by SaveResults in CSV form.
func LoadResultsFromCSV(filePath string) ([]*ScanResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No history is not an error
		}
		return nil, err
	}
	defer file.Close()

	var results []*ScanResult
	if err := gocsv.UnmarshalFile(file, &results); err != nil {
		if errors.Is(err, io.EOF) || err.Error() == "EOF" { // Handle empty file gracefully
			return nil, nil
		}
		return nil, fmt.Errorf("failed to parse resume file (must be CSV): %w", err)
	}
	rehydrate(results)
	return results, nil
}

// LoadResults reads a results file in any SaveResults format, chosen by its
// extension (.json, .jsonl) or CSV otherwise. A missing file is no history.
func LoadResults(filePath string) ([]*ScanResult, error) {
	switch {
	case strings.HasSuffix(filePath, ".jsonl"):
		return loadResultsJSONL(filePath)
	case strings.HasSuffix(filePath, ".json"):
		raw, err := os.ReadFile(filePath)
		if os.IsNotExist(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var results []*ScanResult
		if len(bytes.TrimSpace(raw)) == 0 {
			return nil, nil
		}
		if err := json.Unmarshal(raw, &results); err != nil {
			return nil, fmt.Errorf("failed to parse resume file (JSON): %w", err)
		}
		rehydrate(results)
		return results, nil
	default:
		return LoadResultsFromCSV(filePath)
	}
}

func loadResultsJSONL(filePath string) ([]*ScanResult, error) {
	file, err := os.Open(filePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var results []*ScanResult
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r ScanResult
		if err := json.Unmarshal(line, &r); err != nil {
			// A checkpoint is written atomically, but a hand-edited or
			// truncated file should still resume from its good lines.
			continue
		}
		results = append(results, &r)
	}
	rehydrate(results)
	return results, sc.Err()
}

// rehydrate restores the non-serialized fields after loading.
func rehydrate(results []*ScanResult) {
	for _, r := range results {
		r.Latency = time.Duration(r.LatencyMS) * time.Millisecond
		if r.ErrorStr != "" {
			r.Error = errors.New(r.ErrorStr)
		}
		if r.SpeedErrStr != "" {
			r.SpeedErr = errors.New(r.SpeedErrStr)
		}
	}
}

// SaveResults atomically replaces filePath with results in format (csv,
// json or jsonl).
func SaveResults(filePath, format string, results []*ScanResult) error {
	for _, r := range results {
		r.PrepareForMarshal()
	}
	var buf bytes.Buffer
	switch format {
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		buf.Write(data)
		buf.WriteByte('\n')
	case "jsonl":
		enc := json.NewEncoder(&buf)
		for _, r := range results {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
	default:
		if err := gocsv.Marshal(&results, &buf); err != nil {
			return err
		}
	}
	return pkghttp.WriteFileAtomic(filePath, buf.Bytes())
}

// connClosingBody also closes the underlying conn on Close() because
// BypassJA3Transport manages connections outside of http.Transport's pool.
type connClosingBody struct {
	io.ReadCloser
	conn net.Conn
}

func (c *connClosingBody) Close() error {
	err := c.ReadCloser.Close()
	c.conn.Close()
	return err
}

// BypassJA3Transport dials with DialContext and speaks TLS with a uTLS
// ClientHello, so requests carry a browser fingerprint.
type BypassJA3Transport struct {
	tr1Once     sync.Once
	tr1         *http.Transport
	tr2         *http2.Transport
	clientHello utls.ClientHelloID
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewBypassJA3Transport(helloID utls.ClientHelloID) *BypassJA3Transport {
	return &BypassJA3Transport{
		clientHello: helloID,
		tr2:         &http2.Transport{AllowHTTP: true},
	}
}

func (b *BypassJA3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Scheme {
	case "https":
		return b.httpsRoundTrip(req)
	case "http":
		b.tr1Once.Do(func() { b.tr1 = &http.Transport{DialContext: b.DialContext} })
		return b.tr1.RoundTrip(req)
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", req.URL.Scheme)
	}
}

func (b *BypassJA3Transport) httpsRoundTrip(req *http.Request) (*http.Response, error) {
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	hostname := req.URL.Hostname()

	dialer := b.DialContext
	if dialer == nil {
		dialer = (&net.Dialer{}).DialContext
	}

	conn, err := dialer(req.Context(), "tcp", net.JoinHostPort(hostname, port))
	if err != nil {
		return nil, fmt.Errorf("custom dial failed: %w", err)
	}

	tlsConn, err := b.tlsConnect(req.Context(), conn, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls connect failed: %w", err)
	}

	if deadline, ok := req.Context().Deadline(); ok {
		tlsConn.SetDeadline(deadline)
	}

	httpVersion := tlsConn.ConnectionState().NegotiatedProtocol
	switch httpVersion {
	case "h2":
		// NewClientConn only wraps this conn; the shared Transport's pool is
		// not involved, so concurrent use is safe.
		clientConn, err := b.tr2.NewClientConn(tlsConn)
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("failed to create http2 client connection: %w", err)
		}
		resp, err := clientConn.RoundTrip(req)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}
		resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: tlsConn}
		return resp, nil
	case "http/1.1", "":
		if err := req.Write(tlsConn); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("failed to write http1 request: %w", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}
		resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: tlsConn}
		return resp, nil
	default:
		tlsConn.Close()
		return nil, fmt.Errorf("unsupported http version: %s", httpVersion)
	}
}

func (b *BypassJA3Transport) getTLSConfig(req *http.Request) *utls.Config {
	return &utls.Config{
		ServerName:         req.URL.Hostname(),
		InsecureSkipVerify: false,
		NextProtos:         []string{"h2", "http/1.1"},
	}
}

func (b *BypassJA3Transport) tlsConnect(ctx context.Context, conn net.Conn, req *http.Request) (*utls.UConn, error) {
	tlsConn := utls.UClient(conn, b.getTLSConfig(req), b.clientHello)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

// setAddress points a parsed protocol at newAddr. A config that relied on
// its server name for TLS SNI or the HTTP Host header (empty SNI/Host fields
// with a domain address) keeps that name, so swapping in a CDN IP does not
// also change what the CDN is asked for.
//
// With an empty SNI, xray sends the Host header's name when there is one
// (transportSpec.serverName) and sing-box sends the address, so the SNI is
// only pinned to the old address where the core would have used it.
func setAddress(p interface{}, newAddr string) error {
	val := reflect.ValueOf(p)

	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return fmt.Errorf("provided interface is not a struct or a pointer to a struct")
	}

	addressField := val.FieldByName("Address")
	if addressField.IsValid() {
		if !addressField.CanSet() {
			return fmt.Errorf("'Address' field is not settable")
		}
		if addressField.Kind() != reflect.String {
			return fmt.Errorf("'Address' field is not a string")
		}
		oldHost := strings.Trim(addressField.String(), "[]")
		if _, err := netip.ParseAddr(oldHost); err != nil && oldHost != "" {
			field := func(name string) (reflect.Value, bool) {
				f := val.FieldByName(name)
				return f, f.IsValid() && f.CanSet() && f.Kind() == reflect.String
			}
			sni, hasSNI := field("SNI")
			host, hasHost := field("Host")
			_, isXray := p.(xray.Protocol)
			sniFromHost := isXray && hasHost && host.String() != ""
			if hasSNI && sni.String() == "" && !sniFromHost {
				sni.SetString(oldHost)
			}
			if hasHost && host.String() == "" {
				host.SetString(oldHost)
			}
		}
		addressField.SetString(newAddr)
		return nil
	}

	endpointField := val.FieldByName("Endpoint")
	if endpointField.IsValid() {
		if !endpointField.CanSet() {
			return fmt.Errorf("'Endpoint' field is not settable")
		}
		if endpointField.Kind() != reflect.String {
			return fmt.Errorf("'Endpoint' field is not a string")
		}

		currentEndpoint := endpointField.String()
		_, port, err := net.SplitHostPort(currentEndpoint)
		if err != nil {
			return fmt.Errorf("could not split host:port from endpoint '%s': %w", currentEndpoint, err)
		}
		newEndpoint := net.JoinHostPort(newAddr, port)
		endpointField.SetString(newEndpoint)
		return nil
	}

	return fmt.Errorf("struct has no 'Address' or 'Endpoint' field")
}
