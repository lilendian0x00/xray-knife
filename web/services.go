// web/services.go
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/database"
	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v11/pkg/scanner"
)

// Lifecycle states for managed services.
type ServiceState string

const (
	StateIdle     ServiceState = "idle"
	StateStarting ServiceState = "starting"
	StateRunning  ServiceState = "running"
	StateStopping ServiceState = "stopping"
	StateFinished ServiceState = "finished" // For tasks that complete
	StateError    ServiceState = "error"
)

// stopWaitTimeout bounds how long Stop waits for a run to wind down before
// returning; the run keeps "stopping" and finishes on its own.
const stopWaitTimeout = 30 * time.Second

// runCounter hands out run IDs, unique across services for the process.
var runCounter atomic.Uint64

// ManagedService is the interface all background services must implement.
type ManagedService interface {
	Start(config interface{}) error
	Stop() error
	Status() ServiceState
	Type() string
	Snapshot() ServiceSnapshot
}

// ServiceSnapshot is the /state view of one service.
type ServiceSnapshot struct {
	Status     string         `json:"status"`
	RunID      uint64         `json:"runId"`
	StartedAt  *time.Time     `json:"startedAt,omitempty"`
	FinishedAt *time.Time     `json:"finishedAt,omitempty"`
	Error      string         `json:"error,omitempty"`
	Progress   map[string]int `json:"progress,omitempty"`
	Summary    map[string]int `json:"summary,omitempty"`
	// FailureKinds counts non-passed HTTP results by pkg/http failure kind.
	FailureKinds map[string]int `json:"failureKinds,omitempty"`
}

// BaseService has the shared lock/state/logger that all service runners embed.
//
// Every Start begins a new run with its own ID, context and done channel.
// The run goroutine only changes the service's state while its ID is still
// the current one, so a slow-exiting old run can never clobber a new one.
type BaseService struct {
	mu          sync.RWMutex
	state       ServiceState
	runID       uint64
	cancelFunc  context.CancelFunc
	done        chan struct{}
	stopping    bool // Stop was requested for the current run
	startedAt   time.Time
	finishedAt  time.Time
	lastErr     string
	logger      *log.Logger
	hub         *Hub
	serviceType string
	statusEvent string // SSE event type for status changes

	progress     func() map[string]int
	summary      func() map[string]int
	failureKinds func() map[string]int
	// statusData builds a status event's data; nil sends the bare state.
	statusData func(status string) any
}

// statusPayload is the data of a status event for status.
func (s *BaseService) statusPayload(status string) any {
	if s.statusData != nil {
		return s.statusData(status)
	}
	return status
}

// NewBaseService creates a new BaseService.
func NewBaseService(serviceType string, logger *log.Logger, hub *Hub) *BaseService {
	statusEvent := ""
	switch serviceType {
	case "proxy":
		statusEvent = "proxy_status"
	case "http-tester":
		statusEvent = "http_test_status"
	case "cf-scanner":
		statusEvent = "cfscan_status"
	case "dpi":
		statusEvent = "dpi_status"
	}
	return &BaseService{
		state:       StateIdle,
		logger:      logger,
		hub:         hub,
		serviceType: serviceType,
		statusEvent: statusEvent,
	}
}

func (s *BaseService) recoverAndLogPanic() {
	if r := recover(); r != nil {
		s.logger.Printf("[CRITICAL] Goroutine for service '%s' panicked: %v\n%s\n", s.serviceType, r, string(debug.Stack()))
	}
}

// SetState updates the service state under the write lock.
func (s *BaseService) SetState(newState ServiceState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = newState
}

// Status returns the current state under the read lock.
func (s *BaseService) Status() ServiceState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// Type returns the service type.
func (s *BaseService) Type() string {
	return s.serviceType
}

// busy reports whether a run is in flight (including one still stopping).
func (s *BaseService) busyLocked() bool {
	return s.state == StateStarting || s.state == StateRunning || s.state == StateStopping
}

// run is the per-run handle a runner's goroutine works through.
type run struct {
	svc      *BaseService
	id       uint64
	ctx      context.Context
	done     chan struct{} // closed once the run has fully ended
	doneOnce sync.Once
}

func (rn *run) closeDone() { rn.doneOnce.Do(func() { close(rn.done) }) }

// beginRunLocked starts a new run. The caller holds s.mu. It fails with a
// 409 while a previous run is starting, running, or still stopping.
func (s *BaseService) beginRunLocked(parent context.Context) (*run, error) {
	if s.busyLocked() {
		if s.state == StateStopping {
			return nil, conflict(codeBusy, "%s is still stopping; try again in a moment", s.serviceType)
		}
		return nil, conflict(codeBusy, "%s is already %s", s.serviceType, s.state)
	}
	ctx, cancel := context.WithCancel(parent)
	s.runID = runCounter.Add(1)
	s.state = StateStarting
	s.cancelFunc = cancel
	rn := &run{svc: s, id: s.runID, ctx: ctx, done: make(chan struct{})}
	s.done = rn.done
	s.stopping = false
	s.startedAt = time.Now()
	s.finishedAt = time.Time{}
	s.lastErr = ""
	s.progress, s.summary, s.failureKinds = nil, nil, nil
	return rn, nil
}

// failStartLocked records a start that failed before its goroutine began.
func (s *BaseService) failStartLocked(rn *run, err error) {
	if s.runID != rn.id {
		return
	}
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	s.state = StateError
	s.lastErr = err.Error()
	s.finishedAt = time.Now()
	s.done = nil
	rn.closeDone()
}

// setState changes the service state only if this run is still current.
func (rn *run) setState(state ServiceState) bool {
	s := rn.svc
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runID != rn.id {
		return false
	}
	// Never move a stopping run back to running.
	if s.stopping && state == StateRunning {
		return false
	}
	s.state = state
	return true
}

// stopRequested reports whether Stop was called for this run.
func (rn *run) stopRequested() bool {
	s := rn.svc
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runID == rn.id && s.stopping
}

// publishStatus sends a status event for this run.
func (rn *run) publishStatus(status string, extra map[string]any) {
	if rn.svc.statusEvent == "" || rn.svc.hub == nil {
		return
	}
	if extra == nil {
		extra = map[string]any{}
	}
	extra["runId"] = rn.id
	rn.svc.hub.Publish(rn.svc.statusEvent, rn.svc.statusPayload(status), extra)
}

// finish ends the run: it records the final state (if still current),
// cancels the run context, closes the done channel, and sends the final
// status event. Exactly one final event is sent per run.
func (rn *run) finish(final ServiceState, event string, extra map[string]any) {
	s := rn.svc
	s.mu.Lock()
	if s.runID == rn.id {
		s.state = final
		s.finishedAt = time.Now()
		if msg, ok := extra["error"].(string); ok && msg != "" {
			s.lastErr = msg
		} else if msg, ok := extra["message"].(string); ok && msg != "" && final == StateError {
			s.lastErr = msg
		}
		if s.cancelFunc != nil {
			s.cancelFunc()
		}
		s.done = nil
	}
	s.mu.Unlock()
	// Publish before releasing Stop's waiter, so a client that reacts to the
	// Stop response has the final event queued already.
	rn.publishStatus(event, extra)
	rn.closeDone()
}

// Stop cancels the current run and waits (bounded) for it to finish. The
// run itself sends the final "stopped" event.
func (s *BaseService) Stop() error {
	s.mu.Lock()
	switch s.state {
	case StateStarting, StateRunning:
	case StateStopping:
		done := s.done
		s.mu.Unlock()
		return waitDone(done)
	default:
		s.mu.Unlock()
		return conflict(codeNotRunning, "%s is not running", s.serviceType)
	}

	s.state = StateStopping
	s.stopping = true
	id := s.runID
	done := s.done
	s.logger.Printf("[%s] Stop signal received. Cancelling context.", strings.ToUpper(s.serviceType))
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	s.mu.Unlock()
	if s.statusEvent != "" && s.hub != nil {
		s.hub.Publish(s.statusEvent, s.statusPayload("stopping"), map[string]any{"runId": id})
	}

	if err := waitDone(done); err != nil {
		return err
	}
	s.logger.Printf("[%s] Service stopped successfully.", strings.ToUpper(s.serviceType))
	return nil
}

func waitDone(done chan struct{}) error {
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-time.After(stopWaitTimeout):
		return conflict(codeBusy, "still stopping after %s; it will finish in the background", stopWaitTimeout)
	}
}

// Snapshot returns the /state view of the service.
func (s *BaseService) Snapshot() ServiceSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := ServiceSnapshot{Status: string(s.state), RunID: s.runID, Error: s.lastErr}
	if !s.startedAt.IsZero() {
		t := s.startedAt
		snap.StartedAt = &t
	}
	if !s.finishedAt.IsZero() {
		t := s.finishedAt
		snap.FinishedAt = &t
	}
	if s.progress != nil {
		snap.Progress = s.progress()
	}
	if s.summary != nil {
		snap.Summary = s.summary()
	}
	if s.failureKinds != nil {
		snap.FailureKinds = s.failureKinds()
	}
	return snap
}

// setReporters installs the progress/summary callbacks for /state.
func (rn *run) setReporters(progress, summary func() map[string]int) {
	s := rn.svc
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runID == rn.id {
		s.progress, s.summary = progress, summary
	}
}

// setFailureKinds installs the failure-kind callback for /state.
func (rn *run) setFailureKinds(fn func() map[string]int) {
	s := rn.svc
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runID == rn.id {
		s.failureKinds = fn
	}
}

// reportProgress broadcasts progress every 500ms until the run context ends.
func (rn *run) reportProgress(eventType string, snapshot func() map[string]int) {
	defer rn.svc.recoverAndLogPanic()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var last string
	for {
		select {
		case <-ticker.C:
			data := snapshot()
			// Coalesce: an unchanged counter is not worth an event.
			key := fmt.Sprint(data)
			if key == last {
				continue
			}
			last = key
			rn.svc.hub.Publish(eventType, data, map[string]any{"runId": rn.id})
		case <-rn.ctx.Done():
			return
		}
	}
}

// --- Proxy Service Runner ---

type ProxyServiceRunner struct {
	*BaseService
	service     proxyRunner
	forceRotate chan struct{}
	// newService is proxy.New, swappable in tests.
	newService func(proxy.Config, *log.Logger) (proxyRunner, error)
}

func NewProxyServiceRunner(logger *log.Logger, hub *Hub) *ProxyServiceRunner {
	return &ProxyServiceRunner{
		BaseService: NewBaseService("proxy", logger, hub),
		newService: func(cfg proxy.Config, logger *log.Logger) (proxyRunner, error) {
			svc, err := proxy.New(cfg, logger)
			if err != nil {
				return nil, err
			}
			return svc, nil
		},
	}
}

// proxyRunner is the part of *proxy.Service the web runner uses.
type proxyRunner interface {
	Run(ctx context.Context, forceRotate <-chan struct{}) error
	Close()
	GetCurrentDetails() *proxy.Details
	ConfirmDeadman() bool
	EmergencyCleanup(timeout time.Duration)
}

func (p *ProxyServiceRunner) Start(config interface{}) error {
	cfg, ok := config.(proxy.Config)
	if !ok {
		return fmt.Errorf("invalid config type for proxy service")
	}

	p.mu.Lock()
	rn, err := p.beginRunLocked(context.Background())
	p.mu.Unlock()
	if err != nil {
		return err
	}
	// proxy.New queries the database and runs crash recovery (firewall
	// rules, OS proxy settings), so it runs without the lock: /state, SSE
	// and details must not stall behind it. The run is "starting", which
	// keeps other Starts out; a Stop meanwhile is honored by p.run.
	service, err := p.newService(cfg, p.logger)

	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		stopRequested := p.runID == rn.id && p.stopping
		p.failStartLocked(rn, err)
		p.service, p.forceRotate = nil, nil
		if stopRequested {
			// The client saw "stopping"; end the run for it too.
			rn.publishStatus("stopped", map[string]any{"error": err.Error()})
		}
		return badRequest("failed to create proxy service: %v", err)
	}

	forceRotate := make(chan struct{})
	p.service = service
	p.forceRotate = forceRotate
	rn.publishStatus("starting", nil)

	go p.run(rn, service, forceRotate)
	return nil
}

func (p *ProxyServiceRunner) run(rn *run, service proxyRunner, forceRotate chan struct{}) {
	var runErr error
	defer func() {
		if r := recover(); r != nil {
			p.logger.Printf("[CRITICAL] Goroutine for service '%s' panicked: %v\n%s\n", p.serviceType, r, string(debug.Stack()))
			runErr = fmt.Errorf("proxy crashed: %v", r)
		}
		// Close this run's own service, never whatever p.service points
		// at by now.
		service.Close()
		p.mu.Lock()
		if p.runID == rn.id {
			p.service, p.forceRotate = nil, nil
		}
		p.mu.Unlock()

		extra := map[string]any{}
		final := StateIdle
		if runErr != nil && !rn.stopRequested() {
			p.logger.Printf("Proxy service exited with error: %v", runErr)
			extra["error"] = runErr.Error()
			final = StateError
		}
		// The UI treats "stopped" as terminal and shows `error` if present.
		rn.finish(final, "stopped", extra)
	}()

	if !rn.setState(StateRunning) {
		return
	}
	rn.publishStatus("running", nil)

	// This is the blocking call.
	runErr = service.Run(rn.ctx, forceRotate)
	if runErr != nil && rn.ctx.Err() != nil && rn.stopRequested() {
		runErr = nil
	}
}

func (p *ProxyServiceRunner) GetDetails() (*proxy.Details, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.service == nil || p.state != StateRunning {
		return nil, notFound("proxy service not running")
	}
	return p.service.GetCurrentDetails(), nil
}

// EmergencyCleanup runs the proxy's best-effort teardown (kill switch,
// OS proxy settings) before a forced exit, even while it is stopping.
func (p *ProxyServiceRunner) EmergencyCleanup(timeout time.Duration) {
	p.mu.RLock()
	service := p.service
	p.mu.RUnlock()
	if service != nil {
		service.EmergencyCleanup(timeout)
	}
}

// ConfirmDeadman confirms a pending host-tun deadman timer.
func (p *ProxyServiceRunner) ConfirmDeadman() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.service == nil || p.state != StateRunning {
		return conflict(codeNotRunning, "proxy service not running")
	}
	if !p.service.ConfirmDeadman() {
		return conflict("not_pending", "no deadman confirmation is pending")
	}
	return nil
}

func (p *ProxyServiceRunner) Rotate() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.forceRotate == nil || p.state != StateRunning {
		return conflict(codeNotRunning, "proxy service not running")
	}
	select {
	case p.forceRotate <- struct{}{}:
		return nil
	default:
		return conflict(codeBusy, "failed to send rotate signal (proxy is busy)")
	}
}

// --- HTTP Test Runner ---

// HttpTestJob is a validated HTTP test: links already resolved and the
// examiner already built, so everything that can fail on input fails in
// Start (→ 400) rather than inside the run.
type HttpTestJob struct {
	Links         []string
	ThreadCount   uint16
	SaveToDB      bool
	DedupSemantic bool
	Prescan       bool
	PrescanOpts   pkghttp.PrescanOptions
	MaxPassed     int
	Options       pkghttp.Options
	Examiner      *pkghttp.Examiner
}

type HttpTestRunner struct {
	*BaseService
}

func NewHttpTestRunner(logger *log.Logger, hub *Hub) *HttpTestRunner {
	return &HttpTestRunner{BaseService: NewBaseService("http-tester", logger, hub)}
}

// defaultHttpThreads is used when the request leaves threadCount at 0.
const defaultHttpThreads = 50

// maxHttpThreads bounds concurrent core instances for one web test.
const maxHttpThreads = 2048

// buildHttpTestJob validates a request and builds the examiner.
func buildHttpTestJob(req pkghttp.HttpTestRequest, logger *log.Logger) (*HttpTestJob, error) {
	links := cleanLinks(req.Links)
	if len(links) == 0 {
		return nil, badRequest("no config links to test")
	}
	threads := req.ThreadCount
	if threads == 0 {
		threads = defaultHttpThreads
	}
	if threads > maxHttpThreads {
		return nil, badRequest("threadCount must be at most %d", maxHttpThreads)
	}
	opts := req.Options
	if opts.Logger == nil {
		opts.Logger = logger
	}
	examiner, err := pkghttp.NewExaminer(opts)
	if err != nil {
		return nil, badRequest("invalid test options: %v", err)
	}
	return &HttpTestJob{
		Links:         links,
		ThreadCount:   threads,
		SaveToDB:      req.SaveToDB,
		DedupSemantic: false,
		Options:       opts,
		Examiner:      examiner,
	}, nil
}

// cleanLinks trims links and drops blanks.
func cleanLinks(in []string) []string {
	out := make([]string, 0, len(in))
	for _, l := range in {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Start accepts either a *HttpTestJob (validated by the API layer) or a raw
// pkghttp.HttpTestRequest, which is validated here.
func (ht *HttpTestRunner) Start(config interface{}) error {
	var job *HttpTestJob
	switch c := config.(type) {
	case *HttpTestJob:
		job = c
	case pkghttp.HttpTestRequest:
		j, err := buildHttpTestJob(c, ht.logger)
		if err != nil {
			return err
		}
		job = j
	default:
		return fmt.Errorf("invalid config type for http test service")
	}

	ht.mu.Lock()
	defer ht.mu.Unlock()

	rn, err := ht.beginRunLocked(context.Background())
	if err != nil {
		return err
	}

	if err := os.Remove(httpTesterHistoryFile); err != nil && !os.IsNotExist(err) {
		ht.logger.Printf("Warning: could not clear previous http test history file: %v", err)
	}

	rn.publishStatus("starting", nil)
	go ht.run(rn, job)
	return nil
}

// httpSummary counts results by status and, for failures, by kind.
type httpSummary struct {
	passed, semi, failed, broken, total atomic.Int32

	mu    sync.Mutex
	kinds map[string]int
}

func (s *httpSummary) add(res *pkghttp.Result) {
	s.total.Add(1)
	switch res.Status {
	case "passed":
		s.passed.Add(1)
		return
	case "semi-passed":
		s.semi.Add(1)
	case "broken":
		s.broken.Add(1)
	default:
		s.failed.Add(1)
	}
	kind := res.FailureKind
	if kind == "" {
		kind = pkghttp.FailOther
	}
	s.mu.Lock()
	if s.kinds == nil {
		s.kinds = make(map[string]int)
	}
	s.kinds[kind]++
	s.mu.Unlock()
}

func (s *httpSummary) snapshot() map[string]int {
	return map[string]int{
		"passed":     int(s.passed.Load()),
		"semiPassed": int(s.semi.Load()),
		"failed":     int(s.failed.Load()),
		"broken":     int(s.broken.Load()),
		"total":      int(s.total.Load()),
	}
}

// failureKinds counts non-passed results by failure kind (see pkg/http Fail*).
func (s *httpSummary) failureKinds() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.kinds))
	for k, v := range s.kinds {
		out[k] = v
	}
	return out
}

func (ht *HttpTestRunner) run(rn *run, job *HttpTestJob) {
	var summary httpSummary
	var completed atomic.Int32
	var total atomic.Int32
	final, event := StateFinished, "finished"
	extra := map[string]any{}
	defer func() {
		if r := recover(); r != nil {
			ht.logger.Printf("[CRITICAL] Goroutine for service '%s' panicked: %v\n%s\n", ht.serviceType, r, string(debug.Stack()))
			final, event = StateError, "error"
			extra["error"] = fmt.Sprintf("http test crashed: %v", r)
		}
		if rn.stopRequested() {
			final, event = StateIdle, "stopped"
			delete(extra, "error")
		}
		extra["summary"] = summary.snapshot()
		extra["failureKinds"] = summary.failureKinds()
		rn.finish(final, event, extra)
	}()

	rn.setReporters(func() map[string]int {
		return map[string]int{"completed": int(completed.Load()), "total": int(total.Load())}
	}, summary.snapshot)
	rn.setFailureKinds(summary.failureKinds)

	if !rn.setState(StateRunning) {
		return
	}
	rn.publishStatus("running", nil)

	ctx := rn.ctx

	// Parse every link once; dedup, prescan and the test share the result.
	// Exact duplicates go first (cheap), then connection-level ones.
	unique, removed := pkghttp.DeduplicateLinks(job.Links)
	parsed := pkghttp.ParseLinks(job.Examiner.Core, unique)
	if job.DedupSemantic {
		var n int
		parsed, n = pkghttp.SemanticDeduplicateParsed(parsed)
		removed += n
	}
	if removed > 0 {
		ht.logger.Printf("Removed %d duplicate config link(s). Testing %d unique configs.", removed, len(parsed))
	}
	ht.hub.Publish("http_test_phase", map[string]any{"phase": "dedup", "completed": len(parsed), "total": len(parsed) + removed,
		"message": fmt.Sprintf("%d duplicates removed", removed)}, map[string]any{"runId": rn.id})

	// Every unique link ends up as a result: prescan drops count as failed.
	total.Store(int32(len(parsed)))
	go rn.reportProgress("http_test_progress", func() map[string]int {
		return map[string]int{"completed": int(completed.Load()), "total": int(total.Load())}
	})
	if len(parsed) == 0 {
		ht.logger.Printf("No configs left to test.")
		return
	}

	// Create a DB test run if SaveToDB is requested
	var dbRunID int64
	if job.SaveToDB {
		optsJson, _ := json.Marshal(job.Options)
		var err error
		dbRunID, err = database.CreateHttpTestRun(string(optsJson), len(parsed))
		if err != nil {
			ht.logger.Printf("Warning: failed to create DB test run: %v", err)
		}
	}

	// testCtx ends early when --max-passed is reached; ctx only on Stop.
	testCtx, cancelTests := context.WithCancel(ctx)
	defer cancelTests()
	var maxPassedHit atomic.Bool

	resultsChan := make(chan *pkghttp.Result, job.ThreadCount)
	var consumerWg sync.WaitGroup
	consumerWg.Add(1)
	go func() {
		defer consumerWg.Done()
		defer ht.recoverAndLogPanic()
		ht.consumeResults(rn, resultsChan, dbRunID, func(res *pkghttp.Result) {
			summary.add(res)
			if job.MaxPassed > 0 && int(summary.passed.Load()) >= job.MaxPassed && maxPassedHit.CompareAndSwap(false, true) {
				ht.logger.Printf("Reached maxPassed=%d; stopping early.", job.MaxPassed)
				cancelTests()
			}
		})
	}()
	finishResults := func() {
		close(resultsChan)
		consumerWg.Wait()
		if dbRunID > 0 {
			if err := database.FinishHttpTestRun(dbRunID); err != nil {
				ht.logger.Printf("Warning: %v", err)
			}
		}
	}

	if job.Prescan && ctx.Err() == nil {
		var preDone, preTotal atomic.Int32
		phaseCtx, stopPhase := context.WithCancel(ctx)
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					ht.hub.Publish("http_test_phase", map[string]any{"phase": "prescan", "completed": int(preDone.Load()), "total": int(preTotal.Load())},
						map[string]any{"runId": rn.id})
				case <-phaseCtx.Done():
					return
				}
			}
		}()
		opts := job.PrescanOpts
		if opts.Resolver == nil && job.Examiner.Diagnoser != nil {
			// Same trusted resolver as the diagnostics, so a poisoned
			// system DNS is caught at prescan time too.
			opts.Resolver = job.Examiner.Diagnoser.Trusted
		}
		pre, err := pkghttp.RunPrescanParsed(ctx, parsed, opts,
			func(unique int) { preTotal.Store(int32(unique)) },
			func() { preDone.Add(1) })
		stopPhase()
		if err != nil {
			if ctx.Err() == nil {
				final, event = StateError, "error"
				extra["error"] = fmt.Sprintf("prescan failed: %v", err)
			}
			finishResults()
			return
		}
		ht.logger.Printf("Pre-scan complete: %d reachable, %d filtered out, %d kept without probing.", pre.TCPReachable, pre.FilteredOut, pre.Bypassed)
		ht.hub.Publish("http_test_phase", map[string]any{"phase": "prescan", "completed": int(preDone.Load()), "total": int(preTotal.Load()),
			"message": fmt.Sprintf("%d reachable, %d filtered out", pre.TCPReachable+pre.Bypassed, pre.FilteredOut)}, map[string]any{"runId": rn.id})
		// Report the dropped links as failed results (with their failure
		// kind) instead of letting them vanish from the run.
		for _, res := range pre.DroppedResults() {
			resultsChan <- res
			completed.Add(1)
		}
		parsed = pre.ReachableParsed
		if ctx.Err() != nil {
			finishResults()
			return
		}
	}

	ht.hub.Publish("http_test_phase", map[string]any{"phase": "testing", "completed": int(completed.Load()), "total": int(total.Load())}, map[string]any{"runId": rn.id})
	if len(parsed) > 0 {
		testManager := pkghttp.NewTestManager(job.Examiner, job.ThreadCount, false, ht.logger)
		testManager.RunParsed(testCtx, parsed, resultsChan, func() {
			completed.Add(1)
		})
	}
	finishResults()

	if maxPassedHit.Load() {
		extra["reason"] = "max_passed"
	}
}

// consumeResults streams results to the UI and saves them in batches.
// Every result (including the tail after a stop) is saved: the loop only
// ends when the producer closes the channel.
func (ht *HttpTestRunner) consumeResults(rn *run, resultsChan <-chan *pkghttp.Result, dbRunID int64, onResult func(*pkghttp.Result)) {
	const saveBatchSize = 50
	const saveInterval = 5 * time.Second
	batch := make([]*pkghttp.Result, 0, saveBatchSize)
	ticker := time.NewTicker(saveInterval)
	defer ticker.Stop()

	save := func() {
		if len(batch) == 0 {
			return
		}
		// Save to CSV history file
		if err := appendResultsToCSV(httpTesterHistoryFile, batch); err != nil {
			ht.logger.Printf("HTTP test history save failed: %v", err)
		}
		// Save to DB if a run ID is available
		if dbRunID > 0 {
			if err := database.InsertHttpTestResultsBatch(dbRunID, pkghttp.ResultsToDB(dbRunID, batch)); err != nil {
				ht.logger.Printf("HTTP test DB save failed: %v", err)
			}
		}
		batch = make([]*pkghttp.Result, 0, saveBatchSize)
	}

	for {
		select {
		case result, ok := <-resultsChan:
			if !ok {
				save()
				return
			}
			if onResult != nil {
				onResult(result)
			}
			ht.hub.Publish("http_result", result, map[string]any{"runId": rn.id})
			batch = append(batch, result)
			if len(batch) >= saveBatchSize {
				save()
			}
		case <-ticker.C:
			save()
		}
	}
}

// --- CF Scanner Runner ---

type CfScannerRunner struct {
	*BaseService
	lastPlanned int // addresses the latest scan plans to visit
}

func NewCfScannerRunner(logger *log.Logger, hub *Hub) *CfScannerRunner {
	return &CfScannerRunner{BaseService: NewBaseService("cf-scanner", logger, hub)}
}

// cfScanJob is a validated scan request.
type cfScanJob struct {
	cfg scanner.ScannerConfig
}

func (s *CfScannerRunner) Start(config interface{}) error {
	var job cfScanJob
	switch c := config.(type) {
	case cfScanJob:
		job = c
	case scanner.ScannerConfig:
		j, err := buildCfScanJob(c)
		if err != nil {
			return err
		}
		job = j
	default:
		return fmt.Errorf("invalid config type for cf scanner service")
	}
	cfg := job.cfg
	cfg.OutputFile = cfScannerHistoryFile
	cfg.Verbose = false

	// Set up progress counter via instance-scoped callback (instead of global)
	var completed atomic.Int32
	cfg.OnIPScannedCallback = func() {
		completed.Add(1)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rn, err := s.beginRunLocked(context.Background())
	if err != nil {
		return err
	}
	service, err := scanner.NewScannerService(cfg, s.logger)
	if err != nil {
		s.failStartLocked(rn, err)
		return badRequest("failed to create scanner service: %v", err)
	}

	s.lastPlanned = service.PlannedIPs()
	rn.publishStatus("starting", nil)
	go s.run(rn, service, cfg, s.lastPlanned, &completed)
	return nil
}

func (s *CfScannerRunner) run(rn *run, service *scanner.ScannerService, cfg scanner.ScannerConfig, totalIPs int, completed *atomic.Int32) {
	var succeeded, failed atomic.Int32
	final, event := StateFinished, "finished"
	extra := map[string]any{}
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("[CRITICAL] Goroutine for service '%s' panicked: %v\n%s\n", s.serviceType, r, string(debug.Stack()))
			final, event = StateError, "error"
			extra["message"] = fmt.Sprintf("scanner crashed: %v", r)
		}
		if rn.stopRequested() {
			final, event = StateIdle, "stopped"
			delete(extra, "message")
		}
		rn.finish(final, event, extra)
	}()

	// A scan that runs a whole day is certainly stuck.
	ctx, cancel := context.WithTimeout(rn.ctx, 24*time.Hour)
	defer cancel()

	progress := func() map[string]int {
		return map[string]int{
			"completed": int(completed.Load()),
			"total":     totalIPs,
			"succeeded": int(succeeded.Load()),
			"failed":    int(failed.Load()),
		}
	}
	rn.setReporters(progress, nil)

	if !rn.setState(StateRunning) {
		return
	}
	rn.publishStatus("running", nil)

	go rn.reportProgress("cf_scan_progress", progress)

	progressChan := make(chan *scanner.ScanResult, max(cfg.ThreadCount, 1))
	var forwardWg sync.WaitGroup
	forwardWg.Add(1)
	go func() {
		defer forwardWg.Done()
		defer s.recoverAndLogPanic() // Also recover this goroutine
		seen := make(map[string]bool)
		for result := range progressChan {
			// The scanner hands out copies, so this cannot race its workers.
			result.PrepareForMarshal()
			if result.ErrorStr != "" {
				// Failures only move the counters; streaming every dead IP
				// makes large scans unusable in the browser.
				if !seen[result.IP] {
					seen[result.IP] = true
					failed.Add(1)
				}
				continue
			}
			if !seen[result.IP] {
				seen[result.IP] = true
				succeeded.Add(1)
			}
			s.hub.Publish("cfscan_result", result, map[string]any{"runId": rn.id})
		}
	}()

	err := service.Run(ctx, progressChan)
	forwardWg.Wait()
	if err != nil && !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		s.logger.Printf("[SCAN-STATUS] Scan exited with error: %v", err)
		final, event = StateError, "error"
		extra["message"] = err.Error()
	}
}

// lastPlannedIPs is the planned address count of the latest scan.
func (s *CfScannerRunner) lastPlannedIPs() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastPlanned
}
