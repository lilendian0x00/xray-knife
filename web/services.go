// web/services.go
package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilendian0x00/xray-knife/v7/database"
	pkghttp "github.com/lilendian0x00/xray-knife/v7/pkg/http"
	"github.com/lilendian0x00/xray-knife/v7/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v7/pkg/scanner"
	"github.com/lilendian0x00/xray-knife/v7/utils"
)

// ServiceState represents the lifecycle state of a managed service.
type ServiceState string

const (
	StateIdle     ServiceState = "idle"
	StateStarting ServiceState = "starting"
	StateRunning  ServiceState = "running"
	StateStopping ServiceState = "stopping"
	StateFinished ServiceState = "finished" // For tasks that complete
	StateError    ServiceState = "error"
)

// ManagedService defines the contract for a background service managed by the ServiceManager.
type ManagedService interface {
	Start(config interface{}) error
	Stop() error
	Status() ServiceState
	Type() string
}

// BaseService provides common functionality for all managed services.
type BaseService struct {
	mu          sync.Mutex
	state       ServiceState
	cancelFunc  context.CancelFunc
	wg          sync.WaitGroup
	logger      *log.Logger
	hub         *Hub
	serviceType string
}

// NewBaseService creates a new BaseService.
func NewBaseService(serviceType string, logger *log.Logger, hub *Hub) *BaseService {
	return &BaseService{
		state:       StateIdle,
		logger:      logger,
		hub:         hub,
		serviceType: serviceType,
	}
}

func (s *BaseService) recoverAndLogPanic() {
	if r := recover(); r != nil {
		s.logger.Printf("[CRITICAL] Goroutine for service '%s' panicked: %v\n%s\n", s.serviceType, r, string(debug.Stack()))
	}
}

// SetState safely updates the service's state.
func (s *BaseService) SetState(newState ServiceState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = newState
}

// Status safely returns the current state of the service.
func (s *BaseService) Status() ServiceState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Stop cancels the service's context and waits for it to finish.
func (s *BaseService) Stop() error {
	s.mu.Lock()
	if s.state != StateRunning && s.state != StateStarting {
		s.mu.Unlock()
		return fmt.Errorf("service '%s' is not running or starting", s.serviceType)
	}

	s.state = StateStopping
	s.logger.Printf("[%s] Stop signal received. Cancelling context.", strings.ToUpper(s.serviceType))
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	s.mu.Unlock()

	s.wg.Wait()
	s.logger.Printf("[%s] Service stopped successfully.", strings.ToUpper(s.serviceType))

	var messageType, finalState string
	switch s.serviceType { // stopped = idle in frontend
	case "proxy":
		messageType, finalState = "proxy_status", "stopped"
	case "http-tester":
		messageType, finalState = "http_test_status", "stopped"
	case "cf-scanner":
		messageType, finalState = "cfscan_status", "stopped"
	default:
		return nil
	}

	payload, err := json.Marshal(map[string]interface{}{"type": messageType, "data": finalState})
	if err == nil {
		s.hub.Broadcast(payload)
	}

	return nil
}

// Type returns the service type.
func (s *BaseService) Type() string {
	return s.serviceType
}

// reportProgress broadcasts progress updates periodically.
func (s *BaseService) reportProgress(ctx context.Context, completed *atomic.Int32, total int, messageType string) {
	if total == 0 {
		return
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check the service state before broadcasting. If it's no longer "running",
			// this goroutine belongs to a stale task and should exit immediately.
			if s.Status() != StateRunning {
				return
			}
			progress := map[string]interface{}{
				"type": messageType,
				"data": map[string]int{
					"completed": int(completed.Load()),
					"total":     total,
				},
			}
			jsonProgress, _ := json.Marshal(progress)
			s.hub.Broadcast(jsonProgress)
		case <-ctx.Done():
			return
		}
	}
}

// --- Proxy Service Runner ---

type ProxyServiceRunner struct {
	*BaseService
	service     *proxy.Service
	forceRotate chan struct{}
}

func NewProxyServiceRunner(logger *log.Logger, hub *Hub) *ProxyServiceRunner {
	return &ProxyServiceRunner{
		BaseService: NewBaseService("proxy", logger, hub),
	}
}

func (p *ProxyServiceRunner) Start(config interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state == StateRunning || p.state == StateStarting {
		return fmt.Errorf("proxy service is already running or starting")
	}

	cfg, ok := config.(proxy.Config)
	if !ok {
		return fmt.Errorf("invalid config type for proxy service")
	}

	p.state = StateStarting
	service, err := proxy.New(cfg, p.logger)
	if err != nil {
		p.state = StateError
		return fmt.Errorf("failed to create proxy service: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.service = service
	p.cancelFunc = cancel
	p.forceRotate = make(chan struct{})
	p.wg.Add(1)

	go p.run(ctx)

	return nil
}

func (p *ProxyServiceRunner) run(ctx context.Context) {
	defer p.recoverAndLogPanic()
	defer p.wg.Done()
	defer p.SetState(StateIdle)

	// Immediately set state to running and notify UI.
	p.SetState(StateRunning)
	statusMsgRunning, _ := json.Marshal(map[string]interface{}{"type": "proxy_status", "data": "running"})
	p.hub.Broadcast(statusMsgRunning)

	// This is the blocking call.
	if err := p.service.Run(ctx, p.forceRotate); err != nil {
		// Only broadcast the error if it was NOT caused by a user-initiated stop (context cancellation).
		// Stop() will send its own 'stopped' broadcast after wg.Wait() returns.
		if ctx.Err() == nil {
			p.logger.Printf("Proxy service exited with error: %v", err)
			statusMsgStopped, _ := json.Marshal(map[string]interface{}{
				"type":  "proxy_status",
				"data":  "stopped",
				"error": err.Error(),
			})
			p.hub.Broadcast(statusMsgStopped)
		}
	}
}

func (p *ProxyServiceRunner) GetDetails() (*proxy.Details, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.service == nil || p.state != StateRunning {
		return nil, fmt.Errorf("proxy service not running")
	}
	return p.service.GetCurrentDetails(), nil
}

func (p *ProxyServiceRunner) Rotate() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.forceRotate == nil {
		return fmt.Errorf("proxy service not running or not in rotation mode")
	}
	select {
	case p.forceRotate <- struct{}{}:
		return nil
	default:
		return fmt.Errorf("failed to send rotate signal (proxy is busy)")
	}
}

// --- HTTP Test Runner ---

type HttpTestRunner struct {
	*BaseService
}

func NewHttpTestRunner(logger *log.Logger, hub *Hub) *HttpTestRunner {
	return &HttpTestRunner{BaseService: NewBaseService("http-tester", logger, hub)}
}

func (ht *HttpTestRunner) Start(config interface{}) error {
	ht.mu.Lock()
	defer ht.mu.Unlock()

	if ht.state == StateRunning || ht.state == StateStarting {
		return fmt.Errorf("an HTTP test is already in progress")
	}

	req, ok := config.(pkghttp.HttpTestRequest)
	if !ok {
		return fmt.Errorf("invalid config type for http test service")
	}

	if err := os.Remove(httpTesterHistoryFile); err != nil && !os.IsNotExist(err) {
		ht.logger.Printf("Warning: could not clear previous http test history file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ht.cancelFunc = cancel
	ht.wg.Add(1)
	ht.state = StateStarting

	go ht.run(ctx, req)

	return nil
}

func (ht *HttpTestRunner) run(ctx context.Context, req pkghttp.HttpTestRequest) {
	defer ht.recoverAndLogPanic()
	defer ht.wg.Done()
	defer ht.SetState(StateIdle) // Final state should be idle

	ht.SetState(StateRunning)
	statusMsgRunning, _ := json.Marshal(map[string]interface{}{"type": "http_test_status", "data": "running"})
	ht.hub.Broadcast(statusMsgRunning)

	// Deduplicate links before testing
	req.Links, _ = pkghttp.DeduplicateLinks(req.Links)

	total := len(req.Links)
	var completed atomic.Int32
	go ht.reportProgress(ctx, &completed, total, "http_test_progress")

	examiner, err := pkghttp.NewExaminer(req.Options)
	if err != nil {
		ht.logger.Printf("Failed to create examiner: %v", err)
		ht.SetState(StateError)
		return
	}

	// Create a DB test run if SaveToDB is requested
	var runID int64
	if req.SaveToDB {
		optsJson, _ := json.Marshal(req.Options)
		runID, err = database.CreateHttpTestRun(string(optsJson), total)
		if err != nil {
			ht.logger.Printf("Warning: failed to create DB test run: %v", err)
		}
	}

	testManager := pkghttp.NewTestManager(examiner, req.ThreadCount, false, ht.logger)
	resultsChan := make(chan *pkghttp.Result, req.ThreadCount)

	var consumerWg sync.WaitGroup
	consumerWg.Add(1)
	go func() {
		defer consumerWg.Done()
		ht.consumeResults(ctx, resultsChan, runID)
	}()

	testManager.RunTests(ctx, req.Links, resultsChan, func() {
		completed.Add(1)
	})

	close(resultsChan)
	consumerWg.Wait()

	if ctx.Err() != nil {
		// Was cancelled, Stop() will send the 'stopped' message.
		return
	}

	ht.SetState(StateFinished) // Transient state to signal completion
	statusMsg, _ := json.Marshal(map[string]interface{}{"type": "http_test_status", "data": "finished"})
	ht.hub.Broadcast(statusMsg)
}

func (ht *HttpTestRunner) consumeResults(ctx context.Context, resultsChan <-chan *pkghttp.Result, runID int64) {
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
		if runID > 0 {
			dbResults := make([]database.HttpTestResult, 0, len(batch))
			for _, res := range batch {
				dbRes := database.HttpTestResult{
					RunID:      runID,
					ConfigLink: res.ConfigLink,
					Status:     res.Status,
					Reason:     sql.NullString{String: res.Reason, Valid: res.Reason != ""},
					DelayMs:    -1,
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
			if err := database.InsertHttpTestResultsBatch(runID, dbResults); err != nil {
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
			jsonResult, _ := json.Marshal(map[string]interface{}{"type": "http_result", "data": result})
			ht.hub.Broadcast(jsonResult)
			batch = append(batch, result)
			if len(batch) >= saveBatchSize {
				save()
			}
		case <-ticker.C:
			save()
		case <-ctx.Done():
			save()
			return
		}
	}
}

// --- CF Scanner Runner ---

type CfScannerRunner struct {
	*BaseService
}

func NewCfScannerRunner(logger *log.Logger, hub *Hub) *CfScannerRunner {
	return &CfScannerRunner{BaseService: NewBaseService("cf-scanner", logger, hub)}
}

func (s *CfScannerRunner) Start(config interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StateRunning || s.state == StateStarting {
		return fmt.Errorf("a scan is already in progress")
	}

	cfg, ok := config.(scanner.ScannerConfig)
	if !ok {
		return fmt.Errorf("invalid config type for cf scanner service")
	}

	cfg.OutputFile = cfScannerHistoryFile
	cfg.Verbose = false

	// Set up progress counter via instance-scoped callback (instead of global)
	var completed atomic.Int32
	cfg.OnIPScannedCallback = func() {
		completed.Add(1)
	}

	service, err := scanner.NewScannerService(cfg, s.logger)
	if err != nil {
		return fmt.Errorf("failed to create scanner service: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	s.cancelFunc = cancel
	s.wg.Add(1)
	s.state = StateStarting

	go s.run(ctx, service, cfg, &completed)

	return nil
}

func (s *CfScannerRunner) run(ctx context.Context, service *scanner.ScannerService, cfg scanner.ScannerConfig, completed *atomic.Int32) {
	defer s.recoverAndLogPanic()
	defer s.wg.Done()
	defer s.SetState(StateIdle) // Final state should be idle

	s.SetState(StateRunning)
	statusMsgRunning, _ := json.Marshal(map[string]interface{}{"type": "cfscan_status", "data": "running"})
	s.hub.Broadcast(statusMsgRunning)

	var totalIPs int
	for _, cidr := range cfg.Subnets {
		size, err := utils.CIDRSize(cidr)
		if err == nil {
			totalIPs += size
		}
	}

	go s.reportProgress(ctx, completed, totalIPs, "cf_scan_progress")

	progressChan := make(chan *scanner.ScanResult, cfg.ThreadCount)
	go func() {
		defer s.recoverAndLogPanic() // Also recover this goroutine
		for result := range progressChan {
			result.PrepareForMarshal()
			jsonResult, _ := json.Marshal(map[string]interface{}{"type": "cfscan_result", "data": result})
			s.hub.Broadcast(jsonResult)
		}
	}()

	if err := service.Run(ctx, progressChan); err != nil {
		if !strings.Contains(err.Error(), "context canceled") {
			s.logger.Printf("[SCAN-STATUS] Scan exited with error: %v", err)
			statusMsg, _ := json.Marshal(map[string]interface{}{"type": "cfscan_status", "data": "error", "message": err.Error()})
			s.hub.Broadcast(statusMsg)
			s.SetState(StateError)
			return
		}
	}

	if ctx.Err() != nil {
		// Was cancelled, Stop() will send the 'stopped' message.
		return
	}

	s.SetState(StateFinished)
	statusMsg, _ := json.Marshal(map[string]interface{}{"type": "cfscan_status", "data": "finished"})
	s.hub.Broadcast(statusMsg)
}
