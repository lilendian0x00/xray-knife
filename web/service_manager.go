package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	pkghttp "github.com/lilendian0x00/xray-knife/v5/pkg/http"
	"github.com/lilendian0x00/xray-knife/v5/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v5/pkg/scanner"
)

const cfScannerHistoryFile = "results.csv"
const httpTesterHistoryFile = "http-results.csv"

// ServiceManager holds the state of the running proxy and scanner services.
type ServiceManager struct {
	mu                 sync.Mutex
	logger             *log.Logger
	hub                *Hub
	proxyService       *proxy.Service
	proxyCancelFunc    context.CancelFunc
	proxyForceRotate   chan struct{}
	proxyStatus        string
	scannerCancelFunc  context.CancelFunc
	scannerWg          sync.WaitGroup
	isScanning         bool
	httpTestCancelFunc context.CancelFunc
	httpTestWg         sync.WaitGroup
	httpTestStatus     string // Changed from isHttpTesting
}

// NewServiceManager creates a new service manager.
func NewServiceManager(logger *log.Logger, hub *Hub) *ServiceManager {
	return &ServiceManager{
		logger:         logger,
		hub:            hub,
		proxyStatus:    "stopped",
		httpTestStatus: "idle", // Initial state
	}
}

// recoverAndLogPanic is a helper to gracefully handle and log panics in goroutines.
func (sm *ServiceManager) recoverAndLogPanic() {
	if r := recover(); r != nil {
		sm.logger.Printf("[CRITICAL] A goroutine panicked: %v\n%s\n", r, string(debug.Stack()))
	}
}

func (sm *ServiceManager) GetProxyStatus() string {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.proxyStatus
}

func (sm *ServiceManager) GetProxyDetails() (*proxy.Details, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.proxyService == nil {
		return nil, fmt.Errorf("proxy service not running")
	}
	return sm.proxyService.GetCurrentDetails(), nil
}

func (sm *ServiceManager) StartProxy(cfg proxy.Config) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.proxyCancelFunc != nil {
		sm.proxyCancelFunc() // Stop previous instance if any
	}

	sm.proxyStatus = "starting"
	service, err := proxy.New(cfg, sm.logger)
	if err != nil {
		sm.proxyStatus = "stopped"
		return fmt.Errorf("failed to create proxy service: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sm.proxyService = service
	sm.proxyCancelFunc = cancel
	sm.proxyForceRotate = make(chan struct{})

	go func() {
		defer sm.recoverAndLogPanic()
		defer func() {
			sm.mu.Lock()
			sm.proxyService = nil
			sm.proxyCancelFunc = nil
			sm.proxyForceRotate = nil
			sm.proxyStatus = "stopped"
			sm.mu.Unlock()
		}()

		sm.mu.Lock()
		sm.proxyStatus = "running"
		sm.mu.Unlock()

		if err := service.Run(ctx, sm.proxyForceRotate); err != nil {
			sm.logger.Printf("Proxy service exited with error: %v", err)
		}
	}()

	return nil
}

func (sm *ServiceManager) StopProxy() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.proxyCancelFunc == nil {
		return fmt.Errorf("proxy service not running")
	}
	sm.proxyStatus = "stopping"
	sm.proxyCancelFunc()
	return nil
}

func (sm *ServiceManager) RotateProxy() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.proxyForceRotate == nil {
		return fmt.Errorf("proxy service not running or not in rotation mode")
	}

	select {
	case sm.proxyForceRotate <- struct{}{}:
		return nil
	default:
		return fmt.Errorf("failed to send rotate signal (proxy is busy)")
	}
}

func (sm *ServiceManager) GetHttpTestStatus() string {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.httpTestStatus
}

func (sm *ServiceManager) StartHttpTest(req pkghttp.HttpTestRequest) error {
	sm.mu.Lock()
	if sm.httpTestStatus != "idle" {
		sm.mu.Unlock()
		return fmt.Errorf("an HTTP test is already in progress")
	}

	// Clear previous history before starting a new test
	if err := os.Remove(httpTesterHistoryFile); err != nil && !os.IsNotExist(err) {
		// Log the error but don't necessarily block the test from starting
		sm.logger.Printf("Warning: could not clear previous http test history file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sm.httpTestStatus = "testing"
	sm.httpTestCancelFunc = cancel
	sm.httpTestWg.Add(1)
	sm.mu.Unlock()

	go func() {
		defer sm.recoverAndLogPanic()
		defer sm.httpTestWg.Done()
		defer func() {
			sm.mu.Lock()
			finalStatus := "finished"
			if ctx.Err() != nil {
				finalStatus = "stopped"
			}
			sm.httpTestStatus = "idle"
			sm.httpTestCancelFunc = nil
			sm.mu.Unlock()

			sm.logger.Printf("HTTP test has %s.", finalStatus)
			statusMsg, _ := json.Marshal(map[string]interface{}{"type": "http_test_status", "data": finalStatus})
			sm.hub.Broadcast(statusMsg)
		}()

		sm.logger.Printf("Starting HTTP test for %d links with %d threads.", len(req.Links), req.ThreadCount)
		examiner, err := pkghttp.NewExaminer(req.Options)
		if err != nil {
			sm.logger.Printf("Failed to create examiner: %v", err)
			return
		}
		testManager := pkghttp.NewTestManager(examiner, req.ThreadCount, false, sm.logger)
		resultsChan := make(chan *pkghttp.Result, req.ThreadCount)

		var consumerWg sync.WaitGroup
		consumerWg.Add(1)

		go func() {
			defer sm.recoverAndLogPanic()
			defer consumerWg.Done()

			// Batching logic for saving results to CSV
			const saveBatchSize = 50
			const saveInterval = 5 * time.Second
			batch := make([]*pkghttp.Result, 0, saveBatchSize)
			ticker := time.NewTicker(saveInterval)
			defer ticker.Stop()

			save := func() {
				if len(batch) == 0 {
					return
				}
				if err := appendResultsToCSV(httpTesterHistoryFile, batch); err != nil {
					sm.logger.Printf("HTTP test history save failed: %v", err)
				}
				batch = make([]*pkghttp.Result, 0, saveBatchSize) // Reset batch
			}

			for {
				select {
				case result, ok := <-resultsChan:
					if !ok {
						save() // Save any remaining results
						return
					}
					// Broadcast to UI
					jsonResult, err := json.Marshal(map[string]interface{}{"type": "http_result", "data": result})
					if err == nil {
						sm.hub.Broadcast(jsonResult)
					}
					// Add to batch for saving
					batch = append(batch, result)
					if len(batch) >= saveBatchSize {
						save()
					}
				case <-ticker.C:
					save()
				case <-ctx.Done():
					save() // Final save on context cancellation
					return
				}
			}
		}()

		testManager.RunTests(ctx, req.Links, resultsChan)
		close(resultsChan)
		consumerWg.Wait()
	}()
	return nil
}

func (sm *ServiceManager) StopHttpTest() {
	sm.mu.Lock()
	if sm.httpTestStatus != "testing" || sm.httpTestCancelFunc == nil {
		sm.mu.Unlock()
		return
	}
	sm.logger.Println("HTTP test stop signal received. Cancelling context.")
	sm.httpTestStatus = "stopping"
	sm.httpTestCancelFunc()
	sm.mu.Unlock()

	sm.httpTestWg.Wait()
}

func (sm *ServiceManager) GetScannerStatus() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.isScanning
}

func (sm *ServiceManager) StartScanner(cfg scanner.ScannerConfig) error {
	sm.mu.Lock()
	if sm.isScanning {
		sm.mu.Unlock()
		return fmt.Errorf("a scan is already in progress")
	}

	cfg.OutputFile = cfScannerHistoryFile
	cfg.Verbose = true // Ensure core logs are generated for the web UI

	service, err := scanner.NewScannerService(cfg, sm.logger)
	if err != nil {
		sm.mu.Unlock()
		return fmt.Errorf("failed to create scanner service: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	sm.isScanning = true
	sm.scannerCancelFunc = cancel
	sm.scannerWg.Add(1)
	sm.mu.Unlock()

	go func() {
		defer sm.recoverAndLogPanic()
		defer func() {
			sm.mu.Lock()
			sm.isScanning = false
			sm.scannerCancelFunc = nil
			sm.mu.Unlock()

			sm.logger.Println("[SCAN-STATUS] Scan goroutine finished.")
			statusMsg, _ := json.Marshal(map[string]interface{}{"type": "cfscan_status", "data": "finished"})
			sm.hub.Broadcast(statusMsg)

			sm.scannerWg.Done()
		}()

		progressChan := make(chan *scanner.ScanResult, cfg.ThreadCount)

		go func() {
			defer sm.recoverAndLogPanic()
			for result := range progressChan {
				result.PrepareForMarshal()
				jsonResult, err := json.Marshal(map[string]interface{}{"type": "cfscan_result", "data": result})
				if err == nil {
					sm.hub.Broadcast(jsonResult)
				}
			}
		}()

		if err := service.Run(ctx, progressChan); err != nil {
			if !strings.Contains(err.Error(), "context canceled") {
				sm.logger.Printf("[SCAN-STATUS] Scan exited with error: %v", err)
				statusMsg, _ := json.Marshal(map[string]interface{}{"type": "cfscan_status", "data": "error", "message": err.Error()})
				sm.hub.Broadcast(statusMsg)
			}
		}
	}()
	return nil
}

func (sm *ServiceManager) StopScanner() {
	sm.mu.Lock()
	if !sm.isScanning || sm.scannerCancelFunc == nil {
		sm.mu.Unlock()
		return
	}
	sm.logger.Println("[SCAN-STATUS] Received stop request. Cancelling context...")
	sm.scannerCancelFunc()
	sm.mu.Unlock()

	sm.logger.Println("[SCAN-STATUS] Waiting for scanner to terminate...")
	sm.scannerWg.Wait()
	sm.logger.Println("[SCAN-STATUS] Scanner terminated successfully.")
}
