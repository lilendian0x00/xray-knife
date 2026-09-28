package web

import (
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v11/pkg/scanner"

	"github.com/lilendian0x00/xray-knife/v11/utils/xkhome"
)

// History files live in the xray-knife state directory. They are resolved
// lazily (resolveHistoryPaths) rather than in init(), so importing the
// package has no filesystem side effects; tests override the variables.
var cfScannerHistoryFile string
var httpTesterHistoryFile string

var historyPathsMu sync.Mutex

// resolveHistoryPaths fills in the history file paths that are still unset.
func resolveHistoryPaths() {
	historyPathsMu.Lock()
	defer historyPathsMu.Unlock()
	if cfScannerHistoryFile != "" && httpTesterHistoryFile != "" {
		return
	}
	dataDir, err := xkhome.Dir()
	if err != nil {
		// Fallback to current directory if the state dir is unavailable
		dataDir = "."
	}
	if cfScannerHistoryFile == "" {
		cfScannerHistoryFile = filepath.Join(dataDir, "results.csv")
	}
	if httpTesterHistoryFile == "" {
		httpTesterHistoryFile = filepath.Join(dataDir, "http-results.csv")
	}
}

// ServiceManager holds a registry of all available background services.
type ServiceManager struct {
	services  map[string]ManagedService
	proxy     *ProxyServiceRunner
	http      *HttpTestRunner
	scanner   *CfScannerRunner
	dpi       *DpiRunner
	done      chan struct{}
	closeOnce sync.Once
}

// NewServiceManager sets up the service registry and registers all available services.
func NewServiceManager(logger *log.Logger, hub *Hub) *ServiceManager {
	resolveHistoryPaths()
	sm := &ServiceManager{
		services: make(map[string]ManagedService),
		proxy:    NewProxyServiceRunner(logger, hub),
		http:     NewHttpTestRunner(logger, hub),
		scanner:  NewCfScannerRunner(logger, hub),
		dpi:      NewDpiRunner(logger, hub),
		done:     make(chan struct{}),
	}
	sm.registerService(sm.proxy)
	sm.registerService(sm.http)
	sm.registerService(sm.scanner)
	sm.registerService(sm.dpi)

	// Goroutine to periodically push proxy details
	go sm.proxyDetailsBroadcaster(hub)
	return sm
}

// proxyDetailsBroadcaster broadcast proxy details if the service is running.
func (sm *ServiceManager) proxyDetailsBroadcaster(hub *Hub) {
	ticker := time.NewTicker(2 * time.Second) // Broadcast every 2 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if sm.proxy.Status() == StateRunning {
				details, err := sm.GetProxyDetails()
				if err == nil && details != nil {
					hub.Publish("proxy_details", details, nil)
				}
			}
		case <-sm.done:
			return
		}
	}
}

// Close stops all running services and background goroutines of the ServiceManager.
func (sm *ServiceManager) Close() {
	sm.closeOnce.Do(func() {
		// Stop the proxy first so system proxy settings are restored on
		// shutdown, then the others in parallel.
		if isActive(sm.proxy.Status()) {
			_ = sm.proxy.Stop()
		}
		var wg sync.WaitGroup
		for _, svc := range []ManagedService{sm.http, sm.scanner, sm.dpi} {
			if isActive(svc.Status()) {
				wg.Add(1)
				go func(svc ManagedService) {
					defer wg.Done()
					_ = svc.Stop()
				}(svc)
			}
		}
		wg.Wait()
		close(sm.done)
	})
}

// EmergencyCleanup undoes the proxy's host changes before a forced exit.
func (sm *ServiceManager) EmergencyCleanup(timeout time.Duration) {
	sm.proxy.EmergencyCleanup(timeout)
}

func isActive(s ServiceState) bool {
	return s == StateRunning || s == StateStarting || s == StateStopping
}

func (sm *ServiceManager) registerService(s ManagedService) {
	sm.services[s.Type()] = s
}

// StateSnapshot is the body of GET /state and of the SSE "state" event.
type StateSnapshot struct {
	Seq      uint64                     `json:"seq"`
	Services map[string]ServiceSnapshot `json:"services"`
}

// Snapshot returns the state of every service.
func (sm *ServiceManager) Snapshot(seq uint64) StateSnapshot {
	proxySnap := sm.proxy.Snapshot()
	proxySnap.Status = proxyStatusString(sm.proxy.Status())
	return StateSnapshot{
		Seq: seq,
		Services: map[string]ServiceSnapshot{
			"proxy":  proxySnap,
			"http":   sm.http.Snapshot(),
			"cfscan": sm.scanner.Snapshot(),
			"dpi":    sm.dpi.Snapshot(),
		},
	}
}

// --- Proxy Methods ---

func (sm *ServiceManager) StartProxy(cfg proxy.Config) error {
	return sm.proxy.Start(cfg)
}

func (sm *ServiceManager) StopProxy() error {
	return sm.proxy.Stop()
}

func proxyStatusString(s ServiceState) string {
	// Convert ServiceState to the string values expected by the frontend
	switch s {
	case StateRunning:
		return "running"
	case StateStarting:
		return "starting"
	case StateStopping:
		return "stopping"
	case StateError:
		return "error"
	default:
		return "stopped"
	}
}

func (sm *ServiceManager) GetProxyStatus() string {
	return proxyStatusString(sm.proxy.Status())
}

// ProxyRunID is the ID of the current (or last) proxy run.
func (sm *ServiceManager) ProxyRunID() uint64 { return sm.proxy.Snapshot().RunID }

func (sm *ServiceManager) GetProxyDetails() (*proxy.Details, error) {
	return sm.proxy.GetDetails()
}

func (sm *ServiceManager) RotateProxy() error {
	return sm.proxy.Rotate()
}

// --- HTTP Tester Methods ---

func (sm *ServiceManager) StartHttpTest(job *HttpTestJob) error {
	return sm.http.Start(job)
}

func (sm *ServiceManager) StopHttpTest() error {
	return sm.http.Stop()
}

// GetHttpTestStatus returns idle|starting|running|stopping|finished|error.
func (sm *ServiceManager) GetHttpTestStatus() string {
	return string(sm.http.Status())
}

// HttpRunID is the ID of the current (or last) HTTP test run.
func (sm *ServiceManager) HttpRunID() uint64 { return sm.http.Snapshot().RunID }

// --- CF Scanner Methods ---

func (sm *ServiceManager) StartScanner(cfg scanner.ScannerConfig) error {
	job, err := buildCfScanJob(cfg)
	if err != nil {
		return err
	}
	return sm.scanner.Start(job)
}

func (sm *ServiceManager) StopScanner() error {
	return sm.scanner.Stop()
}

// GetScannerStatus reports whether a scan is in flight (including stopping).
func (sm *ServiceManager) GetScannerStatus() bool {
	return isActive(sm.scanner.Status())
}

// ScannerState returns idle|starting|running|stopping|finished|error.
func (sm *ServiceManager) ScannerState() string { return string(sm.scanner.Status()) }

// ScannerRunID is the ID of the current (or last) scan.
func (sm *ServiceManager) ScannerRunID() uint64 { return sm.scanner.Snapshot().RunID }
