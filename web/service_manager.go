package web

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	pkghttp "github.com/lilendian0x00/xray-knife/v7/pkg/http"
	"github.com/lilendian0x00/xray-knife/v7/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v7/pkg/scanner"
)

const cfScannerHistoryFile = "results.csv"
const httpTesterHistoryFile = "http-results.csv"

// ServiceManager holds a registry of all available background services.
type ServiceManager struct {
	services map[string]ManagedService
}

// NewServiceManager creates a new service manager and initializes all services.
func NewServiceManager(logger *log.Logger, hub *Hub) *ServiceManager {
	sm := &ServiceManager{
		services: make(map[string]ManagedService),
	}
	// Register all the available services
	sm.registerService(NewProxyServiceRunner(logger, hub))
	sm.registerService(NewHttpTestRunner(logger, hub))
	sm.registerService(NewCfScannerRunner(logger, hub))

	// Goroutine to periodically push proxy details
	go sm.proxyDetailsBroadcaster(hub)
	return sm
}

// proxyDetailsBroadcaster broadcast proxy details if the service is running.
func (sm *ServiceManager) proxyDetailsBroadcaster(hub *Hub) {
	ticker := time.NewTicker(2 * time.Second) // Broadcast every 2 seconds
	defer ticker.Stop()

	for range ticker.C {
		if sm.GetProxyStatus() == "running" {
			details, err := sm.GetProxyDetails()
			if err == nil && details != nil {
				payload, _ := json.Marshal(map[string]interface{}{
					"type": "proxy_details",
					"data": details,
				})
				hub.Broadcast(payload)
			}
		}
	}
}

func (sm *ServiceManager) registerService(s ManagedService) {
	sm.services[s.Type()] = s
}

func (sm *ServiceManager) getService(serviceType string) (ManagedService, error) {
	service, ok := sm.services[serviceType]
	if !ok {
		return nil, fmt.Errorf("service '%s' not found", serviceType)
	}
	return service, nil
}

// --- Proxy Methods ---

func (sm *ServiceManager) StartProxy(cfg proxy.Config) error {
	service, err := sm.getService("proxy")
	if err != nil {
		return err
	}
	return service.Start(cfg)
}

func (sm *ServiceManager) StopProxy() error {
	service, err := sm.getService("proxy")
	if err != nil {
		return err
	}
	return service.Stop()
}

func (sm *ServiceManager) GetProxyStatus() string {
	service, err := sm.getService("proxy")
	if err != nil {
		return "error"
	}
	// Convert ServiceState to the string values expected by the frontend
	switch service.Status() {
	case StateRunning:
		return "running"
	case StateStarting:
		return "starting"
	case StateStopping:
		return "stopping"
	default:
		return "stopped"
	}
}

func (sm *ServiceManager) GetProxyDetails() (*proxy.Details, error) {
	service, err := sm.getService("proxy")
	if err != nil {
		return nil, err
	}
	proxyRunner, ok := service.(*ProxyServiceRunner)
	if !ok {
		return nil, fmt.Errorf("internal error: service is not a ProxyServiceRunner")
	}
	return proxyRunner.GetDetails()
}

func (sm *ServiceManager) RotateProxy() error {
	service, err := sm.getService("proxy")
	if err != nil {
		return err
	}
	proxyRunner, ok := service.(*ProxyServiceRunner)
	if !ok {
		return fmt.Errorf("internal error: service is not a ProxyServiceRunner")
	}
	return proxyRunner.Rotate()
}

// --- HTTP Tester Methods ---

func (sm *ServiceManager) StartHttpTest(req pkghttp.HttpTestRequest) error {
	service, err := sm.getService("http-tester")
	if err != nil {
		return err
	}
	return service.Start(req)
}

func (sm *ServiceManager) StopHttpTest() {
	service, _ := sm.getService("http-tester")
	if service != nil {
		service.Stop()
	}
}

func (sm *ServiceManager) GetHttpTestStatus() string {
	service, err := sm.getService("http-tester")
	if err != nil {
		return "error"
	}
	// Convert ServiceState to the string values expected by the frontend
	switch service.Status() {
	case StateRunning:
		return "testing"
	case StateStopping:
		return "stopping"
	default:
		return "idle"
	}
}

// --- CF Scanner Methods ---

func (sm *ServiceManager) StartScanner(cfg scanner.ScannerConfig) error {
	service, err := sm.getService("cf-scanner")
	if err != nil {
		return err
	}
	return service.Start(cfg)
}

func (sm *ServiceManager) StopScanner() {
	service, _ := sm.getService("cf-scanner")
	if service != nil {
		service.Stop()
	}
}

func (sm *ServiceManager) GetScannerStatus() bool {
	service, err := sm.getService("cf-scanner")
	if err != nil {
		return false
	}
	return service.Status() == StateRunning || service.Status() == StateStarting
}
