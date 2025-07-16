package web

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/lilendian0x00/xray-knife/v5/cmd/scanner"
	pkghttp "github.com/lilendian0x00/xray-knife/v5/pkg/http"
	"github.com/lilendian0x00/xray-knife/v5/pkg/proxy"
)

// APIHandler holds dependencies for API endpoints.
type APIHandler struct {
	manager *ServiceManager
	logger  *log.Logger
}

// NewAPIHandler creates a new API handler.
func NewAPIHandler(manager *ServiceManager, logger *log.Logger) *APIHandler {
	return &APIHandler{manager: manager, logger: logger}
}

// RegisterRoutes sets up all the API routes.
func (h *APIHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/proxy/start", h.handleProxyStart)
	mux.HandleFunc("/api/v1/proxy/stop", h.handleProxyStop)
	mux.HandleFunc("/api/v1/proxy/rotate", h.handleProxyRotate)
	mux.HandleFunc("/api/v1/proxy/status", h.handleProxyStatus)
	mux.HandleFunc("/api/v1/proxy/details", h.handleProxyDetails)
	mux.HandleFunc("/api/v1/http/test", h.handleHttpTest)
	mux.HandleFunc("/api/v1/http/test/stop", h.handleHttpTestStop)
	mux.HandleFunc("/api/v1/scanner/cf/start", h.handleCfScannerStart)
	mux.HandleFunc("/api/v1/scanner/cf/stop", h.handleCfScannerStop)
	mux.HandleFunc("/api/v1/scanner/cf/status", h.handleCfScannerStatus)
	mux.HandleFunc("/api/v1/scanner/cf/history", h.handleCfScannerHistory)
	mux.HandleFunc("/api/v1/scanner/cf/clear_history", h.handleCfScannerClearHistory)
	mux.HandleFunc("/api/v1/scanner/cf/ranges", h.handleCfScannerRanges)
}

// --- Proxy Handlers ---

func (h *APIHandler) handleProxyStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var cfg proxy.Config
	if err := decodeJSONBody(w, r, &cfg); err != nil {
		writeJSONError(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	if err := h.manager.StartProxy(cfg); err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "Proxy service started"})
}

func (h *APIHandler) handleProxyStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := h.manager.StopProxy(); err != nil {
		writeJSONError(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "Proxy service stopped"})
}

func (h *APIHandler) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	status := h.manager.GetProxyStatus()
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": status})
}

func (h *APIHandler) handleProxyDetails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	details, err := h.manager.GetProxyDetails()
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSONResponse(w, http.StatusOK, details)
}

func (h *APIHandler) handleProxyRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := h.manager.RotateProxy(); err != nil {
		writeJSONError(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "Rotate signal sent"})
}

// --- HTTP Tester Handler ---

func (h *APIHandler) handleHttpTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	// This combines the flat fields and nested Options struct for decoding
	var requestBody struct {
		Links       []string `json:"links"`
		ThreadCount uint16   `json:"threadCount"`
		pkghttp.Options
	}

	if err := decodeJSONBody(w, r, &requestBody); err != nil {
		writeJSONError(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	req := pkghttp.HttpTestRequest{
		Links:       requestBody.Links,
		ThreadCount: requestBody.ThreadCount,
		Options:     requestBody.Options,
	}

	if err := h.manager.StartHttpTest(req); err != nil {
		writeJSONError(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusAccepted, map[string]string{"status": "HTTP test started"})
}

func (h *APIHandler) handleHttpTestStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	h.manager.StopHttpTest()
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "HTTP test stop signal sent"})
}

// --- CF Scanner Handlers ---

func (h *APIHandler) handleCfScannerStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var cfg scanner.ScannerConfig
	if err := decodeJSONBody(w, r, &cfg); err != nil {
		writeJSONError(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	if err := h.manager.StartScanner(cfg); err != nil {
		writeJSONError(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusAccepted, map[string]string{"status": "Scanner started"})
}

func (h *APIHandler) handleCfScannerStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	h.manager.StopScanner()
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "Scanner stopped"})
}

func (h *APIHandler) handleCfScannerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	isScanning := h.manager.GetScannerStatus()
	writeJSONResponse(w, http.StatusOK, map[string]bool{"is_scanning": isScanning})
}

func (h *APIHandler) handleCfScannerHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	results, err := scanner.LoadResultsForResume(cfScannerHistoryFile)
	if err != nil {
		results = []*scanner.ScanResult{} // Return empty list on error
	}
	writeJSONResponse(w, http.StatusOK, results)
}

func (h *APIHandler) handleCfScannerClearHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	err := os.Remove(cfScannerHistoryFile)
	if err != nil && !os.IsNotExist(err) {
		writeJSONError(w, fmt.Sprintf("Failed to clear history file: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "History cleared"})
}

var cloudflareRangesLink = []string{
	"https://www.cloudflare.com/ips-v4",
	"https://www.cloudflare.com/ips-v6",
}

var cloudflareRanges = []string{
	// IPv4 Fallback
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// IPv6 Fallback
	"2606:4700::/32",
	"2803:f800::/32",
	"2400:cb00::/32",
	"2c0f:f248::/32",
	"2a06:98c0::/29",
}

func (h *APIHandler) handleCfScannerRanges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	fetchAndSendRanges := func() {
		var wg sync.WaitGroup
		var mu sync.Mutex
		var allRanges []string
		var firstError error

		for _, u := range cloudflareRangesLink {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				resp, err := http.Get(url)
				if err != nil {
					mu.Lock()
					if firstError == nil {
						firstError = fmt.Errorf("failed to fetch %s: %w", url, err)
					}
					mu.Unlock()
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					mu.Lock()
					if firstError == nil {
						firstError = fmt.Errorf("bad status from %s: %s", url, resp.Status)
					}
					mu.Unlock()
					return
				}

				body, err := io.ReadAll(resp.Body)
				if err != nil {
					mu.Lock()
					if firstError == nil {
						firstError = fmt.Errorf("failed to read body from %s: %w", url, err)
					}
					mu.Unlock()
					return
				}

				mu.Lock()
				allRanges = append(allRanges, strings.Split(strings.TrimSpace(string(body)), "\n")...)
				mu.Unlock()
			}(u)
		}
		wg.Wait()

		if firstError != nil {
			h.logger.Printf("Failed to fetch live Cloudflare IP ranges, using fallback list. Error: %v", firstError)
			writeJSONResponse(w, http.StatusOK, map[string][]string{"ranges": cloudflareRanges})
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string][]string{"ranges": allRanges})
	}

	fetchAndSendRanges()
}
