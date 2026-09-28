package web

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gocarina/gocsv"
	"github.com/lilendian0x00/xray-knife/v11/database"
	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v11/pkg/scanner"
)

// appendResultsToCSV delegates to the shared implementation in pkg/http.
func appendResultsToCSV(filePath string, batch []*pkghttp.Result) error {
	return pkghttp.AppendResultsToCSV(filePath, batch)
}

// loadResultsFromCSV loads results from a CSV file into the provided slice pointer.
func loadResultsFromCSV(filePath string, v interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	if err := gocsv.UnmarshalFile(file, v); err != nil {
		if err.Error() == "EOF" {
			return nil
		}
		return fmt.Errorf("failed to parse CSV file: %w", err)
	}
	return nil
}

// APIHandler holds dependencies for API endpoints.
type APIHandler struct {
	manager *ServiceManager
	logger  *log.Logger
	// allowHostModes lets proxy/start use the app and host-tun modes.
	allowHostModes bool
	// info is served by GET /info.
	info func() map[string]any
	// hubSeq returns the current event sequence number for /state.
	hubSeq func() uint64
	// subTokens manages the public /sub/<token> URLs.
	subTokens *subTokenStore
	// subCache holds recent /sub selections (dropped when a token changes).
	subCache *selectionCache
}

func NewAPIHandler(manager *ServiceManager, logger *log.Logger) *APIHandler {
	return &APIHandler{manager: manager, logger: logger, hubSeq: func() uint64 { return 0 }, subTokens: &subTokenStore{now: time.Now}}
}

// RegisterRoutes wires up all API endpoints.
func (h *APIHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/state", h.handleState)
	mux.HandleFunc("/api/v1/info", h.handleInfo)

	mux.HandleFunc("/api/v1/proxy/start", h.handleProxyStart)
	mux.HandleFunc("/api/v1/proxy/stop", h.handleProxyStop)
	mux.HandleFunc("/api/v1/proxy/rotate", h.handleProxyRotate)
	mux.HandleFunc("/api/v1/proxy/status", h.handleProxyStatus)
	mux.HandleFunc("/api/v1/proxy/details", h.handleProxyDetails)
	mux.HandleFunc("POST /api/v1/proxy/deadman/confirm", h.handleProxyDeadmanConfirm)
	mux.HandleFunc("POST /api/v1/proxy/restore", h.handleProxyRestore)
	mux.HandleFunc("/api/v1/http/test", h.handleHttpTest)
	mux.HandleFunc("/api/v1/http/test/status", h.handleHttpTestStatus)
	mux.HandleFunc("/api/v1/http/test/stop", h.handleHttpTestStop)
	mux.HandleFunc("/api/v1/http/test/history", h.handleHttpTestHistory)
	mux.HandleFunc("/api/v1/http/test/clear_history", h.handleHttpTestClearHistory)
	mux.HandleFunc("/api/v1/scanner/cf/start", h.handleCfScannerStart)
	mux.HandleFunc("/api/v1/scanner/cf/stop", h.handleCfScannerStop)
	mux.HandleFunc("/api/v1/scanner/cf/status", h.handleCfScannerStatus)
	mux.HandleFunc("/api/v1/scanner/cf/history", h.handleCfScannerHistory)
	mux.HandleFunc("/api/v1/scanner/cf/clear_history", h.handleCfScannerClearHistory)
	mux.HandleFunc("/api/v1/scanner/cf/ranges", h.handleCfScannerRanges)

	h.registerSubscriptionRoutes(mux)
	h.registerHistoryRoutes(mux)
	h.registerDpiRoutes(mux)
	h.registerExportRoutes(mux)
	h.registerSubTokenRoutes(mux)
}

// --- State ---

func (h *APIHandler) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSONResponse(w, http.StatusOK, h.manager.Snapshot(h.hubSeq()))
}

func (h *APIHandler) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	info := map[string]any{}
	if h.info != nil {
		info = h.info()
	}
	writeJSONResponse(w, http.StatusOK, info)
}

// --- Proxy Handlers ---

func (h *APIHandler) handleProxyStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req proxyStartRequest
	if err := decodeJSONBodyLimit(w, r, &req, maxLargeBody); err != nil {
		writeDecodeError(w, err)
		return
	}
	cfg, err := validateProxyConfig(&req, h.allowHostModes)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := h.manager.StartProxy(cfg); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"status": "Proxy service started", "runId": h.manager.ProxyRunID()})
}

func (h *APIHandler) handleProxyStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := h.manager.StopProxy(); err != nil {
		writeError(w, err, http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "Proxy service stopped"})
}

func (h *APIHandler) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"status": h.manager.GetProxyStatus(), "runId": h.manager.ProxyRunID()})
}

func (h *APIHandler) handleProxyDetails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	details, err := h.manager.GetProxyDetails()
	if err != nil {
		writeError(w, err, http.StatusNotFound)
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
		writeError(w, err, http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "Rotate signal sent"})
}

func (h *APIHandler) handleProxyDeadmanConfirm(w http.ResponseWriter, r *http.Request) {
	if err := h.manager.proxy.ConfirmDeadman(); err != nil {
		writeError(w, err, http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"confirmed": true})
}

// restoreFn is proxy.Restore, swappable in tests.
var restoreFn = proxy.Restore

// handleProxyRestore removes what crashed app/tun runs left behind (kill
// switch rules, host-tun routes, namespaces, OS proxy settings). It is a
// host-networking operation, so it needs --allow-host-modes, and it refuses
// while this server's own proxy is active (force would tear it down).
func (h *APIHandler) handleProxyRestore(w http.ResponseWriter, r *http.Request) {
	if !h.allowHostModes {
		writeJSONErrorCode(w, "restore changes host networking; restart webui with --allow-host-modes or run `xray-knife proxy restore`", "host_modes_disabled", http.StatusForbidden)
		return
	}
	var body struct {
		Force bool `json:"force"`
	}
	if err := decodeOptionalJSONBody(w, r, &body, maxSmallBody); err != nil {
		writeDecodeError(w, err)
		return
	}
	if isActive(h.manager.proxy.Status()) {
		writeError(w, conflict(codeBusy, "stop the proxy before restoring"), http.StatusConflict)
		return
	}
	rep := restoreFn(body.Force)
	h.logger.Printf("[PROXY] restore (force=%v): %d removed, %d kept, %d errors", body.Force, len(rep.Removed), len(rep.Kept), len(rep.Errors))
	nonNil := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"removed": nonNil(rep.Removed),
		"kept":    nonNil(rep.Kept),
		"errors":  nonNil(rep.Errors),
		"clean":   rep.Empty(),
	})
}

// --- HTTP Tester Handler ---

// httpTestRequestBody is the flat body the UI posts. Examiner options sit beside
// links and threadCount rather than in a nested object.
type httpTestRequestBody struct {
	Links       []string `json:"links"`
	ThreadCount uint16   `json:"threadCount"`
	SaveToDB    bool     `json:"saveToDB"`

	// Link sources besides Links: a subscription's configs, or the whole DB.
	SubscriptionID int64  `json:"subscriptionId"`
	FromDB         bool   `json:"fromDB"`
	Protocol       string `json:"protocol"`
	Limit          int    `json:"limit"`

	// Batch controls mirrored from `xray-knife http`.
	DedupSemantic  *bool  `json:"dedupSemantic"`
	Prescan        bool   `json:"prescan"`
	PrescanTimeout uint16 `json:"prescanTimeout"`
	PrescanWorkers uint16 `json:"prescanWorkers"`
	MaxPassed      int    `json:"maxPassed"`
	CheckPreset    string `json:"checkPreset"`

	pkghttp.Options
}

// buildJob resolves links and options into a validated HttpTestJob.
func (body *httpTestRequestBody) buildJob(logger *log.Logger) (*HttpTestJob, error) {
	links := cleanLinks(body.Links)
	if body.SubscriptionID < 0 || body.Limit < 0 || body.MaxPassed < 0 {
		return nil, badRequest("subscriptionId, limit and maxPassed must not be negative")
	}
	if body.SubscriptionID > 0 || body.FromDB {
		if err := dbReady(); err != nil {
			return nil, err
		}
		if body.SubscriptionID > 0 {
			if _, err := database.GetSubscriptionByID(body.SubscriptionID); err != nil {
				return nil, notFound("%v", err)
			}
		}
		dbLinks, err := database.GetConfigsFromDB(body.SubscriptionID, body.Protocol, body.Limit)
		if err != nil {
			return nil, err
		}
		links = append(links, dbLinks...)
	}
	if len(links) == 0 {
		return nil, badRequest("no config links to test (give links, subscriptionId or fromDB)")
	}

	opts := body.Options
	if body.CheckPreset != "" && len(opts.TestEndpoints) == 0 {
		panel, ok := pkghttp.CheckPresets[body.CheckPreset]
		if !ok {
			return nil, badRequest("unknown checkPreset %q; available: %s", body.CheckPreset, strings.Join(pkghttp.PresetNames(), ", "))
		}
		opts.TestEndpoints = panel
	}
	if opts.SuccessThreshold < 0 || opts.SuccessThreshold > 1 {
		return nil, badRequest("successThreshold must be between 0 and 1")
	}

	job, err := buildHttpTestJob(pkghttp.HttpTestRequest{
		Links:       links,
		ThreadCount: body.ThreadCount,
		SaveToDB:    body.SaveToDB,
		Options:     opts,
	}, logger)
	if err != nil {
		return nil, err
	}
	if job.SaveToDB {
		if err := dbReady(); err != nil {
			return nil, err
		}
	}
	// Semantic dedup is the CLI default.
	job.DedupSemantic = body.DedupSemantic == nil || *body.DedupSemantic
	job.MaxPassed = body.MaxPassed
	if body.Prescan {
		job.Prescan = true
		timeout := body.PrescanTimeout
		if timeout == 0 {
			timeout = 2000
		}
		workers := body.PrescanWorkers
		if workers == 0 {
			workers = 512
		}
		job.PrescanOpts = pkghttp.PrescanOptions{
			Workers:       int(workers),
			Timeout:       time.Duration(timeout) * time.Millisecond,
			BindInterface: opts.BindInterface,
		}
	}
	return job, nil
}

func (h *APIHandler) handleHttpTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var requestBody httpTestRequestBody
	if err := decodeJSONBodyLimit(w, r, &requestBody, maxLargeBody); err != nil {
		writeDecodeError(w, err)
		return
	}
	h.startHttpTest(w, &requestBody)
}

func (h *APIHandler) startHttpTest(w http.ResponseWriter, body *httpTestRequestBody) {
	job, err := body.buildJob(h.logger)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := h.manager.StartHttpTest(job); err != nil {
		writeError(w, err, http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusAccepted, map[string]any{"status": "HTTP test started", "runId": h.manager.HttpRunID(), "total": len(job.Links)})
}

func (h *APIHandler) handleHttpTestStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"status": h.manager.GetHttpTestStatus(), "runId": h.manager.HttpRunID()})
}

func (h *APIHandler) handleHttpTestStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := h.manager.StopHttpTest(); err != nil {
		writeError(w, err, http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "HTTP test stopped"})
}

func (h *APIHandler) handleHttpTestHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	var results []*pkghttp.Result
	if err := loadResultsFromCSV(httpTesterHistoryFile, &results); err != nil {
		writeJSONError(w, fmt.Sprintf("failed to load http test history: %v", err), http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []*pkghttp.Result{}
	}
	writePaginatedResponse(w, r, results)
}

func (h *APIHandler) handleHttpTestClearHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if isActive(h.manager.http.Status()) {
		writeJSONErrorCode(w, "an HTTP test is running; stop it first", codeBusy, http.StatusConflict)
		return
	}
	err := os.Remove(httpTesterHistoryFile)
	if err != nil && !os.IsNotExist(err) {
		writeJSONError(w, fmt.Sprintf("Failed to clear http test history file: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "History cleared"})
}

// --- CF Scanner Handlers ---

func (h *APIHandler) handleCfScannerStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var cfg scanner.ScannerConfig
	if err := decodeJSONBodyLimit(w, r, &cfg, maxLargeBody); err != nil {
		writeDecodeError(w, err)
		return
	}
	job, err := buildCfScanJob(cfg)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := h.manager.scanner.Start(job); err != nil {
		writeError(w, err, http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusAccepted, map[string]any{"status": "Scanner started", "runId": h.manager.ScannerRunID(), "total": h.manager.scanner.lastPlannedIPs()})
}

func (h *APIHandler) handleCfScannerStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := h.manager.StopScanner(); err != nil {
		writeError(w, err, http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "Scanner stopped"})
}

func (h *APIHandler) handleCfScannerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"is_scanning": h.manager.GetScannerStatus(),
		"status":      h.manager.ScannerState(),
		"runId":       h.manager.ScannerRunID(),
	})
}

func (h *APIHandler) handleCfScannerHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	var results []*scanner.ScanResult
	if err := loadResultsFromCSV(cfScannerHistoryFile, &results); err != nil {
		writeJSONError(w, fmt.Sprintf("failed to load scanner history: %v", err), http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []*scanner.ScanResult{}
	}
	writePaginatedResponse(w, r, results)
}

func (h *APIHandler) handleCfScannerClearHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if h.manager.GetScannerStatus() {
		writeJSONErrorCode(w, "a scan is running; stop it first", codeBusy, http.StatusConflict)
		return
	}
	err := os.Remove(cfScannerHistoryFile)
	if err != nil && !os.IsNotExist(err) {
		writeJSONError(w, fmt.Sprintf("Failed to clear history file: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "History cleared"})
}

var cloudflareRangesV4Link = "https://www.cloudflare.com/ips-v4"
var cloudflareRangesV6Link = "https://www.cloudflare.com/ips-v6"

var cloudflareRangesV4 = []string{
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
}

var cloudflareRangesV6 = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

const (
	cfRangesCacheTTL    = 1 * time.Hour
	cfRangesFallbackTTL = 5 * time.Minute
)

// cfRanges caches Cloudflare's published ranges. The fetch runs outside the
// lock; concurrent callers wait for the one in flight.
type cfRangeCache struct {
	mu        sync.Mutex
	v4, v6    []string
	source    string
	fetchedAt time.Time
	expires   time.Time
	inflight  chan struct{}
	// fetch is swappable in tests.
	fetch func(ctx context.Context, url string) ([]string, error)
}

var cfRanges = &cfRangeCache{fetch: fetchPrefixList}

// fetchPrefixList downloads a newline-separated prefix list, keeping only
// lines that parse as prefixes.
func fetchPrefixList(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status from %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			continue
		}
		out = append(out, p.Masked().String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid prefixes from %s", url)
	}
	return out, nil
}

func (c *cfRangeCache) get(logger *log.Logger) (v4, v6 []string, source string, fetchedAt time.Time) {
	for {
		c.mu.Lock()
		if c.source != "" && time.Now().Before(c.expires) {
			v4, v6, source, fetchedAt = c.v4, c.v6, c.source, c.fetchedAt
			c.mu.Unlock()
			return
		}
		if c.inflight != nil {
			ch := c.inflight
			c.mu.Unlock()
			<-ch
			continue
		}
		ch := make(chan struct{})
		c.inflight = ch
		c.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var wg sync.WaitGroup
		var liveV4, liveV6 []string
		var errV4, errV6 error
		wg.Add(2)
		go func() { defer wg.Done(); liveV4, errV4 = c.fetch(ctx, cloudflareRangesV4Link) }()
		go func() { defer wg.Done(); liveV6, errV6 = c.fetch(ctx, cloudflareRangesV6Link) }()
		wg.Wait()
		cancel()

		c.mu.Lock()
		now := time.Now()
		if errV4 != nil || errV6 != nil {
			if logger != nil {
				logger.Printf("Failed to fetch live Cloudflare IP ranges, using fallback list. Error: %v", firstErr(errV4, errV6))
			}
			c.v4, c.v6, c.source = cloudflareRangesV4, cloudflareRangesV6, "fallback"
			c.expires = now.Add(cfRangesFallbackTTL)
		} else {
			c.v4, c.v6, c.source = liveV4, liveV6, "live"
			c.expires = now.Add(cfRangesCacheTTL)
		}
		c.fetchedAt = now
		c.inflight = nil
		close(ch)
		c.mu.Unlock()
	}
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *APIHandler) handleCfScannerRanges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	v4, v6, source, fetchedAt := cfRanges.get(h.logger)
	ranges := append([]string(nil), v4...)
	includeV6 := r.URL.Query().Get("v6") == "1" || r.URL.Query().Get("v6") == "true"
	if includeV6 {
		ranges = append(ranges, v6...)
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"ranges":    ranges,
		"v4":        v4,
		"v6":        v6,
		"source":    source,
		"fetchedAt": fetchedAt.UTC().Format(time.RFC3339),
	})
}
