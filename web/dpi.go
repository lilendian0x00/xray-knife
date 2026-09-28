package web

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/dpi"
)

// DPI request limits: every spec × SNI pair is a profile, and each profile
// opens Attempts connections to one server.
const (
	maxDpiSpecs    = 128
	maxDpiSNIs     = 16
	maxDpiProfiles = 1024
)

// dpiStartRequest is the body of POST /dpi/start; it mirrors dpi.Options.
type dpiStartRequest struct {
	Link          string   `json:"link"`
	Core          string   `json:"core"` // auto (default), xray, sing-box
	TestURL       string   `json:"testURL"`
	TimeoutMs     int      `json:"timeoutMs"`
	Attempts      int      `json:"attempts"`
	Threads       int      `json:"threads"`
	Mode          string   `json:"mode"` // quick (default) or full
	Specs         []string `json:"specs"`
	SNIs          []string `json:"snis"`
	MixedCaseSNI  bool     `json:"mixedCaseSNI"`
	StopAfter     int      `json:"stopAfter"`
	Insecure      bool     `json:"insecure"`
	BindInterface string   `json:"bindInterface"`
}

// buildDpiOptions validates a request into dpi.Options. It rejects what can
// be checked up front (bad link, mode, specs, limits) so the caller gets a
// 400 instead of an asynchronous error event.
func buildDpiOptions(req dpiStartRequest) (dpi.Options, error) {
	opts := dpi.Options{
		Link:          strings.TrimSpace(req.Link),
		TestURL:       strings.TrimSpace(req.TestURL),
		Attempts:      req.Attempts,
		Threads:       req.Threads,
		MixedCaseSNI:  req.MixedCaseSNI,
		StopAfter:     req.StopAfter,
		Insecure:      req.Insecure,
		BindInterface: strings.TrimSpace(req.BindInterface),
	}
	if opts.Link == "" {
		return opts, badRequest("link is required")
	}
	switch strings.ToLower(strings.TrimSpace(req.Core)) {
	case "", "auto":
		opts.CoreType = core.AutoCoreType
	case "xray":
		opts.CoreType = core.XrayCoreType
	case "sing-box", "singbox":
		opts.CoreType = core.SingboxCoreType
	default:
		return opts, badRequest("core must be auto, xray or sing-box")
	}
	mode, err := dpi.ParseMode(req.Mode)
	if err != nil {
		return opts, badRequest("%v", err)
	}
	opts.Mode = mode
	if req.TimeoutMs < 0 || req.TimeoutMs > 60000 {
		return opts, badRequest("timeoutMs must be between 0 (default 8000) and 60000")
	}
	opts.Timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	if req.Attempts < 0 || req.Attempts > 50 {
		return opts, badRequest("attempts must be between 0 (default 3) and 50")
	}
	if req.Threads < 0 || req.Threads > 64 {
		return opts, badRequest("threads must be between 0 (default 4) and 64")
	}
	if req.StopAfter < 0 {
		return opts, badRequest("stopAfter must not be negative")
	}
	if opts.TestURL != "" {
		u, err := url.Parse(opts.TestURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return opts, badRequest("testURL must be an http(s) URL")
		}
	}
	if len(req.Specs) > maxDpiSpecs {
		return opts, badRequest("at most %d specs", maxDpiSpecs)
	}
	if len(req.SNIs) > maxDpiSNIs {
		return opts, badRequest("at most %d SNIs", maxDpiSNIs)
	}
	for _, spec := range req.Specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		// "none"/"off" is the baseline; anything else must parse.
		if _, err := fragment.Parse(spec); err != nil {
			return opts, badRequest("invalid spec %q: %v", spec, err)
		}
		opts.Specs = append(opts.Specs, spec)
	}
	for _, sni := range req.SNIs {
		if sni = strings.TrimSpace(sni); sni != "" {
			if strings.ContainsAny(sni, " /:@") {
				return opts, badRequest("invalid SNI %q", sni)
			}
			opts.SNIs = append(opts.SNIs, sni)
		}
	}

	specCount := len(opts.Specs)
	if specCount == 0 {
		specCount = len(dpi.Specs(mode))
	}
	sniCount := len(opts.SNIs)
	if opts.MixedCaseSNI {
		sniCount++
	}
	if profiles := specCount * (1 + sniCount); profiles > maxDpiProfiles {
		return opts, badRequest("%d profiles (specs × SNIs) is too many; at most %d", profiles, maxDpiProfiles)
	}

	// Parse the link now so an unusable one is a 400, not a failed run.
	parser := core.NewAutomaticCore(false, req.Insecure)
	if opts.CoreType != core.AutoCoreType {
		parser = core.CoreFactory(opts.CoreType, req.Insecure, false)
	}
	p, err := parser.CreateProtocol(opts.Link)
	if err != nil {
		return opts, badRequest("invalid config link: %v", err)
	}
	if err := p.Parse(); err != nil {
		return opts, badRequest("invalid config link: %v", err)
	}
	if _, ok := p.(protocol.Prober); ok {
		return opts, badRequest("MTProto proxies are not tunnelled through a core; test them in the HTTP tester")
	}
	return opts, nil
}

// DpiRunner runs one DPI finder at a time.
type DpiRunner struct {
	*BaseService
	total, done atomic.Int32

	reportMu   sync.Mutex
	lastReport *dpi.Report
	results    []dpi.Result // results of the current/last run, in finish order

	// run is dpi.Run, swappable in tests.
	runFn func(context.Context, dpi.Options) (*dpi.Report, error)
}

func NewDpiRunner(logger *log.Logger, hub *Hub) *DpiRunner {
	d := &DpiRunner{BaseService: NewBaseService("dpi", logger, hub), runFn: dpi.Run}
	d.statusData = func(status string) any {
		return map[string]any{"state": status, "total": int(d.total.Load()), "done": int(d.done.Load())}
	}
	return d
}

// Start accepts dpi.Options (already validated).
func (d *DpiRunner) Start(config interface{}) error {
	opts, ok := config.(dpi.Options)
	if !ok {
		return fmt.Errorf("invalid config type for dpi service")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rn, err := d.beginRunLocked(context.Background())
	if err != nil {
		return err
	}
	d.total.Store(0)
	d.done.Store(0)
	d.reportMu.Lock()
	d.lastReport, d.results = nil, nil
	d.reportMu.Unlock()
	rn.publishStatus("starting", nil)
	go d.run(rn, opts)
	return nil
}

func (d *DpiRunner) run(rn *run, opts dpi.Options) {
	final, event := StateFinished, "finished"
	extra := map[string]any{}
	defer func() {
		if r := recover(); r != nil {
			d.logger.Printf("[CRITICAL] Goroutine for service '%s' panicked: %v\n%s\n", d.serviceType, r, string(debug.Stack()))
			final, event = StateError, "error"
			extra["error"] = fmt.Sprintf("dpi finder crashed: %v", r)
		}
		if rn.stopRequested() && final != StateError {
			final, event = StateIdle, "stopped"
		}
		rn.finish(final, event, extra)
	}()

	rn.setReporters(func() map[string]int {
		return map[string]int{"completed": int(d.done.Load()), "total": int(d.total.Load())}
	}, nil)
	if !rn.setState(StateRunning) {
		return
	}

	opts.OnStart = func(profiles []dpi.Profile) {
		d.total.Store(int32(len(profiles)))
		d.hub.Publish("dpi_profiles", profiles, map[string]any{"runId": rn.id})
		rn.publishStatus("running", nil)
	}
	opts.OnResult = func(r dpi.Result) {
		d.done.Add(1)
		d.reportMu.Lock()
		d.results = append(d.results, r)
		d.reportMu.Unlock()
		d.hub.Publish("dpi_result", r, map[string]any{"runId": rn.id, "done": int(d.done.Load()), "total": int(d.total.Load())})
	}

	report, err := d.runFn(rn.ctx, opts)
	if err != nil {
		if errors.Is(err, context.Canceled) || rn.stopRequested() {
			return
		}
		final, event = StateError, "error"
		extra["error"] = err.Error()
		d.logger.Printf("[DPI] finder failed: %v", err)
		return
	}
	d.reportMu.Lock()
	d.lastReport = report
	d.reportMu.Unlock()
	d.hub.Publish("dpi_report", report, map[string]any{"runId": rn.id, "durationMs": report.Duration.Milliseconds()})
	extra["verdict"] = report.Verdict
}

// Report returns the last completed report (nil if none) and the results
// streamed so far for the current or last run.
func (d *DpiRunner) Report() (*dpi.Report, []dpi.Result) {
	d.reportMu.Lock()
	defer d.reportMu.Unlock()
	return d.lastReport, append([]dpi.Result(nil), d.results...)
}

// --- handlers ---

func (h *APIHandler) registerDpiRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/dpi/start", h.handleDpiStart)
	mux.HandleFunc("POST /api/v1/dpi/stop", h.handleDpiStop)
	mux.HandleFunc("GET /api/v1/dpi/status", h.handleDpiStatus)
	mux.HandleFunc("GET /api/v1/dpi/defaults", h.handleDpiDefaults)
}

func (h *APIHandler) handleDpiStart(w http.ResponseWriter, r *http.Request) {
	var req dpiStartRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	opts, err := buildDpiOptions(req)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := h.manager.dpi.Start(opts); err != nil {
		writeError(w, err, http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusAccepted, map[string]any{"status": "DPI finder started", "runId": h.manager.dpi.Snapshot().RunID})
}

func (h *APIHandler) handleDpiStop(w http.ResponseWriter, r *http.Request) {
	if err := h.manager.dpi.Stop(); err != nil {
		writeError(w, err, http.StatusConflict)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "DPI finder stopped"})
}

func (h *APIHandler) handleDpiStatus(w http.ResponseWriter, r *http.Request) {
	snap := h.manager.dpi.Snapshot()
	report, results := h.manager.dpi.Report()
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"status":  snap.Status,
		"runId":   snap.RunID,
		"total":   int(h.manager.dpi.total.Load()),
		"done":    int(h.manager.dpi.done.Load()),
		"error":   snap.Error,
		"results": results,
		"report":  report,
	})
}

// handleDpiDefaults lists the built-in candidate specs, so the UI can show
// (and let users edit) what quick and full modes will try.
func (h *APIHandler) handleDpiDefaults(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"testURL": dpi.DefaultTestURL,
		"modes": map[string][]string{
			"quick": dpi.Specs(dpi.ModeQuick),
			"full":  dpi.Specs(dpi.ModeFull),
		},
		"defaults": map[string]int{"timeoutMs": 8000, "attempts": 3, "threads": 4},
	})
}
