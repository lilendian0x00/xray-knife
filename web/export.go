package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/convert"
)

// exportFormat describes one output format of the export endpoints.
type exportFormat struct {
	contentType string
	ext         string
}

// exportFormats are the formats pkg/convert can render. Clash clients look
// at the Content-Type loosely; text/yaml is what most panels send.
var exportFormats = map[string]exportFormat{
	"plain":   {"text/plain; charset=utf-8", "txt"},
	"base64":  {"text/plain; charset=utf-8", "txt"},
	"clash":   {"text/yaml; charset=utf-8", "yaml"},
	"singbox": {"application/json; charset=utf-8", "json"},
	"xray":    {"application/json; charset=utf-8", "json"},
}

// maxExportLinks bounds one export (a served subscription is fetched by
// phones on every refresh).
const maxExportLinks = 5000

// skippedView is the JSON form of convert.Skipped.
type skippedView struct {
	Index  int    `json:"index"`
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason"`
}

func skippedViews(r *convert.Report) []skippedView {
	if r == nil {
		return nil
	}
	out := make([]skippedView, 0, len(r.Skipped))
	for _, s := range r.Skipped {
		out = append(out, skippedView{Index: s.Index, Name: s.Name, Reason: s.Reason})
	}
	return out
}

// renderExport converts links to format. Plain and base64 keep every link,
// so their report just counts them.
func renderExport(format string, links []string, insecure bool) ([]byte, *convert.Report, error) {
	switch format {
	case "plain":
		return convert.ToPlain(links), &convert.Report{Converted: len(links)}, nil
	case "base64":
		return convert.ToBase64(links), &convert.Report{Converted: len(links)}, nil
	case "clash":
		return convert.ToClash(links, convert.ClashOptions{})
	case "singbox":
		return convert.ToSingbox(links, convert.SingboxOptions{InsecureTLS: insecure})
	case "xray":
		return convert.ToXray(links)
	}
	return nil, nil, badRequest("unknown format %q (want plain, base64, clash, singbox or xray)", format)
}

// exportQuery is what an export selects and how it renders it.
type exportQuery struct {
	Format          string
	Status          string // "", passed, semi-passed
	Protocol        string
	Limit           int
	SubscriptionIDs []int64
	MaxAge          time.Duration // only links tested within MaxAge (0 = any)
	Insecure        bool
}

// parseIDList reads "1,2,3".
func parseIDList(s string) ([]int64, error) {
	var ids []int64
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseInt(part, 10, 64)
		if err != nil || id <= 0 {
			return nil, badRequest("invalid subscription id %q", part)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// applyExportParams overlays URL query parameters on q.
func applyExportParams(q *exportQuery, v url.Values, limitParam string) error {
	if f := strings.ToLower(strings.TrimSpace(v.Get("format"))); f != "" {
		q.Format = f
	}
	if _, ok := exportFormats[q.Format]; !ok {
		return badRequest("unknown format %q (want plain, base64, clash, singbox or xray)", q.Format)
	}
	if st, ok := v["status"]; ok {
		q.Status = strings.ToLower(strings.TrimSpace(st[0]))
		if q.Status == "any" || q.Status == "all" {
			q.Status = ""
		}
	}
	if !database.ValidExportStatus(q.Status) {
		return badRequest("status must be passed, semi-passed or any")
	}
	if p := strings.TrimSpace(v.Get("protocol")); p != "" {
		q.Protocol = strings.ToLower(p)
	}
	if l := v.Get(limitParam); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 0 {
			return badRequest("%s must be a non-negative number", limitParam)
		}
		q.Limit = n
	}
	if q.Limit == 0 || q.Limit > maxExportLinks {
		if q.Limit > maxExportLinks {
			return badRequest("%s must be at most %d", limitParam, maxExportLinks)
		}
		q.Limit = maxExportLinks
	}
	if h := v.Get("maxAgeHours"); h != "" {
		n, err := strconv.Atoi(h)
		if err != nil || n < 0 {
			return badRequest("maxAgeHours must be a non-negative number")
		}
		q.MaxAge = time.Duration(n) * time.Hour
	}
	if ins := v.Get("insecure"); ins == "1" || ins == "true" {
		q.Insecure = true
	}
	return nil
}

// selectExportLinks runs the query against the DB: configs of the given
// subscriptions (or every enabled one), filtered by the status and age of
// each link's latest test, fastest first, capped at the limit. Filtering,
// ordering and the limit all happen in SQL.
func selectExportLinks(q exportQuery) ([]string, error) {
	f := database.ExportFilter{
		SubscriptionIDs: q.SubscriptionIDs,
		Protocol:        q.Protocol,
		Status:          q.Status,
		Limit:           q.Limit,
	}
	if q.MaxAge > 0 {
		f.TestedSince = time.Now().Add(-q.MaxAge)
	}
	rows, err := database.ConfigsForExport(f)
	if err != nil {
		return nil, err
	}
	links := make([]string, 0, len(rows))
	for _, r := range rows {
		links = append(links, r.Link)
	}
	return links, nil
}

// writeExport renders links and writes them (or, with asReport, a JSON
// wrapper with the skip report).
func writeExport(w http.ResponseWriter, q exportQuery, links []string, filename string, asReport bool, disposition string) {
	if len(links) == 0 {
		writeError(w, notFound("no configs match (check the status/protocol filters, or run an HTTP test first)"), http.StatusNotFound)
		return
	}
	body, report, err := renderExport(q.Format, links, q.Insecure)
	if err != nil {
		if errors.Is(err, convert.ErrNothingToExport) {
			writeJSONResponse(w, http.StatusUnprocessableEntity, map[string]any{
				"error":   fmt.Sprintf("none of the %d configs can be expressed as %s", len(links), q.Format),
				"code":    codeNothingExport,
				"skipped": skippedViews(report),
			})
			return
		}
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	skipped := 0
	converted := len(links)
	if report != nil {
		skipped = len(report.Skipped)
		converted = report.Converted
	}
	if asReport {
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"format":    q.Format,
			"selected":  len(links),
			"converted": converted,
			"skipped":   skippedViews(report),
			"content":   string(body),
		})
		return
	}
	f := exportFormats[q.Format]
	h := w.Header()
	h.Set("Content-Type", f.contentType)
	h.Set("Content-Disposition", fmt.Sprintf(`%s; filename="%s.%s"`, disposition, filename, f.ext))
	h.Set("X-Export-Converted", strconv.Itoa(converted))
	h.Set("X-Export-Skipped", strconv.Itoa(skipped))
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// --- authenticated export endpoints ---

func (h *APIHandler) registerExportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/subscriptions/{id}/export", h.handleSubscriptionExport)
	mux.HandleFunc("GET /api/v1/configs/export", h.handleConfigsExport)
}

func (h *APIHandler) handleSubscriptionExport(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	if err := dbReady(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	if _, err := lookupSubscription(id); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	q := exportQuery{Format: "base64", SubscriptionIDs: []int64{id}}
	h.serveExport(w, r, q, fmt.Sprintf("xray-knife-sub-%d", id))
}

func (h *APIHandler) handleConfigsExport(w http.ResponseWriter, r *http.Request) {
	if err := dbReady(); err != nil {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}
	q := exportQuery{Format: "base64"}
	if s := r.URL.Query().Get("subscriptionId"); s != "" {
		ids, err := parseIDList(s)
		if err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}
		q.SubscriptionIDs = ids
	}
	h.serveExport(w, r, q, "xray-knife-configs")
}

func (h *APIHandler) serveExport(w http.ResponseWriter, r *http.Request, q exportQuery, filename string) {
	if err := applyExportParams(&q, r.URL.Query(), "limit"); err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	links, err := selectExportLinks(q)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	rep := r.URL.Query().Get("report")
	writeExport(w, q, links, filename, rep == "1" || rep == "true", "attachment")
}
