package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lilendian0x00/xray-knife/v11/database"
	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
)

// History endpoints read test runs and scan results straight from the DB,
// paginated server-side, so the browser never loads a whole CSV.

func (h *APIHandler) registerHistoryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/history/http/runs", h.handleHistoryRuns)
	mux.HandleFunc("GET /api/v1/history/http/runs/{id}", h.handleHistoryRun)
	mux.HandleFunc("DELETE /api/v1/history/http/runs/{id}", h.handleDeleteHistoryRun)
	mux.HandleFunc("GET /api/v1/history/http/runs/{id}/results", h.handleHistoryRunResults)
	mux.HandleFunc("GET /api/v1/history/cf", h.handleHistoryCf)
	mux.HandleFunc("DELETE /api/v1/history/cf", h.handleClearHistoryCf)
}

type runCounts struct {
	Passed     int `json:"passed" db:"passed"`
	SemiPassed int `json:"semiPassed" db:"semi_passed"`
	Failed     int `json:"failed" db:"failed"`
	Broken     int `json:"broken" db:"broken"`
	Total      int `json:"total" db:"total"`
}

type runRow struct {
	ID          int64             `db:"id"`
	StartTime   database.NullTime `db:"start_time"`
	EndTime     database.NullTime `db:"end_time"`
	OptionsJSON sql.NullString    `db:"options_json"`
	ConfigCount sql.NullInt64     `db:"config_count"`
	runCounts
}

type runView struct {
	ID          int64           `json:"id"`
	StartTime   *time.Time      `json:"startTime"`
	EndTime     *time.Time      `json:"endTime"`
	ConfigCount int64           `json:"configCount"`
	Options     json.RawMessage `json:"options"`
	Counts      runCounts       `json:"counts"`
}

func (r runRow) view() runView {
	v := runView{ID: r.ID, ConfigCount: r.ConfigCount.Int64, Counts: r.runCounts, Options: json.RawMessage("null")}
	if r.StartTime.Valid {
		t := r.StartTime.Time
		v.StartTime = &t
	}
	if r.EndTime.Valid {
		t := r.EndTime.Time
		v.EndTime = &t
	}
	if r.OptionsJSON.Valid && json.Valid([]byte(r.OptionsJSON.String)) {
		v.Options = json.RawMessage(r.OptionsJSON.String)
	}
	return v
}

// runSelect counts a run's results by status. Anything not passed,
// semi-passed or broken (failed, timeout) counts as failed, as the live
// test summary does, so the counts add up to total.
const runSelect = `
	SELECT r.id, r.start_time, r.end_time, r.options_json, r.config_count,
		COALESCE(SUM(CASE WHEN res.status = 'passed' THEN 1 ELSE 0 END), 0) AS passed,
		COALESCE(SUM(CASE WHEN res.status = 'semi-passed' THEN 1 ELSE 0 END), 0) AS semi_passed,
		COALESCE(SUM(CASE WHEN res.status NOT IN ('passed', 'semi-passed', 'broken') THEN 1 ELSE 0 END), 0) AS failed,
		COALESCE(SUM(CASE WHEN res.status = 'broken' THEN 1 ELSE 0 END), 0) AS broken,
		COUNT(res.id) AS total
	FROM http_test_runs r
	LEFT JOIN http_test_results res ON res.run_id = r.id`

func (h *APIHandler) handleHistoryRuns(w http.ResponseWriter, r *http.Request) {
	db, err := database.Conn()
	if err != nil {
		writeError(w, dbReady(), http.StatusServiceUnavailable)
		return
	}
	page, perPage, _ := pageParams(r)
	var total int
	if err := db.GetContext(r.Context(), &total, `SELECT COUNT(*) FROM http_test_runs`); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	var rows []runRow
	q := runSelect + ` GROUP BY r.id ORDER BY r.id DESC LIMIT ? OFFSET ?`
	if err := db.SelectContext(r.Context(), &rows, q, perPage, (page-1)*perPage); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	items := make([]runView, 0, len(rows))
	for _, row := range rows {
		items = append(items, row.view())
	}
	writeJSONResponse(w, http.StatusOK, paginated[runView]{Items: items, Total: total, Page: page, PerPage: perPage})
}

func (h *APIHandler) handleHistoryRun(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	db, err := database.Conn()
	if err != nil {
		writeError(w, dbReady(), http.StatusServiceUnavailable)
		return
	}
	var rows []runRow
	if err := db.SelectContext(r.Context(), &rows, runSelect+` WHERE r.id = ? GROUP BY r.id`, id); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	if len(rows) == 0 {
		writeError(w, notFound("no test run with id %d", id), http.StatusNotFound)
		return
	}
	writeJSONResponse(w, http.StatusOK, rows[0].view())
}

func (h *APIHandler) handleDeleteHistoryRun(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	db, err := database.Conn()
	if err != nil {
		writeError(w, dbReady(), http.StatusServiceUnavailable)
		return
	}
	tx, err := db.BeginTxx(r.Context(), nil)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback() }()
	// Delete results explicitly: older databases may have foreign keys off.
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM http_test_results WHERE run_id = ?`, id); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	res, err := tx.ExecContext(r.Context(), `DELETE FROM http_test_runs WHERE id = ?`, id)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, notFound("no test run with id %d", id), http.StatusNotFound)
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type resultRow struct {
	ID            int64           `db:"id"`
	RunID         int64           `db:"run_id"`
	ConfigLink    string          `db:"config_link"`
	Status        string          `db:"status"`
	Reason        sql.NullString  `db:"reason"`
	DelayMs       sql.NullInt64   `db:"delay_ms"`
	DownloadMbps  sql.NullFloat64 `db:"download_mbps"`
	UploadMbps    sql.NullFloat64 `db:"upload_mbps"`
	IPAddress     sql.NullString  `db:"ip_address"`
	IPLocation    sql.NullString  `db:"ip_location"`
	TTFBMs        sql.NullInt64   `db:"ttfb_ms"`
	ConnectTimeMs sql.NullInt64   `db:"connect_time_ms"`
	FailureKind   sql.NullString  `db:"failure_kind"`
}

type resultView struct {
	ID          int64   `json:"id"`
	RunID       int64   `json:"runId"`
	Link        string  `json:"link"`
	Protocol    string  `json:"protocol"`
	Status      string  `json:"status"`
	Reason      string  `json:"reason"`
	Delay       int64   `json:"delay"`
	Download    float64 `json:"download"`
	Upload      float64 `json:"upload"`
	IP          string  `json:"ip"`
	Location    string  `json:"location"`
	TTFB        int64   `json:"ttfb"`
	ConnectTime int64   `json:"connectTime"`
	FailureKind string  `json:"failureKind,omitempty"`
}

func (r resultRow) view() resultView {
	v := resultView{
		ID: r.ID, RunID: r.RunID, Link: r.ConfigLink, Status: r.Status, Reason: r.Reason.String,
		Delay: -1, Download: r.DownloadMbps.Float64, Upload: r.UploadMbps.Float64,
		IP: r.IPAddress.String, Location: r.IPLocation.String, TTFB: r.TTFBMs.Int64, ConnectTime: r.ConnectTimeMs.Int64,
		FailureKind: r.FailureKind.String,
	}
	if !r.FailureKind.Valid || r.FailureKind.String == "" {
		// Rows saved before failure kinds existed: infer from the reason.
		v.FailureKind = pkghttp.KindFromReason(r.Status, r.Reason.String)
	}
	if r.DelayMs.Valid {
		v.Delay = r.DelayMs.Int64
	}
	if scheme, _, ok := strings.Cut(r.ConfigLink, "://"); ok {
		v.Protocol = strings.ToLower(scheme)
	}
	return v
}

// hasColumn reports whether table has column (table is a constant here).
func hasColumn(ctx context.Context, db *sqlx.DB, table, column string) bool {
	var names []string
	if err := db.SelectContext(ctx, &names, `SELECT name FROM pragma_table_info(?)`, table); err != nil {
		return false
	}
	for _, n := range names {
		if n == column {
			return true
		}
	}
	return false
}

// likeEscape escapes LIKE wildcards for use with ESCAPE '\'.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

var resultSorts = map[string]string{
	"delay":     "CASE WHEN delay_ms IS NULL OR delay_ms < 0 THEN 1 ELSE 0 END, delay_ms ASC, id ASC",
	"-delay":    "delay_ms DESC, id ASC",
	"download":  "download_mbps ASC, id ASC",
	"-download": "COALESCE(download_mbps, 0) DESC, id ASC",
	"upload":    "upload_mbps ASC, id ASC",
	"-upload":   "COALESCE(upload_mbps, 0) DESC, id ASC",
	"status": "CASE status WHEN 'passed' THEN 0 WHEN 'semi-passed' THEN 1 WHEN 'broken' THEN 3 ELSE 2 END, " +
		"CASE WHEN delay_ms IS NULL OR delay_ms < 0 THEN 1 ELSE 0 END, delay_ms ASC, id ASC",
	"id": "id ASC",
}

func (h *APIHandler) handleHistoryRunResults(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	db, err := database.Conn()
	if err != nil {
		writeError(w, dbReady(), http.StatusServiceUnavailable)
		return
	}
	where := []string{"run_id = ?"}
	args := []any{id}
	if st := strings.TrimSpace(r.URL.Query().Get("status")); st != "" {
		var ph []string
		for _, s := range strings.Split(st, ",") {
			if s = strings.TrimSpace(s); s != "" {
				ph = append(ph, "?")
				args = append(args, s)
			}
		}
		if len(ph) > 0 {
			where = append(where, "status IN ("+strings.Join(ph, ",")+")")
		}
	}
	if p := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("protocol"))); p != "" {
		where = append(where, `LOWER(config_link) LIKE ? ESCAPE '\'`)
		args = append(args, likeEscape(p)+"://%")
	}
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		where = append(where, `(config_link LIKE ? ESCAPE '\' OR reason LIKE ? ESCAPE '\' OR ip_location LIKE ? ESCAPE '\')`)
		pat := "%" + likeEscape(q) + "%"
		args = append(args, pat, pat, pat)
	}
	sortKey := r.URL.Query().Get("sort")
	order, ok := resultSorts[sortKey]
	if !ok {
		if sortKey != "" {
			writeError(w, badRequest("unknown sort %q", sortKey), http.StatusBadRequest)
			return
		}
		order = resultSorts["status"]
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := db.GetContext(r.Context(), &total, `SELECT COUNT(*) FROM http_test_results WHERE `+cond, args...); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	page, perPage, _ := pageParams(r)
	var rows []resultRow
	// failure_kind arrives with a later migration; older databases read NULL.
	kindCol := "NULL AS failure_kind"
	if hasColumn(r.Context(), db, "http_test_results", "failure_kind") {
		kindCol = "failure_kind"
	}
	q := `SELECT id, run_id, config_link, status, reason, delay_ms, download_mbps, upload_mbps, ip_address, ip_location,
		ttfb_ms, connect_time_ms, ` + kindCol + ` FROM http_test_results WHERE ` + cond + ` ORDER BY ` + order + ` LIMIT ? OFFSET ?`
	if err := db.SelectContext(r.Context(), &rows, q, append(args, perPage, (page-1)*perPage)...); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	items := make([]resultView, 0, len(rows))
	for _, row := range rows {
		items = append(items, row.view())
	}
	writeJSONResponse(w, http.StatusOK, paginated[resultView]{Items: items, Total: total, Page: page, PerPage: perPage})
}

type cfRow struct {
	ID            int64             `db:"id"`
	IP            string            `db:"ip"`
	LatencyMs     sql.NullInt64     `db:"latency_ms"`
	DownloadMbps  sql.NullFloat64   `db:"download_mbps"`
	UploadMbps    sql.NullFloat64   `db:"upload_mbps"`
	Error         sql.NullString    `db:"error"`
	LastScannedAt database.NullTime `db:"last_scanned_at"`
}

type cfView struct {
	IP            string     `json:"ip"`
	Latency       *int64     `json:"latency"`
	Download      *float64   `json:"download"`
	Upload        *float64   `json:"upload"`
	Error         *string    `json:"error"`
	LastScannedAt *time.Time `json:"lastScannedAt"`
}

func (r cfRow) view() cfView {
	v := cfView{IP: r.IP}
	if r.LatencyMs.Valid {
		v.Latency = &r.LatencyMs.Int64
	}
	if r.DownloadMbps.Valid {
		v.Download = &r.DownloadMbps.Float64
	}
	if r.UploadMbps.Valid {
		v.Upload = &r.UploadMbps.Float64
	}
	if r.Error.Valid && r.Error.String != "" {
		v.Error = &r.Error.String
	}
	if r.LastScannedAt.Valid {
		t := r.LastScannedAt.Time
		v.LastScannedAt = &t
	}
	return v
}

var cfSorts = map[string]string{
	"latency":   "CASE WHEN error IS NULL OR error = '' THEN 0 ELSE 1 END, latency_ms IS NULL, latency_ms ASC, ip ASC",
	"-download": "COALESCE(download_mbps, -1) DESC, latency_ms ASC, ip ASC",
	"-upload":   "COALESCE(upload_mbps, -1) DESC, latency_ms ASC, ip ASC",
	"recent":    "last_scanned_at DESC, ip ASC",
}

func (h *APIHandler) handleHistoryCf(w http.ResponseWriter, r *http.Request) {
	db, err := database.Conn()
	if err != nil {
		writeError(w, dbReady(), http.StatusServiceUnavailable)
		return
	}
	cond := "1=1"
	if v := r.URL.Query().Get("ok"); v == "1" || v == "true" {
		cond = "(error IS NULL OR error = '')"
	}
	order, ok := cfSorts[r.URL.Query().Get("sort")]
	if !ok {
		if s := r.URL.Query().Get("sort"); s != "" {
			writeError(w, badRequest("unknown sort %q", s), http.StatusBadRequest)
			return
		}
		order = cfSorts["latency"]
	}
	var total int
	if err := db.GetContext(r.Context(), &total, `SELECT COUNT(*) FROM cf_scan_results WHERE `+cond); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	page, perPage, _ := pageParams(r)
	var rows []cfRow
	q := `SELECT id, ip, latency_ms, download_mbps, upload_mbps, error, last_scanned_at FROM cf_scan_results WHERE ` +
		cond + ` ORDER BY ` + order + ` LIMIT ? OFFSET ?`
	if err := db.SelectContext(r.Context(), &rows, q, perPage, (page-1)*perPage); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	items := make([]cfView, 0, len(rows))
	for _, row := range rows {
		items = append(items, row.view())
	}
	writeJSONResponse(w, http.StatusOK, paginated[cfView]{Items: items, Total: total, Page: page, PerPage: perPage})
}

func (h *APIHandler) handleClearHistoryCf(w http.ResponseWriter, r *http.Request) {
	if h.manager.GetScannerStatus() {
		writeJSONErrorCode(w, "a scan is running; stop it first", codeBusy, http.StatusConflict)
		return
	}
	db, err := database.Conn()
	if err != nil {
		writeError(w, dbReady(), http.StatusServiceUnavailable)
		return
	}
	if _, err := db.ExecContext(r.Context(), `DELETE FROM cf_scan_results`); err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "cleared"})
}
