package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ExportFilter selects stored configs for `subs export`.
type ExportFilter struct {
	// SubscriptionIDs restricts to configs these subscriptions provide
	// (whether or not they are enabled: the caller named them). Empty means
	// every config an enabled subscription provides.
	SubscriptionIDs []int64
	// Protocol keeps only configs of this protocol ("" = all).
	Protocol string
	// Status keeps only configs whose latest HTTP test result is at least
	// this good: "passed", or "semi-passed" (passed or semi-passed).
	// "" keeps everything, tested or not.
	Status string
	// TestedSince, when set, keeps only configs whose latest HTTP test
	// belongs to a run that started at or after it.
	TestedSince time.Time
	// Limit caps the number of configs (0 = no cap), applied after the
	// status filter.
	Limit int
}

// ExportedConfig is a stored config with its latest HTTP test result.
type ExportedConfig struct {
	Link    string         `db:"config_link"`
	Status  sql.NullString `db:"status"`
	DelayMs sql.NullInt64  `db:"delay_ms"`
}

// ValidExportStatus reports whether s is a status ExportFilter accepts.
func ValidExportStatus(s string) bool {
	return s == "" || s == "passed" || s == "semi-passed"
}

// statusesFor lists the latest-result statuses a Status filter keeps.
func statusesFor(status string) []string {
	if status == "semi-passed" {
		return []string{"passed", "semi-passed"}
	}
	return []string{status}
}

// ConfigsForExport returns the configs f selects. With a status filter they
// are ordered passed first, then fastest first (by the latest test's
// delay); otherwise in the order they were first stored.
//
// Filtering, ordering and the limit all run in SQL against
// http_latest_results (the newest result per link, kept by triggers), so the
// cost follows the number of matching configs, not the size of the history.
func ConfigsForExport(f ExportFilter) ([]ExportedConfig, error) {
	if !ValidExportStatus(f.Status) {
		return nil, fmt.Errorf("invalid status %q (want passed or semi-passed)", f.Status)
	}
	query, args := exportQueryForPlan(f)
	db, err := conn()
	if err != nil {
		return nil, err
	}
	var rows []ExportedConfig
	if err := db.SelectContext(bg(), &rows, query, args...); err != nil {
		return nil, fmt.Errorf("could not select configs to export: %w", err)
	}
	return rows, nil
}

// exportQueryForPlan builds ConfigsForExport's SQL (split out so a test can
// EXPLAIN it).
func exportQueryForPlan(f ExportFilter) (string, []any) {
	var (
		query string
		args  []any
	)
	filtered := f.Status != "" || !f.TestedSince.IsZero()
	if filtered {
		// Walk the (small) set of matching latest results and probe the
		// config by its unique link, rather than every config.
		query = `SELECT sc.config_link, l.status, l.delay_ms
			FROM http_latest_results l CROSS JOIN subscription_configs sc ON sc.config_link = l.config_link
			WHERE 1=1`
	} else {
		query = `SELECT sc.config_link, l.status, l.delay_ms
			FROM subscription_configs sc LEFT JOIN http_latest_results l ON l.config_link = sc.config_link
			WHERE 1=1`
	}
	if f.Status != "" {
		st := statusesFor(f.Status)
		query += ` AND l.status IN (?` + strings.Repeat(",?", len(st)-1) + `)`
		for _, v := range st {
			args = append(args, v)
		}
	}
	if !f.TestedSince.IsZero() {
		query += ` AND l.run_started >= ?`
		args = append(args, f.TestedSince.UTC().Format("2006-01-02 15:04:05"))
	}
	if len(f.SubscriptionIDs) > 0 {
		query += ` AND EXISTS (SELECT 1 FROM subscription_config_sources s
			WHERE s.config_id = sc.id AND s.subscription_id IN (?` + strings.Repeat(",?", len(f.SubscriptionIDs)-1) + `))`
		for _, id := range f.SubscriptionIDs {
			args = append(args, id)
		}
	} else {
		query += ` AND ` + fromEnabledSubscription
	}
	if f.Protocol != "" {
		query += ` AND sc.protocol = ?`
		args = append(args, f.Protocol)
	}
	if f.Status != "" {
		// "passed" sorts before "semi-passed", so ordering by the status
		// column itself puts passed first and lets the (status, delay_ms)
		// index deliver rows already sorted: with a LIMIT the scan stops
		// after the first matches instead of sorting every one.
		query += ` ORDER BY l.status, l.delay_ms, sc.id`
	} else {
		query += ` ORDER BY sc.id`
	}
	if f.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, f.Limit)
	}
	return query, args
}

// LatestHttpResults looks up the newest HTTP test result of each link (for
// links that are not stored as configs, e.g. read from a file), in one
// query. Links never tested are returned without a status. The output keeps
// the input order.
func LatestHttpResults(links []string) ([]ExportedConfig, error) {
	out := make([]ExportedConfig, len(links))
	for i, l := range links {
		out[i].Link = l
	}
	if len(links) == 0 {
		return out, nil
	}
	db, err := conn()
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(links)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryxContext(bg(), `SELECT j.key, l.status, l.delay_ms
		FROM json_each(?) j JOIN http_latest_results l ON l.config_link = j.value`, string(payload))
	if err != nil {
		return nil, fmt.Errorf("could not look up results of links: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			idx    int
			status sql.NullString
			delay  sql.NullInt64
		)
		if err := rows.Scan(&idx, &status, &delay); err != nil {
			return nil, err
		}
		if idx >= 0 && idx < len(out) {
			out[idx].Status, out[idx].DelayMs = status, delay
		}
	}
	return out, rows.Err()
}

// FilterExport applies ExportFilter's Status and Limit to looked-up links.
func FilterExport(rows []ExportedConfig, status string, limit int) ([]ExportedConfig, error) {
	if !ValidExportStatus(status) {
		return nil, fmt.Errorf("invalid status %q (want passed or semi-passed)", status)
	}
	return filterExport(rows, status, limit), nil
}

func filterExport(rows []ExportedConfig, status string, limit int) []ExportedConfig {
	if status != "" {
		kept := rows[:0:0]
		for _, r := range rows {
			switch {
			case r.Status.String == "passed":
			case status == "semi-passed" && r.Status.String == "semi-passed":
			default:
				continue
			}
			kept = append(kept, r)
		}
		rows = kept
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Status.String != rows[j].Status.String {
				return rows[i].Status.String == "passed"
			}
			return rows[i].DelayMs.Int64 < rows[j].DelayMs.Int64
		})
	}
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}
