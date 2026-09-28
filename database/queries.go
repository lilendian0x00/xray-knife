package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Data Models

type Subscription struct {
	ID            int64          `db:"id"`
	URL           string         `db:"url"`
	Remark        sql.NullString `db:"remark"`
	UserAgent     sql.NullString `db:"user_agent"`
	Enabled       bool           `db:"enabled"`
	LastFetchedAt NullTime       `db:"last_fetched_at"`
	CreatedAt     time.Time      `db:"created_at"`
}

type SubscriptionConfig struct {
	ID             int64          `db:"id"`
	SubscriptionID sql.NullInt64  `db:"subscription_id"`
	ConfigLink     string         `db:"config_link"`
	Protocol       sql.NullString `db:"protocol"`
	Remark         sql.NullString `db:"remark"`
	AddedAt        time.Time      `db:"added_at"`
	LastSeenAt     NullTime       `db:"last_seen_at"`
}

type HttpTestRun struct {
	ID          int64      `db:"id"`
	StartTime   time.Time  `db:"start_time"`
	EndTime     *time.Time `db:"end_time"`
	OptionsJSON string     `db:"options_json"`
	ConfigCount int        `db:"config_count"`
}

type HttpTestResult struct {
	ID            int64          `db:"id"`
	RunID         int64          `db:"run_id"`
	ConfigLink    string         `db:"config_link"`
	Status        string         `db:"status"`
	Reason        sql.NullString `db:"reason"`
	DelayMs       int64          `db:"delay_ms"`
	DownloadMbps  float64        `db:"download_mbps"`
	UploadMbps    float64        `db:"upload_mbps"`
	IPAddress     sql.NullString `db:"ip_address"`
	IPLocation    sql.NullString `db:"ip_location"`
	TTFBMs        int64          `db:"ttfb_ms"`
	ConnectTimeMs int64          `db:"connect_time_ms"`
	// FailureKind says why a result did not pass (pkg/http's failure kinds,
	// e.g. "tls-reset"). NULL for passed results and pre-v4 rows.
	FailureKind sql.NullString `db:"failure_kind"`
}

type CfScanResult struct {
	ID            int64           `db:"id"`
	IP            string          `db:"ip"`
	LatencyMs     sql.NullInt64   `db:"latency_ms"`
	DownloadMbps  sql.NullFloat64 `db:"download_mbps"`
	UploadMbps    sql.NullFloat64 `db:"upload_mbps"`
	Error         sql.NullString  `db:"error"`
	LastScannedAt time.Time       `db:"last_scanned_at"`
}

// Column lists used instead of SELECT *, so adding a column in a migration
// never breaks scanning into these structs. Nullable numeric columns are
// COALESCEd because the structs use plain numbers.
const (
	httpResultColumns = `id, run_id, config_link, status, reason,
		COALESCE(delay_ms, 0) AS delay_ms, COALESCE(download_mbps, 0) AS download_mbps,
		COALESCE(upload_mbps, 0) AS upload_mbps, ip_address, ip_location,
		COALESCE(ttfb_ms, 0) AS ttfb_ms, COALESCE(connect_time_ms, 0) AS connect_time_ms,
		failure_kind`
	cfResultColumns = `id, ip, latency_ms, download_mbps, upload_mbps, error, last_scanned_at`
)

// SQL fragments selecting configs by source; they expect the config table
// aliased as sc.
const (
	fromSubscription = `EXISTS (SELECT 1 FROM subscription_config_sources s
		WHERE s.config_id = sc.id AND s.subscription_id = ?)`
	fromEnabledSubscription = `EXISTS (SELECT 1 FROM subscription_config_sources s
		JOIN subscriptions sub ON sub.id = s.subscription_id
		WHERE s.config_id = sc.id AND sub.enabled = 1)`
)

// === Functions === /

// Subscriptions //

func AddSubscription(url, remark, userAgent string) error {
	query := `INSERT INTO subscriptions (url, remark, user_agent) VALUES (?, ?, ?)`
	remarkNull := sql.NullString{String: remark, Valid: remark != ""}
	uaNull := sql.NullString{String: userAgent, Valid: userAgent != ""}
	db, err := conn()
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(bg(), query, url, remarkNull, uaNull); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("a subscription with URL %s already exists", url)
		}
		return fmt.Errorf("could not add subscription: %w", err)
	}
	return nil
}

// DeleteSubscription removes a subscription and the configs only it
// provided. Configs another subscription also returns are kept (their
// display subscription_id moves to that other source).
func DeleteSubscription(id int64) error {
	_, err := DeleteSubscriptionCounted(id)
	return err
}

// DeleteSubscriptionCounted is DeleteSubscription that also reports how many
// configs were deleted with it.
func DeleteSubscriptionCounted(id int64) (int64, error) {
	db, err := conn()
	if err != nil {
		return 0, err
	}
	tx, err := db.BeginTxx(bg(), nil)
	if err != nil {
		return 0, fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	var exists int
	if err := tx.GetContext(bg(), &exists, `SELECT COUNT(*) FROM subscriptions WHERE id = ?`, id); err != nil {
		return 0, fmt.Errorf("could not look up subscription %d: %w", id, err)
	}
	if exists == 0 {
		return 0, fmt.Errorf("no subscription found with id %d", id)
	}

	res, err := tx.ExecContext(bg(), `
		DELETE FROM subscription_configs
		WHERE id IN (SELECT config_id FROM subscription_config_sources WHERE subscription_id = ?)
		  AND NOT EXISTS (
			SELECT 1 FROM subscription_config_sources o
			WHERE o.config_id = subscription_configs.id AND o.subscription_id != ?)`, id, id)
	if err != nil {
		return 0, fmt.Errorf("could not delete configs of subscription %d: %w", id, err)
	}
	deleted, _ := res.RowsAffected()

	// Shared configs keep pointing at a subscription that still exists.
	if _, err := tx.ExecContext(bg(), `
		UPDATE subscription_configs SET subscription_id = (
			SELECT s.subscription_id FROM subscription_config_sources s
			WHERE s.config_id = subscription_configs.id AND s.subscription_id != ?
			ORDER BY s.last_seen_at DESC LIMIT 1)
		WHERE subscription_id = ?`, id, id); err != nil {
		return 0, fmt.Errorf("could not reassign shared configs of subscription %d: %w", id, err)
	}

	if _, err := tx.ExecContext(bg(), `DELETE FROM subscriptions WHERE id = ?`, id); err != nil {
		return 0, fmt.Errorf("could not delete subscription with id %d: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

// CountExclusiveSubscriptionConfigs counts the configs that only subscription
// subID provides, i.e. the ones DeleteSubscription(subID) would delete.
func CountExclusiveSubscriptionConfigs(subID int64) (int, error) {
	db, err := conn()
	if err != nil {
		return 0, err
	}
	var count int
	err = db.GetContext(bg(), &count, `
		SELECT COUNT(*) FROM subscription_config_sources s
		WHERE s.subscription_id = ?
		  AND NOT EXISTS (
			SELECT 1 FROM subscription_config_sources o
			WHERE o.config_id = s.config_id AND o.subscription_id != ?)`, subID, subID)
	if err != nil {
		return 0, fmt.Errorf("could not count subscription configs: %w", err)
	}
	return count, nil
}

func ListSubscriptions() ([]Subscription, error) {
	var subs []Subscription
	query := `SELECT id, url, remark, user_agent, enabled, last_fetched_at, created_at FROM subscriptions ORDER BY id`
	db, err := conn()
	if err != nil {
		return nil, err
	}
	if err := db.SelectContext(bg(), &subs, query); err != nil {
		return nil, fmt.Errorf("could not list subscriptions: %w", err)
	}
	return subs, nil
}

func GetSubscriptionByID(id int64) (*Subscription, error) {
	var sub Subscription
	query := `SELECT id, url, remark, user_agent, enabled, last_fetched_at, created_at FROM subscriptions WHERE id = ?`
	db, err := conn()
	if err != nil {
		return nil, err
	}
	if err := db.GetContext(bg(), &sub, query, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no subscription found with id %d", id)
		}
		return nil, fmt.Errorf("could not get subscription: %w", err)
	}
	return &sub, nil
}

func UpdateSubscriptionFetched(id int64, fetchTime time.Time) error {
	query := `UPDATE subscriptions SET last_fetched_at = ? WHERE id = ?`
	db, err := conn()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(bg(), query, fetchTime.UTC(), id)
	return err
}

func UpdateSubscription(id int64, urlVal, remark, userAgent *string, enabled *bool) error {
	setClauses := []string{}
	args := []interface{}{}

	if urlVal != nil {
		setClauses = append(setClauses, "url = ?")
		args = append(args, *urlVal)
	}
	if remark != nil {
		setClauses = append(setClauses, "remark = ?")
		if *remark == "" {
			args = append(args, sql.NullString{})
		} else {
			args = append(args, *remark)
		}
	}
	if userAgent != nil {
		setClauses = append(setClauses, "user_agent = ?")
		if *userAgent == "" {
			args = append(args, sql.NullString{})
		} else {
			args = append(args, *userAgent)
		}
	}
	if enabled != nil {
		setClauses = append(setClauses, "enabled = ?")
		args = append(args, *enabled)
	}

	if len(setClauses) == 0 {
		return fmt.Errorf("no fields to update")
	}

	query := fmt.Sprintf("UPDATE subscriptions SET %s WHERE id = ?", strings.Join(setClauses, ", "))
	args = append(args, id)

	db, err := conn()
	if err != nil {
		return err
	}
	res, err := db.ExecContext(bg(), query, args...)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("another subscription already uses URL %s", *urlVal)
		}
		return fmt.Errorf("could not update subscription %d: %w", id, err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("no subscription found with id %d", id)
	}
	return nil
}

func ListSubscriptionConfigs(subID int64, protocol string, limit int) ([]SubscriptionConfig, error) {
	query := `SELECT sc.id, sc.subscription_id, sc.config_link, sc.protocol, sc.remark, sc.added_at, sc.last_seen_at FROM subscription_configs sc WHERE 1=1`
	args := []interface{}{}

	if subID > 0 {
		query += " AND " + fromSubscription
		args = append(args, subID)
	}
	if protocol != "" {
		query += " AND sc.protocol = ?"
		args = append(args, protocol)
	}

	query += " ORDER BY sc.last_seen_at DESC, sc.id DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	var configs []SubscriptionConfig
	db, err := conn()
	if err != nil {
		return nil, err
	}
	if err := db.SelectContext(bg(), &configs, query, args...); err != nil {
		return nil, fmt.Errorf("could not list subscription configs: %w", err)
	}
	return configs, nil
}

func CountSubscriptionConfigs(subID int64) (int, error) {
	query := `SELECT COUNT(*) FROM subscription_configs sc WHERE 1=1`
	args := []interface{}{}

	if subID > 0 {
		query += " AND " + fromSubscription
		args = append(args, subID)
	}

	var count int
	db, err := conn()
	if err != nil {
		return 0, err
	}
	if err := db.GetContext(bg(), &count, query, args...); err != nil {
		return 0, fmt.Errorf("could not count subscription configs: %w", err)
	}
	return count, nil
}

// Subscription Configs

// UpsertSubscriptionConfigs inserts or refreshes configs. A config with a
// SubscriptionID is also recorded as provided by that subscription, so a link
// several subscriptions share is tracked for each of them.
func UpsertSubscriptionConfigs(configs []SubscriptionConfig) error {
	db, err := conn()
	if err != nil {
		return err
	}
	tx, err := db.BeginTxx(bg(), nil)
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareNamedContext(bg(), `
		INSERT INTO subscription_configs (subscription_id, config_link, protocol, remark, last_seen_at) 
		VALUES (:subscription_id, :config_link, :protocol, :remark, :last_seen_at)
		ON CONFLICT(config_link) DO UPDATE SET 
			last_seen_at = excluded.last_seen_at,
			subscription_id = COALESCE(excluded.subscription_id, subscription_configs.subscription_id),
			remark = excluded.remark,
			protocol = excluded.protocol
	`)
	if err != nil {
		return fmt.Errorf("could not prepare named statement: %w", err)
	}
	defer stmt.Close()

	sourceStmt, err := tx.PreparexContext(bg(), `
		INSERT INTO subscription_config_sources (subscription_id, config_id, last_seen_at)
		SELECT ?, id, ? FROM subscription_configs WHERE config_link = ?
		ON CONFLICT(subscription_id, config_id) DO UPDATE SET last_seen_at = excluded.last_seen_at
	`)
	if err != nil {
		return fmt.Errorf("could not prepare source statement: %w", err)
	}
	defer sourceStmt.Close()

	for _, config := range configs {
		if _, err := stmt.ExecContext(bg(), config); err != nil {
			return fmt.Errorf("failed to execute upsert for config %s: %w", config.ConfigLink, err)
		}
		if config.SubscriptionID.Valid {
			if _, err := sourceStmt.ExecContext(bg(), config.SubscriptionID.Int64, config.LastSeenAt, config.ConfigLink); err != nil {
				return fmt.Errorf("failed to record source of config %s: %w", config.ConfigLink, err)
			}
		}
	}

	return tx.Commit()
}

// GetConfigsFromDB returns stored config links for testing. With subID > 0
// it returns that subscription's configs (even if it is disabled: the caller
// asked for it by ID). Otherwise it returns every config at least one enabled
// subscription provides, plus one-off configs fetched with --url/--file,
// which belong to no subscription.
func GetConfigsFromDB(subID int64, protocol string, limit int) ([]string, error) {
	query := `SELECT sc.config_link FROM subscription_configs sc WHERE 1=1`
	args := []interface{}{}

	if subID > 0 {
		query += " AND " + fromSubscription
		args = append(args, subID)
	} else {
		query += ` AND (NOT EXISTS (SELECT 1 FROM subscription_config_sources s WHERE s.config_id = sc.id) OR ` + fromEnabledSubscription + `)`
	}
	if protocol != "" {
		query += " AND sc.protocol = ?"
		args = append(args, protocol)
	}

	// Add randomness to not always test the same configs
	query += " ORDER BY RANDOM()"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	var links []string
	db, err := conn()
	if err != nil {
		return nil, err
	}
	if err := db.SelectContext(bg(), &links, query, args...); err != nil {
		return nil, fmt.Errorf("could not get configs from DB: %w", err)
	}
	return links, nil
}

// GetConfigsForProxy returns every config at least one enabled subscription
// provides.
func GetConfigsForProxy() ([]string, error) {
	query := `SELECT sc.config_link FROM subscription_configs sc WHERE ` + fromEnabledSubscription
	var links []string
	db, err := conn()
	if err != nil {
		return nil, err
	}
	if err := db.SelectContext(bg(), &links, query); err != nil {
		return nil, fmt.Errorf("could not get proxy configs from DB: %w", err)
	}
	return links, nil
}

// HTTP Tester //

func CreateHttpTestRun(optionsJSON string, configCount int) (int64, error) {
	query := `INSERT INTO http_test_runs (options_json, config_count) VALUES (?, ?)`
	db, err := conn()
	if err != nil {
		return 0, err
	}
	res, err := db.ExecContext(bg(), query, optionsJSON, configCount)
	if err != nil {
		return 0, fmt.Errorf("could not create http_test_run: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("could not get last insert id for http_test_run: %w", err)
	}
	return id, nil
}

// FinishHttpTestRun records when a run ended.
func FinishHttpTestRun(runID int64) error {
	db, err := conn()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(bg(), `UPDATE http_test_runs SET end_time = ? WHERE id = ?`, time.Now().UTC(), runID)
	if err != nil {
		return fmt.Errorf("could not finish http_test_run %d: %w", runID, err)
	}
	return nil
}

// InsertHttpTestResultsBatch stores a batch of results. It also moves the
// run's end_time forward, so a run whose caller never reaches
// FinishHttpTestRun (killed, crashed) still records roughly when it stopped.
func InsertHttpTestResultsBatch(runID int64, results []HttpTestResult) error {
	db, err := conn()
	if err != nil {
		return err
	}
	tx, err := db.BeginTxx(bg(), nil)
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareNamedContext(bg(), `
        INSERT INTO http_test_results (run_id, config_link, status, reason, delay_ms, download_mbps, upload_mbps, ip_address, ip_location, ttfb_ms, connect_time_ms, failure_kind)
        VALUES (:run_id, :config_link, :status, :reason, :delay_ms, :download_mbps, :upload_mbps, :ip_address, :ip_location, :ttfb_ms, :connect_time_ms, :failure_kind)
    `)
	if err != nil {
		return fmt.Errorf("could not prepare named statement for http_test_results: %w", err)
	}
	defer stmt.Close()

	for _, result := range results {
		result.RunID = runID // Ensure the run ID is set
		if _, err := stmt.ExecContext(bg(), result); err != nil {
			return fmt.Errorf("failed to execute insert for result of %s: %w", result.ConfigLink, err)
		}
	}
	if _, err := tx.ExecContext(bg(), `UPDATE http_test_runs SET end_time = ? WHERE id = ?`, time.Now().UTC(), runID); err != nil {
		return fmt.Errorf("could not update end time of run %d: %w", runID, err)
	}

	return tx.Commit()
}

func GetHttpTestHistory(limit int) ([]HttpTestResult, error) {
	var results []HttpTestResult
	// Results of the latest run that stored any (by id: start_time only has
	// one-second resolution), passed first, then semi-passed, fastest first.
	query := `
        SELECT ` + httpResultColumns + ` FROM http_test_results
        WHERE run_id = (SELECT MAX(run_id) FROM http_test_results)
        ORDER BY CASE status WHEN 'passed' THEN 0 WHEN 'semi-passed' THEN 1 ELSE 2 END,
                 COALESCE(delay_ms, 0) ASC, id ASC
        LIMIT ?
    `
	db, err := conn()
	if err != nil {
		return nil, err
	}
	if err := db.SelectContext(bg(), &results, query, limit); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []HttpTestResult{}, nil // Return empty slice, not an error
		}
		return nil, fmt.Errorf("could not list http test history: %w", err)
	}
	return results, nil
}

// CF Scanner //

func UpsertCfScanResultsBatch(results []CfScanResult) error {
	db, err := conn()
	if err != nil {
		return err
	}
	tx, err := db.BeginTxx(bg(), nil)
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareNamedContext(bg(), `
		INSERT INTO cf_scan_results (ip, latency_ms, download_mbps, upload_mbps, error, last_scanned_at) 
		VALUES (:ip, :latency_ms, :download_mbps, :upload_mbps, :error, CURRENT_TIMESTAMP)
		ON CONFLICT(ip) DO UPDATE SET 
			latency_ms = COALESCE(excluded.latency_ms, cf_scan_results.latency_ms),
			download_mbps = COALESCE(excluded.download_mbps, cf_scan_results.download_mbps),
			upload_mbps = COALESCE(excluded.upload_mbps, cf_scan_results.upload_mbps),
			error = excluded.error,
			last_scanned_at = CURRENT_TIMESTAMP
	`)
	if err != nil {
		return fmt.Errorf("could not prepare named statement for cf_scan_results: %w", err)
	}
	defer stmt.Close()

	for _, result := range results {
		if _, err := stmt.ExecContext(bg(), result); err != nil {
			return fmt.Errorf("failed to execute upsert for IP %s: %w", result.IP, err)
		}
	}

	return tx.Commit()
}

func GetCfScanResults() (map[string]CfScanResult, error) {
	var results []CfScanResult
	query := `SELECT ` + cfResultColumns + ` FROM cf_scan_results`
	db, err := conn()
	if err != nil {
		return nil, err
	}
	if err := db.SelectContext(bg(), &results, query); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return make(map[string]CfScanResult), nil
		}
		return nil, fmt.Errorf("could not get cf scan results from DB: %w", err)
	}

	resultsMap := make(map[string]CfScanResult, len(results))
	for _, res := range results {
		resultsMap[res.IP] = res
	}

	return resultsMap, nil
}

func GetCfScanHistory(limit int) ([]CfScanResult, error) {
	var results []CfScanResult
	query := `
		SELECT ` + cfResultColumns + ` FROM cf_scan_results
		ORDER BY
			CASE WHEN error IS NULL THEN 0 ELSE 1 END,
			latency_ms ASC,
			download_mbps DESC
		LIMIT ?
	`
	db, err := conn()
	if err != nil {
		return nil, err
	}
	if err := db.SelectContext(bg(), &results, query, limit); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []CfScanResult{}, nil
		}
		return nil, fmt.Errorf("could not list cf scan history: %w", err)
	}
	return results, nil
}
