package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Data Models

type Subscription struct {
	ID            int64          `db:"id"`
	URL           string         `db:"url"`
	Remark        sql.NullString `db:"remark"`
	UserAgent     sql.NullString `db:"user_agent"`
	Enabled       bool           `db:"enabled"`
	LastFetchedAt sql.NullTime   `db:"last_fetched_at"`
	CreatedAt     time.Time      `db:"created_at"`
}

type SubscriptionConfig struct {
	ID             int64          `db:"id"`
	SubscriptionID sql.NullInt64  `db:"subscription_id"`
	ConfigLink     string         `db:"config_link"`
	Protocol       sql.NullString `db:"protocol"`
	Remark         sql.NullString `db:"remark"`
	AddedAt        time.Time      `db:"added_at"`
	LastSeenAt     sql.NullTime   `db:"last_seen_at"`
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

// === Functions === /

// Subscriptions //

func AddSubscription(url, remark, userAgent string) error {
	query := `INSERT INTO subscriptions (url, remark, user_agent) VALUES (?, ?, ?)`
	_, err := DB.ExecContext(context.Background(), query, url, remark, userAgent)
	if err != nil {
		return fmt.Errorf("could not add subscription: %w", err)
	}
	return nil
}

func DeleteSubscription(id int64) error {
	query := `DELETE FROM subscriptions WHERE id = ?`
	res, err := DB.ExecContext(context.Background(), query, id)
	if err != nil {
		return fmt.Errorf("could not delete subscription with id %d: %w", id, err)
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

func ListSubscriptions() ([]Subscription, error) {
	var subs []Subscription
	query := `SELECT id, url, remark, user_agent, enabled, last_fetched_at, created_at FROM subscriptions ORDER BY id`
	err := DB.SelectContext(context.Background(), &subs, query)
	if err != nil {
		return nil, fmt.Errorf("could not list subscriptions: %w", err)
	}
	return subs, nil
}

func GetSubscriptionByID(id int64) (*Subscription, error) {
	var sub Subscription
	query := `SELECT id, url, remark, user_agent, enabled, last_fetched_at, created_at FROM subscriptions WHERE id = ?`
	err := DB.GetContext(context.Background(), &sub, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no subscription found with id %d", id)
		}
		return nil, fmt.Errorf("could not get subscription: %w", err)
	}
	return &sub, nil
}

func UpdateSubscriptionFetched(id int64, fetchTime time.Time) error {
	query := `UPDATE subscriptions SET last_fetched_at = ? WHERE id = ?`
	_, err := DB.ExecContext(context.Background(), query, fetchTime, id)
	return err
}

// Subscription Configs

func UpsertSubscriptionConfigs(configs []SubscriptionConfig) error {
	tx, err := DB.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareNamedContext(context.Background(), `
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

	for _, config := range configs {
		if _, err := stmt.ExecContext(context.Background(), config); err != nil {
			return fmt.Errorf("failed to execute upsert for config %s: %w", config.ConfigLink, err)
		}
	}

	return tx.Commit()
}

func GetConfigsFromDB(subID int64, protocol string, limit int) ([]string, error) {
	query := `SELECT config_link FROM subscription_configs WHERE 1=1`
	args := []interface{}{}

	if subID > 0 {
		query += " AND subscription_id = ?"
		args = append(args, subID)
	}
	if protocol != "" {
		query += " AND protocol = ?"
		args = append(args, protocol)
	}

	// Add randomness to not always test the same configs
	query += " ORDER BY RANDOM()"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	var links []string
	err := DB.SelectContext(context.Background(), &links, query, args...)
	if err != nil {
		return nil, fmt.Errorf("could not get configs from DB: %w", err)
	}
	return links, nil
}

func GetConfigsForProxy() ([]string, error) {
	query := `
		SELECT DISTINCT sc.config_link 
		FROM subscription_configs sc
		JOIN subscriptions s ON sc.subscription_id = s.id
		WHERE s.enabled = 1
	`
	var links []string
	err := DB.SelectContext(context.Background(), &links, query)
	if err != nil {
		return nil, fmt.Errorf("could not get proxy configs from DB: %w", err)
	}
	return links, nil
}

// HTTP Tester //

func CreateHttpTestRun(optionsJSON string, configCount int) (int64, error) {
	query := `INSERT INTO http_test_runs (options_json, config_count) VALUES (?, ?)`
	res, err := DB.ExecContext(context.Background(), query, optionsJSON, configCount)
	if err != nil {
		return 0, fmt.Errorf("could not create http_test_run: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("could not get last insert id for http_test_run: %w", err)
	}
	return id, nil
}

func InsertHttpTestResultsBatch(runID int64, results []HttpTestResult) error {
	tx, err := DB.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareNamedContext(context.Background(), `
        INSERT INTO http_test_results (run_id, config_link, status, reason, delay_ms, download_mbps, upload_mbps, ip_address, ip_location, ttfb_ms, connect_time_ms)
        VALUES (:run_id, :config_link, :status, :reason, :delay_ms, :download_mbps, :upload_mbps, :ip_address, :ip_location, :ttfb_ms, :connect_time_ms)
    `)
	if err != nil {
		return fmt.Errorf("could not prepare named statement for http_test_results: %w", err)
	}
	defer stmt.Close()

	for _, result := range results {
		result.RunID = runID // Ensure the run ID is set
		if _, err := stmt.ExecContext(context.Background(), result); err != nil {
			return fmt.Errorf("failed to execute insert for result of %s: %w", result.ConfigLink, err)
		}
	}

	return tx.Commit()
}

func GetHttpTestHistory(limit int) ([]HttpTestResult, error) {
	var results []HttpTestResult
	// Get results from the latest run
	query := `
        SELECT * FROM http_test_results 
        WHERE run_id = (SELECT id FROM http_test_runs ORDER BY start_time DESC LIMIT 1)
        ORDER BY status DESC, delay_ms ASC 
        LIMIT ?
    `
	err := DB.SelectContext(context.Background(), &results, query, limit)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []HttpTestResult{}, nil // Return empty slice, not an error
		}
		return nil, fmt.Errorf("could not list http test history: %w", err)
	}
	return results, nil
}

// CF Scanner //

func UpsertCfScanResultsBatch(results []CfScanResult) error {
	tx, err := DB.BeginTxx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareNamedContext(context.Background(), `
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
		if _, err := stmt.ExecContext(context.Background(), result); err != nil {
			return fmt.Errorf("failed to execute upsert for IP %s: %w", result.IP, err)
		}
	}

	return tx.Commit()
}

func GetCfScanResults() (map[string]CfScanResult, error) {
	var results []CfScanResult
	query := `SELECT * FROM cf_scan_results`
	err := DB.SelectContext(context.Background(), &results, query)
	if err != nil {
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
		SELECT * FROM cf_scan_results
		ORDER BY
			CASE WHEN error IS NULL THEN 0 ELSE 1 END,
			latency_ms ASC,
			download_mbps DESC
		LIMIT ?
	`
	err := DB.SelectContext(context.Background(), &results, query, limit)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []CfScanResult{}, nil
		}
		return nil, fmt.Errorf("could not list cf scan history: %w", err)
	}
	return results, nil
}
