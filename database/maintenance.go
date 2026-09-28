package database

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jmoiron/sqlx"
)

// Stats summarises what the database holds.
type Stats struct {
	Path              string `json:"path"`
	SizeBytes         int64  `json:"sizeBytes"`
	WALBytes          int64  `json:"walBytes"`
	SchemaVersion     uint   `json:"schemaVersion"`
	SchemaDirty       bool   `json:"schemaDirty,omitempty"`
	Subscriptions     int64  `json:"subscriptions"`
	EnabledSubs       int64  `json:"enabledSubscriptions"`
	Configs           int64  `json:"configs"`
	OneOffConfigs     int64  `json:"oneOffConfigs"`
	HttpTestRuns      int64  `json:"httpTestRuns"`
	HttpTestResults   int64  `json:"httpTestResults"`
	CfScanResults     int64  `json:"cfScanResults"`
	OldestRunStart    string `json:"oldestRunStart,omitempty"`
	LatestRunStart    string `json:"latestRunStart,omitempty"`
	LastSubscriptionF string `json:"lastSubscriptionFetch,omitempty"`
}

// OpenExisting opens the database at dbPath for maintenance: without
// migrating it (so it works on a dirty or older schema) and without creating
// it when it does not exist.
func OpenExisting(dbPath string) (*sqlx.DB, error) {
	if !isMemoryPath(dbPath) {
		if _, err := os.Stat(dbPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("no database at %s (it is created by the first command that stores something, e.g. 'xray-knife subs add')", dbPath)
			}
			return nil, err
		}
	}
	return OpenNoMigrate(dbPath)
}

// GetStats counts rows per table and reports the file sizes of dbPath.
func GetStats(dbPath string) (*Stats, error) {
	db, err := conn()
	if err != nil {
		return nil, err
	}
	return GetStatsDB(db, dbPath)
}

// GetStatsDB is GetStats on an already open database, which may be dirty or
// on an older schema: counts of tables that do not exist yet stay 0.
func GetStatsDB(db *sqlx.DB, dbPath string) (*Stats, error) {
	st := &Stats{Path: dbPath}
	if fi, err := os.Stat(dbPath); err == nil {
		st.SizeBytes = fi.Size()
	}
	if fi, err := os.Stat(dbPath + "-wal"); err == nil {
		st.WALBytes = fi.Size()
	}
	if v, dirty, err := MigrationStatus(db.DB); err == nil {
		st.SchemaVersion, st.SchemaDirty = v, dirty
	}
	counts := []struct {
		dst   *int64
		query string
	}{
		{&st.Subscriptions, `SELECT COUNT(*) FROM subscriptions`},
		{&st.EnabledSubs, `SELECT COUNT(*) FROM subscriptions WHERE enabled = 1`},
		{&st.Configs, `SELECT COUNT(*) FROM subscription_configs`},
		{&st.OneOffConfigs, `SELECT COUNT(*) FROM subscription_configs sc
			WHERE NOT EXISTS (SELECT 1 FROM subscription_config_sources s WHERE s.config_id = sc.id)`},
		{&st.HttpTestRuns, `SELECT COUNT(*) FROM http_test_runs`},
		{&st.HttpTestResults, `SELECT COUNT(*) FROM http_test_results`},
		{&st.CfScanResults, `SELECT COUNT(*) FROM cf_scan_results`},
	}
	for _, c := range counts {
		// A table from a later migration may not exist on a dirty or old
		// database; report what is there rather than failing.
		_ = db.GetContext(bg(), c.dst, c.query)
	}
	var s struct {
		Oldest, Latest, Fetched *string
	}
	row := db.QueryRowxContext(bg(), `SELECT
		(SELECT CAST(MIN(start_time) AS TEXT) FROM http_test_runs),
		(SELECT CAST(MAX(start_time) AS TEXT) FROM http_test_runs),
		(SELECT CAST(MAX(last_fetched_at) AS TEXT) FROM subscriptions)`)
	if err := row.Scan(&s.Oldest, &s.Latest, &s.Fetched); err == nil {
		if s.Oldest != nil {
			st.OldestRunStart = *s.Oldest
		}
		if s.Latest != nil {
			st.LatestRunStart = *s.Latest
		}
		if s.Fetched != nil {
			st.LastSubscriptionF = *s.Fetched
		}
	}
	return st, nil
}

// Vacuum rebuilds the database file to reclaim space and truncates the WAL.
func Vacuum() error {
	db, err := conn()
	if err != nil {
		return err
	}
	return VacuumDB(db)
}

// VacuumDB is Vacuum on an already open database (migrated or not).
func VacuumDB(db *sqlx.DB) error {
	if _, err := db.ExecContext(bg(), `VACUUM`); err != nil {
		return fmt.Errorf("vacuum failed: %w", err)
	}
	if _, err := db.ExecContext(bg(), `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("wal checkpoint failed: %w", err)
	}
	return nil
}

// Backup writes a consistent, compacted copy of the database to dest, which
// must not exist yet. It is safe while other processes use the database.
func Backup(dest string) error {
	db, err := conn()
	if err != nil {
		return err
	}
	return BackupDB(db, dest)
}

// BackupDB is Backup on an already open database (migrated or not). The
// target is created empty with mode 0600 first (VACUUM INTO accepts an
// empty file), so the copy, which holds subscription URLs and credentials,
// is never readable by others, not even for a moment.
func BackupDB(db *sqlx.DB, dest string) error {
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite it", dest)
		}
		return fmt.Errorf("could not create %s: %w", dest, err)
	}
	f.Close()
	if _, err := db.ExecContext(bg(), `VACUUM INTO ?`, dest); err != nil {
		os.Remove(dest)
		return fmt.Errorf("backup failed: %w", err)
	}
	return nil
}

// PruneOptions selects what Prune deletes. Zero values disable each part.
type PruneOptions struct {
	// RunsOlderThan deletes HTTP test runs (and their results) that started
	// before now minus this duration...
	RunsOlderThan time.Duration
	// ...but always keeps the KeepRuns most recent runs.
	KeepRuns int
	// ConfigsUnseenFor deletes configs no subscription (and no one-off
	// fetch) has returned for this long, and forgets per-subscription
	// sources that stopped returning a config.
	ConfigsUnseenFor time.Duration
	// CfScansOlderThan deletes CF scanner results last scanned before now
	// minus this duration.
	CfScansOlderThan time.Duration
	// DryRun counts without deleting.
	DryRun bool
}

// PruneResult reports how many rows Prune deleted (or would delete).
type PruneResult struct {
	Runs    int64 `json:"runs"`
	Results int64 `json:"results"`
	Sources int64 `json:"sources"`
	Configs int64 `json:"configs"`
	CfScans int64 `json:"cfScans"`
}

// sqliteTimeKey normalises a stored timestamp to UTC "YYYY-MM-DD HH:MM:SS"
// so the formats rows were written in compare correctly with cutoff:
//
//   - SQLite / RFC 3339 text, with or without an offset: datetime()
//     converts it to UTC.
//   - time.Time.String() text from earlier releases ("... +0330 +0330
//     m=+0.1"): its "+HHMM" offset (the first field after the seconds) is
//     rewritten as "+HH:MM" for datetime().
//   - anything else: its first 19 characters, as before.
//
// It is NULL only for a NULL column. Migration 0006 normalises
// http_latest_results.run_started with the same expression.
func sqliteTimeKey(col string) string {
	off := `(20 + instr(substr(` + col + `, 20), ' '))`
	legacy := `datetime(substr(` + col + `, 1, 19) || CASE WHEN substr(` + col + `, ` + off + `, 5) GLOB '[+-][0-9][0-9][0-9][0-9]' ` +
		`THEN substr(` + col + `, ` + off + `, 3) || ':' || substr(` + col + `, ` + off + ` + 3, 2) END)`
	return `COALESCE(datetime(` + col + `), ` + legacy + `, replace(substr(` + col + `, 1, 19), 'T', ' '))`
}

func cutoff(d time.Duration) string {
	return time.Now().UTC().Add(-d).Format("2006-01-02 15:04:05")
}

// Prune deletes old test history and stale configs in one transaction.
func Prune(opts PruneOptions) (*PruneResult, error) {
	db, err := conn()
	if err != nil {
		return nil, err
	}
	tx, err := db.BeginTxx(bg(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	res := &PruneResult{}
	exec := func(dst *int64, count, del string, args ...any) error {
		if err := tx.GetContext(bg(), dst, count, args...); err != nil {
			return err
		}
		if opts.DryRun || *dst == 0 {
			return nil
		}
		_, err := tx.ExecContext(bg(), del, args...)
		return err
	}

	if opts.RunsOlderThan > 0 {
		where := `FROM http_test_runs WHERE ` + sqliteTimeKey("start_time") + ` < ?
			AND id NOT IN (SELECT id FROM http_test_runs ORDER BY id DESC LIMIT ?)`
		args := []any{cutoff(opts.RunsOlderThan), opts.KeepRuns}
		if err := tx.GetContext(bg(), &res.Results,
			`SELECT COUNT(*) FROM http_test_results WHERE run_id IN (SELECT id `+where+`)`, args...); err != nil {
			return nil, fmt.Errorf("could not count test results: %w", err)
		}
		if err := exec(&res.Runs, `SELECT COUNT(*) `+where, `DELETE `+where, args...); err != nil {
			return nil, fmt.Errorf("could not prune test runs: %w", err)
		}
	}

	if opts.ConfigsUnseenFor > 0 {
		c := cutoff(opts.ConfigsUnseenFor)
		srcWhere := `FROM subscription_config_sources WHERE COALESCE(` + sqliteTimeKey("last_seen_at") + `, '') < ?`
		if err := exec(&res.Sources, `SELECT COUNT(*) `+srcWhere, `DELETE `+srcWhere, c); err != nil {
			return nil, fmt.Errorf("could not prune config sources: %w", err)
		}
		cfgWhere := `FROM subscription_configs WHERE ` + sqliteTimeKey("COALESCE(last_seen_at, added_at)") + ` < ?`
		if err := exec(&res.Configs, `SELECT COUNT(*) `+cfgWhere, `DELETE `+cfgWhere, c); err != nil {
			return nil, fmt.Errorf("could not prune configs: %w", err)
		}
	}

	if opts.CfScansOlderThan > 0 {
		where := `FROM cf_scan_results WHERE ` + sqliteTimeKey("last_scanned_at") + ` < ?`
		if err := exec(&res.CfScans, `SELECT COUNT(*) `+where, `DELETE `+where, cutoff(opts.CfScansOlderThan)); err != nil {
			return nil, fmt.Errorf("could not prune CF scan results: %w", err)
		}
	}

	if opts.DryRun {
		return res, nil
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}

// CompletionSubscriptions lists subscriptions for shell completion. It opens
// the database read-only and never migrates it; any problem (no database
// yet, old schema) yields an empty list.
func CompletionSubscriptions() []Subscription {
	path, err := completionPath()
	if err != nil {
		return nil
	}
	db, err := OpenReadOnly(path)
	if err != nil || db == nil {
		return nil
	}
	defer db.Close()
	var subs []Subscription
	if err := db.SelectContext(bg(), &subs,
		`SELECT id, url, remark, user_agent, enabled, last_fetched_at, created_at FROM subscriptions ORDER BY id`); err != nil {
		return nil
	}
	return subs
}

// completionResolver, when set, resolves the database path without side
// effects (no directory creation). The CLI sets it next to SetPathResolver.
var completionResolver func() (string, error)

// SetCompletionPathResolver registers the side-effect-free path resolver
// CompletionSubscriptions uses.
func SetCompletionPathResolver(fn func() (string, error)) {
	connMu.Lock()
	defer connMu.Unlock()
	completionResolver = fn
}

func completionPath() (string, error) {
	connMu.Lock()
	fn := completionResolver
	connMu.Unlock()
	if fn == nil {
		return ResolvePath()
	}
	return fn()
}
