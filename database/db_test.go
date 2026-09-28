package database

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// useTempDB points the package at a fresh database for one test.
func useTempDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	if err := InitDB(path); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = Close() })
	return path
}

func TestFreshDatabaseMigratesToLatest(t *testing.T) {
	path := useTempDB(t)
	latest, err := LatestVersion()
	if err != nil {
		t.Fatal(err)
	}
	v, dirty, err := MigrationStatus(DB.DB)
	if err != nil || dirty || v != latest {
		t.Fatalf("version = %d dirty=%v err=%v, want %d clean", v, dirty, err, latest)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Fatalf("database mode = %o, want no group/other access", perm)
		}
	}
}

func TestConcurrentFirstOpenNeverLeavesDirtyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.db")
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := openAndMigrate(path)
			if err == nil {
				db.Close()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent open: %v", err)
		}
	}
	db, err := OpenNoMigrate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	v, dirty, err := MigrationStatus(db.DB)
	latest, _ := LatestVersion()
	if err != nil || dirty || v != latest {
		t.Fatalf("after concurrent opens: version %d dirty=%v err=%v", v, dirty, err)
	}
}

func TestPathWithQuestionMark(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "we?ird#name%.db")
	if runtime.GOOS == "windows" {
		t.Skip("'?' is not a valid Windows file name character")
	}
	if err := InitDB(path); err != nil {
		t.Fatalf("InitDB(%q): %v", path, err)
	}
	t.Cleanup(func() { _ = Close() })
	if err := AddSubscription("https://example.com/s", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database not created at the exact path: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() == "we" {
			t.Fatalf("path was truncated at '?': %v", entries)
		}
	}
}

func TestMissingDirectoryIsReportedClearly(t *testing.T) {
	err := InitDB(filepath.Join(t.TempDir(), "nope", "x.db"))
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v, want a missing-directory error", err)
	}
}

func TestLazyConnUsesResolver(t *testing.T) {
	_ = Close()
	path := filepath.Join(t.TempDir(), "lazy.db")
	calls := 0
	SetPathResolver(func() (string, error) { calls++; return path, nil })
	t.Cleanup(func() { SetPathResolver(nil); _ = Close() })

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("database exists before first use")
	}
	if _, err := ListSubscriptions(); err != nil {
		t.Fatal(err)
	}
	if _, err := ListSubscriptions(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("resolver called %d times, want 1", calls)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database not created on first use: %v", err)
	}
}

// Upgrading a v2 database (one subscription_id per config, cascading) keeps
// the data and records each config's source.
func TestUpgradeFromV2BackfillsSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.db")
	db, err := OpenNoMigrate(path)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := newMigrator(db.DB)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(2); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.DB, `INSERT INTO subscriptions (id, url) VALUES (1, 'https://a'), (2, 'https://b')`)
	mustExec(t, db.DB, `INSERT INTO subscription_configs (subscription_id, config_link, protocol, last_seen_at)
		VALUES (1, 'vless://one', 'vless', '2026-01-01 00:00:00'), (2, 'vless://two', 'vless', '2026-01-01 00:00:00'), (NULL, 'vless://oneoff', 'vless', NULL)`)
	db.Close()

	if err := InitDB(path); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	t.Cleanup(func() { _ = Close() })

	if n, _ := CountSubscriptionConfigs(1); n != 1 {
		t.Fatalf("sub 1 configs = %d, want 1", n)
	}
	all, err := ListSubscriptionConfigs(0, "", 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("configs after upgrade = %d, %v", len(all), err)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func addSub(t *testing.T, url string) int64 {
	t.Helper()
	if err := AddSubscription(url, "", ""); err != nil {
		t.Fatal(err)
	}
	subs, err := ListSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range subs {
		if s.URL == url {
			return s.ID
		}
	}
	t.Fatalf("subscription %s not found", url)
	return 0
}

func upsert(t *testing.T, subID int64, links ...string) {
	t.Helper()
	now := NullTime{Time: time.Now().UTC(), Valid: true}
	var cs []SubscriptionConfig
	for _, l := range links {
		c := SubscriptionConfig{ConfigLink: l, Protocol: sql.NullString{String: "vless", Valid: true}, LastSeenAt: now}
		if subID > 0 {
			c.SubscriptionID = sql.NullInt64{Int64: subID, Valid: true}
		}
		cs = append(cs, c)
	}
	if err := UpsertSubscriptionConfigs(cs); err != nil {
		t.Fatal(err)
	}
}

func sorted(s []string) []string { sort.Strings(s); return s }

func TestDeleteSubscriptionKeepsSharedConfigs(t *testing.T) {
	useTempDB(t)
	a := addSub(t, "https://a.example/sub")
	b := addSub(t, "https://b.example/sub")
	upsert(t, a, "vless://only-a", "vless://shared")
	upsert(t, b, "vless://shared", "vless://only-b")

	if n, _ := CountExclusiveSubscriptionConfigs(b); n != 1 {
		t.Fatalf("exclusive configs of b = %d, want 1", n)
	}
	deleted, err := DeleteSubscriptionCounted(b)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted %d configs, want 1", deleted)
	}
	links, err := GetConfigsFromDB(0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sorted(links), ","); got != "vless://only-a,vless://shared" {
		t.Fatalf("remaining configs = %s", got)
	}
	cfgs, _ := ListSubscriptionConfigs(a, "", 0)
	for _, c := range cfgs {
		if !c.SubscriptionID.Valid || c.SubscriptionID.Int64 != a {
			t.Errorf("config %s points at subscription %v, want %d", c.ConfigLink, c.SubscriptionID, a)
		}
	}
	if err := DeleteSubscription(b); err == nil {
		t.Fatal("deleting a missing subscription succeeded")
	}
}

func TestFromDBRespectsDisabledSubscriptions(t *testing.T) {
	useTempDB(t)
	on := addSub(t, "https://on.example/sub")
	off := addSub(t, "https://off.example/sub")
	upsert(t, on, "vless://on")
	upsert(t, off, "vless://off", "vless://both")
	upsert(t, on, "vless://both")
	upsert(t, 0, "vless://oneoff")
	disabled := false
	if err := UpdateSubscription(off, nil, nil, nil, &disabled); err != nil {
		t.Fatal(err)
	}

	links, err := GetConfigsFromDB(0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sorted(links), ","); got != "vless://both,vless://on,vless://oneoff" {
		t.Fatalf("--from-db = %s", got)
	}
	links, _ = GetConfigsFromDB(off, "", 0)
	if got := strings.Join(sorted(links), ","); got != "vless://both,vless://off" {
		t.Fatalf("--from-db --sub-id <disabled> = %s", got)
	}
	links, _ = GetConfigsForProxy()
	if got := strings.Join(sorted(links), ","); got != "vless://both,vless://on" {
		t.Fatalf("proxy pool = %s", got)
	}
}

func TestHttpHistoryOrderingAndNulls(t *testing.T) {
	useTempDB(t)
	old, err := CreateHttpTestRun("{}", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertHttpTestResultsBatch(old, []HttpTestResult{{ConfigLink: "old", Status: "passed", DelayMs: 1}}); err != nil {
		t.Fatal(err)
	}
	run, err := CreateHttpTestRun("{}", 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertHttpTestResultsBatch(run, []HttpTestResult{
		{ConfigLink: "semi", Status: "semi-passed", DelayMs: 10},
		{ConfigLink: "slow", Status: "passed", DelayMs: 300},
		{ConfigLink: "fast", Status: "passed", DelayMs: 100},
		{ConfigLink: "dead", Status: "failed", FailureKind: sql.NullString{String: "tls-reset", Valid: true}},
	}); err != nil {
		t.Fatal(err)
	}
	// Rows written by other tools may leave numeric columns NULL.
	mustExec(t, DB.DB, `INSERT INTO http_test_results (run_id, config_link, status) VALUES (?, 'nulls', 'failed')`, run)

	res, err := GetHttpTestHistory(10)
	if err != nil {
		t.Fatalf("history with NULL columns: %v", err)
	}
	var order []string
	for _, r := range res {
		order = append(order, r.ConfigLink)
	}
	if got := strings.Join(order, ","); got != "fast,slow,semi,dead,nulls" {
		t.Fatalf("order = %s", got)
	}
	if k := res[3].FailureKind; !k.Valid || k.String != "tls-reset" {
		t.Fatalf("failure kind of dead = %+v", k)
	}
	if res[0].FailureKind.Valid || res[4].FailureKind.Valid {
		t.Fatal("passed result / legacy row has a failure kind")
	}

	if err := FinishHttpTestRun(run); err != nil {
		t.Fatal(err)
	}
	var end sql.NullString
	if err := DB.Get(&end, `SELECT CAST(end_time AS TEXT) FROM http_test_runs WHERE id = ?`, run); err != nil || !end.Valid {
		t.Fatalf("end_time not written: %v %v", end, err)
	}
}

func TestPrune(t *testing.T) {
	useTempDB(t)
	sub := addSub(t, "https://s.example/sub")
	upsert(t, sub, "vless://fresh")
	upsert(t, sub, "vless://stale")
	upsert(t, sub, "vless://legacy")
	mustExec(t, DB.DB, `UPDATE subscription_configs SET last_seen_at = '2020-01-01 00:00:00+00:00' WHERE config_link = 'vless://stale'`)
	// Written by an earlier release as time.Time.String() in +03:30: 26h
	// old in UTC, though its local wall clock reads only 22.5h old.
	legacySeen := time.Now().Add(-26 * time.Hour).In(time.FixedZone("", 12600)).String()
	mustExec(t, DB.DB, `UPDATE subscription_configs SET last_seen_at = ? WHERE config_link = 'vless://legacy'`, legacySeen)
	mustExec(t, DB.DB, `UPDATE subscription_config_sources SET last_seen_at = '2020-01-01 00:00:00+00:00'
		WHERE config_id = (SELECT id FROM subscription_configs WHERE config_link = 'vless://stale')`)

	for i := 0; i < 3; i++ {
		id, err := CreateHttpTestRun("{}", 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := InsertHttpTestResultsBatch(id, []HttpTestResult{{ConfigLink: "x", Status: "passed"}}); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(t, DB.DB, `UPDATE http_test_runs SET start_time = '2020-01-01 00:00:00'`)

	opts := PruneOptions{RunsOlderThan: 24 * time.Hour, KeepRuns: 1, ConfigsUnseenFor: 24 * time.Hour, DryRun: true}
	dry, err := Prune(opts)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Runs != 2 || dry.Results != 2 || dry.Configs != 2 || dry.Sources != 1 {
		t.Fatalf("dry run = %+v", dry)
	}
	if n, _ := CountSubscriptionConfigs(0); n != 3 {
		t.Fatal("dry run deleted configs")
	}

	opts.DryRun = false
	got, err := Prune(opts)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *dry {
		t.Fatalf("prune = %+v, dry run said %+v", got, dry)
	}
	links, _ := GetConfigsFromDB(0, "", 0)
	if strings.Join(links, ",") != "vless://fresh" {
		t.Fatalf("configs after prune = %v", links)
	}
	var runs int
	_ = DB.Get(&runs, `SELECT COUNT(*) FROM http_test_runs`)
	if runs != 1 {
		t.Fatalf("runs after prune = %d, want 1", runs)
	}
}

// Rows written by earlier releases carry their local offset; the prune key
// must compare them in UTC like everything else.
func TestSQLiteTimeKey(t *testing.T) {
	useTempDB(t)
	cases := map[string]string{
		"2026-09-01 02:00:00":                                 "2026-09-01 02:00:00",
		"2026-09-01T02:00:00Z":                                "2026-09-01 02:00:00",
		"2026-09-01 02:00:00.123456789+03:30":                 "2026-08-31 22:30:00",
		"2026-09-01T02:00:00.5-07:00":                         "2026-09-01 09:00:00",
		"2026-09-01 02:00:00.1 +0330 +0330":                   "2026-08-31 22:30:00",
		"2026-09-01 02:00:00.123456789 +0330 +0330 m=+0.0001": "2026-08-31 22:30:00",
		"2026-09-01 02:00:00 -0700 PDT":                       "2026-09-01 09:00:00",
		"2026-09-01 02:00:00.1 +0000 UTC":                     "2026-09-01 02:00:00",
		"2026-09-01 02:00:00.1 garbage":                       "2026-09-01 02:00:00",
	}
	for in, want := range cases {
		var got string
		if err := DB.Get(&got, `WITH v(c) AS (SELECT ?) SELECT `+sqliteTimeKey("c")+` FROM v`, in); err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Errorf("sqliteTimeKey(%q) = %q, want %q", in, got, want)
		}
	}
	var null sql.NullString
	if err := DB.Get(&null, `SELECT `+sqliteTimeKey("NULL")); err != nil || null.Valid {
		t.Fatalf("NULL column: %v %v", null, err)
	}
}

// http_latest_results.run_started is the run's start in UTC, also for a
// run whose start an earlier release wrote with its local offset.
func TestLatestResultRunStartedIsUTC(t *testing.T) {
	useTempDB(t)
	id, err := CreateHttpTestRun("{}", 1)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, DB.DB, `UPDATE http_test_runs SET start_time = '2026-09-01 02:00:00.1 +0330 +0330' WHERE id = ?`, id)
	if err := InsertHttpTestResultsBatch(id, []HttpTestResult{{ConfigLink: "vless://x", Status: "passed"}}); err != nil {
		t.Fatal(err)
	}
	var started string
	if err := DB.Get(&started, `SELECT run_started FROM http_latest_results WHERE config_link = 'vless://x'`); err != nil {
		t.Fatal(err)
	}
	if started != "2026-08-31 22:30:00" {
		t.Fatalf("run_started = %q", started)
	}
	mustExec(t, DB.DB, `UPDATE http_test_runs SET start_time = '2026-09-01T02:00:00-07:00' WHERE id = ?`, id)
	if err := DB.Get(&started, `SELECT run_started FROM http_latest_results WHERE config_link = 'vless://x'`); err != nil {
		t.Fatal(err)
	}
	if started != "2026-09-01 09:00:00" {
		t.Fatalf("run_started after update = %q", started)
	}
}

func TestBackupAndStats(t *testing.T) {
	path := useTempDB(t)
	addSub(t, "https://s.example/sub")
	st, err := GetStats(path)
	if err != nil {
		t.Fatal(err)
	}
	latest, _ := LatestVersion()
	if st.Subscriptions != 1 || st.SchemaVersion != latest {
		t.Fatalf("stats = %+v", st)
	}
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := Backup(dest); err != nil {
		t.Fatal(err)
	}
	if err := Backup(dest); err == nil {
		t.Fatal("backup overwrote an existing file")
	}
	if err := Vacuum(); err != nil {
		t.Fatal(err)
	}
}

func TestCompletionSubscriptionsIsReadOnly(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.db")
	SetCompletionPathResolver(func() (string, error) { return missing, nil })
	t.Cleanup(func() { SetCompletionPathResolver(nil) })
	if subs := CompletionSubscriptions(); subs != nil {
		t.Fatalf("got %v from a missing database", subs)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("completion created the database")
	}

	path := useTempDB(t)
	addSub(t, "https://c.example/sub")
	SetCompletionPathResolver(func() (string, error) { return path, nil })
	if subs := CompletionSubscriptions(); len(subs) != 1 {
		t.Fatalf("completion subscriptions = %v", subs)
	}
}

func TestNullTimeFormats(t *testing.T) {
	for _, in := range []any{
		"2026-09-23 10:11:12.123456789+03:30",
		"2026-09-23T10:11:12Z",
		"2026-09-23 10:11:12",
		"2026-09-23 10:11:12.5 +0330 +0330 m=+1.000000001",
		[]byte("2026-09-23"),
		time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC),
	} {
		var n NullTime
		if err := n.Scan(in); err != nil || !n.Valid || n.Time.Year() != 2026 {
			t.Errorf("Scan(%v) = %+v, %v", in, n, err)
		}
	}
	var n NullTime
	if err := n.Scan(nil); err != nil || n.Valid {
		t.Errorf("Scan(nil) = %+v, %v", n, err)
	}
	if err := n.Scan("garbage"); err == nil {
		t.Error("garbage accepted")
	}
	if v, _ := (NullTime{}).Value(); v != nil {
		t.Errorf("invalid NullTime Value() = %v", v)
	}
}

func TestSubscriptionURLUniqueError(t *testing.T) {
	useTempDB(t)
	addSub(t, "https://dup.example/sub")
	if err := AddSubscription("https://dup.example/sub", "", ""); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate add: %v", err)
	}
}

// A v3 database with results keeps them (failure_kind NULL) after v4.
func TestUpgradeFromV3KeepsResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.db")
	db, err := OpenNoMigrate(path)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := newMigrator(db.DB)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(3); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.DB, `INSERT INTO http_test_runs (id, config_count) VALUES (1, 1)`)
	mustExec(t, db.DB, `INSERT INTO http_test_results (run_id, config_link, status, reason, delay_ms) VALUES (1, 'vless://x', 'failed', 'boom', 0)`)
	db.Close()

	if err := InitDB(path); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	t.Cleanup(func() { _ = Close() })
	res, err := GetHttpTestHistory(10)
	if err != nil || len(res) != 1 || res[0].FailureKind.Valid || res[0].Reason.String != "boom" {
		t.Fatalf("after v4: %+v, %v", res, err)
	}
}

// Every down migration undoes its up migration cleanly.
func TestMigrationsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roundtrip.db")
	db, err := OpenNoMigrate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m, _, err := newMigrator(db.DB)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Up(); err != nil {
		t.Fatal(err)
	}
	if err := m.Down(); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("up again: %v", err)
	}
}

// A v2 database with a config pointing at a deleted subscription (possible
// when rows were written with foreign keys off) still migrates, keeping the
// config as a one-off.
func TestUpgradeWithOrphanConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orphan.db")
	db, err := OpenNoMigrate(path)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := newMigrator(db.DB)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(2); err != nil {
		t.Fatal(err)
	}
	c, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`PRAGMA foreign_keys = OFF`,
		`INSERT INTO subscriptions (id, url) VALUES (1, 'https://a')`,
		`INSERT INTO subscription_configs (subscription_id, config_link) VALUES (1, 'vless://kept'), (99, 'vless://orphan')`,
	} {
		if _, err := c.ExecContext(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	c.Close()
	db.Close()

	if err := InitDB(path); err != nil {
		t.Fatalf("upgrade with an orphan row: %v", err)
	}
	t.Cleanup(func() { _ = Close() })
	v, dirty, err := MigrationStatus(DB.DB)
	latest, _ := LatestVersion()
	if err != nil || dirty || v != latest {
		t.Fatalf("version %d dirty=%v err=%v", v, dirty, err)
	}
	cfgs, err := ListSubscriptionConfigs(0, "", 0)
	if err != nil || len(cfgs) != 2 {
		t.Fatalf("configs = %+v, %v", cfgs, err)
	}
	for _, c := range cfgs {
		if c.ConfigLink == "vless://orphan" && c.SubscriptionID.Valid {
			t.Fatalf("orphan kept subscription_id %d", c.SubscriptionID.Int64)
		}
	}
	if links, _ := GetConfigsFromDB(1, "", 0); len(links) != 1 || links[0] != "vless://kept" {
		t.Fatalf("sub 1 configs = %v", links)
	}
}

// Maintenance works on a dirty database and never creates a missing one.
func TestMaintenanceOnDirtyAndMissingDB(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.db")
	if _, err := OpenExisting(missing); err == nil {
		t.Fatal("OpenExisting accepted a missing database")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("OpenExisting created the database")
	}

	path := filepath.Join(t.TempDir(), "dirty.db")
	if err := InitDB(path); err != nil {
		t.Fatal(err)
	}
	addSub(t, "https://d.example/sub")
	_ = Close()
	db, err := OpenNoMigrate(path)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db.DB, `UPDATE schema_migrations SET dirty = 1`)
	db.Close()
	if err := InitDB(path); err == nil {
		t.Fatal("dirty database migrated silently")
	}

	db, err = OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := GetStatsDB(db, path)
	if err != nil || !st.SchemaDirty || st.Subscriptions != 1 {
		t.Fatalf("stats on a dirty db = %+v, %v", st, err)
	}
	if err := VacuumDB(db); err != nil {
		t.Fatalf("vacuum on a dirty db: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := BackupDB(db, dest); err != nil {
		t.Fatalf("backup of a dirty db: %v", err)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(dest); info.Mode().Perm() != 0o600 {
			t.Fatalf("backup mode = %o, want 600", info.Mode().Perm())
		}
	}
	if err := BackupDB(db, dest); err == nil {
		t.Fatal("backup overwrote an existing file")
	}

	// Forcing "none" clears the version.
	if err := ForceMigrationVersion(db.DB, -1); err != nil {
		t.Fatal(err)
	}
	if v, dirty, err := MigrationStatus(db.DB); err != nil || v != 0 || dirty {
		t.Fatalf("after force none: v=%d dirty=%v err=%v", v, dirty, err)
	}
}
