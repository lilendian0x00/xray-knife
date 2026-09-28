package database

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func links(rows []ExportedConfig) string {
	var out []string
	for _, r := range rows {
		out = append(out, r.Link)
	}
	return strings.Join(out, ",")
}

func TestConfigsForExport(t *testing.T) {
	useTempDB(t)
	a := addSub(t, "https://a.example/sub")
	b := addSub(t, "https://b.example/sub")
	upsert(t, a, "vless://a1", "vless://a2", "vless://a3")
	upsert(t, b, "vless://b1")
	upsert(t, 0, "vless://oneoff")
	off := false
	if err := UpdateSubscription(b, nil, nil, nil, &off); err != nil {
		t.Fatal(err)
	}

	old, _ := CreateHttpTestRun("{}", 3)
	if err := InsertHttpTestResultsBatch(old, []HttpTestResult{
		{ConfigLink: "vless://a1", Status: "failed"},
		{ConfigLink: "vless://a2", Status: "passed", DelayMs: 50},
	}); err != nil {
		t.Fatal(err)
	}
	run, _ := CreateHttpTestRun("{}", 3)
	if err := InsertHttpTestResultsBatch(run, []HttpTestResult{
		{ConfigLink: "vless://a1", Status: "passed", DelayMs: 300}, // newer run wins
		{ConfigLink: "vless://a2", Status: "semi-passed", DelayMs: 40},
		{ConfigLink: "vless://a3", Status: "passed", DelayMs: 100},
		{ConfigLink: "vless://b1", Status: "passed", DelayMs: 10},
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		f    ExportFilter
		want string
	}{
		{"enabled subs only", ExportFilter{}, "vless://a1,vless://a2,vless://a3"},
		{"named disabled sub", ExportFilter{SubscriptionIDs: []int64{b}}, "vless://b1"},
		{"two subs", ExportFilter{SubscriptionIDs: []int64{a, b}}, "vless://a1,vless://a2,vless://a3,vless://b1"},
		{"passed, fastest first", ExportFilter{Status: "passed"}, "vless://a3,vless://a1"},
		{"semi-passed includes passed", ExportFilter{Status: "semi-passed"}, "vless://a3,vless://a1,vless://a2"},
		{"limit after filter", ExportFilter{Status: "passed", Limit: 1}, "vless://a3"},
		{"protocol", ExportFilter{Protocol: "vmess"}, ""},
	}
	for _, tc := range cases {
		rows, err := ConfigsForExport(tc.f)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := links(rows); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	if _, err := ConfigsForExport(ExportFilter{Status: "failed"}); err == nil {
		t.Error("unsupported status accepted")
	}

	looked, err := LatestHttpResults([]string{"vless://a2", "vless://never"})
	if err != nil {
		t.Fatal(err)
	}
	if looked[0].Status.String != "semi-passed" || looked[1].Status.Valid {
		t.Fatalf("latest results = %+v", looked)
	}
	kept, _ := FilterExport(looked, "semi-passed", 0)
	if links(kept) != "vless://a2" {
		t.Fatalf("filtered = %q", links(kept))
	}
}

// latestByBruteForce computes each link's newest result straight from the
// history, the definition http_latest_results must match.
func latestByBruteForce(t *testing.T) map[string]string {
	t.Helper()
	var rows []struct {
		Link   string `db:"config_link"`
		Status string `db:"status"`
		ID     int64  `db:"id"`
	}
	if err := DB.Select(&rows, `SELECT config_link, status, id FROM (
		SELECT config_link, status, id, ROW_NUMBER() OVER (PARTITION BY config_link ORDER BY run_id DESC, id DESC) rn
		FROM http_test_results) WHERE rn = 1`); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Link] = fmt.Sprintf("%s#%d", r.Status, r.ID)
	}
	return out
}

func latestFromTable(t *testing.T) map[string]string {
	t.Helper()
	var rows []struct {
		Link   string `db:"config_link"`
		Status string `db:"status"`
		ID     int64  `db:"result_id"`
	}
	if err := DB.Select(&rows, `SELECT config_link, status, result_id FROM http_latest_results`); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Link] = fmt.Sprintf("%s#%d", r.Status, r.ID)
	}
	return out
}

// The triggers keep http_latest_results equal to the brute-force answer
// through out-of-order inserts, updates and deletes.
func TestLatestResultsStayConsistent(t *testing.T) {
	useTempDB(t)
	check := func(step string) {
		t.Helper()
		want, got := latestByBruteForce(t), latestFromTable(t)
		if fmt.Sprint(want) != fmt.Sprint(got) {
			t.Fatalf("%s: latest table %v, want %v", step, got, want)
		}
	}
	r1, _ := CreateHttpTestRun("{}", 2)
	r2, _ := CreateHttpTestRun("{}", 2)
	// The newer run is written first; the older run's later rows (higher
	// ids) must not replace its results.
	if err := InsertHttpTestResultsBatch(r2, []HttpTestResult{{ConfigLink: "a", Status: "passed", DelayMs: 5}, {ConfigLink: "b", Status: "failed"}}); err != nil {
		t.Fatal(err)
	}
	if err := InsertHttpTestResultsBatch(r1, []HttpTestResult{{ConfigLink: "a", Status: "failed"}, {ConfigLink: "c", Status: "passed"}}); err != nil {
		t.Fatal(err)
	}
	check("out-of-order inserts")
	// Two results for one link in one run: the later row wins.
	if err := InsertHttpTestResultsBatch(r2, []HttpTestResult{{ConfigLink: "b", Status: "semi-passed", DelayMs: 9}}); err != nil {
		t.Fatal(err)
	}
	check("same-run retry")
	mustExec(t, DB.DB, `UPDATE http_test_results SET status = 'failed' WHERE config_link = 'a' AND run_id = ?`, r2)
	check("update")
	mustExec(t, DB.DB, `DELETE FROM http_test_runs WHERE id = ?`, r2) // cascades
	check("delete newest run")
	mustExec(t, DB.DB, `DELETE FROM http_test_results`)
	check("delete all")
	if n := len(latestFromTable(t)); n != 0 {
		t.Fatalf("%d stale latest entries", n)
	}
}

func TestConfigsForExportTestedSince(t *testing.T) {
	useTempDB(t)
	sub := addSub(t, "https://s.example/sub")
	upsert(t, sub, "vless://old", "vless://new")
	oldRun, _ := CreateHttpTestRun("{}", 1)
	if err := InsertHttpTestResultsBatch(oldRun, []HttpTestResult{{ConfigLink: "vless://old", Status: "passed", DelayMs: 1}}); err != nil {
		t.Fatal(err)
	}
	mustExec(t, DB.DB, `UPDATE http_test_runs SET start_time = '2020-01-01 00:00:00' WHERE id = ?`, oldRun)
	newRun, _ := CreateHttpTestRun("{}", 1)
	if err := InsertHttpTestResultsBatch(newRun, []HttpTestResult{{ConfigLink: "vless://new", Status: "passed", DelayMs: 2}}); err != nil {
		t.Fatal(err)
	}
	since := time.Now().Add(-time.Hour)
	rows, err := ConfigsForExport(ExportFilter{Status: "passed", TestedSince: since})
	if err != nil || links(rows) != "vless://new" {
		t.Fatalf("tested since an hour ago = %q, %v", links(rows), err)
	}
	rows, _ = ConfigsForExport(ExportFilter{TestedSince: since})
	if links(rows) != "vless://new" {
		t.Fatalf("age filter without status = %q", links(rows))
	}
	rows, _ = ConfigsForExport(ExportFilter{Status: "passed"})
	if links(rows) != "vless://old,vless://new" {
		t.Fatalf("no age filter = %q", links(rows))
	}
}

// The status query must not touch the result history at all (no scan and no
// per-config correlated subquery of http_test_results).
func TestConfigsForExportPlanAvoidsHistory(t *testing.T) {
	useTempDB(t)
	for _, f := range []ExportFilter{{Status: "passed", Limit: 10}, {Status: "semi-passed", TestedSince: time.Now()}, {}} {
		var plan []struct {
			ID     int    `db:"id"`
			Parent int    `db:"parent"`
			NotUse int    `db:"notused"`
			Detail string `db:"detail"`
		}
		query, args := exportQueryForPlan(f)
		if err := DB.Select(&plan, "EXPLAIN QUERY PLAN "+query, args...); err != nil {
			t.Fatal(err)
		}
		for _, p := range plan {
			if strings.Contains(p.Detail, "http_test_results") || strings.Contains(p.Detail, "CORRELATED") && strings.Contains(p.Detail, "http_") {
				t.Errorf("filter %+v: plan touches the history: %q", f, p.Detail)
			}
		}
	}
}

// BenchmarkConfigsForExport measures a /sub-sized request against 100k
// configs with 300k results: go test -run x -bench ConfigsForExport ./database
func BenchmarkConfigsForExport(b *testing.B) {
	path := filepath.Join(b.TempDir(), "bench.db")
	if err := InitDB(path); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = Close() })
	const configs = 100_000
	if err := AddSubscription("https://bench.example/sub", "", ""); err != nil {
		b.Fatal(err)
	}
	now := NullTime{Time: time.Now().UTC(), Valid: true}
	batch := make([]SubscriptionConfig, 0, configs)
	for i := 0; i < configs; i++ {
		batch = append(batch, SubscriptionConfig{
			SubscriptionID: sql.NullInt64{Int64: 1, Valid: true},
			ConfigLink:     fmt.Sprintf("vless://u@h%d:443", i),
			Protocol:       sql.NullString{String: "vless", Valid: true},
			LastSeenAt:     now,
		})
	}
	if err := UpsertSubscriptionConfigs(batch); err != nil {
		b.Fatal(err)
	}
	for run := 0; run < 3; run++ {
		id, err := CreateHttpTestRun("{}", configs)
		if err != nil {
			b.Fatal(err)
		}
		results := make([]HttpTestResult, 0, configs)
		for i := 0; i < configs; i++ {
			status := "failed"
			if (i+run)%4 == 0 {
				status = "passed"
			}
			results = append(results, HttpTestResult{ConfigLink: fmt.Sprintf("vless://u@h%d:443", i), Status: status, DelayMs: int64((i * 7919) % 3000)})
		}
		if err := InsertHttpTestResultsBatch(id, results); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, err := ConfigsForExport(ExportFilter{Status: "passed", Limit: 1000, TestedSince: time.Now().Add(-time.Hour)})
		if err != nil || len(rows) != 1000 {
			b.Fatalf("%d rows, %v", len(rows), err)
		}
	}
}
