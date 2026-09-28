package web

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/database"
)

// useTempDB points the lazily opened database at a fresh file.
func useTempDB(t *testing.T) {
	t.Helper()
	_ = database.Close()
	path := filepath.Join(t.TempDir(), "test.db")
	database.SetPathResolver(func() (string, error) { return path, nil })
	t.Cleanup(func() {
		_ = database.Close()
		database.SetPathResolver(nil)
	})
}

func authedServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	_, ts := newTestServer(t, Options{})
	useTempDB(t)
	_, body := login(t, ts, "admin", "s3cret-pass")
	return ts, body["token"].(string)
}

func TestSubscriptionAPI(t *testing.T) {
	ts, token := authedServer(t)

	subBody := "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=tls&type=tcp#one\n" +
		"#profile-title: my sub\n" +
		"trojan://pass@5.6.7.8:443?security=tls#two\n"
	var gotUA string
	subSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		fmt.Fprint(w, subBody)
	}))
	defer subSrv.Close()

	resp, out := doJSON(t, "POST", ts.URL+"/api/v1/subscriptions", token, `{"url":"ftp://nope"}`)
	if resp.StatusCode != 400 {
		t.Fatalf("bad url: %d %v", resp.StatusCode, out)
	}
	resp, out = doJSON(t, "POST", ts.URL+"/api/v1/subscriptions", token,
		fmt.Sprintf(`{"url":%q,"remark":"test","userAgent":"knife-test/1"}`, subSrv.URL))
	if resp.StatusCode != 201 || out["id"] == nil {
		t.Fatalf("add: %d %v", resp.StatusCode, out)
	}
	id := int(out["id"].(float64))
	resp, _ = doJSON(t, "POST", ts.URL+"/api/v1/subscriptions", token, fmt.Sprintf(`{"url":%q}`, subSrv.URL))
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate add: %d", resp.StatusCode)
	}

	resp, out = doJSON(t, "POST", fmt.Sprintf("%s/api/v1/subscriptions/%d/fetch", ts.URL, id), token, "")
	if resp.StatusCode != 200 || out["saved"].(float64) != 2 || out["format"] != "plain" {
		t.Fatalf("fetch: %d %v", resp.StatusCode, out)
	}
	if gotUA != "knife-test/1" {
		t.Fatalf("subscription User-Agent = %q", gotUA)
	}
	if sub := out["subscription"].(map[string]any); sub["configCount"].(float64) != 2 || sub["lastFetchedAt"] == nil {
		t.Fatalf("subscription after fetch: %v", sub)
	}

	resp, out = doJSON(t, "GET", fmt.Sprintf("%s/api/v1/subscriptions/%d/configs?protocol=vless&per_page=10", ts.URL, id), token, "")
	if resp.StatusCode != 200 || out["total"].(float64) != 1 {
		t.Fatalf("configs: %d %v", resp.StatusCode, out)
	}
	resp, out = doJSON(t, "GET", ts.URL+"/api/v1/configs?q=two", token, "")
	if resp.StatusCode != 200 || out["total"].(float64) != 1 {
		t.Fatalf("config search: %d %v", resp.StatusCode, out)
	}

	resp, out = doJSON(t, "PATCH", fmt.Sprintf("%s/api/v1/subscriptions/%d", ts.URL, id), token, `{"enabled":false,"remark":"renamed"}`)
	if resp.StatusCode != 200 || out["enabled"] != false || out["remark"] != "renamed" {
		t.Fatalf("patch: %d %v", resp.StatusCode, out)
	}
	resp, _ = doJSON(t, "GET", ts.URL+"/api/v1/subscriptions/999", token, "")
	if resp.StatusCode != 404 {
		t.Fatalf("missing subscription: %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "GET", ts.URL+"/api/v1/subscriptions/abc", token, "")
	if resp.StatusCode != 400 {
		t.Fatalf("non-numeric id: %d", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/subscriptions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	listResp.Body.Close()
	if listResp.StatusCode != 200 {
		t.Fatalf("list: %d", listResp.StatusCode)
	}

	resp, out = doJSON(t, "DELETE", fmt.Sprintf("%s/api/v1/subscriptions/%d", ts.URL, id), token, "")
	if resp.StatusCode != 200 || out["configsDeleted"].(float64) != 2 {
		t.Fatalf("delete: %d %v", resp.StatusCode, out)
	}

	// A failing source reports 502 without echoing the URL.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer bad.Close()
	_, out = doJSON(t, "POST", ts.URL+"/api/v1/subscriptions", token, fmt.Sprintf(`{"url":%q}`, bad.URL+"/secret-token"))
	badID := int(out["id"].(float64))
	resp, out = doJSON(t, "POST", fmt.Sprintf("%s/api/v1/subscriptions/%d/fetch", ts.URL, badID), token, `{"timeoutSec":5}`)
	if resp.StatusCode != 502 || out["code"] != codeFetchFailed || strings.Contains(fmt.Sprint(out["error"]), "secret-token") {
		t.Fatalf("failing fetch: %d %v", resp.StatusCode, out)
	}
}

func TestHistoryAPI(t *testing.T) {
	ts, token := authedServer(t)

	runID, err := database.CreateHttpTestRun(`{"maxDelay":3000}`, 3)
	if err != nil {
		t.Fatal(err)
	}
	results := []database.HttpTestResult{
		{ConfigLink: "vless://a@1.1.1.1:443", Status: "passed", DelayMs: 200, DownloadMbps: 5},
		{ConfigLink: "vless://b@1.1.1.2:443", Status: "passed", DelayMs: 100},
		{ConfigLink: "trojan://c@1.1.1.3:443", Status: "failed", DelayMs: -1, Reason: sql.NullString{String: "timeout", Valid: true},
			FailureKind: sql.NullString{String: "tls-reset", Valid: true}},
		// Too slow for maxDelay: counts as failed, as in the live summary.
		{ConfigLink: "vless://d@1.1.1.4:443", Status: "timeout", DelayMs: -1},
	}
	if err := database.InsertHttpTestResultsBatch(runID, results); err != nil {
		t.Fatal(err)
	}

	resp, out := doJSON(t, "GET", ts.URL+"/api/v1/history/http/runs", token, "")
	if resp.StatusCode != 200 || out["total"].(float64) != 1 {
		t.Fatalf("runs: %d %v", resp.StatusCode, out)
	}
	run := out["items"].([]any)[0].(map[string]any)
	counts := run["counts"].(map[string]any)
	if counts["passed"].(float64) != 2 || counts["failed"].(float64) != 2 || counts["total"].(float64) != 4 || run["options"].(map[string]any)["maxDelay"].(float64) != 3000 {
		t.Fatalf("run = %v", run)
	}

	base := fmt.Sprintf("%s/api/v1/history/http/runs/%d", ts.URL, runID)
	resp, out = doJSON(t, "GET", base+"/results?status=passed&sort=delay", token, "")
	if resp.StatusCode != 200 || out["total"].(float64) != 2 {
		t.Fatalf("results: %d %v", resp.StatusCode, out)
	}
	first := out["items"].([]any)[0].(map[string]any)
	if first["delay"].(float64) != 100 || first["protocol"] != "vless" {
		t.Fatalf("sorted first = %v", first)
	}
	resp, out = doJSON(t, "GET", base+"/results?protocol=trojan", token, "")
	if resp.StatusCode != 200 || out["total"].(float64) != 1 {
		t.Fatalf("protocol filter: %d %v", resp.StatusCode, out)
	}
	if kind := out["items"].([]any)[0].(map[string]any)["failureKind"]; kind != "tls-reset" {
		t.Fatalf("failureKind = %v", kind)
	}
	resp, out = doJSON(t, "GET", base+"/results?q=time%25out", token, "")
	if resp.StatusCode != 200 || out["total"].(float64) != 0 {
		t.Fatalf("LIKE wildcard not escaped: %d %v", resp.StatusCode, out)
	}
	resp, _ = doJSON(t, "GET", base+"/results?sort=drop%20table", token, "")
	if resp.StatusCode != 400 {
		t.Fatalf("unknown sort: %d", resp.StatusCode)
	}

	if err := database.UpsertCfScanResultsBatch([]database.CfScanResult{
		{IP: "104.16.0.1", LatencyMs: sql.NullInt64{Int64: 50, Valid: true}},
		{IP: "104.16.0.2", Error: sql.NullString{String: "timeout", Valid: true}},
	}); err != nil {
		t.Fatal(err)
	}
	resp, out = doJSON(t, "GET", ts.URL+"/api/v1/history/cf?ok=1", token, "")
	if resp.StatusCode != 200 || out["total"].(float64) != 1 {
		t.Fatalf("cf history: %d %v", resp.StatusCode, out)
	}

	resp, _ = doJSON(t, "DELETE", base, token, "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete run: %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "GET", base, token, "")
	if resp.StatusCode != 404 {
		t.Fatalf("deleted run still there: %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "DELETE", ts.URL+"/api/v1/history/cf", token, "")
	if resp.StatusCode != 200 {
		t.Fatalf("clear cf: %d", resp.StatusCode)
	}
}
