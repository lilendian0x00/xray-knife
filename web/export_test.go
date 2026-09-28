package web

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/database"
)

const (
	exportPassedLink = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=tls&sni=a.example&type=tcp#passed-one"
	exportFailedLink = "trojan://secret@5.6.7.8:443?security=tls&sni=b.example#failed-one"
)

// seedExportDB stores one subscription with a passed and a failed config.
func seedExportDB(t *testing.T) int64 {
	t.Helper()
	if err := database.AddSubscription("https://sub.example/list", "seed", ""); err != nil {
		t.Fatal(err)
	}
	subs, err := database.ListSubscriptions()
	if err != nil || len(subs) != 1 {
		t.Fatalf("subs = %v err=%v", subs, err)
	}
	id := subs[0].ID
	now := database.NullTime{Time: time.Now().UTC(), Valid: true}
	var configs []database.SubscriptionConfig
	for _, l := range []string{exportPassedLink, exportFailedLink} {
		configs = append(configs, database.SubscriptionConfig{SubscriptionID: sql.NullInt64{Int64: id, Valid: true}, ConfigLink: l, LastSeenAt: now})
	}
	if err := database.UpsertSubscriptionConfigs(configs); err != nil {
		t.Fatal(err)
	}
	runID, err := database.CreateHttpTestRun(`{}`, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.InsertHttpTestResultsBatch(runID, []database.HttpTestResult{
		{ConfigLink: exportPassedLink, Status: "passed", DelayMs: 120},
		{ConfigLink: exportFailedLink, Status: "failed", DelayMs: -1},
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func getRaw(t *testing.T, url, token string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestSubscriptionExport(t *testing.T) {
	ts, token := authedServer(t)
	id := seedExportDB(t)
	base := fmt.Sprintf("%s/api/v1/subscriptions/%d/export", ts.URL, id)

	resp, body := getRaw(t, base+"?format=plain", token)
	if resp.StatusCode != 200 || !strings.Contains(body, exportPassedLink) || !strings.Contains(body, exportFailedLink) {
		t.Fatalf("plain: %d %q", resp.StatusCode, body)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment;") || resp.Header.Get("X-Export-Converted") != "2" {
		t.Fatalf("headers: %v", resp.Header)
	}

	resp, body = getRaw(t, base+"?status=passed", token) // base64 by default
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if resp.StatusCode != 200 || err != nil || strings.TrimSpace(string(raw)) != exportPassedLink {
		t.Fatalf("base64 passed: %d %q (%v)", resp.StatusCode, raw, err)
	}

	resp, body = getRaw(t, base+"?format=clash&status=passed", token)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "yaml") || !strings.Contains(body, "proxies:") {
		t.Fatalf("clash: %d %s %q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}

	resp, out := doJSON(t, "GET", base+"?format=singbox&report=1", token, "")
	if resp.StatusCode != 200 || out["format"] != "singbox" || out["selected"].(float64) != 2 || out["content"] == "" {
		t.Fatalf("report: %d %v", resp.StatusCode, out)
	}

	for _, q := range []string{"?format=bogus", "?status=great", "?limit=-1", "?limit=999999"} {
		if resp, _ := getRaw(t, base+q, token); resp.StatusCode != 400 {
			t.Errorf("%s: %d, want 400", q, resp.StatusCode)
		}
	}
	if resp, _ := getRaw(t, base+"?protocol=ss", token); resp.StatusCode != 404 {
		t.Errorf("empty selection: %d, want 404", resp.StatusCode)
	}
	if resp, _ := getRaw(t, fmt.Sprintf("%s/api/v1/subscriptions/%d/export", ts.URL, id+100), token); resp.StatusCode != 404 {
		t.Errorf("unknown subscription: %d", resp.StatusCode)
	}
	if resp, _ := getRaw(t, base, ""); resp.StatusCode != 401 {
		t.Errorf("export without auth: %d", resp.StatusCode)
	}

	// Across all enabled subscriptions.
	resp, body = getRaw(t, ts.URL+"/api/v1/configs/export?format=plain&status=passed", token)
	if resp.StatusCode != 200 || strings.TrimSpace(body) != exportPassedLink {
		t.Fatalf("configs export: %d %q", resp.StatusCode, body)
	}
}

func TestExportNothingConvertible(t *testing.T) {
	ts, token := authedServer(t)
	if err := database.AddSubscription("https://tg.example/list", "tg", ""); err != nil {
		t.Fatal(err)
	}
	subs, _ := database.ListSubscriptions()
	id := subs[0].ID
	tg := "tg://proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff"
	if err := database.UpsertSubscriptionConfigs([]database.SubscriptionConfig{{SubscriptionID: sql.NullInt64{Int64: id, Valid: true}, ConfigLink: tg}}); err != nil {
		t.Fatal(err)
	}
	resp, out := doJSON(t, "GET", fmt.Sprintf("%s/api/v1/subscriptions/%d/export?format=clash", ts.URL, id), token, "")
	if resp.StatusCode != http.StatusUnprocessableEntity || out["code"] != codeNothingExport || len(out["skipped"].([]any)) != 1 {
		t.Fatalf("mtproto to clash: %d %v", resp.StatusCode, out)
	}
}

func TestPublicSubscriptionTokens(t *testing.T) {
	ts, token := authedServer(t)
	seedExportDB(t)

	resp, out := doJSON(t, "POST", ts.URL+"/api/v1/sub-tokens", token, `{"name":"my phone","format":"plain","updateIntervalHours":12}`)
	if resp.StatusCode != 201 || out["token"] == nil {
		t.Fatalf("create: %d %v", resp.StatusCode, out)
	}
	subTok := out["token"].(string)
	tokID := out["subscription"].(map[string]any)["id"].(string)
	if !strings.HasPrefix(subTok, subTokenPrefix) || out["path"] != "/sub/"+subTok {
		t.Fatalf("token = %q path = %v", subTok, out["path"])
	}
	for _, bad := range []string{`{"format":"pdf"}`, `{"status":"ok"}`, `{"max":-1}`, `{"name":""}`, `{"name":"<script>"}`} {
		if resp, _ := doJSON(t, "POST", ts.URL+"/api/v1/sub-tokens", token, bad); resp.StatusCode != 400 {
			t.Errorf("create %s: %d", bad, resp.StatusCode)
		}
	}

	// The listing never exposes the token or its hash.
	resp, listBody := getRaw(t, ts.URL+"/api/v1/sub-tokens", token)
	if resp.StatusCode != 200 || strings.Contains(listBody, subTok) || strings.Contains(listBody, hashSubToken(subTok)) || !strings.Contains(listBody, "my phone") {
		t.Fatalf("list: %d %s", resp.StatusCode, listBody)
	}

	// No JWT needed; default filter is "passed".
	resp, body := getRaw(t, ts.URL+"/sub/"+subTok, "")
	if resp.StatusCode != 200 || strings.TrimSpace(body) != exportPassedLink {
		t.Fatalf("public sub: %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("Profile-Update-Interval") != "12" || !strings.HasPrefix(resp.Header.Get("Profile-Title"), "base64:") ||
		resp.Header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "inline;") {
		t.Fatalf("public sub headers: %v", resp.Header)
	}
	// The client picks the format, but cannot widen the token's
	// "passed" scope with status=any.
	resp, body = getRaw(t, ts.URL+"/sub/"+subTok+"?format=clash&status=any", "")
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "text/yaml") || strings.Count(body, "server:") != 1 {
		t.Fatalf("public clash: %d %q", resp.StatusCode, body)
	}
	if resp, _ := getRaw(t, ts.URL+"/sub/"+subTok+"?protocol=ss", ""); resp.StatusCode != 404 {
		t.Fatalf("empty selection: %d, want 404", resp.StatusCode)
	}

	// Update defaults, then revoke.
	resp, out = doJSON(t, "PATCH", ts.URL+"/api/v1/sub-tokens/"+tokID, token, `{"defaults":{"format":"base64","status":"any","max":1}}`)
	if resp.StatusCode != 200 || out["defaults"].(map[string]any)["max"].(float64) != 1 {
		t.Fatalf("patch: %d %v", resp.StatusCode, out)
	}
	resp, body = getRaw(t, ts.URL+"/sub/"+subTok, "")
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if resp.StatusCode != 200 || strings.Count(strings.TrimSpace(string(raw)), "\n") != 0 {
		t.Fatalf("max=1: %d %q", resp.StatusCode, raw)
	}
	if resp, _ := doJSON(t, "DELETE", ts.URL+"/api/v1/sub-tokens/"+tokID, token, ""); resp.StatusCode != 200 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if resp, _ := getRaw(t, ts.URL+"/sub/"+subTok, ""); resp.StatusCode != 404 {
		t.Fatalf("revoked token still works: %d", resp.StatusCode)
	}
	if resp, _ := doJSON(t, "DELETE", ts.URL+"/api/v1/sub-tokens/"+tokID, token, ""); resp.StatusCode != 404 {
		t.Fatalf("double revoke: %d", resp.StatusCode)
	}

	// Guessing is rate-limited per client IP.
	var last int
	for i := 0; i < 8; i++ {
		resp, _ := getRaw(t, ts.URL+"/sub/xks_guess"+fmt.Sprint(i), "")
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("guessing not rate-limited: last status %d", last)
	}
}

func TestSubTokenStorePersistenceAndBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	st, err := loadSubTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	st.now = func() time.Time { return now }
	d := subTokenDefaults{}
	if err := validateSubDefaults(&d); err != nil {
		t.Fatal(err)
	}
	plain, view, err := st.create("phone", d)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), plain) || !strings.Contains(string(data), hashSubToken(plain)) {
		t.Fatal("file must hold the hash, never the token")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}
	if d.Format != "base64" || d.Status != "passed" || d.Max != defaultSubMax || d.UpdateIntervalHours != defaultSubUpdateHrs {
		t.Fatalf("defaults = %+v", d)
	}

	reloaded, err := loadSubTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.now = func() time.Time { return now }
	if tok, _ := reloaded.lookup(plain); tok == nil || tok.ID != view.ID {
		t.Fatal("token lost across reload")
	}
	if tok, _ := reloaded.lookup(plain + "x"); tok != nil {
		t.Fatal("wrong token accepted")
	}
	for i := 1; i < subTokenRatePerMin; i++ {
		if _, limited := reloaded.lookup(plain); limited {
			t.Fatalf("limited after %d requests", i+1)
		}
	}
	if _, limited := reloaded.lookup(plain); !limited {
		t.Fatal("per-token budget not enforced")
	}
	now = now.Add(time.Minute)
	if _, limited := reloaded.lookup(plain); limited {
		t.Fatal("budget did not reset")
	}
}

// A public subscription on a server without tokens configured just 404s.
func TestPublicSubUnknownWithoutTokens(t *testing.T) {
	h := httptest.NewRecorder()
	s, _ := newTestServer(t, Options{SubTokenFile: "-"})
	req := httptest.NewRequest("GET", "/sub/xks_anything", nil)
	req.Host = "localhost"
	s.Handler().ServeHTTP(h, req)
	if h.Code != 404 {
		t.Fatalf("status %d", h.Code)
	}
}

// The age filter and limit are applied by the database query.
func TestExportAgeAndLimitInSQL(t *testing.T) {
	ts, token := authedServer(t)
	id := seedExportDB(t)
	base := fmt.Sprintf("%s/api/v1/subscriptions/%d/export?format=plain", ts.URL, id)
	if resp, body := getRaw(t, base+"&limit=1", token); resp.StatusCode != 200 || strings.Count(strings.TrimSpace(body), "\n") != 0 {
		t.Fatalf("limit=1: %d %q", resp.StatusCode, body)
	}
	db, err := database.Conn()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE http_test_runs SET start_time = datetime('now', '-3 days')`); err != nil {
		t.Fatal(err)
	}
	if resp, _ := getRaw(t, base+"&status=passed&maxAgeHours=24", token); resp.StatusCode != 404 {
		t.Fatalf("3-day-old result within 24h: %d", resp.StatusCode)
	}
	if resp, body := getRaw(t, base+"&status=passed&maxAgeHours=100", token); resp.StatusCode != 200 || strings.TrimSpace(body) != exportPassedLink {
		t.Fatalf("maxAgeHours=100: %d %q", resp.StatusCode, body)
	}
	sub := createSubToken(t, ts, token, `{"name":"fresh","format":"plain","maxAgeHours":24}`)
	if resp, _ := getRaw(t, ts.URL+"/sub/"+sub, ""); resp.StatusCode != 404 {
		t.Fatalf("token age cap ignored: %d", resp.StatusCode)
	}
}
