package web

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/scanner"
)

// seedPrivateSub adds a disabled subscription holding one untested config.
func seedPrivateSub(t *testing.T) (int64, string) {
	t.Helper()
	if err := database.AddSubscription("https://private.example/paid", "private", ""); err != nil {
		t.Fatal(err)
	}
	subs, _ := database.ListSubscriptions()
	var id int64
	for _, s := range subs {
		if s.URL == "https://private.example/paid" {
			id = s.ID
		}
	}
	secret := "trojan://PRIVATE-PASSWORD@9.9.9.9:443?security=tls&sni=p.example#private"
	now := database.NullTime{Time: time.Now().UTC(), Valid: true}
	if err := database.UpsertSubscriptionConfigs([]database.SubscriptionConfig{{SubscriptionID: sql.NullInt64{Int64: id, Valid: true}, ConfigLink: secret, LastSeenAt: now}}); err != nil {
		t.Fatal(err)
	}
	f := false
	if err := database.UpdateSubscription(id, nil, nil, nil, &f); err != nil {
		t.Fatal(err)
	}
	return id, secret
}

func createSubToken(t *testing.T, ts *httptest.Server, jwtTok, body string) string {
	t.Helper()
	resp, out := doJSON(t, "POST", ts.URL+"/api/v1/sub-tokens", jwtTok, body)
	if resp.StatusCode != 201 {
		t.Fatalf("create token: %d %v", resp.StatusCode, out)
	}
	return out["token"].(string)
}

// Review HIGH #1: query parameters could widen a token's scope and dump a
// disabled subscription's configs.
func TestPublicSubQueryOnlyNarrows(t *testing.T) {
	ts, jwtTok := authedServer(t)
	idA := seedExportDB(t)
	idB, _ := seedPrivateSub(t)

	scoped := createSubToken(t, ts, jwtTok, fmt.Sprintf(`{"name":"scoped","format":"plain","status":"passed","max":1,"subscriptionIds":[%d]}`, idA))
	for _, q := range []string{
		fmt.Sprintf("?sub=%d&status=any&max=5000", idB),
		fmt.Sprintf("?sub=%d,%d&status=any", idA, idB),
		"?status=any&max=5000",
	} {
		resp, body := getRaw(t, ts.URL+"/sub/"+scoped+q, "")
		if strings.Contains(body, "PRIVATE-PASSWORD") || strings.Contains(body, exportFailedLink) {
			t.Fatalf("%s widened the token: %d %q", q, resp.StatusCode, body)
		}
		if resp.StatusCode == 200 && strings.Count(strings.TrimSpace(body), "\n") != 0 {
			t.Fatalf("%s raised max above the token's 1: %q", q, body)
		}
	}
	if resp, _ := getRaw(t, ts.URL+"/sub/"+scoped+fmt.Sprintf("?sub=%d", idB), ""); resp.StatusCode != 404 {
		t.Fatalf("subscription outside the token's list: %d", resp.StatusCode)
	}

	// A token without its own list covers enabled subscriptions only.
	open := createSubToken(t, ts, jwtTok, `{"name":"open","format":"plain","status":"any"}`)
	resp, body := getRaw(t, ts.URL+"/sub/"+open+fmt.Sprintf("?sub=%d", idB), "")
	if resp.StatusCode != 404 || strings.Contains(body, "PRIVATE-PASSWORD") {
		t.Fatalf("disabled subscription reachable by id: %d %q", resp.StatusCode, body)
	}
	resp, body = getRaw(t, ts.URL+"/sub/"+open, "")
	if resp.StatusCode != 200 || strings.Contains(body, "PRIVATE-PASSWORD") {
		t.Fatalf("open token: %d %q", resp.StatusCode, body)
	}
	// Narrowing still works: status may get stricter.
	resp, body = getRaw(t, ts.URL+"/sub/"+open+"?status=passed", "")
	if resp.StatusCode != 200 || strings.TrimSpace(body) != exportPassedLink {
		t.Fatalf("stricter status: %d %q", resp.StatusCode, body)
	}
	// A token limited to one protocol cannot be switched to another.
	vlessOnly := createSubToken(t, ts, jwtTok, `{"name":"vless","format":"plain","status":"any","protocol":"vless"}`)
	if resp, _ := getRaw(t, ts.URL+"/sub/"+vlessOnly+"?protocol=trojan", ""); resp.StatusCode != 404 {
		t.Fatalf("protocol widened: %d", resp.StatusCode)
	}
}

func TestPublicSubQueryBounds(t *testing.T) {
	enabled := func() (map[int64]bool, error) { return map[int64]bool{1: true}, nil }
	d := subTokenDefaults{Format: "base64", Status: "semi-passed", Max: 50, MaxAgeHours: 24, SubscriptionIDs: []int64{1, 2}}
	q, empty, err := publicSubQuery(d, url.Values{"status": {"any"}, "max": {"900"}, "maxAgeHours": {"0"}, "sub": {"2,3"}}, enabled)
	if err != nil || empty {
		t.Fatalf("err=%v empty=%v", err, empty)
	}
	if q.Status != "semi-passed" || q.Limit != 50 || q.MaxAge != 24*time.Hour || len(q.SubscriptionIDs) != 1 || q.SubscriptionIDs[0] != 2 {
		t.Fatalf("widened: %+v", q)
	}
	q, _, _ = publicSubQuery(d, url.Values{"status": {"passed"}, "max": {"5"}, "maxAgeHours": {"2"}}, enabled)
	if q.Status != "passed" || q.Limit != 5 || q.MaxAge != 2*time.Hour || len(q.SubscriptionIDs) != 2 {
		t.Fatalf("narrowing ignored: %+v", q)
	}
	// A token with no age cap accepts one from the request.
	q, _, _ = publicSubQuery(subTokenDefaults{Format: "plain", Status: "passed", Max: 10}, url.Values{"maxAgeHours": {"6"}}, enabled)
	if q.MaxAge != 6*time.Hour {
		t.Fatalf("maxAge = %v", q.MaxAge)
	}
	if _, empty, _ := publicSubQuery(subTokenDefaults{Format: "plain", Max: 10}, url.Values{"sub": {"7"}}, enabled); !empty {
		t.Fatal("disabled/unknown subscription not rejected for a list-less token")
	}
	if _, _, err := publicSubQuery(d, url.Values{"status": {"great"}}, enabled); err == nil {
		t.Fatal("bad status accepted")
	}
}

// Review MED #4: bad guesses from one address locked out valid tokens.
func TestValidTokenNotLockedByGuesses(t *testing.T) {
	ts, jwtTok := authedServer(t)
	seedExportDB(t)
	tok := createSubToken(t, ts, jwtTok, `{"name":"phone","format":"plain"}`)
	for i := 0; i < 10; i++ {
		getRaw(t, ts.URL+"/sub/xks_bad"+fmt.Sprint(i), "")
	}
	if resp, _ := getRaw(t, ts.URL+"/sub/xks_bad-again", ""); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("guessing not limited: %d", resp.StatusCode)
	}
	if resp, body := getRaw(t, ts.URL+"/sub/"+tok, ""); resp.StatusCode != 200 {
		t.Fatalf("valid token locked out by other guesses: %d %q", resp.StatusCode, body)
	}
}

func TestLimiterKeysAndCap(t *testing.T) {
	if limiterKey("2001:db8:1:2:aaaa::1") != limiterKey("2001:db8:1:2:bbbb::2") {
		t.Fatal("IPv6 addresses of one /64 must share a key")
	}
	if limiterKey("2001:db8:1:2::1") == limiterKey("2001:db8:1:3::1") {
		t.Fatal("different /64s must not share a key")
	}
	if limiterKey("::ffff:1.2.3.4") != "1.2.3.4" || limiterKey("1.2.3.4") == limiterKey("1.2.3.5") {
		t.Fatal("IPv4 keys wrong")
	}
	l := newLoginLimiter()
	l.maxClients = 3
	now := time.Unix(0, 0)
	l.now = func() time.Time { now = now.Add(time.Second); return now }
	for i := 0; i < 10; i++ {
		l.fail(fmt.Sprintf("10.0.0.%d", i))
	}
	if len(l.clients) > 3 {
		t.Fatalf("limiter tracks %d clients, cap 3", len(l.clients))
	}
	if _, ok := l.clients["10.0.0.9"]; !ok {
		t.Fatal("newest client evicted instead of the stalest")
	}
}

func TestTrustProxyHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	plain := &Server{}
	if got := plain.clientIP(r); got != "127.0.0.1" {
		t.Fatalf("headers trusted by default: %s", got)
	}
	trusting := &Server{opts: Options{TrustProxyHeaders: true}}
	if got := trusting.clientIP(r); got != "203.0.113.9" {
		t.Fatalf("X-Forwarded-For: got %s, want the right-most entry", got)
	}
	r.Header.Set("X-Real-IP", "198.51.100.7")
	if got := trusting.clientIP(r); got != "198.51.100.7" {
		t.Fatalf("X-Real-IP: %s", got)
	}
}

// Review #16: a corrupt token file must not be replaced by an empty one.
func TestCorruptSubTokenFileDisablesTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, ts := newTestServer(t, Options{SubTokenFile: path})
	_ = s
	_, body := login(t, ts, "admin", "s3cret-pass")
	jwtTok := body["token"].(string)
	resp, out := doJSON(t, "POST", ts.URL+"/api/v1/sub-tokens", jwtTok, `{"name":"x"}`)
	if resp.StatusCode != http.StatusServiceUnavailable || out["code"] != "tokens_unavailable" {
		t.Fatalf("create with corrupt file: %d %v", resp.StatusCode, out)
	}
	if resp, _ := getRaw(t, ts.URL+"/api/v1/sub-tokens", jwtTok); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("list: %d", resp.StatusCode)
	}
	if resp, _ := getRaw(t, ts.URL+"/sub/xks_x", ""); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("public sub: %d", resp.StatusCode)
	}
	if data, _ := os.ReadFile(path); string(data) != "{not json" {
		t.Fatalf("corrupt file was rewritten: %q", data)
	}
	if data, err := os.ReadFile(path + ".bak"); err != nil || string(data) != "{not json" {
		t.Fatalf("no backup: %v", err)
	}
}

// Review #15: a DB failure on /sub must not reveal paths.
func TestPublicSubTerse503(t *testing.T) {
	ts, jwtTok := authedServer(t)
	tok := createSubToken(t, ts, jwtTok, `{"name":"phone"}`)
	_ = database.Close()
	bad := filepath.Join(t.TempDir(), "missing-dir", "sub", "x.db")
	database.SetPathResolver(func() (string, error) { return bad, nil })
	resp, body := getRaw(t, ts.URL+"/sub/"+tok, "")
	if resp.StatusCode != http.StatusServiceUnavailable || strings.Contains(body, "missing-dir") || strings.Contains(body, "/") {
		t.Fatalf("503 body leaks detail: %d %q", resp.StatusCode, body)
	}
}

// Review #17: repeated /sub requests reuse the selection for a while.
func TestSelectionCache(t *testing.T) {
	c := newSelectionCache()
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }
	calls := 0
	load := func() ([]string, error) { calls++; return []string{"a"}, nil }
	q := exportQuery{Status: "passed", Limit: 10}
	for i := 0; i < 3; i++ {
		if _, err := c.get("tok", q, load); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("loaded %d times within the TTL", calls)
	}
	q2 := q
	q2.Limit = 5
	c.get("tok", q2, load)
	if calls != 2 {
		t.Fatal("a different query shared the cache entry")
	}
	now = now.Add(subSelectionTTL + time.Second)
	c.get("tok", q, load)
	if calls != 3 {
		t.Fatal("entry not refreshed after the TTL")
	}
	c.forget("tok")
	c.get("tok", q, load)
	if calls != 4 {
		t.Fatal("forget did not drop the token's entries")
	}
}

// Review MED #3 / #19: session binding.
func TestJWTBindingAndPersistedRevocation(t *testing.T) {
	prevSecret, prevUser := jwtSecret, jwtUsername
	t.Cleanup(func() { jwtSecret, jwtUsername = prevSecret, prevUser })

	jwtSecret, jwtUsername = deriveJWTKey("secret", "admin", 0), "admin"
	tok, err := GenerateJWT("admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateJWT(tok); err != nil {
		t.Fatal(err)
	}
	// A new epoch (password change) or username invalidates it.
	jwtSecret = deriveJWTKey("secret", "admin", 1)
	if _, err := ValidateJWT(tok); err == nil {
		t.Fatal("token survived an epoch bump")
	}
	jwtSecret = deriveJWTKey("secret", "admin", 0)
	jwtUsername = "root"
	if _, err := ValidateJWT(tok); err == nil {
		t.Fatal("token for another username accepted")
	}
	jwtUsername = "admin"
	// Tokens without an ID (issued before revocation support) are refused.
	noID, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{Username: "admin",
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}).SignedString(jwtSecret)
	if _, err := ValidateJWT(noID); err == nil {
		t.Fatal("token without jti accepted")
	}

	// Revocations persist across a reload of the denylist.
	path := filepath.Join(t.TempDir(), "revoked.json")
	prevRev := revokedTokens
	revokedTokens = &tokenDenylist{revoked: map[string]time.Time{}}
	t.Cleanup(func() { revokedTokens = prevRev })
	if err := revokedTokens.useRevocationFile(path); err != nil {
		t.Fatal(err)
	}
	revokeToken(tok)
	revokedTokens = &tokenDenylist{revoked: map[string]time.Time{}}
	if err := revokedTokens.useRevocationFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateJWT(tok); err == nil {
		t.Fatal("revocation lost across restart")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("revocation file mode %v", fi.Mode().Perm())
	}
}

// Review #20: HSTS never on loopback hosts.
func TestHSTSNotOnLoopback(t *testing.T) {
	s := &Server{opts: Options{TLSCertFile: "c", TLSKeyFile: "k"}}
	h := s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for host, want := range map[string]bool{"localhost:8443": false, "127.0.0.1": false, "[::1]:8443": false, "knife.example:8443": true} {
		r := httptest.NewRequest("GET", "https://"+host+"/", nil)
		r.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if got := w.Header().Get("Strict-Transport-Security") != ""; got != want {
			t.Errorf("%s: HSTS=%v, want %v", host, got, want)
		}
	}
}

// Review #24 / #6: request size caps.
func TestDpiAndScannerCaps(t *testing.T) {
	many := make([]string, maxDpiSpecs+1)
	for i := range many {
		many[i] = "tlshello,100-200,10-20"
	}
	if _, err := buildDpiOptions(dpiStartRequest{Link: dpiTestLink, Specs: many}); err == nil {
		t.Fatal("too many specs accepted")
	}
	snis := make([]string, maxDpiSNIs+1)
	for i := range snis {
		snis[i] = fmt.Sprintf("s%d.example", i)
	}
	if _, err := buildDpiOptions(dpiStartRequest{Link: dpiTestLink, SNIs: snis}); err == nil {
		t.Fatal("too many SNIs accepted")
	}
	// 100 specs × (1 + 15 SNIs) = 1600 profiles > cap.
	if _, err := buildDpiOptions(dpiStartRequest{Link: dpiTestLink, Specs: many[:100], SNIs: snis[:15]}); err == nil {
		t.Fatal("too many profiles accepted")
	}
	if _, err := buildCfScanJob(scanner.ScannerConfig{Subnets: []string{"2606:4700::/32"}, SamplePerSubnet: maxSamplePerSubnet + 1}); err == nil {
		t.Fatal("huge samplePerSubnet accepted")
	}
}
