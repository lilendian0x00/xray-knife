package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func newTestServer(t *testing.T, opts Options) (*Server, *httptest.Server) {
	t.Helper()
	t.Setenv("XRAY_KNIFE_HOME", t.TempDir())
	prevCost := bcryptCost
	bcryptCost = bcrypt.MinCost
	t.Cleanup(func() { bcryptCost = prevCost })
	if opts.Username == "" {
		opts.Username = "admin"
		opts.Password = "s3cret-pass"
		opts.Secret = "test-secret"
	}
	if opts.ListenAddr == "" {
		opts.ListenAddr = "127.0.0.1:0"
	}
	s, err := NewServerWithOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		s.hub.CloseAll()
		ts.Close()
		s.manager.Close()
	})
	return s, ts
}

func doJSON(t *testing.T, method, url, token, body string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

func login(t *testing.T, ts *httptest.Server, user, pass string) (*http.Response, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	return doJSON(t, "POST", ts.URL+"/api/v1/login", "", string(body))
}

func TestLoginRateLimitAndRevocation(t *testing.T) {
	_, ts := newTestServer(t, Options{})

	resp, body := login(t, ts, "admin", "s3cret-pass")
	if resp.StatusCode != 200 || body["token"] == nil || body["expiresAt"] == nil {
		t.Fatalf("login: %d %v", resp.StatusCode, body)
	}
	token := body["token"].(string)

	resp, _ = doJSON(t, "GET", ts.URL+"/api/v1/state", token, "")
	if resp.StatusCode != 200 {
		t.Fatalf("state with token: %d", resp.StatusCode)
	}

	// Logout revokes the token server-side.
	resp, _ = doJSON(t, "POST", ts.URL+"/api/v1/logout", token, "")
	if resp.StatusCode != 200 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	resp, body = doJSON(t, "GET", ts.URL+"/api/v1/state", token, "")
	if resp.StatusCode != 401 || body["code"] != codeTokenRevoked {
		t.Fatalf("revoked token: %d %v", resp.StatusCode, body)
	}

	// Unknown user and wrong password look the same.
	r1, b1 := login(t, ts, "nobody", "x")
	r2, b2 := login(t, ts, "admin", "wrong")
	if r1.StatusCode != 401 || r2.StatusCode != 401 || b1["error"] != b2["error"] {
		t.Fatalf("failure responses differ: %v / %v", b1, b2)
	}

	// After the free attempts the client is locked out, even with the
	// right password.
	for i := 0; i < 5; i++ {
		login(t, ts, "admin", "wrong")
	}
	resp, body = login(t, ts, "admin", "s3cret-pass")
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" || body["code"] != codeRateLimited {
		t.Fatalf("lockout: %d %v", resp.StatusCode, body)
	}
}

func TestLoginBodyLimit(t *testing.T) {
	_, ts := newTestServer(t, Options{})
	big := `{"username":"admin","password":"` + strings.Repeat("a", maxLoginBody) + `"}`
	resp, body := doJSON(t, "POST", ts.URL+"/api/v1/login", "", big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || body["code"] != codeTooLarge {
		t.Fatalf("oversized login: %d %v", resp.StatusCode, body)
	}
}

func TestExpiredTokenCode(t *testing.T) {
	_, ts := newTestServer(t, Options{})
	claims := &Claims{Username: "admin", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute))}}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := doJSON(t, "GET", ts.URL+"/api/v1/state", tok, "")
	if resp.StatusCode != 401 || body["code"] != codeTokenExpired {
		t.Fatalf("expired: %d %v", resp.StatusCode, body)
	}
	// "none"-signed tokens are rejected outright.
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, &Claims{Username: "admin"}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	resp, _ = doJSON(t, "GET", ts.URL+"/api/v1/state", none, "")
	if resp.StatusCode != 401 {
		t.Fatalf("alg=none accepted: %d", resp.StatusCode)
	}
}

func TestAPIValidationCodes(t *testing.T) {
	_, ts := newTestServer(t, Options{})
	_, body := login(t, ts, "admin", "s3cret-pass")
	token := body["token"].(string)

	for _, tc := range []struct {
		name, path, body string
		status           int
		code             string
	}{
		{"no links", "/api/v1/http/test", `{"links":[" "]}`, 400, codeInvalidRequest},
		{"probe samples", "/api/v1/http/test", `{"links":["vless://x"],"probeSamples":33}`, 400, codeInvalidRequest},
		{"bad preset", "/api/v1/http/test", `{"links":["vless://x"],"checkPreset":"nope"}`, 400, codeInvalidRequest},
		{"bad fragment", "/api/v1/http/test", `{"links":["vless://x"],"fragmentSpec":"tlshello"}`, 400, codeInvalidRequest},
		{"negative threads", "/api/v1/http/test", `{"links":["vless://x"],"threadCount":-1}`, 400, codeInvalidRequest},
		{"ipv6 range", "/api/v1/scanner/cf/start", `{"subnets":["2606:4700::/32"]}`, 400, codeInvalidRequest},
		{"scanner threads", "/api/v1/scanner/cf/start", `{"subnets":["1.1.1.1"],"threadCount":-5}`, 400, codeInvalidRequest},
		{"app mode", "/api/v1/proxy/start", `{"mode":"app","configLinks":["vless://x"]}`, 400, codeInvalidRequest},
		{"proxy listen", "/api/v1/proxy/start", `{"listenAddr":"example.com","configLinks":["vless://x"]}`, 400, codeInvalidRequest},
		{"not json", "/api/v1/proxy/start", `{`, 400, codeInvalidRequest},
		{"stop idle", "/api/v1/http/test/stop", ``, 409, codeNotRunning},
		{"stop scan idle", "/api/v1/scanner/cf/stop", ``, 409, codeNotRunning},
		{"stop proxy idle", "/api/v1/proxy/stop", ``, 409, codeNotRunning},
	} {
		resp, out := doJSON(t, "POST", ts.URL+tc.path, token, tc.body)
		if resp.StatusCode != tc.status || out["code"] != tc.code {
			t.Errorf("%s: %d %v, want %d %s", tc.name, resp.StatusCode, out, tc.status, tc.code)
		}
	}

	resp, out := doJSON(t, "GET", ts.URL+"/api/v1/info", token, "")
	if resp.StatusCode != 200 || out["checkPresets"] == nil || out["limits"] == nil {
		t.Fatalf("info: %d %v", resp.StatusCode, out)
	}
}

func TestSecurityHeadersAndHostCheck(t *testing.T) {
	_, ts := newTestServer(t, Options{})
	resp, err := http.Get(ts.URL + "/api/v1/auth/check")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("API Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}

	// DNS rebinding: a foreign Host is refused on a loopback bind.
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/auth/check", nil)
	req.Host = "evil.example"
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("foreign Host: %d", resp.StatusCode)
	}
	req.Host = "localhost:1234"
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("localhost Host: %d", resp.StatusCode)
	}

	_, ts2 := newTestServer(t, Options{AllowedHosts: []string{"knife.lan"}})
	req, _ = http.NewRequest("GET", ts2.URL+"/api/v1/auth/check", nil)
	req.Host = "knife.lan:8080"
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("--allow-host entry: %d", resp.StatusCode)
	}
}

func TestStaticCachingAndMissingAssets(t *testing.T) {
	h, err := newFrontendHandler()
	if err != nil {
		t.Fatal(err)
	}
	var asset string
	_ = fs.WalkDir(embeddedFiles, "dist-gzip/assets", func(name string, e fs.DirEntry, err error) error {
		if err == nil && !e.IsDir() && asset == "" {
			asset = "/" + strings.TrimSuffix(strings.TrimPrefix(name, "dist-gzip/"), ".gz")
		}
		return nil
	})
	if asset == "" {
		t.Skip("no hashed assets embedded")
	}
	w := frontendRequest(h, "GET", asset, "gzip", "")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") || w.Header().Get("ETag") == "" {
		t.Fatalf("asset: %d cc=%q etag=%q", w.Code, w.Header().Get("Cache-Control"), w.Header().Get("ETag"))
	}
	etag := w.Header().Get("ETag")
	r := httptest.NewRequest("GET", asset, nil)
	r.Header.Set("Accept-Encoding", "gzip")
	r.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("revalidation: %d", rec.Code)
	}
	if id := frontendRequest(h, "GET", asset, "identity", ""); id.Header().Get("ETag") == etag {
		t.Fatal("gzip and identity share an ETag")
	}

	w = frontendRequest(h, "GET", "/", "gzip", "")
	if w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("index Cache-Control = %q", w.Header().Get("Cache-Control"))
	}
	for _, p := range []string{"/assets/index-old.js", "/favicon.ico", "/assets/missing.css"} {
		if w := frontendRequest(h, "GET", p, "gzip", ""); w.Code != 404 {
			t.Errorf("%s: %d, want 404", p, w.Code)
		}
	}
	if w := frontendRequest(h, "GET", "/history/runs/3", "gzip", ""); w.Code != 200 {
		t.Errorf("SPA route: %d", w.Code)
	}
}

// sseReader reads SSE frames from a stream.
type sseReader struct{ r *bufio.Reader }

type sseFrame struct {
	id, event, data string
	retry           bool
}

func (s *sseReader) next(t *testing.T) sseFrame {
	t.Helper()
	f, err := s.read()
	if err != nil {
		t.Fatalf("sse read: %v", err)
	}
	return f
}

func (s *sseReader) read() (sseFrame, error) {
	var f sseFrame
	for {
		line, err := s.r.ReadString('\n')
		if err != nil {
			return f, err
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case line == "":
			if f.event != "" || f.retry {
				return f, nil
			}
		case strings.HasPrefix(line, "retry: "):
			f.retry = true
		case strings.HasPrefix(line, "id: "):
			f.id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "event: "):
			f.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			f.data = strings.TrimPrefix(line, "data: ")
		}
	}
}

func openSSE(t *testing.T, ts *httptest.Server, token, lastID string) (*sseReader, func()) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+"/events", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("sse status %d", resp.StatusCode)
	}
	return &sseReader{r: bufio.NewReader(resp.Body)}, func() { resp.Body.Close() }
}

func TestSSEFlushStateAndReplay(t *testing.T) {
	s, ts := newTestServer(t, Options{})
	_, body := login(t, ts, "admin", "s3cret-pass")
	token := body["token"].(string)

	// Unauthenticated SSE is refused.
	resp, err := http.Get(ts.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("anonymous sse: %d", resp.StatusCode)
	}

	sse, closeSSE := openSSE(t, ts, token, "")
	// Headers and the retry hint arrive immediately, not with the first event.
	got := make(chan sseFrame, 1)
	go func() {
		f, _ := sse.read()
		got <- f
	}()
	select {
	case f := <-got:
		if !f.retry {
			t.Fatalf("first frame = %+v, want retry hint", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSE stream not flushed on connect")
	}
	if f := sse.next(t); f.event != "state" {
		t.Fatalf("second frame = %+v, want state", f)
	}

	s.hub.Publish("log", "one", nil)
	s.hub.Publish("log", "two", nil)
	first := sse.next(t)
	second := sse.next(t)
	if first.event != "log" || second.event != "log" || first.id == "" {
		t.Fatalf("frames = %+v %+v", first, second)
	}
	closeSSE()

	// Events published while disconnected are replayed after Last-Event-ID.
	s.hub.Publish("log", "three", nil)
	sse2, close2 := openSSE(t, ts, token, first.id)
	defer close2()
	sse2.next(t) // retry
	if f := sse2.next(t); f.event != "state" {
		t.Fatalf("reconnect first event = %+v", f)
	}
	var datas []string
	for i := 0; i < 2; i++ {
		f := sse2.next(t)
		var env struct {
			Data string `json:"data"`
		}
		_ = json.Unmarshal([]byte(f.data), &env)
		datas = append(datas, env.Data)
	}
	if strings.Join(datas, ",") != "two,three" {
		t.Fatalf("replayed %v, want two,three", datas)
	}

	// An ID the server never issued (restart) triggers a resync.
	sse3, close3 := openSSE(t, ts, token, strconv.FormatUint(s.hub.Seq()+100, 10))
	defer close3()
	sse3.next(t) // retry
	if f := sse3.next(t); f.event != "resync" {
		t.Fatalf("stale id: %+v, want resync", f)
	}
}

func TestHubReplayWindowAndLag(t *testing.T) {
	h := newHub()
	for i := 0; i < hubReplaySize+10; i++ {
		h.Publish("log", fmt.Sprint(i), nil)
	}
	if _, _, _, ok := h.Subscribe(5); ok {
		t.Fatal("replay from before the window should fail")
	}
	c, replay, seq, ok := h.Subscribe(h.Seq() - 3)
	if !ok || len(replay) != 3 || replay[2].ID != seq {
		t.Fatalf("replay = %d events ok=%v", len(replay), ok)
	}
	// A client that never reads is flagged, not blocking the publisher.
	for i := 0; i < clientBufferSize+5; i++ {
		h.Publish("log", "x", nil)
	}
	if !c.lagged.Load() {
		t.Fatal("slow client not flagged")
	}
	h.Unsubscribe(c)
	h.CloseAll()
	h.Publish("log", "after close", nil) // must not panic
}

func TestLoginLimiterBackoff(t *testing.T) {
	now := time.Unix(0, 0)
	l := newLoginLimiter()
	l.now = func() time.Time { return now }
	for i := 0; i < l.freeFail; i++ {
		if wait := l.fail("1.2.3.4"); wait != 0 {
			t.Fatalf("free attempt %d locked for %s", i, wait)
		}
	}
	w1 := l.fail("1.2.3.4")
	w2 := l.fail("1.2.3.4")
	if w1 != time.Second || w2 != 2*time.Second {
		t.Fatalf("backoff = %s, %s", w1, w2)
	}
	if ok, _ := l.allow("1.2.3.4"); ok {
		t.Fatal("locked client allowed")
	}
	if ok, _ := l.allow("5.6.7.8"); !ok {
		t.Fatal("other client blocked")
	}
	now = now.Add(3 * time.Second)
	if ok, _ := l.allow("1.2.3.4"); !ok {
		t.Fatal("lockout did not expire")
	}
	for i := 0; i < 40; i++ {
		l.fail("1.2.3.4")
	}
	if w := l.fail("1.2.3.4"); w != l.maxWait {
		t.Fatalf("backoff not capped: %s", w)
	}
	l.succeed("1.2.3.4")
	if ok, _ := l.allow("1.2.3.4"); !ok {
		t.Fatal("success did not reset")
	}
}

func TestVerifyRunsBcryptForUnknownUsers(t *testing.T) {
	prev := bcryptCost
	bcryptCost = bcrypt.MinCost
	defer func() { bcryptCost = prev }()
	a := &AuthDetails{Username: "admin"}
	if err := a.HashPassword("pw"); err != nil {
		t.Fatal(err)
	}
	if !a.Verify("admin", "pw") || a.Verify("admin", "nope") || a.Verify("root", "pw") || a.Verify("", "") {
		t.Fatal("verify results wrong")
	}
	var empty AuthDetails
	if empty.Verify("", "") {
		t.Fatal("empty credentials verified")
	}
}

// With the production ReadTimeout (shortened here) an SSE stream must
// outlive the deadline instead of being cancelled by it (net/http clears the
// read deadline before its background read; this guards that assumption).
func TestSSESurvivesReadTimeout(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	srv := s.newHTTPServer()
	srv.ReadTimeout = 200 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	base := "http://" + ln.Addr().String()

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "s3cret-pass"})
	_, out := doJSON(t, "POST", base+"/api/v1/login", "", string(body))
	token := out["token"].(string)

	req, _ := http.NewRequest("GET", base+"/events", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sse := &sseReader{r: bufio.NewReader(resp.Body)}
	sse.next(t) // retry
	sse.next(t) // state

	time.Sleep(3 * srv.ReadTimeout)
	s.hub.Publish("log", "still here", nil)
	if f := sse.next(t); f.event != "log" {
		t.Fatalf("after the read timeout got %+v", f)
	}
}
