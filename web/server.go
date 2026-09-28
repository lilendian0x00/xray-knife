package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
	"github.com/lilendian0x00/xray-knife/v11/utils/interrupt"
)

// Options configures the web server.
type Options struct {
	ListenAddr string
	Username   string
	// Password is hashed at startup; PasswordHash (bcrypt) is used as-is
	// and wins when both are set.
	Password     string
	PasswordHash string
	Secret       string
	// TLSCertFile/TLSKeyFile serve HTTPS when both are set.
	TLSCertFile string
	TLSKeyFile  string
	// AllowedHosts are extra Host header values accepted besides the
	// loopback names (only enforced for loopback binds, or when set).
	AllowedHosts []string
	// AllowHostModes lets the API start the proxy in app/host-tun mode,
	// which reconfigures host networking.
	AllowHostModes bool
	// Version is reported by GET /info.
	Version string
	// LogToStderr also writes logs to the terminal (default on through NewServer).
	LogToStderr bool
	// SubTokenFile stores public subscription tokens (hashed). Empty uses
	// webui-sub-tokens.json in the xray-knife directory; "-" keeps them in
	// memory only.
	SubTokenFile string
	// RevocationFile persists logged-out token IDs. Empty uses
	// webui-revoked.json in the xray-knife directory; "-" keeps them in
	// memory only.
	RevocationFile string
	// SessionEpoch is mixed into the JWT key; bumping it (the webui command
	// does on a credential change) ends every existing session.
	SessionEpoch uint64
	// TrustProxyHeaders takes the client address from X-Real-IP /
	// X-Forwarded-For (for rate limiting) when behind a reverse proxy. Off
	// by default: clients could forge them.
	TrustProxyHeaders bool
}

// Server is the main web server.
type Server struct {
	opts        Options
	listenAddr  string
	router      *http.ServeMux
	handler     http.Handler
	hub         *Hub
	logger      *log.Logger
	manager     *ServiceManager
	authDetails *AuthDetails
	limiter     *loginLimiter
	subLimiter  *loginLimiter
	subTokens   *subTokenStore
	subCache    *selectionCache
}

// NewServer builds the web server, sets up auth, and configures routing.
func NewServer(listenAddr, user, pass, secret string) (*Server, error) {
	return NewServerWithOptions(Options{
		ListenAddr:  listenAddr,
		Username:    user,
		Password:    pass,
		Secret:      secret,
		LogToStderr: true,
	})
}

// NewServerWithOptions builds the web server from Options.
func NewServerWithOptions(opts Options) (*Server, error) {
	hub := newHub()

	// Logs go to the browser (hub) and, unless disabled, the terminal too,
	// so the server's own output and journald still see them.
	var out io.Writer = hub
	if opts.LogToStderr {
		out = io.MultiWriter(os.Stderr, hub)
	}
	customlog.SetOutput(out)
	logger := log.New(out, "", 0)

	s := &Server{
		opts:       opts,
		listenAddr: opts.ListenAddr,
		router:     http.NewServeMux(),
		hub:        hub,
		logger:     logger,
		manager:    NewServiceManager(logger, hub),
		limiter:    newLoginLimiter(),
		subLimiter: newLoginLimiter(),
		subCache:   newSelectionCache(),
	}

	tokenPath := opts.SubTokenFile
	switch tokenPath {
	case "":
		tokenPath = defaultSubTokenPath()
	case "-":
		tokenPath = ""
	}
	store, err := loadSubTokenStore(tokenPath)
	if err != nil {
		// Keep serving the rest of the UI; token features stay off until
		// the file is fixed (it is never overwritten).
		logger.Printf("Warning: %v", err)
	}
	s.subTokens = store

	// Setup authentication if all credentials are provided
	if opts.Username != "" && (opts.Password != "" || opts.PasswordHash != "") && opts.Secret != "" {
		jwtSecret = deriveJWTKey(opts.Secret, opts.Username, opts.SessionEpoch)
		jwtUsername = opts.Username
		revPath := opts.RevocationFile
		switch revPath {
		case "":
			revPath = defaultStatePath(revocationFileName)
		case "-":
			revPath = ""
		}
		if err := revokedTokens.useRevocationFile(revPath); err != nil {
			logger.Printf("Warning: could not load revoked sessions: %v", err)
		}
		auth := &AuthDetails{Username: opts.Username}
		if opts.PasswordHash != "" {
			if err := auth.SetPasswordHash(opts.PasswordHash); err != nil {
				return nil, err
			}
		} else if err := auth.HashPassword(opts.Password); err != nil {
			return nil, fmt.Errorf("failed to hash admin password: %w", err)
		}
		auth.warmDummyHash()
		s.authDetails = auth
		logger.Println("Web UI authentication is enabled.")
	} else {
		logger.Println("Web UI authentication is disabled. To enable, provide --auth.user, --auth.password, and --auth.secret flags.")
	}

	s.setupRoutes()
	s.handler = s.securityHeaders(s.hostCheck(s.router))
	return s, nil
}

// Handler returns the full HTTP handler (routes plus middleware).
func (s *Server) Handler() http.Handler { return s.handler }

// newHTTPServer builds the http.Server with timeouts that suit SSE: no
// write timeout (the event stream is long-lived), but bounded header/body
// reads so slow clients cannot pin connections.
func (s *Server) newHTTPServer() *http.Server {
	srv := &http.Server{
		Addr:              s.listenAddr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	// Shutdown does not cancel hijacked/streaming requests; closing the hub
	// ends every SSE handler so shutdown does not wait out its timeout.
	srv.RegisterOnShutdown(s.hub.CloseAll)
	return srv
}

// Run starts listening and blocks until SIGINT/SIGTERM or an error.
func (s *Server) Run() error {
	srv := s.newHTTPServer()

	// The first signal starts a graceful shutdown. Repeated signals are
	// ours to handle until the services are stopped: a running proxy may
	// hold a kill switch or the OS proxy settings, which the root
	// handler's immediate exit would leave behind.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	release := interrupt.Own()
	quit := make(chan struct{})
	var quitOnce sync.Once
	watchDone := make(chan struct{})
	go interrupt.Watch(watchDone, sigs, func() { quitOnce.Do(func() { close(quit) }) },
		func() { s.manager.EmergencyCleanup(3 * time.Second) },
		time.Now, func() { os.Exit(exitcode.Interrupted) })
	defer func() {
		close(watchDone)
		signal.Stop(sigs)
		release()
	}()

	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("web server failed: %w", err)
	}

	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		scheme := "http"
		if s.tlsEnabled() {
			scheme = "https"
		}
		s.logger.Printf("Web server listening on %s://%s", scheme, s.listenAddr)
		var err error
		if s.tlsEnabled() {
			err = srv.ServeTLS(ln, s.opts.TLSCertFile, s.opts.TLSKeyFile)
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for signal or server error
	select {
	case <-quit:
		s.logger.Printf("Shutting down gracefully...")
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("web server failed: %w", err)
		}
	}

	// Stop all managed services (proxy, http-tester, cf-scanner) immediately.
	// This runs in parallel with the HTTP server shutdown so we don't wait
	// for the HTTP server to drain before cancelling long-running background work.
	managerDone := make(chan struct{})
	go func() {
		s.manager.Close()
		close(managerDone)
	}()

	// Graceful shutdown with a 3-second timeout for in-flight HTTP requests.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		s.logger.Printf("HTTP server forced to shutdown: %v", err)
	}

	<-managerDone
	s.logger.Println("Server shutdown complete.")
	return nil
}

func (s *Server) tlsEnabled() bool {
	return s.opts.TLSCertFile != "" && s.opts.TLSKeyFile != ""
}

func (s *Server) authEnabled() bool {
	return s.authDetails != nil && s.authDetails.Username != ""
}

// setupRoutes configures the routing for the server.
func (s *Server) setupRoutes() {
	// API Handlers for protected routes
	apiHandler := NewAPIHandler(s.manager, s.logger)
	apiHandler.allowHostModes = s.opts.AllowHostModes
	apiHandler.hubSeq = s.hub.Seq
	apiHandler.info = s.info
	apiHandler.subTokens = s.subTokens
	apiHandler.subCache = s.subCache
	protectedMux := http.NewServeMux()
	apiHandler.RegisterRoutes(protectedMux)

	// Public Routes
	s.router.HandleFunc("/api/v1/login", s.handleLogin)
	s.router.HandleFunc("/api/v1/auth/check", s.handleAuthCheck)
	s.router.HandleFunc("/api/v1/logout", s.handleLogout)
	s.router.HandleFunc("/events", s.handleSSE)
	// Public, token-protected subscription for phone clients (no JWT).
	s.router.HandleFunc("GET /sub/{token}", s.handlePublicSub)

	// Protected API Routes
	s.router.Handle("/api/v1/", s.JWTMiddleware(protectedMux))

	frontend, err := newFrontendHandler()
	if err != nil {
		panic(fmt.Sprintf("could not load frontend assets: %v", err))
	}
	s.router.Handle("/", frontend)
}

// info is the body of GET /info.
func (s *Server) info() map[string]any {
	tags := []string{}
	goVersion := runtime.Version()
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, st := range bi.Settings {
			if st.Key == "-tags" && st.Value != "" {
				tags = strings.Split(st.Value, ",")
			}
		}
	}
	version := s.opts.Version
	if version == "" {
		version = "dev"
	}
	_, dbErr := dbConnForInfo()
	return map[string]any{
		"version":        version,
		"go":             goVersion,
		"cores":          []string{"xray", "sing-box", "mtproto"},
		"protocols":      supportedProtocols(),
		"buildTags":      tags,
		"listenAddr":     s.listenAddr,
		"tls":            s.tlsEnabled(),
		"authRequired":   s.authEnabled(),
		"dbAvailable":    dbErr == nil,
		"allowHostModes": s.opts.AllowHostModes,
		"checkPresets":   pkghttp.CheckPresets,
		"limits": map[string]int{
			"maxThreads":        maxHttpThreads,
			"maxScannerThreads": maxScannerThreads,
			"maxIPsPerScan":     maxIPsPerScan,
		},
	}
}

// dbConnForInfo is swappable in tests.
var dbConnForInfo = func() (any, error) { return nil, dbReady() }

// --- middleware ---

// contentSecurityPolicy only allows same-origin resources. Inline styles are
// allowed because the UI libraries set style attributes at runtime.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; " +
	"base-uri 'self'; frame-ancestors 'none'; form-action 'self'"

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		// HSTS pins a hostname to HTTPS for a year; never do that to
		// localhost, where other local services speak plain HTTP.
		if s.tlsEnabled() && r.TLS != nil {
			host := r.Host
			if hh, _, err := net.SplitHostPort(host); err == nil {
				host = hh
			}
			if !isLoopbackHost(host) {
				h.Set("Strict-Transport-Security", "max-age=31536000")
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopbackHost reports whether host (no port) names the loopback.
func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// hostCheck defends a loopback-bound server against DNS rebinding: a page on
// evil.example that resolves to 127.0.0.1 would otherwise reach the API.
// Only Host headers naming the loopback (or --allow-host entries) pass.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	bindHost, _, err := net.SplitHostPort(s.listenAddr)
	if err != nil {
		bindHost = s.listenAddr
	}
	enforce := isLoopbackHost(bindHost) || len(s.opts.AllowedHosts) > 0
	allowed := make(map[string]bool)
	for _, h := range s.opts.AllowedHosts {
		allowed[strings.ToLower(strings.TrimSpace(h))] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enforce {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			host = strings.ToLower(host)
			if !isLoopbackHost(host) && !allowed[host] && !allowed[strings.Trim(host, "[]")] {
				writeJSONErrorCode(w, "Host not allowed; start webui with --allow-host "+strconv.Quote(host)+" to permit it", "host_not_allowed", http.StatusMisdirectedRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP is the client's address for rate limiting and logs. By default
// it is the connection's remote address: proxy headers are client-
// controlled and would let anyone dodge the limits. Behind a trusted
// reverse proxy (--trust-proxy-headers) X-Real-IP, else the right-most
// X-Forwarded-For entry (the one the proxy itself appended), is used.
func (s *Server) clientIP(r *http.Request) string {
	if s.opts.TrustProxyHeaders {
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" && net.ParseIP(v) != nil {
			return v
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if v := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(v) != nil {
				return v
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiterKey groups IPv6 clients by /64 (one host usually owns the whole
// prefix, so per-address limits are trivial to dodge).
func limiterKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is6() {
		if p, err := addr.Prefix(64); err == nil {
			return p.String()
		}
	}
	return addr.String()
}

// --- auth handlers ---

// handleLogin authenticates a user and returns a JWT.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.authEnabled() {
		writeJSONError(w, "Authentication is disabled on the server", http.StatusNotImplemented)
		return
	}

	ip := limiterKey(s.clientIP(r))
	if ok, wait := s.limiter.allow(ip); !ok {
		writeRateLimited(w, wait)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSONBodyLimit(w, r, &creds, maxLoginBody); err != nil {
		writeDecodeError(w, err)
		return
	}

	if !s.limiter.acquire() {
		writeRateLimited(w, time.Second)
		return
	}
	ok := s.authDetails.Verify(creds.Username, creds.Password)
	s.limiter.release()
	if !ok {
		if wait := s.limiter.fail(ip); wait > 0 {
			s.logger.Printf("Web UI: failed login from %s; locked out for %s", ip, wait.Round(time.Second))
		}
		writeJSONErrorCode(w, "Invalid credentials", codeUnauthorized, http.StatusUnauthorized)
		return
	}
	s.limiter.succeed(ip)

	tokenString, expires, err := generateJWT(creds.Username)
	if err != nil {
		writeJSONError(w, "Could not generate token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(tokenTTL.Seconds()),
	})

	writeJSONResponse(w, http.StatusOK, map[string]string{"token": tokenString, "expiresAt": expires.UTC().Format(time.RFC3339)})
}

func writeRateLimited(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Round(time.Second).Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprintf(w, `{"error":"Too many login attempts; try again in %d seconds","code":%q,"retryAfter":%d}`+"\n", secs, codeRateLimited, secs)
}

// handleAuthCheck returns whether the server requires authentication.
func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]bool{"auth_required": s.authEnabled()})
}

// handleLogout revokes the caller's token(s) and clears the auth cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if s.authEnabled() {
		if tok, ok := bearerToken(r.Header.Get("Authorization")); ok {
			revokeToken(tok)
		}
		if c, err := r.Cookie("auth_token"); err == nil && c.Value != "" {
			revokeToken(c.Value)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSONResponse(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// requestToken returns the token from the Bearer header or the auth cookie.
func requestToken(r *http.Request) string {
	if tok, ok := bearerToken(r.Header.Get("Authorization")); ok {
		return tok
	}
	if c, err := r.Cookie("auth_token"); err == nil {
		return c.Value
	}
	return ""
}

// writeTokenError answers a failed token check with the matching code.
func writeTokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errTokenExpired):
		writeJSONErrorCode(w, "Session expired; please log in again", codeTokenExpired, http.StatusUnauthorized)
	case errors.Is(err, errTokenRevoked):
		writeJSONErrorCode(w, "Session ended; please log in again", codeTokenRevoked, http.StatusUnauthorized)
	default:
		writeJSONErrorCode(w, "Invalid or expired token", codeUnauthorized, http.StatusUnauthorized)
	}
}

// --- SSE ---

const (
	sseHeartbeat = 15 * time.Second
	sseRetryMs   = 3000
)

// handleSSE keeps an SSE connection open and streams events to the client.
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	// The browser's EventSource cannot set headers, so the auth cookie
	// (set by /login) is the normal path; a Bearer header also works.
	token := ""
	if s.authEnabled() {
		token = requestToken(r)
		if token == "" {
			writeJSONErrorCode(w, "Authentication required", codeUnauthorized, http.StatusUnauthorized)
			return
		}
		if _, err := ValidateJWT(token); err != nil {
			writeTokenError(w, err)
			return
		}
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	var lastID uint64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		lastID, _ = strconv.ParseUint(v, 10, 64)
	} else if v := r.URL.Query().Get("lastEventId"); v != "" {
		lastID, _ = strconv.ParseUint(v, 10, 64)
	}

	client, replay, seq, replayOK := s.hub.Subscribe(lastID)
	defer s.hub.Unsubscribe(client)

	// Set SSE headers and flush right away, so the browser's onopen fires
	// now rather than with the first event.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	writeEvent := func(id uint64, eventType string, data []byte) bool {
		var err error
		if id > 0 {
			_, err = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", id, eventType, data)
		} else {
			_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, data)
		}
		return err == nil
	}
	publishLocal := func(eventType string, data any, id uint64) bool {
		payload, err := marshalEnvelope(eventType, data)
		if err != nil {
			return true
		}
		return writeEvent(id, eventType, payload)
	}

	fmt.Fprintf(w, "retry: %d\n\n", sseRetryMs)
	if !replayOK {
		reason := "gap"
		if lastID > seq {
			reason = "restart"
		}
		publishLocal("resync", map[string]string{"reason": reason}, 0)
	}
	// The state snapshot lets a (re)connecting client resync without an
	// extra request. It carries the current seq as its ID so the next
	// reconnect replays from here.
	publishLocal("state", s.manager.Snapshot(seq), seq)
	for _, ev := range replay {
		if !writeEvent(ev.ID, ev.Type, ev.Data) {
			return
		}
	}
	flusher.Flush()

	heartbeat := time.NewTicker(sseHeartbeat)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-client.send:
			if !ok {
				return
			}
			if !writeEvent(ev.ID, ev.Type, ev.Data) {
				return
			}
			if client.lagged.Swap(false) {
				publishLocal("resync", map[string]string{"reason": "lagging"}, 0)
			}
			flusher.Flush()
		case <-heartbeat.C:
			if token != "" {
				if _, err := ValidateJWT(token); err != nil {
					publishLocal("auth_expired", map[string]string{}, 0)
					flusher.Flush()
					return
				}
			}
			if client.lagged.Swap(false) {
				publishLocal("resync", map[string]string{"reason": "lagging"}, 0)
			}
			if _, err := fmt.Fprintf(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
