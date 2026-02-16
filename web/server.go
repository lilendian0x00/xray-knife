package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"
)

//go:embed dist
var embeddedFiles embed.FS

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for the WebSocket
	},
}

// Server represents the web application server.
type Server struct {
	listenAddr  string
	router      *http.ServeMux
	hub         *Hub
	logger      *log.Logger
	manager     *ServiceManager
	authDetails *AuthDetails
}

// NewServer creates and initializes a new web server.
func NewServer(listenAddr, user, pass, secret string) (*Server, error) {
	hub := newHub()
	go hub.run()

	// Redirect the global custom logger to the WebSocket hub.
	customlog.SetOutput(hub)

	// The internal server logger will also write to the hub.
	logger := log.New(hub, "", 0)

	s := &Server{
		listenAddr: listenAddr,
		router:     http.NewServeMux(),
		hub:        hub,
		logger:     logger,
		manager:    NewServiceManager(logger, hub),
	}

	// Setup authentication if all credentials are provided
	if user != "" && pass != "" && secret != "" {
		jwtSecret = []byte(secret)
		auth := &AuthDetails{Username: user}
		if err := auth.HashPassword(pass); err != nil {
			return nil, fmt.Errorf("failed to hash admin password: %w", err)
		}
		s.authDetails = auth
		logger.Println("Web UI authentication is enabled.")
	} else {
		logger.Println("Web UI authentication is disabled. To enable, provide --auth.user, --auth.password, and --auth.secret flags.")
	}

	s.setupRoutes()
	return s, nil
}

// Run starts the web server and handles graceful shutdown on SIGINT/SIGTERM.
func (s *Server) Run() error {
	srv := &http.Server{
		Addr:    s.listenAddr,
		Handler: s.router,
	}

	// Channel to receive OS signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		s.logger.Printf("Web server listening on http://%s", s.listenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for signal or server error
	select {
	case sig := <-quit:
		s.logger.Printf("Received signal %v, shutting down gracefully...", sig)
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("web server failed: %w", err)
		}
	}

	// Graceful shutdown with a 10-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	s.logger.Println("Server shutdown complete.")
	return nil
}

// setupRoutes configures the routing for the server.
func (s *Server) setupRoutes() {
	// API Handlers for protected routes
	apiHandler := NewAPIHandler(s.manager, s.logger)
	protectedMux := http.NewServeMux()
	apiHandler.RegisterRoutes(protectedMux)

	// Public Routes
	s.router.HandleFunc("/api/v1/login", s.handleLogin)
	s.router.HandleFunc("/api/v1/auth/check", s.handleAuthCheck)
	s.router.HandleFunc("/ws", s.handleWebSocket)

	// Protected API Routes
	s.router.Handle("/api/v1/", s.JWTMiddleware(protectedMux))

	// Static File Server for Frontend
	distFS, err := fs.Sub(embeddedFiles, "dist")
	if err != nil {
		panic(fmt.Sprintf("could not create sub-filesystem for frontend assets: %v", err))
	}
	fileServer := http.FileServer(http.FS(distFS))

	// Fallback to index.html for SPA routing
	s.router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Public API routes are handled above, so we don't need to check for them here
		path := strings.TrimPrefix(r.URL.Path, "/")
		// If the file exists in our embedded assets, serve it.
		if _, err := distFS.Open(path); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Otherwise, serve index.html for client-side routing.
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

// handleLogin authenticates a user and returns a JWT.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if s.authDetails == nil || s.authDetails.Username == "" {
		writeJSONError(w, "Authentication is disabled on the server", http.StatusNotImplemented)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := decodeJSONBody(w, r, &creds); err != nil {
		writeJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if creds.Username != s.authDetails.Username || !s.authDetails.CheckPassword(creds.Password) {
		writeJSONError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	tokenString, err := GenerateJWT(creds.Username)
	if err != nil {
		writeJSONError(w, "Could not generate token", http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"token": tokenString})
}

// handleAuthCheck returns whether the server requires authentication.
func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	authRequired := s.authDetails != nil && s.authDetails.Username != ""
	writeJSONResponse(w, http.StatusOK, map[string]bool{"auth_required": authRequired})
}

// handleWebSocket upgrades HTTP connections to WebSocket connections.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Printf("Failed to upgrade websocket: %v\n", err)
		return
	}

	// If auth is enabled, perform authentication handshake
	if s.authDetails != nil && s.authDetails.Username != "" {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Timeout for auth
		_, msg, err := conn.ReadMessage()
		if err != nil {
			s.logger.Printf("WebSocket auth failed: could not read auth message: %v", err)
			conn.Close()
			return
		}

		var authMsg struct {
			Type  string `json:"type"`
			Token string `json:"token"`
		}
		if err := json.Unmarshal(msg, &authMsg); err != nil || authMsg.Type != "auth" {
			s.logger.Println("WebSocket auth failed: invalid auth message format")
			conn.Close()
			return
		}

		if _, err := ValidateJWT(authMsg.Token); err != nil {
			s.logger.Printf("WebSocket auth failed: invalid token: %v", err)
			conn.Close()
			return
		}
		conn.SetReadDeadline(time.Time{}) // Clear the read deadline after successful auth
	}

	client := &Client{hub: s.hub, conn: conn, send: make(chan []byte, 256)}
	s.hub.register <- client
	go client.writePump()
	go client.readPump()
}
