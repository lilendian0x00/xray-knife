package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	pkghttp "github.com/lilendian0x00/xray-knife/v5/pkg/http"
	"github.com/lilendian0x00/xray-knife/v5/pkg/proxy"
)

//go:embed dist
var embeddedFiles embed.FS

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Allow all origins for simplicity in development.
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// ServiceManager holds the state of the running proxy service.
type ServiceManager struct {
	mu          sync.Mutex
	service     *proxy.Service
	cancelFunc  context.CancelFunc
	forceRotate chan struct{}
}

// Server represents the web application server.
type Server struct {
	listenAddr string
	router     *http.ServeMux
	hub        *Hub
	logger     *log.Logger // Web-specific logger
	manager    *ServiceManager
}

// NewServer creates and initializes a new web server.
func NewServer(listenAddr string) (*Server, error) {
	hub := newHub()
	go hub.run()

	s := &Server{
		listenAddr: listenAddr,
		router:     http.NewServeMux(),
		hub:        hub,
		logger:     log.New(hub, "", 0), // Initialize web logger
		manager:    &ServiceManager{},
	}

	s.setupRoutes()
	return s, nil
}

// Run starts the web server and listens for requests.
func (s *Server) Run() error {
	// Use web logger for server-side messages that should appear in the UI
	s.logger.Printf("Web server listening on http://%s\n", s.listenAddr)

	err := http.ListenAndServe(s.listenAddr, s.router)
	if err != nil {
		s.logger.Printf("Web server failed: %v\n", err)
		return fmt.Errorf("web server failed: %w", err)
	}
	return nil
}

// setupRoutes configures all the HTTP routes for the server.
func (s *Server) setupRoutes() {
	// JSON error helper
	writeJSONError := func(w http.ResponseWriter, message string, statusCode int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(map[string]string{"error": message})
	}
	// API routes
	s.router.HandleFunc("/ws", s.handleWebSocket)
	s.router.HandleFunc("/api/v1/proxy/start", func(w http.ResponseWriter, r *http.Request) {
		s.handleProxyStart(w, r, writeJSONError)
	})
	s.router.HandleFunc("/api/v1/proxy/stop", func(w http.ResponseWriter, r *http.Request) {
		s.handleProxyStop(w, r, writeJSONError)
	})
	s.router.HandleFunc("/api/v1/proxy/rotate", func(w http.ResponseWriter, r *http.Request) {
		s.handleProxyRotate(w, r, writeJSONError)
	})
	s.router.HandleFunc("/api/v1/http/test", func(w http.ResponseWriter, r *http.Request) {
		s.handleHttpTest(w, r, writeJSONError)
	})

	// Static file serving for the frontend
	distFS, err := fs.Sub(embeddedFiles, "dist")
	if err != nil {
		panic(fmt.Sprintf("could not create sub-filesystem for frontend assets: %v", err))
	}
	fileServer := http.FileServer(http.FS(distFS))
	s.router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Let the main router handle API and WebSocket endpoints first.
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/ws" {
			s.router.ServeHTTP(w, r)
			return
		}
		// Check for static file, otherwise serve index.html for client-side routing.
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html" // Serve index.html for root
		}
		_, err := distFS.Open(path)
		if err != nil {
			// File does not exist, serve index.html
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

// handleWebSocket handles WebSocket connection requests.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade websocket: %v\n", err) // Use standard log here
		return
	}
	client := &Client{hub: s.hub, conn: conn, send: make(chan []byte, 256)}
	s.hub.register <- client
	go client.writePump()
	go client.readPump()
}

// handleProxyStart starts the proxy service based on JSON config from the request.
func (s *Server) handleProxyStart(w http.ResponseWriter, r *http.Request, writeJSONError func(w http.ResponseWriter, message string, statusCode int)) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()

	// Stop any existing service
	if s.manager.cancelFunc != nil {
		s.manager.cancelFunc()
	}

	var cfg proxy.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSONError(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	service, err := proxy.New(cfg, s.logger)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("Failed to create proxy service: %v", err), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.manager.service = service
	s.manager.cancelFunc = cancel
	s.manager.forceRotate = make(chan struct{})

	go func() {
		defer func() {
			s.manager.mu.Lock()
			s.manager.service = nil
			s.manager.cancelFunc = nil
			s.manager.forceRotate = nil
			s.manager.mu.Unlock()
		}()
		if err := service.Run(ctx, s.manager.forceRotate); err != nil {
			s.logger.Printf("Proxy service exited with error: %v", err)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Proxy service started"})
}

// handleProxyStop stops the currently running proxy service.
func (s *Server) handleProxyStop(w http.ResponseWriter, r *http.Request, writeJSONError func(w http.ResponseWriter, message string, statusCode int)) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()

	if s.manager.cancelFunc == nil {
		writeJSONError(w, "Proxy service not running", http.StatusNotFound)
		return
	}

	s.manager.cancelFunc()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Proxy service stopped"})
}

// handleProxyRotate triggers a manual rotation of the proxy.
func (s *Server) handleProxyRotate(w http.ResponseWriter, r *http.Request, writeJSONError func(w http.ResponseWriter, message string, statusCode int)) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()

	if s.manager.forceRotate == nil {
		writeJSONError(w, "Proxy service not running or not in rotation mode", http.StatusConflict)
		return
	}

	select {
	case s.manager.forceRotate <- struct{}{}:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "Rotate signal sent"})
	default:
		writeJSONError(w, "Failed to send rotate signal (channel may be busy)", http.StatusServiceUnavailable)
	}
}

// handleHttpTest runs a configuration test.
func (s *Server) handleHttpTest(w http.ResponseWriter, r *http.Request, writeJSONError func(w http.ResponseWriter, message string, statusCode int)) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Define a struct that matches the expected JSON payload for this API.
	type httpTestRequest struct {
		Links           []string `json:"links"`
		ThreadCount     uint16   `json:"threadCount"`
		MaxDelay        uint16   `json:"maxDelay"`
		InsecureTLS     bool     `json:"insecureTLS"`
		CoreType        string   `json:"coreType"`
		DestURL         string   `json:"destURL"`
		HTTPMethod      string   `json:"httpMethod"`
		Speedtest       bool     `json:"speedtest"`
		GetIPInfo       bool     `json:"getIPInfo"`
		SpeedtestAmount uint32   `json:"speedtestAmount"`
	}

	var req httpTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	go func() {
		s.logger.Printf("Starting HTTP test for %d links with %d threads.\n", len(req.Links), req.ThreadCount)
		examiner, err := pkghttp.NewExaminer(pkghttp.Options{
			Core:                   req.CoreType,
			MaxDelay:               req.MaxDelay,
			InsecureTLS:            req.InsecureTLS,
			Verbose:                false, // Verbosity is handled by the web logger
			DoSpeedtest:            req.Speedtest,
			DoIPInfo:               req.GetIPInfo,
			TestEndpoint:           req.DestURL,
			TestEndpointHttpMethod: req.HTTPMethod,
			SpeedtestKbAmount:      req.SpeedtestAmount,
		})
		if err != nil {
			s.logger.Printf("Failed to create examiner: %v", err)
			return
		}

		testManager := pkghttp.NewTestManager(examiner, req.ThreadCount, false, s.logger)

		resultsChan := make(chan *pkghttp.Result, len(req.Links))

		// This goroutine consumes results and sends them to the websocket hub
		go func() {
			for result := range resultsChan {
				jsonResult, err := json.Marshal(map[string]interface{}{"type": "http_result", "data": result})
				if err == nil {
					s.hub.broadcast <- jsonResult
				} else {
					s.logger.Printf("Failed to marshal result to JSON: %v", err)
				}
			}
		}()

		testManager.RunTests(req.Links, resultsChan)
		close(resultsChan) // This will terminate the consumer goroutine's range loop.

		s.logger.Printf("HTTP test finished.\n")
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "HTTP test started"})
}
