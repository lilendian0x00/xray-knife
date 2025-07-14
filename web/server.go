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
	"time"

	"github.com/gorilla/websocket"
	"github.com/lilendian0x00/xray-knife/v5/cmd/scanner"
	pkghttp "github.com/lilendian0x00/xray-knife/v5/pkg/http"
	"github.com/lilendian0x00/xray-knife/v5/pkg/proxy"
)

//go:embed dist
var embeddedFiles embed.FS

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// ServiceManager holds the state of the running proxy and scanner services.
type ServiceManager struct {
	mu                sync.Mutex
	proxyService      *proxy.Service
	proxyCancelFunc   context.CancelFunc
	proxyForceRotate  chan struct{}
	scannerCancelFunc context.CancelFunc
	isScanning        bool
}

// Server represents the web application server.
type Server struct {
	listenAddr string
	router     *http.ServeMux
	hub        *Hub
	logger     *log.Logger
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
		logger:     log.New(hub, "", 0),
		manager:    &ServiceManager{},
	}

	s.setupRoutes()
	return s, nil
}

// Run starts the web server and listens for requests.
func (s *Server) Run() error {
	s.logger.Printf("Web server listening on http://%s", s.listenAddr)
	err := http.ListenAndServe(s.listenAddr, s.router)
	if err != nil {
		s.logger.Printf("Web server failed: %v", err)
		return fmt.Errorf("web server failed: %w", err)
	}
	return nil
}

func (s *Server) setupRoutes() {
	writeJSONError := func(w http.ResponseWriter, message string, statusCode int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(map[string]string{"error": message})
	}

	s.router.HandleFunc("/ws", s.handleWebSocket)
	s.router.HandleFunc("/api/v1/proxy/start", func(w http.ResponseWriter, r *http.Request) { s.handleProxyStart(w, r, writeJSONError) })
	s.router.HandleFunc("/api/v1/proxy/stop", func(w http.ResponseWriter, r *http.Request) { s.handleProxyStop(w, r, writeJSONError) })
	s.router.HandleFunc("/api/v1/proxy/rotate", func(w http.ResponseWriter, r *http.Request) { s.handleProxyRotate(w, r, writeJSONError) })
	s.router.HandleFunc("/api/v1/http/test", func(w http.ResponseWriter, r *http.Request) { s.handleHttpTest(w, r, writeJSONError) })
	s.router.HandleFunc("/api/v1/scanner/cf/start", func(w http.ResponseWriter, r *http.Request) { s.handleCfScannerStart(w, r, writeJSONError) })
	s.router.HandleFunc("/api/v1/scanner/cf/stop", func(w http.ResponseWriter, r *http.Request) { s.handleCfScannerStop(w, r, writeJSONError) })

	distFS, err := fs.Sub(embeddedFiles, "dist")
	if err != nil {
		panic(fmt.Sprintf("could not create sub-filesystem for frontend assets: %v", err))
	}
	fileServer := http.FileServer(http.FS(distFS))

	s.router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/ws" {
			s.router.ServeHTTP(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := distFS.Open(path); err != nil {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

// ... handleWebSocket, handleProxyStart, handleProxyStop, handleProxyRotate, handleHttpTest (unchanged) ...

// handleCfScannerStart starts the Cloudflare scanner service.
func (s *Server) handleCfScannerStart(w http.ResponseWriter, r *http.Request, writeJSONError func(http.ResponseWriter, string, int)) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.manager.mu.Lock()
	if s.manager.isScanning {
		s.manager.mu.Unlock()
		writeJSONError(w, "A scan is already in progress.", http.StatusConflict)
		return
	}

	var cfg scanner.ScannerConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.manager.mu.Unlock()
		writeJSONError(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Use a consistent output file for the web UI's resume functionality
	cfg.OutputFile = "results.csv"

	service, err := scanner.NewScannerService(cfg, s.logger)
	if err != nil {
		s.manager.mu.Unlock()
		writeJSONError(w, fmt.Sprintf("Failed to create scanner service: %v", err), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.manager.isScanning = true
	s.manager.scannerCancelFunc = cancel
	s.manager.mu.Unlock()

	// Run the scanner in a goroutine so the HTTP request can return immediately.
	go func() {
		defer func() {
			s.manager.mu.Lock()
			s.manager.isScanning = false
			s.manager.scannerCancelFunc = nil
			s.manager.mu.Unlock()
			s.logger.Println("[SCAN-STATUS] Scan finished.")
			// Send a final status update to the client
			statusMsg, _ := json.Marshal(map[string]interface{}{"type": "cfscan_status", "data": "finished"})
			s.hub.broadcast <- statusMsg
		}()

		progressChan := make(chan *scanner.ScanResult, cfg.ThreadCount)

		// Goroutine to forward results to the websocket hub
		go func() {
			for result := range progressChan {
				result.PrepareForMarshal()
				jsonResult, err := json.Marshal(map[string]interface{}{"type": "cfscan_result", "data": result})
				if err == nil {
					s.hub.broadcast <- jsonResult
				} else {
					s.logger.Printf("Failed to marshal scan result to JSON: %v", err)
				}
			}
		}()

		if err := service.Run(ctx, progressChan); err != nil {
			s.logger.Printf("[SCAN-STATUS] Scan exited with error: %v", err)
			statusMsg, _ := json.Marshal(map[string]interface{}{"type": "cfscan_status", "data": "error", "message": err.Error()})
			s.hub.broadcast <- statusMsg
		}
	}()

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "Scanner started"})
}

// handleCfScannerStop stops the currently running scanner service.
func (s *Server) handleCfScannerStop(w http.ResponseWriter, r *http.Request, writeJSONError func(http.ResponseWriter, string, int)) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()

	if !s.manager.isScanning || s.manager.scannerCancelFunc == nil {
		writeJSONError(w, "Scanner is not running.", http.StatusNotFound)
		return
	}
	s.logger.Println("[SCAN-STATUS] Stopping scan on user request...")
	s.manager.scannerCancelFunc()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Scanner stop signal sent"})
}

// handleWebSocket, handleProxyStart, handleProxyStop, handleProxyRotate, handleHttpTest are mostly unchanged
// so I'm omitting them to keep the output concise. The key changes are the new scanner handlers above.

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

func (s *Server) handleProxyStart(w http.ResponseWriter, r *http.Request, writeJSONError func(w http.ResponseWriter, message string, statusCode int)) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()
	if s.manager.proxyCancelFunc != nil {
		s.manager.proxyCancelFunc()
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
	s.manager.proxyService = service
	s.manager.proxyCancelFunc = cancel
	s.manager.proxyForceRotate = make(chan struct{})
	go func() {
		defer func() {
			s.manager.mu.Lock()
			s.manager.proxyService = nil
			s.manager.proxyCancelFunc = nil
			s.manager.proxyForceRotate = nil
			s.manager.mu.Unlock()
		}()
		if err := service.Run(ctx, s.manager.proxyForceRotate); err != nil {
			s.logger.Printf("Proxy service exited with error: %v", err)
		}
	}()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Proxy service started"})
}

func (s *Server) handleProxyStop(w http.ResponseWriter, r *http.Request, writeJSONError func(w http.ResponseWriter, message string, statusCode int)) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()
	if s.manager.proxyCancelFunc == nil {
		writeJSONError(w, "Proxy service not running", http.StatusNotFound)
		return
	}
	s.manager.proxyCancelFunc()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Proxy service stopped"})
}

func (s *Server) handleProxyRotate(w http.ResponseWriter, r *http.Request, writeJSONError func(w http.ResponseWriter, message string, statusCode int)) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()
	if s.manager.proxyForceRotate == nil {
		writeJSONError(w, "Proxy service not running or not in rotation mode", http.StatusConflict)
		return
	}
	select {
	case s.manager.proxyForceRotate <- struct{}{}:
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "Rotate signal sent"})
	default:
		time.Sleep(100 * time.Millisecond) // Give a moment for channel to be ready
		select {
		case s.manager.proxyForceRotate <- struct{}{}:
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "Rotate signal sent"})
		default:
			writeJSONError(w, "Failed to send rotate signal (channel may be busy)", http.StatusServiceUnavailable)
		}
	}
}

func (s *Server) handleHttpTest(w http.ResponseWriter, r *http.Request, writeJSONError func(w http.ResponseWriter, message string, statusCode int)) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
		s.logger.Printf("Starting HTTP test for %d links with %d threads.", len(req.Links), req.ThreadCount)
		examiner, err := pkghttp.NewExaminer(pkghttp.Options{
			Core:                   req.CoreType,
			MaxDelay:               req.MaxDelay,
			InsecureTLS:            req.InsecureTLS,
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
		go func() {
			for result := range resultsChan {
				jsonResult, err := json.Marshal(map[string]interface{}{"type": "http_result", "data": result})
				if err == nil {
					s.hub.broadcast <- jsonResult
				}
			}
		}()
		testManager.RunTests(req.Links, resultsChan)
		close(resultsChan)
		s.logger.Println("HTTP test finished.")
	}()

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "HTTP test started"})
}
