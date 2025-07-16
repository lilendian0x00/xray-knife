package web

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"
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

// setupRoutes configures the routing for the server.
func (s *Server) setupRoutes() {
	// API Handlers
	apiHandler := NewAPIHandler(s.manager, s.logger)
	apiHandler.RegisterRoutes(s.router)

	// WebSocket Handler
	s.router.HandleFunc("/ws", s.handleWebSocket)

	// Static File Server for Frontend
	distFS, err := fs.Sub(embeddedFiles, "dist")
	if err != nil {
		panic(fmt.Sprintf("could not create sub-filesystem for frontend assets: %v", err))
	}
	fileServer := http.FileServer(http.FS(distFS))

	// Fallback to index.html for SPA routing
	s.router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

// handleWebSocket upgrades HTTP connections to WebSocket connections.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Printf("Failed to upgrade websocket: %v\n", err)
		return
	}
	client := &Client{hub: s.hub, conn: conn, send: make(chan []byte, 256)}
	s.hub.register <- client
	go client.writePump()
	go client.readPump()
}
