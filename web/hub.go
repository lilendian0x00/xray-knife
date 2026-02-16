package web

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	// Registered clients.
	clients map[*Client]bool

	// Inbound messages to be broadcasted to all clients.
	broadcast chan []byte

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client

	mu sync.RWMutex
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte, 1024),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
			var staleClients []*Client
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					staleClients = append(staleClients, client)
				}
			}
			h.mu.RUnlock()

			// Clean up stale clients under a write lock.
			if len(staleClients) > 0 {
				h.mu.Lock()
				for _, client := range staleClients {
					if _, ok := h.clients[client]; ok {
						close(client.send)
						delete(h.clients, client)
					}
				}
				h.mu.Unlock()
			}
		}
	}
}

// Write allows Hub to be used as an io.Writer.
// It wraps the raw log message in a structured JSON object before broadcasting.
func (h *Hub) Write(p []byte) (n int, err error) {
	// The log package may send empty messages or just newlines, which we can ignore.
	trimmedMessage := strings.TrimSpace(string(p))
	if trimmedMessage == "" {
		return len(p), nil
	}

	// Wrap the log message in a structured JSON object.
	logEntry := map[string]string{
		"type": "log",
		"data": trimmedMessage,
	}

	jsonMessage, err := json.Marshal(logEntry)
	if err != nil {
		// This is a programmatic error, should not happen in normal operation.
		// Log to stderr directly to avoid an infinite loop.
		fmt.Fprintf(os.Stderr, "Web UI Hub: failed to marshal log message to JSON: %v\n", err)
		return len(p), nil // Report as written to not break the logger.
	}

	h.Broadcast(jsonMessage)
	return len(p), nil
}

// Broadcast sends a message to the hub's broadcast channel without blocking.
func (h *Hub) Broadcast(message []byte) {
	select {
	case h.broadcast <- message:
	default:
		fmt.Fprintf(os.Stderr, "Web UI Hub: broadcast channel full, dropping broadcast message.\n")
	}
}

// Client is a middleman between the SSE connection and the hub.
type Client struct {
	hub *Hub

	// Buffered channel of outbound messages.
	send chan []byte

	// Closed when the SSE handler exits.
	done chan struct{}
}
