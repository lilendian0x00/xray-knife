package web

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// hubReplaySize is how many recent events a reconnecting SSE client can
// catch up on through Last-Event-ID before it is told to resync.
const hubReplaySize = 1024

// clientBufferSize is the per-client queue. A client that falls this far
// behind gets a resync notice instead of the events it missed.
const clientBufferSize = 512

// Event is one message on the SSE stream. Data is the JSON envelope the UI
// parses ({"type": ..., "data": ...}); Type is extracted once at publish time.
type Event struct {
	ID   uint64
	Type string
	Data []byte
}

// Hub fans events out to the connected SSE clients and keeps a short replay
// buffer so a reconnecting client can pick up where it left off.
type Hub struct {
	mu      sync.Mutex
	clients map[*Client]struct{}
	seq     uint64
	ring    []Event // circular, len <= hubReplaySize
	head    int     // index of the oldest event once the ring is full
	closed  bool
}

func newHub() *Hub {
	return &Hub{
		clients: make(map[*Client]struct{}),
		ring:    make([]Event, 0, hubReplaySize),
	}
}

// Client is one SSE connection.
type Client struct {
	send chan Event
	// lagged is set when events had to be dropped for this client; the SSE
	// writer then sends a resync notice.
	lagged atomic.Bool
}

// Subscribe registers a client. When lastID > 0 it also returns the buffered
// events after lastID, or ok=false when that gap can no longer be replayed
// (too old, or the ID is from before a restart). Registration and the replay
// snapshot happen under one lock, so no event falls between them.
func (h *Hub) Subscribe(lastID uint64) (c *Client, replay []Event, seq uint64, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c = &Client{send: make(chan Event, clientBufferSize)}
	if h.closed {
		close(c.send)
		return c, nil, h.seq, true
	}
	h.clients[c] = struct{}{}
	seq = h.seq
	if lastID == 0 || lastID == seq {
		return c, nil, seq, true
	}
	if lastID > seq {
		return c, nil, seq, false
	}
	events := h.orderedLocked()
	if len(events) == 0 || events[0].ID > lastID+1 {
		return c, nil, seq, false
	}
	for _, ev := range events {
		if ev.ID > lastID {
			replay = append(replay, ev)
		}
	}
	return c, replay, seq, true
}

// Unsubscribe removes a client and closes its channel.
func (h *Hub) Unsubscribe(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
	}
}

// CloseAll disconnects every client (server shutdown). Later subscribers get
// an already-closed channel.
func (h *Hub) CloseAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for c := range h.clients {
		delete(h.clients, c)
		close(c.send)
	}
}

// Seq is the ID of the latest published event.
func (h *Hub) Seq() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.seq
}

func (h *Hub) orderedLocked() []Event {
	if len(h.ring) < hubReplaySize {
		return h.ring
	}
	out := make([]Event, 0, len(h.ring))
	out = append(out, h.ring[h.head:]...)
	return append(out, h.ring[:h.head]...)
}

// Publish marshals {"type": eventType, "data": data, ...extra} and sends it.
func (h *Hub) Publish(eventType string, data any, extra map[string]any) {
	envelope := make(map[string]any, len(extra)+2)
	for k, v := range extra {
		envelope[k] = v
	}
	envelope["type"] = eventType
	envelope["data"] = data
	payload, err := json.Marshal(envelope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Web UI Hub: failed to marshal %s event: %v\n", eventType, err)
		return
	}
	h.publish(eventType, payload)
}

// Broadcast sends a pre-marshalled envelope. The event type is read from its
// "type" field once, here, rather than by every client.
func (h *Hub) Broadcast(message []byte) {
	var envelope struct {
		Type string `json:"type"`
	}
	eventType := "message"
	if json.Unmarshal(message, &envelope) == nil && envelope.Type != "" {
		eventType = envelope.Type
	}
	h.publish(eventType, message)
}

func (h *Hub) publish(eventType string, payload []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.seq++
	ev := Event{ID: h.seq, Type: eventType, Data: payload}
	if len(h.ring) < hubReplaySize {
		h.ring = append(h.ring, ev)
	} else {
		h.ring[h.head] = ev
		h.head = (h.head + 1) % hubReplaySize
	}
	for c := range h.clients {
		select {
		case c.send <- ev:
		default:
			// Never block the publisher on a slow browser tab; the client
			// is told to resync once it drains.
			c.lagged.Store(true)
		}
	}
}

// Write lets the hub back a log.Logger / customlog output: each write
// becomes a "log" event.
func (h *Hub) Write(p []byte) (n int, err error) {
	// The log package may send empty messages or just newlines, which we can ignore.
	trimmedMessage := strings.TrimSpace(string(p))
	if trimmedMessage == "" {
		return len(p), nil
	}
	h.Publish("log", trimmedMessage, nil)
	return len(p), nil
}

// marshalEnvelope builds the {"type": ..., "data": ...} envelope for events
// written directly to one client (state, resync, auth_expired).
func marshalEnvelope(eventType string, data any) ([]byte, error) {
	return json.Marshal(map[string]any{"type": eventType, "data": data})
}
