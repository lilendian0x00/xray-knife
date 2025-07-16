package web

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// writeJSONError sends a JSON-formatted error message.
func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// writeJSONResponse sends a JSON-formatted response.
func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// If encoding fails, log it and send a fallback error
		// Note: This might happen if headers are already written.
		http.Error(w, `{"error":"Failed to encode response"}`, http.StatusInternalServerError)
	}
}

// decodeJSONBody safely decodes the request body into a given struct.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// methodNotAllowed is a helper to respond with a 405 Method Not Allowed error.
func methodNotAllowed(w http.ResponseWriter) {
	writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
}
