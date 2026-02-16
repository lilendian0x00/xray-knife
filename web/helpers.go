package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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

// writePaginatedResponse supports optional ?page=N&per_page=M query parameters.
// If no pagination params are provided, returns all results (backwards compatible).
func writePaginatedResponse[T any](w http.ResponseWriter, r *http.Request, items []T) {
	pageStr := r.URL.Query().Get("page")
	perPageStr := r.URL.Query().Get("per_page")

	// If no pagination params, return all results
	if pageStr == "" && perPageStr == "" {
		writeJSONResponse(w, http.StatusOK, items)
		return
	}

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	perPage, err := strconv.Atoi(perPageStr)
	if err != nil || perPage < 1 {
		perPage = 100
	}
	if perPage > 1000 {
		perPage = 1000
	}

	total := len(items)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"items":    items[start:end],
		"total":    total,
		"page":     page,
		"per_page": perPage,
	})
}
