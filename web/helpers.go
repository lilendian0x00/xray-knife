package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// Request body limits. Link lists for the HTTP tester and proxy can be tens
// of thousands of lines, everything else is small.
const (
	maxLoginBody = 4 << 10
	maxSmallBody = 1 << 20
	maxLargeBody = 32 << 20
)

// Machine-readable error codes sent next to the human message.
const (
	codeInvalidRequest = "invalid_request"
	codeUnauthorized   = "unauthorized"
	codeTokenExpired   = "token_expired"
	codeTokenRevoked   = "token_revoked"
	codeNotFound       = "not_found"
	codeMethod         = "method_not_allowed"
	codeBusy           = "busy"
	codeNotRunning     = "not_running"
	codeExists         = "exists"
	codeTooLarge       = "body_too_large"
	codeRateLimited    = "rate_limited"
	codeDBUnavailable  = "db_unavailable"
	codeFetchFailed    = "fetch_failed"
	codeInvalidFormat  = "invalid_format"
	codeNothingExport  = "nothing_to_export"
	codeInternal       = "internal"
)

// apiError is an error that knows its HTTP status and code.
type apiError struct {
	status int
	code   string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &apiError{status: http.StatusBadRequest, code: codeInvalidRequest, msg: fmt.Sprintf(format, args...)}
}

func conflict(code, format string, args ...any) error {
	return &apiError{status: http.StatusConflict, code: code, msg: fmt.Sprintf(format, args...)}
}

func notFound(format string, args ...any) error {
	return &apiError{status: http.StatusNotFound, code: codeNotFound, msg: fmt.Sprintf(format, args...)}
}

// writeError maps err to a status: *apiError carries its own, everything
// else is fallbackStatus.
func writeError(w http.ResponseWriter, err error, fallbackStatus int) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeJSONErrorCode(w, ae.msg, ae.code, ae.status)
		return
	}
	code := codeInternal
	switch fallbackStatus {
	case http.StatusBadRequest:
		code = codeInvalidRequest
	case http.StatusNotFound:
		code = codeNotFound
	case http.StatusConflict:
		code = codeBusy
	}
	writeJSONErrorCode(w, err.Error(), code, fallbackStatus)
}

// writeJSONError sends a JSON-formatted error message.
func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	code := codeInternal
	switch statusCode {
	case http.StatusBadRequest:
		code = codeInvalidRequest
	case http.StatusUnauthorized:
		code = codeUnauthorized
	case http.StatusNotFound:
		code = codeNotFound
	case http.StatusMethodNotAllowed:
		code = codeMethod
	case http.StatusConflict:
		code = codeBusy
	case http.StatusRequestEntityTooLarge:
		code = codeTooLarge
	case http.StatusTooManyRequests:
		code = codeRateLimited
	case http.StatusServiceUnavailable:
		code = codeDBUnavailable
	}
	writeJSONErrorCode(w, message, code, statusCode)
}

func writeJSONErrorCode(w http.ResponseWriter, message, code string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message, "code": code})
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

// decodeJSONBody decodes the JSON request body into v, capped at maxSmallBody.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
	return decodeJSONBodyLimit(w, r, v, maxSmallBody)
}

// decodeJSONBodyLimit decodes the JSON request body into v, rejecting bodies
// over limit bytes. An empty body is an error.
func decodeJSONBodyLimit(w http.ResponseWriter, r *http.Request, v interface{}, limit int64) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("request body is empty")
		}
		return err
	}
	return nil
}

// decodeOptionalJSONBody is decodeJSONBodyLimit that accepts an empty body.
func decodeOptionalJSONBody(w http.ResponseWriter, r *http.Request, v interface{}, limit int64) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// writeDecodeError answers a failed body decode with 413 or 400.
func writeDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeJSONErrorCode(w, fmt.Sprintf("Request body too large (limit %d bytes)", tooLarge.Limit), codeTooLarge, http.StatusRequestEntityTooLarge)
		return
	}
	writeJSONErrorCode(w, fmt.Sprintf("Invalid request body: %v", err), codeInvalidRequest, http.StatusBadRequest)
}

// methodNotAllowed is a helper to respond with a 405 Method Not Allowed error.
func methodNotAllowed(w http.ResponseWriter) {
	writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// pageParams reads ?page=&per_page= (1-based page, per_page default 100,
// capped at 1000). ok is false when neither parameter was given.
func pageParams(r *http.Request) (page, perPage int, ok bool) {
	pageStr := r.URL.Query().Get("page")
	perPageStr := r.URL.Query().Get("per_page")
	ok = pageStr != "" || perPageStr != ""

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}
	perPage, err = strconv.Atoi(perPageStr)
	if err != nil || perPage < 1 {
		perPage = 100
	}
	if perPage > 1000 {
		perPage = 1000
	}
	return page, perPage, ok
}

// paginated is the envelope of every paginated list response.
type paginated[T any] struct {
	Items   []T `json:"items"`
	Total   int `json:"total"`
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
}

// writePaginatedResponse supports optional ?page=N&per_page=M query parameters.
// If no pagination params are provided, returns all results (backwards compatible).
func writePaginatedResponse[T any](w http.ResponseWriter, r *http.Request, items []T) {
	page, perPage, ok := pageParams(r)

	// If no pagination params, return all results
	if !ok {
		writeJSONResponse(w, http.StatusOK, items)
		return
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

	writeJSONResponse(w, http.StatusOK, paginated[T]{
		Items:   items[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}
