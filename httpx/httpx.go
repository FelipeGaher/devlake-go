// Package httpx holds small JSON HTTP helpers and net/http middleware for
// JSON APIs: a consistent error body, a JSON-tag-aware validator, client-IP
// extraction behind a reverse proxy, rate limiting, security headers, a
// request body cap and the structured access log.
package httpx

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse is the error body written by this library:
// {"error":"MACHINE_CODE","message":"human text"}. Clients switch on Error
// (the code), never string-match Message.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// Error codes written by this library's middleware.
const (
	CodeUnauthorized   = "UNAUTHORIZED"
	CodeForbidden      = "FORBIDDEN"
	CodeRateLimited    = "RATE_LIMITED"
	CodeInvalidRequest = "INVALID_REQUEST"
	CodeInternal       = "INTERNAL"
)

// ErrorWriter writes an error response. Middleware in this library accepts
// one so an app can keep its own error body shape; nil means WriteError.
type ErrorWriter func(w http.ResponseWriter, status int, code, message string)

// WriteJSON writes v as a JSON body with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes an ErrorResponse.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, ErrorResponse{Error: code, Message: message})
}

// OrDefault returns ew, or WriteError if ew is nil.
func (ew ErrorWriter) OrDefault() ErrorWriter {
	if ew == nil {
		return WriteError
	}
	return ew
}
