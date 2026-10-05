// Package accesslog writes a fixed-schema JSON traffic log line — one per
// incoming HTTP request (httpx.AccessLog) and one per outgoing call such as a
// Web Push send attempt (webpush.Send). It deliberately bypasses the app's
// global slog default logger: that handler always emits time/level/msg keys,
// and this schema is fixed and external-facing, so marshaling the struct
// directly gives exact, predictable output with no extra keys.
package accesslog

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"
)

// TimeFormat matches "2026-12-10T13:55:36.002Z" — millisecond-precision, UTC.
const TimeFormat = "2006-01-02T15:04:05.000Z"

// Type values used by this library.
const (
	TypeIncoming = "incoming"
	TypeOutgoing = "outgoing"
)

type Entry struct {
	Type       string  `json:"type"`
	Timestamp  string  `json:"timestamp"`
	ClientIP   string  `json:"client_ip"`
	HTTPMethod string  `json:"http_method"`
	RequestURI string  `json:"request_uri"`
	StatusCode int     `json:"status_code"`
	BytesSent  int     `json:"bytes_sent"`
	DurationMs float64 `json:"duration_ms"`
	UserID     int64   `json:"user_id"`
	UserAgent  string  `json:"user_agent"`
}

var (
	mu  sync.Mutex
	out io.Writer = os.Stdout
)

// SetOutput redirects log lines (default os.Stdout). Intended for tests.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	out = w
}

// Write marshals e and writes it as one JSON line, guarded by a mutex since
// this is called concurrently from HTTP handler goroutines and background
// workers alike.
func Write(e Entry) {
	b, err := json.Marshal(e)
	if err != nil {
		slog.Error("accesslog: marshal failed", "error", err)
		return
	}
	b = append(b, '\n')
	mu.Lock()
	defer mu.Unlock()
	if _, err := out.Write(b); err != nil {
		slog.Error("accesslog: write failed", "error", err)
	}
}
