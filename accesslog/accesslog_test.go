package accesslog

import (
	"encoding/json"
	"testing"
)

func TestEntry_MarshalsExactFieldSet(t *testing.T) {
	e := Entry{
		Type:       "incoming",
		Timestamp:  "2026-12-10T13:55:36.002Z",
		ClientIP:   "127.0.0.1",
		HTTPMethod: "GET",
		RequestURI: "/index.html",
		StatusCode: 200,
		BytesSent:  2326,
		DurationMs: 14.5,
		UserID:     2,
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	}

	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	wantKeys := []string{
		"type", "timestamp", "client_ip", "http_method", "request_uri",
		"status_code", "bytes_sent", "duration_ms", "user_id", "user_agent",
	}
	if len(m) != len(wantKeys) {
		t.Fatalf("got %d keys, want exactly %d: %v", len(m), len(wantKeys), m)
	}
	for _, k := range wantKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("missing expected key %q", k)
		}
	}

	if m["type"] != "incoming" {
		t.Errorf("type = %v, want %q", m["type"], "incoming")
	}
	if m["status_code"] != float64(200) {
		t.Errorf("status_code = %v, want 200", m["status_code"])
	}
	if m["user_id"] != float64(2) {
		t.Errorf("user_id = %v, want 2", m["user_id"])
	}
}

func TestEntry_ZeroValueFieldsStillPresent(t *testing.T) {
	// Outgoing (push) entries deliberately leave client_ip/user_agent empty —
	// confirm the keys still round-trip rather than being omitted.
	e := Entry{Type: "outgoing", UserID: 5}

	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if v, ok := m["client_ip"]; !ok || v != "" {
		t.Errorf("client_ip = %v, ok=%v; want present and empty", v, ok)
	}
	if v, ok := m["user_agent"]; !ok || v != "" {
		t.Errorf("user_agent = %v, ok=%v; want present and empty", v, ok)
	}
}
