package oapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FelipeGaher/devlake-go/httpx"
)

const spec = `
openapi: 3.0.3
info: {title: test, version: "1"}
paths:
  /api/v1/items:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name: {type: string, maxLength: 5}
      responses:
        "201": {description: created}
  /api/v1/composite:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              allOf:
                - type: object
                  required: [name]
                  properties:
                    name: {type: string}
                - type: object
                  required: [goals]
                  properties:
                    goals: {type: integer, minimum: 0}
      responses:
        "201": {description: created}
  /api/v1/items/{id}:
    get:
      parameters:
        - {name: id, in: path, required: true, schema: {type: string, minLength: 3}}
      responses:
        "200": {description: ok}
`

func TestLint(t *testing.T) {
	summary, err := Lint([]byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "3 paths") {
		t.Errorf("summary = %q", summary)
	}
	if _, err := Lint([]byte("openapi: 3.0.3\ninfo: {}\npaths: {}")); err == nil {
		t.Error("invalid spec: want error")
	}
}

func TestValidator(t *testing.T) {
	mw, err := Validator([]byte(spec), Options{})
	if err != nil {
		t.Fatal(err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }))

	run := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://api.test"+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if c := run("POST", "/api/v1/items", `{"name":"ok"}`).Code; c != 299 {
		t.Errorf("valid body: %d", c)
	}
	rec := run("POST", "/api/v1/items", `{"name":"too-long-name"}`)
	if rec.Code != 400 {
		t.Fatalf("invalid body: %d", rec.Code)
	}
	var body httpx.ErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Error != httpx.CodeInvalidRequest || !strings.Contains(body.Message, "maxLength") {
		t.Errorf("error body = %+v", body)
	}
	if c := run("POST", "/api/v1/items", `{}`).Code; c != 400 {
		t.Errorf("missing required: %d", c)
	}
	if c := run("GET", "/api/v1/items/ab", "").Code; c != 400 {
		t.Errorf("short path param: %d", c)
	}
	if c := run("GET", "/health", "").Code; c != 299 {
		t.Errorf("route not in spec should pass through: %d", c)
	}
}

func TestValidator_RejectUnknownRoutes(t *testing.T) {
	mw, err := Validator([]byte(spec), Options{RejectUnknownRoutes: true})
	if err != nil {
		t.Fatal(err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }))
	run := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "http://api.test"+path, nil))
		return rec
	}
	rec := run("GET", "/api/v1/secret-admin")
	var body httpx.ErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 404 || body.Error != CodeNotFound {
		t.Errorf("unknown path: %d %+v", rec.Code, body)
	}
	if c := run("DELETE", "/api/v1/items").Code; c != 404 {
		t.Errorf("known path, unknown method: %d, want 404", c)
	}
	if c := run("GET", "/api/v1/items/abc").Code; c != 299 {
		t.Errorf("known route: %d, want pass-through", c)
	}
}

func TestMessage_CompositeSchemaReportsInnerField(t *testing.T) {
	mw, err := Validator([]byte(spec), Options{})
	if err != nil {
		t.Fatal(err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }))
	req := httptest.NewRequest("POST", "http://api.test/api/v1/composite", strings.NewReader(`{"name":"x","goals":-1}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body httpx.ErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 400 || !strings.Contains(body.Message, "goals") {
		t.Errorf("got %d %q, want 400 naming the goals field", rec.Code, body.Message)
	}
}
