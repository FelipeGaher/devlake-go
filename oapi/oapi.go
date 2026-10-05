// Package oapi validates HTTP requests against an embedded OpenAPI 3 spec
// (kin-openapi), and lints the spec itself for CI.
//
// Mount the validator at the root router so it sees the full request path
// (e.g. /api/v1/...), not inside a chi sub-router whose mount prefix has been
// stripped.
package oapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/FelipeGaher/devlake-go/httpx"
)

// Options configures Validator.
type Options struct {
	// ValidateResponses also validates response bodies and logs (never
	// rejects) mismatches — useful in integration tests to catch drift
	// between Go types and the spec. Leave off in production.
	ValidateResponses bool
	// RejectUnknownRoutes makes the spec a strict allow-list: a request that
	// matches no path+method in the spec gets 404 (code NOT_FOUND) instead of
	// passing through, so a handler registered on the router but missing
	// from the spec can never be reached unvalidated. Mount anything that is
	// deliberately outside the spec (e.g. /health) before the validator.
	RejectUnknownRoutes bool
	// ErrorWriter writes the 400/404 responses. Optional (default
	// httpx.WriteError).
	ErrorWriter httpx.ErrorWriter
}

// CodeNotFound is the error code for a request matching no route in the
// spec when Options.RejectUnknownRoutes is set.
const CodeNotFound = "NOT_FOUND"

// Load parses and validates spec.
func Load(spec []byte) (*openapi3.T, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	if err != nil {
		return nil, fmt.Errorf("openapi: load: %w", err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		return nil, fmt.Errorf("openapi: validate: %w", err)
	}
	return doc, nil
}

// Lint loads and validates spec, checks that every path can be routed the
// way Validator routes requests at runtime, and returns a one-line summary,
// for a CI `speccheck`-style command:
//
//	summary, err := oapi.Lint(apispec.OpenAPI)
func Lint(spec []byte) (string, error) {
	doc, err := Load(spec)
	if err != nil {
		return "", err
	}
	if _, err := gorillamux.NewRouter(doc); err != nil {
		return "", fmt.Errorf("openapi: router: %w", err)
	}
	schemas := 0
	if doc.Components != nil {
		schemas = len(doc.Components.Schemas)
	}
	return fmt.Sprintf("openapi: spec OK (%d paths, %d schemas)", len(doc.Paths.Map()), schemas), nil
}

// Validator returns middleware that validates every request matching a route
// in spec before it reaches a handler. Requests for routes not in the spec
// (e.g. /health) pass through untouched, unless Options.RejectUnknownRoutes
// is set. Spec-level security requirements are
// ignored: authentication is the auth middleware's job.
func Validator(spec []byte, opts Options) (func(http.Handler) http.Handler, error) {
	doc, err := Load(spec)
	if err != nil {
		return nil, err
	}
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		return nil, fmt.Errorf("openapi: router: %w", err)
	}
	ew := opts.ErrorWriter.OrDefault()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route, pathParams, err := router.FindRoute(r)
			if err != nil {
				if opts.RejectUnknownRoutes {
					ew(w, http.StatusNotFound, CodeNotFound, "no matching route")
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			input := &openapi3filter.RequestValidationInput{
				Request:    r,
				PathParams: pathParams,
				Route:      route,
				Options: &openapi3filter.Options{
					AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
				},
			}
			if err := openapi3filter.ValidateRequest(r.Context(), input); err != nil {
				ew(w, http.StatusBadRequest, httpx.CodeInvalidRequest, Message(err))
				return
			}
			if !opts.ValidateResponses {
				next.ServeHTTP(w, r)
				return
			}

			rw := &recorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			respInput := &openapi3filter.ResponseValidationInput{
				RequestValidationInput: input,
				Status:                 rw.status,
				Header:                 w.Header(),
				Body:                   io.NopCloser(bytes.NewReader(rw.body)),
				Options:                &openapi3filter.Options{IncludeResponseStatus: true},
			}
			if err := openapi3filter.ValidateResponse(context.WithoutCancel(r.Context()), respInput); err != nil {
				slog.WarnContext(r.Context(), "response does not match OpenAPI spec",
					"method", r.Method, "path", r.URL.Path, "error", err)
			}
		})
	}, nil
}

// Message pulls a concise message out of a kin-openapi validation error,
// dropping the verbose schema/value dumps that are only useful for debugging.
func Message(err error) string {
	var reqErr *openapi3filter.RequestError
	if errors.As(err, &reqErr) {
		var schemaErr *openapi3.SchemaError
		if errors.As(reqErr.Err, &schemaErr) {
			field := schemaErr.SchemaField
			if p := schemaErr.JSONPointer(); len(p) > 0 {
				field = fmt.Sprint(p[len(p)-1]) + " " + field
			}
			return field + ": " + schemaErr.Reason
		}
		if reqErr.Parameter != nil {
			return "invalid parameter " + reqErr.Parameter.Name
		}
	}
	return "invalid request body"
}

type recorder struct {
	http.ResponseWriter
	status int
	body   []byte
}

func (rr *recorder) WriteHeader(status int) {
	rr.status = status
	rr.ResponseWriter.WriteHeader(status)
}

func (rr *recorder) Write(b []byte) (int, error) {
	rr.body = append(rr.body, b...)
	return rr.ResponseWriter.Write(b)
}
