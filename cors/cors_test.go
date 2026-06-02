package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewareSetsHeadersAndPassesThrough(t *testing.T) {
	called := false
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/checkpoint", nil))

	if !called {
		t.Error("next handler was not called for a non-preflight request")
	}
	if got := rw.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}
	if got := rw.Header().Get("Access-Control-Expose-Headers"); got != ExposeHeaders {
		t.Errorf("Access-Control-Expose-Headers = %q, want %q", got, ExposeHeaders)
	}
	// Expose-Headers must match Boulder's set exactly.
	if ExposeHeaders != "Link, Replay-Nonce, Location, Retry-After" {
		t.Errorf("ExposeHeaders = %q, drifted from Boulder's set", ExposeHeaders)
	}
}

func TestMiddlewareHandlesPreflight(t *testing.T) {
	called := false
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodOptions, "/acme/new-order", nil)
	req.Header.Set("Origin", "https://example.test")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if called {
		t.Error("preflight request should be short-circuited, not passed to next")
	}
	if rw.Code != http.StatusOK {
		t.Errorf("preflight status = %d, want 200", rw.Code)
	}
	for k, want := range map[string]string{
		"Access-Control-Allow-Origin":   "*",
		"Access-Control-Allow-Methods":  "GET, HEAD, POST, OPTIONS",
		"Access-Control-Allow-Headers":  "Content-Type",
		"Access-Control-Max-Age":        "86400",
		"Access-Control-Expose-Headers": ExposeHeaders,
	} {
		if got := rw.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestMiddlewarePlainOptionsPassesThrough(t *testing.T) {
	// An OPTIONS request without Access-Control-Request-Method is not a
	// CORS preflight; it should reach the next handler.
	called := false
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, httptest.NewRequest(http.MethodOptions, "/", nil))
	if !called {
		t.Error("plain OPTIONS (no preflight) should pass through to next")
	}
	if got := rw.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}
}
