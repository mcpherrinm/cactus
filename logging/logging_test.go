package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewProducesJSON(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "info")
	l.Info("hello", "k", "v")
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("not JSON: %v: %q", err, buf.String())
	}
	if rec["msg"] != "hello" || rec["k"] != "v" {
		t.Errorf("unexpected record: %v", rec)
	}
}

func TestMiddlewareAttachesRequestID(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "info")
	var seenID string
	h := Middleware(l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenID = RequestIDFromContext(r.Context())
		w.WriteHeader(204)
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/foo")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seenID == "" {
		t.Errorf("expected request ID in context")
	}
	if !strings.Contains(buf.String(), `"path":"/foo"`) {
		t.Errorf("expected path log, got %q", buf.String())
	}
	if !strings.Contains(buf.String(), `"status":204`) {
		t.Errorf("expected status log, got %q", buf.String())
	}
}

func TestRequestIDPassthrough(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "info")
	var seenID string
	h := Middleware(l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenID = RequestIDFromContext(r.Context())
	}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Request-Id", "deadbeef")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if seenID != "deadbeef" {
		t.Errorf("seenID = %q, want %q", seenID, "deadbeef")
	}
	_ = context.Background
}
