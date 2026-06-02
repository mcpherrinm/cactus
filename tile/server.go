// Package tile serves the cactus issuance log over HTTP using the
// tlog-tiles read-path conventions: cacheable, immutable tiles plus a
// signed checkpoint at /checkpoint.
//
// In the serving layout, paths under "log/" in storage map directly
// to URL paths, with the leading "log/" stripped (since the monitoring
// listener is rooted at the log).
package tile

import (
	_ "embed"
	"errors"
	"io/fs"
	"net/http"
	"strings"

	"github.com/letsencrypt/cactus/landmark"
	"github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/storage"
)

// indexHTML and appJS are the browser UI served at the log root. They are
// pure HTML/CSS/JS with no dependencies and use only relative URLs, so the
// page works under any log-number prefix. index.html loads app.js via a
// relative <script src="app.js">.
//
//go:embed index.html
var indexHTML []byte

//go:embed app.js
var appJS []byte

// Server is the read-path HTTP handler.
type Server struct {
	log       *log.Log
	fs        storage.FS
	landmarks *landmark.Sequence // optional; nil disables /landmarks
}

// New returns a Server backed by l and fs.
func New(l *log.Log, fs storage.FS) *Server {
	return &Server{log: l, fs: fs}
}

// WithLandmarks attaches a landmark.Sequence so the server exposes
// the §6.3.1 /landmarks endpoint.
func (s *Server) WithLandmarks(seq *landmark.Sequence) *Server {
	s.landmarks = seq
	return s
}

// Handler returns the HTTP handler. Routes:
//
//	GET /                      — browser UI (index.html)
//	GET /app.js                — browser UI logic
//	GET /checkpoint            — latest signed note
//	GET /tile/<L>/<NNN..>      — hash tiles (c2sp tlog-tiles)
//	GET /tile/entries/<NNN..>  — entry (data) tiles (c2sp tlog-tiles)
//	GET /subtree/<start>-<end> — cached signed subtree signature
//	GET /landmarks             — §6.3.1 landmark list (only if WithLandmarks)
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /app.js", s.handleAppJS)
	mux.HandleFunc("GET /checkpoint", s.handleCheckpoint)
	mux.HandleFunc("GET /tile/", s.handleTile)
	mux.HandleFunc("GET /subtree/{name}", s.handleSubtree)
	if s.landmarks != nil {
		mux.Handle("GET /landmarks", s.landmarks.Handler())
		mux.Handle("HEAD /landmarks", s.landmarks.Handler())
	}
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, max-age=0")
	w.Write(indexHTML)
}

func (s *Server) handleAppJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, max-age=0")
	w.Write(appJS)
}

func (s *Server) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	cp := s.log.CurrentCheckpoint()
	if len(cp.SignedNote) == 0 {
		http.Error(w, "no checkpoint yet", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, max-age=0")
	w.Write(cp.SignedNote)
}

func (s *Server) handleTile(w http.ResponseWriter, r *http.Request) {
	// Path format (c2sp tlog-tiles): /tile/<L>/NNN[.p/W] for hash tiles,
	// /tile/entries/NNN[.p/W] for entry (data) tiles.
	rel := strings.TrimPrefix(r.URL.Path, "/")
	if !strings.HasPrefix(rel, "tile/") {
		http.NotFound(w, r)
		return
	}
	storagePath := "log/" + rel
	data, err := s.fs.Get(storagePath)
	if errors.Is(err, fs.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "tile read failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	// Full tiles are immutable; partial tiles can change. Use the
	// presence of ".p/" in the path as the gate.
	if strings.Contains(rel, ".p/") {
		w.Header().Set("Cache-Control", "no-cache, max-age=0")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	}
	w.Write(data)
}

func (s *Server) handleSubtree(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name") // e.g. "8-13"
	data, err := s.fs.Get("log/subtrees/" + name)
	if errors.Is(err, fs.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "subtree read failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Write(data)
}
