// Package tile serves the cactus issuance log over HTTP using the
// tlog-tiles read-path conventions: cacheable, immutable tiles plus a
// signed checkpoint at /checkpoint.
//
// The serving layout matches PROJECT_PLAN §4: paths under "log/" in
// storage map directly to URL paths, with the leading "log/" stripped
// (since the monitoring listener is rooted at the log).
package tile

import (
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/letsencrypt/cactus/landmark"
	"github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/log/tilewriter"
	"github.com/letsencrypt/cactus/storage"
)

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
// the §6.3.1 /landmarks endpoint (path configurable; "/landmarks" by
// default in cmd/cactus).
func (s *Server) WithLandmarks(seq *landmark.Sequence) *Server {
	s.landmarks = seq
	return s
}

// Handler returns the HTTP handler. Routes:
//
//	GET /checkpoint            — latest signed note
//	GET /tile/<H>/<L>/<NNN..>  — hash tiles
//	GET /tile/data/<NNN..>     — data tiles (level -1)
//	GET /log/v1/entry/<index>  — single entry blob (the §5.3 MerkleTreeCertEntry)
//	GET /subtree/<start>-<end> — cached signed subtree signature
//	GET /landmarks             — §6.3.1 landmark list (only if WithLandmarks)
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /checkpoint", s.handleCheckpoint)
	mux.HandleFunc("GET /tile/", s.handleTile)
	mux.HandleFunc("GET /log/v1/entry/{index}", s.handleEntry)
	mux.HandleFunc("GET /subtree/{name}", s.handleSubtree)
	if s.landmarks != nil {
		mux.Handle("GET /landmarks", s.landmarks.Handler())
		mux.Handle("HEAD /landmarks", s.landmarks.Handler())
	}
	return mux
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
	// Path format: /tile/H/L/NNN[.p/W] or /tile/data/NNN[.p/W].
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

func (s *Server) handleEntry(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.ParseUint(idxStr, 10, 64)
	if err != nil {
		http.Error(w, "bad index", http.StatusBadRequest)
		return
	}

	// Locate the data tile and the position of the requested entry within it.
	tileN := int64(idx) / int64(tilewriter.EntriesPerDataTile)
	posInTile := int(int64(idx) - tileN*int64(tilewriter.EntriesPerDataTile))

	// Find any persisted data tile at width >= posInTile+1, preferring
	// the widest (most up-to-date) one.
	for width := tilewriter.EntriesPerDataTile; width >= posInTile+1; width-- {
		data, err := s.fs.Get(dataTilePath(tileN, width))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			http.Error(w, "entry read failed", http.StatusInternalServerError)
			return
		}
		entries, err := tilewriter.SplitDataTile(data)
		if err != nil {
			http.Error(w, "data tile parse failed", http.StatusInternalServerError)
			return
		}
		if posInTile >= len(entries) {
			continue
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		w.Write(entries[posInTile])
		return
	}
	http.NotFound(w, r)
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

func dataTilePath(tileN int64, recordsInTile int) string {
	// Mirror tilewriter — uses tlog.Tile.Path() which includes the
	// height segment: "tile/<H>/data/<NNN>[.p/<W>]".
	prefix := "log/tile/" + strconv.Itoa(tilewriter.TileHeight) + "/data/"
	if recordsInTile == tilewriter.EntriesPerDataTile {
		return prefix + nnnPath(tileN, false)
	}
	return prefix + nnnPath(tileN, false) + ".p/" + strconv.Itoa(recordsInTile)
}

// nnnPath formats N as the 3-digit-segmented "NNN" tlog tile encoding.
// All but the last component start with "x". For example, N=1234067
// yields "x001/x234/067".
func nnnPath(n int64, _ bool) string {
	if n == 0 {
		return "000"
	}
	var parts []string
	for n > 0 {
		parts = append([]string{padDigit(int(n % 1000))}, parts...)
		n /= 1000
	}
	for i := 0; i < len(parts)-1; i++ {
		parts[i] = "x" + parts[i]
	}
	return strings.Join(parts, "/")
}

func padDigit(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}
