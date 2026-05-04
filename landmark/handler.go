package landmark

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Handler returns an http.Handler that serves the §6.3.1 landmark
// list. Plain text, one line of `<last> <num_active>` followed by
// `num_active + 1` tree sizes in strictly decreasing order.
func (s *Sequence) Handler() http.Handler {
	return http.HandlerFunc(s.serveLandmarks)
}

func (s *Sequence) serveLandmarks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body := s.encode()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// §6.3.1: the file changes whenever a new landmark is allocated,
	// so we cannot serve it as immutable. RPs poll on their own
	// schedule.
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// encode builds the §6.3.1 text body: `<last> <num_active>\n` followed
// by num_active + 1 tree-size lines, strictly decreasing.
//
// Special case: when only landmark 0 exists, last = 0, num_active = 0,
// and we emit just one tree-size line (0).
func (s *Sequence) encode() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	maxActive := s.cfg.MaxActive()
	if maxActive < 0 {
		maxActive = 0
	}
	last := s.landmarks[len(s.landmarks)-1].Number

	// num_active = min(last, maxActive). Per §6.3.1:
	//   num_active_landmarks <= max_active_landmarks
	//   num_active_landmarks <= last_landmark
	numActive := uint64(maxActive)
	if numActive > last {
		numActive = last
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d %d\n", last, numActive)
	// num_active + 1 tree-size lines: line i = tree size for landmark (last - i),
	// for i in [0, num_active].
	for i := uint64(0); i <= numActive; i++ {
		n := last - i
		fmt.Fprintf(&b, "%d\n", s.landmarks[n].TreeSize)
	}
	return []byte(b.String())
}
