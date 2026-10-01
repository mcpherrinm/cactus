package landmark

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Handler returns an http.Handler that serves the §6.4.3 landmark list
// (see Encode).
func (s *Sequence) Handler() http.Handler {
	return http.HandlerFunc(s.serveLandmarks)
}

func (s *Sequence) serveLandmarks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body := s.Encode(time.Now())

	// c2sp.org/mtc-tlog fixes the content type.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// The file changes whenever a new landmark is allocated or one
	// expires, so we cannot serve it as immutable. RPs poll on their own
	// schedule.
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// Encode builds the §6.4.3 text body as of now:
//
//	<latest_landmark>\n
//	<tree_size> <expiry>\n      (for landmark latest_landmark - i, i = 0, 1, ...)
//
// listing every landmark active at now, newest first, followed by the
// newest expired landmark, which marks the end of the active ones.
// Landmark 0 expires at the Epoch, so there always is one.
func (s *Sequence) Encode(now time.Time) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "%d\n", s.landmarks[len(s.landmarks)-1].Number)
	for i := len(s.landmarks) - 1; i >= 0; i-- {
		l := s.landmarks[i]
		fmt.Fprintf(&b, "%d %d\n", l.TreeSize, l.Expiry.Unix())
		if !l.Active(now) {
			break
		}
	}
	return []byte(b.String())
}

// maxUint48 bounds the latest landmark number and tree sizes (§6.4.3).
const maxUint48 = 1<<48 - 1

// ParseList decodes a §6.4.3 landmark list, as served by Encode, and
// returns its landmarks newest first (AllocatedAt is unset). It rejects
// any document that does not strictly conform to the format, including
// one without a landmark expired as of now. Use Landmark.Active to pick
// out the active landmarks; the oldest returned landmark is expired.
func ParseList(body []byte, now time.Time) ([]Landmark, error) {
	text, ok := strings.CutSuffix(string(body), "\n")
	if !ok {
		return nil, errors.New("landmark: list does not end in a newline")
	}
	lines := strings.Split(text, "\n")
	latest, err := parseDecimal(lines[0])
	if err != nil {
		return nil, fmt.Errorf("landmark: header: %w", err)
	}
	if latest > maxUint48 {
		return nil, fmt.Errorf("landmark: latest landmark %d exceeds 2^48-1", latest)
	}
	lines = lines[1:]
	if len(lines) == 0 {
		return nil, errors.New("landmark: list has no landmarks")
	}
	if uint64(len(lines)) > latest+1 {
		return nil, fmt.Errorf("landmark: %d landmark lines for latest landmark %d", len(lines), latest)
	}
	out := make([]Landmark, len(lines))
	expired := false
	for i, line := range lines {
		sizeStr, expiryStr, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("landmark: line %q is not <tree_size> <expiry>", line)
		}
		size, err := parseDecimal(sizeStr)
		if err != nil {
			return nil, fmt.Errorf("landmark: tree size: %w", err)
		}
		if size > maxUint48 {
			return nil, fmt.Errorf("landmark: tree size %d exceeds 2^48-1", size)
		}
		expiry, err := parseDecimal(expiryStr)
		if err != nil {
			return nil, fmt.Errorf("landmark: expiry: %w", err)
		}
		if expiry > 1<<63-1 {
			return nil, fmt.Errorf("landmark: expiry %d out of range", expiry)
		}
		l := Landmark{Number: latest - uint64(i), TreeSize: size, Expiry: time.Unix(int64(expiry), 0).UTC()}
		if i > 0 {
			prev := out[i-1]
			if l.TreeSize >= prev.TreeSize {
				return nil, fmt.Errorf("landmark: tree sizes not strictly decreasing: %d then %d", prev.TreeSize, l.TreeSize)
			}
			if l.Expiry.After(prev.Expiry) {
				return nil, fmt.Errorf("landmark: expiries increase: %d then %d", prev.Expiry.Unix(), expiry)
			}
		}
		if l.Number == 0 && (l.TreeSize != 0 || expiry != 0) {
			return nil, fmt.Errorf("landmark: landmark 0 has tree size %d and expiry %d, want 0 and 0", l.TreeSize, expiry)
		}
		expired = expired || l.Expiry.Before(now)
		out[i] = l
	}
	if !expired {
		return nil, errors.New("landmark: list has no expired landmark to end the active ones")
	}
	return out, nil
}

// parseDecimal parses a §2 decimal representation: ASCII digits only,
// and no leading zero except for zero itself.
func parseDecimal(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') || strings.TrimLeft(s, "0123456789") != "" {
		return 0, fmt.Errorf("%q is not a decimal integer", s)
	}
	return strconv.ParseUint(s, 10, 64)
}
