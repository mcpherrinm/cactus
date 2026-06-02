package main

import "testing"

func TestParseLandmarks(t *testing.T) {
	// last=3, num_active=2 → three size lines for landmarks 3, 2, 1.
	body := []byte("3 2\n120\n80\n40\n")
	lms, err := parseLandmarks(body)
	if err != nil {
		t.Fatal(err)
	}
	want := []landmarkEntry{{3, 120}, {2, 80}, {1, 40}}
	if len(lms) != len(want) {
		t.Fatalf("got %d entries, want %d", len(lms), len(want))
	}
	for i, w := range want {
		if lms[i] != w {
			t.Errorf("entry %d = %+v, want %+v", i, lms[i], w)
		}
	}
}

func TestParseLandmarksOnlyZero(t *testing.T) {
	// Special case from §6.3.1: only landmark 0 exists.
	lms, err := parseLandmarks([]byte("0 0\n0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(lms) != 1 || lms[0] != (landmarkEntry{0, 0}) {
		t.Fatalf("got %+v, want [{0 0}]", lms)
	}
}

func TestParseLandmarksBad(t *testing.T) {
	for _, body := range []string{
		"",          // empty
		"3\n1\n",    // bad header
		"3 2\n10\n", // wrong number of size lines
		"2 5\n",     // num_active > last
	} {
		if _, err := parseLandmarks([]byte(body)); err == nil {
			t.Errorf("parseLandmarks(%q) = nil error, want error", body)
		}
	}
}

func TestCoveringLandmark(t *testing.T) {
	// Landmarks (descending): 3→[80,120), 2→[40,80), 1→[0,40), plus the
	// extra older line 0→0 so landmark 1's lower bound is known.
	desc := []landmarkEntry{{3, 120}, {2, 80}, {1, 40}, {0, 0}}
	cases := []struct {
		index                  uint64
		wantNum, wantSz, wantPrev uint64
		wantOK                 bool
	}{
		{0, 1, 40, 0, true},    // first entry of landmark 1
		{39, 1, 40, 0, true},   // last entry of landmark 1
		{40, 2, 80, 40, true},  // first entry of landmark 2
		{119, 3, 120, 80, true}, // last entry of landmark 3
		{120, 0, 0, 0, false},  // past the newest landmark
		{500, 0, 0, 0, false},  // well past
	}
	for _, c := range cases {
		num, sz, prev, ok := coveringLandmark(desc, c.index)
		if ok != c.wantOK || num != c.wantNum || sz != c.wantSz || prev != c.wantPrev {
			t.Errorf("coveringLandmark(index=%d) = (%d,%d,%d,%v), want (%d,%d,%d,%v)",
				c.index, num, sz, prev, ok, c.wantNum, c.wantSz, c.wantPrev, c.wantOK)
		}
	}
}

func TestCoveringLandmarkOlderThanWindow(t *testing.T) {
	// index falls in the oldest *listed* landmark, whose predecessor's
	// tree size isn't published — can't bound it, so not ok.
	desc := []landmarkEntry{{5, 200}, {4, 150}, {3, 100}}
	// index 50 falls in landmark 3 (the oldest listed); its lower bound
	// is landmark 2's tree size, which isn't published.
	if _, _, _, ok := coveringLandmark(desc, 50); ok {
		t.Errorf("expected ok=false when covering landmark is the oldest listed")
	}
	// But an index inside landmark 4 (>=150 line known via landmark 3) works.
	if num, _, prev, ok := coveringLandmark(desc, 160); !ok || num != 5 || prev != 150 {
		t.Errorf("index 160 → (num=%d prev=%d ok=%v), want (5,150,true)", num, prev, ok)
	}
}
