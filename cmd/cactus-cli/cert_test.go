package main

import (
	"testing"

	"github.com/letsencrypt/cactus/landmark"
)

func lm(number, treeSize uint64) landmark.Landmark {
	return landmark.Landmark{Number: number, TreeSize: treeSize}
}

func TestCoveringLandmark(t *testing.T) {
	// Landmarks (descending): 3→[80,120), 2→[40,80), 1→[0,40), plus the
	// extra older line 0→0 so landmark 1's lower bound is known.
	desc := []landmark.Landmark{lm(3, 120), lm(2, 80), lm(1, 40), lm(0, 0)}
	cases := []struct {
		index                     uint64
		wantNum, wantSz, wantPrev uint64
		wantOK                    bool
	}{
		{0, 1, 40, 0, true},     // first entry of landmark 1
		{39, 1, 40, 0, true},    // last entry of landmark 1
		{40, 2, 80, 40, true},   // first entry of landmark 2
		{119, 3, 120, 80, true}, // last entry of landmark 3
		{120, 0, 0, 0, false},   // past the newest landmark
		{500, 0, 0, 0, false},   // well past
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
	desc := []landmark.Landmark{lm(5, 200), lm(4, 150), lm(3, 100)}
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
