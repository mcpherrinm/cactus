package landmark

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/storage"
)

func newTestSeq(t *testing.T) (*Sequence, storage.FS, time.Time) {
	t.Helper()
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	cfg := Config{
		CAID:                 cert.TrustAnchorID("32473.1"),
		LogNumber:            1,
		TimeBetweenLandmarks: time.Hour,
		MaxCertLifetime:      7 * 24 * time.Hour,
	}
	s, err := New(cfg, fs, t0)
	if err != nil {
		t.Fatal(err)
	}
	return s, fs, t0
}

// TestTimeUntilNextLandmark checks the Retry-After source: the remainder
// of the §6.4.2 interval since the most recent landmark, floored at zero,
// and reset when a new landmark is allocated.
func TestTimeUntilNextLandmark(t *testing.T) {
	s, _, t0 := newTestSeq(t) // 1h interval, seed landmark 0 at t0

	if got := s.TimeUntilNextLandmark(t0); got != time.Hour {
		t.Errorf("at t0: %v, want 1h", got)
	}
	if got := s.TimeUntilNextLandmark(t0.Add(20 * time.Minute)); got != 40*time.Minute {
		t.Errorf("at t0+20m: %v, want 40m", got)
	}
	// Overdue: the next landmark should already have been allocated.
	if got := s.TimeUntilNextLandmark(t0.Add(2 * time.Hour)); got != 0 {
		t.Errorf("at t0+2h: %v, want 0", got)
	}

	// Allocating a landmark resets the countdown to its allocation time.
	if _, ok, err := s.Append(context.Background(), 5, t0.Add(90*time.Minute)); err != nil || !ok {
		t.Fatalf("Append: ok=%v err=%v", ok, err)
	}
	if got := s.TimeUntilNextLandmark(t0.Add(2 * time.Hour)); got != 30*time.Minute {
		t.Errorf("after allocation, at t0+2h: %v, want 30m", got)
	}
}

// TestAppendSetsExpiry pins §6.4.2: a landmark allocated at t expires at
// t + max_cert_lifetime, rounded up to a whole second, and never before
// the previous landmark.
func TestAppendSetsExpiry(t *testing.T) {
	s, _, t0 := newTestSeq(t) // 7d max lifetime
	at := t0.Add(time.Hour + 300*time.Millisecond)
	l, ok, err := s.Append(context.Background(), 10, at)
	if err != nil || !ok {
		t.Fatalf("Append: ok=%v err=%v", ok, err)
	}
	if want := t0.Add(time.Hour + 7*24*time.Hour + time.Second); !l.Expiry.Equal(want) {
		t.Errorf("expiry = %v, want %v", l.Expiry, want)
	}

	// Lowering max_cert_lifetime must not make expiries decrease.
	s.cfg.MaxCertLifetime = time.Hour
	l2, ok, err := s.Append(context.Background(), 20, at.Add(time.Hour))
	if err != nil || !ok {
		t.Fatalf("Append: ok=%v err=%v", ok, err)
	}
	if !l2.Expiry.Equal(l.Expiry) {
		t.Errorf("expiry after lowering lifetime = %v, want previous %v", l2.Expiry, l.Expiry)
	}
}

// TestReplayMigratesMissingExpiry covers sequence files written before
// draft-07 support: landmarks without an expiry get allocated_at +
// max_cert_lifetime (landmark 0: the Epoch), and the file is rewritten.
func TestReplayMigratesMissingExpiry(t *testing.T) {
	fs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := `{"number":0,"tree_size":0,"allocated_at":"2026-05-01T00:00:00Z"}
{"number":1,"tree_size":10,"allocated_at":"2026-05-01T01:00:00Z"}
`
	if err := fs.Put(SequenceFile, []byte(old), false); err != nil {
		t.Fatal(err)
	}
	cfg := Config{CAID: cert.TrustAnchorID("32473.1"), LogNumber: 1, TimeBetweenLandmarks: time.Hour, MaxCertLifetime: 24 * time.Hour}
	s, err := New(cfg, fs, time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	all := s.All()
	if !all[0].Expiry.Equal(time.Unix(0, 0)) {
		t.Errorf("landmark 0 expiry = %v, want the Epoch", all[0].Expiry)
	}
	if want := time.Date(2026, 5, 2, 1, 0, 0, 0, time.UTC); !all[1].Expiry.Equal(want) {
		t.Errorf("landmark 1 expiry = %v, want %v", all[1].Expiry, want)
	}
	data, err := fs.Get(SequenceFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"expiry":"2026-05-02T01:00:00Z"`) {
		t.Errorf("migrated file not rewritten with expiries:\n%s", data)
	}
}

// TestNewSeedsLandmarkZero confirms a fresh sequence starts with one
// landmark at (number=0, treeSize=0, expiry=0), per §6.4.1.
func TestNewSeedsLandmarkZero(t *testing.T) {
	s, _, _ := newTestSeq(t)
	all := s.All()
	if len(all) != 1 {
		t.Fatalf("got %d landmarks, want 1", len(all))
	}
	if all[0].Number != 0 || all[0].TreeSize != 0 || all[0].Expiry.Unix() != 0 {
		t.Errorf("seed = %+v, want (0,0,0)", all[0])
	}
}

// TestAppendRespectsTimeBetween confirms the §6.4.2 step-2 condition:
// at most once per TimeBetweenLandmarks.
func TestAppendRespectsTimeBetween(t *testing.T) {
	s, _, t0 := newTestSeq(t)

	// 30 minutes after t0 — too early; nothing happens.
	_, ok, err := s.Append(context.Background(), 100, t0.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("Append at t+30m should be rejected")
	}

	// Exactly 1 hour after t0 — boundary, should succeed.
	got, ok, err := s.Append(context.Background(), 100, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("Append at t+1h should succeed")
	}
	if got.Number != 1 || got.TreeSize != 100 {
		t.Errorf("got %+v, want (1,100)", got)
	}

	// 1 hour and 30 min — too soon since the previous landmark.
	_, ok, _ = s.Append(context.Background(), 200, t0.Add(90*time.Minute))
	if ok {
		t.Errorf("Append 30 min after previous should be rejected")
	}
}

// TestAppendRequiresGrowth confirms the §6.4.1 monotonic-growth rule:
// new landmark MUST have strictly greater tree size.
func TestAppendRequiresGrowth(t *testing.T) {
	s, _, t0 := newTestSeq(t)
	_, ok, _ := s.Append(context.Background(), 0, t0.Add(time.Hour))
	if ok {
		t.Errorf("Append with treeSize=0 should be rejected (== last)")
	}
	_, ok, _ = s.Append(context.Background(), 50, t0.Add(time.Hour))
	if !ok {
		t.Errorf("Append with treeSize=50 should succeed")
	}
	_, ok, _ = s.Append(context.Background(), 50, t0.Add(2*time.Hour))
	if ok {
		t.Errorf("Append with treeSize=50 (==last) should be rejected")
	}
	_, ok, _ = s.Append(context.Background(), 49, t0.Add(2*time.Hour))
	if ok {
		t.Errorf("Append with treeSize=49 (<last) should be rejected")
	}
}

// TestRestartResume confirms the on-disk JSONL is read on New and the
// sequence resumes without duplicates or skipped numbers.
func TestRestartResume(t *testing.T) {
	dir := t.TempDir()
	fs, _ := storage.New(dir)
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	cfg := Config{
		CAID:                 cert.TrustAnchorID("32473.1"),
		LogNumber:            1,
		TimeBetweenLandmarks: time.Hour,
		MaxCertLifetime:      7 * 24 * time.Hour,
	}
	s1, err := New(cfg, fs, t0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		_, ok, err := s1.Append(context.Background(), uint64(i*100),
			t0.Add(time.Duration(i)*time.Hour))
		if err != nil || !ok {
			t.Fatalf("append %d: ok=%v err=%v", i, ok, err)
		}
	}

	// Reopen.
	fs2, _ := storage.New(dir)
	s2, err := New(cfg, fs2, t0.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	all := s2.All()
	if len(all) != 4 {
		t.Fatalf("after reload: %d landmarks, want 4 (incl. seed)", len(all))
	}
	if all[3].Number != 3 || all[3].TreeSize != 300 {
		t.Errorf("last landmark = %+v, want (3,300)", all[3])
	}

	// Next allocation should pick up at number 4 with no double-count
	// even if "now" is far in the future.
	got, ok, _ := s2.Append(context.Background(), 400, t0.Add(5*time.Hour))
	if !ok {
		t.Fatal("post-restart append rejected")
	}
	if got.Number != 4 || got.TreeSize != 400 {
		t.Errorf("post-restart got %+v, want (4,400)", got)
	}
}

// TestActiveDescending pins §6.4.1: the active landmarks are the
// unexpired ones, most recent first, and landmark 0 never is.
func TestActiveDescending(t *testing.T) {
	cfg := Config{
		CAID:                 cert.TrustAnchorID("32473.1"),
		LogNumber:            1,
		TimeBetweenLandmarks: time.Hour,
		MaxCertLifetime:      3 * time.Hour,
	}
	dir := t.TempDir()
	fs, _ := storage.New(dir)
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	s, err := New(cfg, fs, t0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 6; i++ {
		_, ok, err := s.Append(context.Background(), uint64(i*10),
			t0.Add(time.Duration(i)*time.Hour))
		if err != nil || !ok {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// Landmark i expires at t0 + (i+3)h, so at t0+6h landmarks 3..6 are
	// active (expiry is inclusive).
	active := s.Active(t0.Add(6 * time.Hour))
	if len(active) != 4 {
		t.Fatalf("Active len = %d, want 4", len(active))
	}
	for i, l := range active {
		if want := uint64(6 - i); l.Number != want {
			t.Errorf("Active[%d].Number = %d, want %d", i, l.Number, want)
		}
	}
	if got := s.Active(t0); len(got) != 6 {
		t.Errorf("Active(t0) len = %d, want 6 (landmark 0 excluded)", len(got))
	}
	if got := s.Active(t0.Add(10 * time.Hour)); len(got) != 0 {
		t.Errorf("Active after all expire = %+v, want none", got)
	}
}

// TestContainingIndex covers the helper used by the cert assembler:
// "find the smallest landmark whose subtree contains entry index".
func TestContainingIndex(t *testing.T) {
	s, _, t0 := newTestSeq(t)
	for i := 1; i <= 3; i++ {
		_, ok, err := s.Append(context.Background(), uint64(i*100),
			t0.Add(time.Duration(i)*time.Hour))
		if !ok || err != nil {
			t.Fatal(err)
		}
	}
	// Sequence is now: (0,0), (1,100), (2,200), (3,300).

	cases := []struct {
		index    uint64
		want     uint64 // Landmark.Number; or math.MaxUint64 for "not found"
		notFound bool
	}{
		{0, 1, false},
		{50, 1, false},
		{99, 1, false},
		{100, 2, false}, // landmark 1 covers [0, 100), so index 100 needs landmark 2.
		{199, 2, false},
		{200, 3, false},
		{299, 3, false},
		{300, 0, true}, // beyond the latest landmark
		{400, 0, true},
	}
	for _, tc := range cases {
		got, ok := s.ContainingIndex(tc.index)
		if tc.notFound {
			if ok {
				t.Errorf("ContainingIndex(%d) = %+v, want not-found", tc.index, got)
			}
			continue
		}
		if !ok {
			t.Errorf("ContainingIndex(%d) = not-found, want %d", tc.index, tc.want)
			continue
		}
		if got.Number != tc.want {
			t.Errorf("ContainingIndex(%d) = %d, want %d", tc.index, got.Number, tc.want)
		}
	}
}

// TestLandmarkSubtrees pins §6.4.1's covering-subtree definition: for a
// landmark l, returns the §4.5 covering subtrees of [prev.TreeSize, l.TreeSize).
func TestLandmarkSubtrees(t *testing.T) {
	s, _, t0 := newTestSeq(t)
	// Append landmark 1 at tree size 13, so covers [0, 13).
	_, ok, err := s.Append(context.Background(), 13, t0.Add(time.Hour))
	if !ok || err != nil {
		t.Fatal(err)
	}
	subs := s.LandmarkSubtrees(s.All()[1])
	// FindSubtrees(0, 13) per §4.5 example = [(0, 8), (8, 13)].
	if len(subs) != 2 {
		t.Fatalf("got %d subtrees, want 2", len(subs))
	}
	if subs[0].Start != 0 || subs[0].End != 8 {
		t.Errorf("subs[0] = [%d,%d), want [0,8)", subs[0].Start, subs[0].End)
	}
	if subs[1].Start != 8 || subs[1].End != 13 {
		t.Errorf("subs[1] = [%d,%d), want [8,13)", subs[1].Start, subs[1].End)
	}

	// Landmark 0's subtrees are both the empty [0, 0).
	if subs0 := s.LandmarkSubtrees(s.All()[0]); len(subs0) != 2 || !subs0[0].Empty() || !subs0[1].Empty() || subs0[0].Start != 0 || subs0[1].Start != 0 {
		t.Errorf("landmark 0 subtrees = %+v, want [0,0) [0,0)", subs0)
	}

	// A one-entry landmark has the entry's subtree plus an empty one.
	if _, ok, err := s.Append(context.Background(), 14, t0.Add(2*time.Hour)); !ok || err != nil {
		t.Fatal(err)
	}
	subs2 := s.LandmarkSubtrees(s.All()[2])
	if len(subs2) != 2 || subs2[0].Start != 13 || subs2[0].End != 14 || subs2[1].Start != 14 || subs2[1].End != 14 {
		t.Errorf("landmark 2 subtrees = %+v, want [13,14) [14,14)", subs2)
	}
}

// TestTrustAnchorID confirms §6.4.1/§8.2 naming:
// CA-ID ‖ 1 ‖ logNumber ‖ landmarkNumber.
func TestTrustAnchorID(t *testing.T) {
	l := Landmark{Number: 42}
	got := l.TrustAnchorID(cert.TrustAnchorID("32473.1"), 8)
	if string(got) != "32473.1.1.8.42" {
		t.Errorf("got %q, want %q", got, "32473.1.1.8.42")
	}
	group := l.GroupID(cert.TrustAnchorID("32473.1"), 8)
	if string(group) != "32473.1.2.8.42" {
		t.Errorf("group got %q, want %q", group, "32473.1.2.8.42")
	}
}

// TestSimulatedYear runs a fake-clock month of issuance and confirms
// landmarks accumulate at the right cadence and ordering invariants.
func TestSimulatedMonth(t *testing.T) {
	s, _, t0 := newTestSeq(t)
	const totalHours = 24 * 30
	now := t0
	treeSize := uint64(0)
	allocated := 0
	for h := 1; h <= totalHours; h++ {
		now = now.Add(time.Hour)
		treeSize += 5
		_, ok, err := s.Append(context.Background(), treeSize, now)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			allocated++
		}
	}
	// We added one landmark at t+1h, t+2h, … so should get totalHours of them.
	if allocated != totalHours {
		t.Errorf("allocated = %d, want %d (one per hour)", allocated, totalHours)
	}
	all := s.All()
	for i := 1; i < len(all); i++ {
		if all[i].Number != all[i-1].Number+1 {
			t.Errorf("number gap at %d: %d -> %d", i, all[i-1].Number, all[i].Number)
		}
		if all[i].TreeSize <= all[i-1].TreeSize {
			t.Errorf("tree size not strictly growing at %d", i)
		}
		if !all[i].AllocatedAt.After(all[i-1].AllocatedAt) {
			t.Errorf("time not strictly growing at %d", i)
		}
	}
}
