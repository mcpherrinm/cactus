package pollinate

import (
	"testing"
	"time"

	"github.com/letsencrypt/cactus/storage"
)

func TestHeadHistoryLagWindow(t *testing.T) {
	const delay = 10 * time.Minute
	t0 := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	ls := &LogState{}

	// No history: no lag verdicts possible.
	if _, ok := ls.headAt(t0); ok {
		t.Fatal("headAt on empty history reported ok")
	}

	ls.recordHead(t0, 100, delay)
	// Immediately after the first observation nothing is old enough:
	// this is the startup grace period.
	if _, ok := ls.headAt(t0.Add(-delay)); ok {
		t.Fatal("fresh observation counted as one delay old")
	}
	// Once the observation ages past the window it becomes the
	// threshold: a mirror below 100 has been behind for >= delay.
	if size, ok := ls.headAt(t0.Add(delay).Add(-delay)); !ok || size != 100 {
		t.Fatalf("headAt = %d, %v; want 100, true", size, ok)
	}

	// Growth is recorded; the threshold lags it by the window.
	ls.recordHead(t0.Add(5*time.Minute), 200, delay)
	ls.recordHead(t0.Add(12*time.Minute), 300, delay)
	now := t0.Add(14 * time.Minute)
	if size, ok := ls.headAt(now.Add(-delay)); !ok || size != 100 {
		t.Fatalf("threshold at t0+4m = %d, %v; want 100 (the 200 observation is only 9m old)", size, ok)
	}
	now = t0.Add(16 * time.Minute)
	if size, ok := ls.headAt(now.Add(-delay)); !ok || size != 200 {
		t.Fatalf("threshold at t0+6m = %d, %v; want 200", size, ok)
	}

	// Unchanged sizes add no observations.
	ls.recordHead(now, 300, delay)
	if len(ls.HeadHistory) > 3 {
		t.Fatalf("history has %d entries after flat observation", len(ls.HeadHistory))
	}

	// Pruning keeps the newest at-or-beyond-window observation so the
	// threshold stays defined, and drops everything older.
	far := t0.Add(2 * time.Hour)
	ls.recordHead(far, 400, delay)
	if size, ok := ls.headAt(far.Add(-delay)); !ok || size != 300 {
		t.Fatalf("threshold after prune = %d, %v; want 300", size, ok)
	}
	if len(ls.HeadHistory) != 2 {
		t.Fatalf("history has %d entries after prune, want 2", len(ls.HeadHistory))
	}
}

func TestStateRoundTrip(t *testing.T) {
	fsys, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := loadState(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Logs) != 0 {
		t.Fatal("fresh state is not empty")
	}

	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	ls := st.logState("oid/1.3.6.1.4.1.32473.1.0.1")
	ls.IssuerID = "32473.1"
	ls.URL = "https://ca.example/1"
	ls.recordHead(now, 55, time.Minute)
	ms := ls.mirrorState("32473.77")
	ms.Carries = CarryYes
	ms.Size = 40
	ms.LastSeen = now
	st.CosignersVersion = "2.0.2"

	if err := saveState(fsys, st); err != nil {
		t.Fatal(err)
	}
	got, err := loadState(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if got.CosignersVersion != "2.0.2" {
		t.Errorf("version = %q", got.CosignersVersion)
	}
	gls := got.Logs["oid/1.3.6.1.4.1.32473.1.0.1"]
	if gls == nil {
		t.Fatal("log missing after round trip")
	}
	if gls.IssuerID != "32473.1" || gls.URL != "https://ca.example/1" {
		t.Errorf("log state = %+v", gls)
	}
	if size, ok := gls.headAt(now); !ok || size != 55 {
		t.Errorf("head history did not survive: %d, %v", size, ok)
	}
	gms := gls.Mirrors["32473.77"]
	if gms == nil || gms.Carries != CarryYes || gms.Size != 40 || !gms.LastSeen.Equal(now) {
		t.Errorf("mirror state = %+v", gms)
	}
}
