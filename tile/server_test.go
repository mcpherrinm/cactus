package tile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
)

func newTestServer(t *testing.T) (*httptest.Server, *log.Log) {
	t.Helper()
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x33}, signer.SeedSize)
	s, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	l, err := log.New(context.Background(), log.Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1.ca"),
		Signer:      s,
		FS:          fs,
		FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)

	srv := httptest.NewServer(New(l, fs).Handler())
	t.Cleanup(srv.Close)
	return srv, l
}

func TestCheckpointEndpoint(t *testing.T) {
	srv, l := newTestServer(t)
	resp, err := http.Get(srv.URL + "/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, l.CurrentCheckpoint().SignedNote) {
		t.Errorf("body != current SignedNote")
	}
}

func TestEntryEndpoint(t *testing.T) {
	srv, l := newTestServer(t)
	entry := cert.EncodeTBSCertEntry([]byte("payload-1"))
	idem := sha256.Sum256(entry)
	idx, err := l.Append(context.Background(), entry, idem)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := l.Wait(ctx, idx); err != nil {
		t.Fatal(err)
	}
	url := srv.URL + "/log/v1/entry/" + uint64s(idx)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, entry) {
		t.Errorf("body mismatch")
	}
}

func TestSubtreeEndpoint(t *testing.T) {
	srv, l := newTestServer(t)
	// Append one entry so a covering subtree gets signed.
	entry := cert.EncodeTBSCertEntry([]byte("x"))
	idem := sha256.Sum256(entry)
	idx, _ := l.Append(context.Background(), entry, idem)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	iss, err := l.Wait(ctx, idx)
	if err != nil {
		t.Fatal(err)
	}
	name := uint64s(iss.Subtree.Start) + "-" + uint64s(iss.Subtree.End)
	resp, err := http.Get(srv.URL + "/subtree/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestNNNPath(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "000"},
		{42, "042"},
		{1000, "x001/000"},
		{1234067, "x001/x234/067"},
	}
	for _, tc := range cases {
		if got := nnnPath(tc.n, false); got != tc.want {
			t.Errorf("nnnPath(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func uint64s(n uint64) string {
	if n == 0 {
		return "0"
	}
	var s string
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
