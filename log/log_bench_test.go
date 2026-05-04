package log

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
)

// BenchmarkAppendWait measures the end-to-end latency of submitting an
// entry and waiting for it to appear in a signed checkpoint.
//
// The flush period dominates this benchmark: with FlushPeriod=10ms the
// observed per-op latency floors near 10ms because every Wait blocks
// until the next periodic flush completes.
//
//	go test -bench=BenchmarkAppendWait -benchtime=1s ./log/...
func BenchmarkAppendWait(b *testing.B) {
	fs, err := storage.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x88}, signer.SeedSize)
	s, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	l, err := New(context.Background(), Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1.ca"),
		Signer:      s,
		FS:          fs,
		FlushPeriod: 10 * time.Millisecond,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(l.Stop)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry := cert.EncodeTBSCertEntry([]byte(fmt.Sprintf("entry-%d", i)))
		idem := sha256.Sum256(entry)
		idx, err := l.Append(context.Background(), entry, idem)
		if err != nil {
			b.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = l.Wait(ctx, idx)
		cancel()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAppendBatch measures the throughput of appending entries
// without waiting for individual checkpoints — the realistic
// per-issuance cost amortised across a flush.
//
//	go test -bench=BenchmarkAppendBatch -benchtime=1s ./log/...
func BenchmarkAppendBatch(b *testing.B) {
	fs, err := storage.New(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x88}, signer.SeedSize)
	s, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	l, err := New(context.Background(), Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1.ca"),
		Signer:      s,
		FS:          fs,
		FlushPeriod: 10 * time.Millisecond,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(l.Stop)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry := cert.EncodeTBSCertEntry([]byte(fmt.Sprintf("entry-%d", i)))
		idem := sha256.Sum256(entry)
		_, err := l.Append(context.Background(), entry, idem)
		if err != nil {
			b.Fatal(err)
		}
	}
}
