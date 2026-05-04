//go:build mldsa

package integration

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/acme"
	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
)

// TestMLDSAIssuance runs the full ACME issuance flow using an ML-DSA-44
// CA cosigner. We don't re-verify the cosignature here (that requires
// an ML-DSA verifier outside the test), but exercising the code paths
// confirms the signer abstraction is plumbed correctly through the
// log + cert + cosigner stack.
func TestMLDSAIssuance(t *testing.T) {
	for _, alg := range []signer.Algorithm{signer.AlgMLDSA44, signer.AlgMLDSA65} {
		t.Run(alg.String(), func(t *testing.T) {
			dir := t.TempDir()
			fs, _ := storage.New(dir)
			seed := make([]byte, signer.SeedSize)
			for i := range seed {
				seed[i] = 0xCC
			}
			s, err := signer.FromSeed(alg, seed)
			if err != nil {
				t.Fatal(err)
			}
			l, err := cactuslog.New(context.Background(), cactuslog.Config{
				LogID:       cert.TrustAnchorID("32473.1"),
				CosignerID:  cert.TrustAnchorID("32473.1.ca"),
				Signer:      s,
				FS:          fs,
				FlushPeriod: 25 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer l.Stop()
			issuer, _ := ca.New(l, "32473.1")
			srv, _ := acme.New(acme.Config{
				Issuer:        issuer,
				ChallengeMode: acme.ChallengeAutoPass,
			})
			h := httptest.NewServer(srv.Handler())
			defer h.Close()
			srv.SetExternalURL(h.URL)
			if _, err := acmeIssueOne(h.URL, "x.test"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
