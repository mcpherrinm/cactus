// cactus-keygen writes a fresh 32-byte cosigner seed file, or (with
// -pub) prints the cosigner public key of an existing seed as a PEM
// block. The seed is used by the cactus server to derive its cosigner
// private key via HKDF (see signer/signer.go); the public key is what
// other components configure to verify that cosigner — a mirror's
// upstream.ca_cosigner_key_pem or a CA quorum mirror's public_key_pem.
// Those config fields take a PEM block whose body is the raw public key,
// which is exactly what -pub emits.
package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/letsencrypt/cactus/signer"
)

func main() {
	out := flag.String("o", "ca-cosigner.seed", "seed file path (written when generating, read when -pub)")
	force := flag.Bool("f", false, "overwrite an existing seed file when generating")
	pub := flag.Bool("pub", false, "print the PEM SubjectPublicKeyInfo for the seed at -o instead of generating one")
	alg := flag.String("alg", "mldsa-44", "cosigner algorithm (used with -pub)")
	flag.Parse()

	if *pub {
		if err := printPublicKey(*out, *alg); err != nil {
			die("%v", err)
		}
		return
	}

	dir := filepath.Dir(*out)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			die("mkdir %q: %v", dir, err)
		}
	}

	if *force {
		_ = os.Remove(*out)
	}
	if err := signer.WriteSeed(*out); err != nil {
		die("write seed: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", *out, signer.SeedSize)
}

// printPublicKey derives the cosigner key from the seed at seedPath and
// writes the raw public key as a PEM "PUBLIC KEY" block to stdout — the
// form the mirror/quorum config fields consume.
func printPublicKey(seedPath, algName string) error {
	alg, err := signer.ParseAlgorithm(algName)
	if err != nil {
		return err
	}
	seed, err := signer.LoadSeed(seedPath)
	if err != nil {
		return err
	}
	s, err := signer.FromSeed(alg, seed)
	if err != nil {
		return err
	}
	return pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: s.PublicKey()})
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cactus-keygen: "+format+"\n", args...)
	os.Exit(1)
}
