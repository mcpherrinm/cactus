// cactus-keygen writes a fresh 32-byte cosigner seed file. The seed is
// then used by the cactus server to derive its CA cosigner private key
// via HKDF (see signer/signer.go).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/letsencrypt/cactus/signer"
)

func main() {
	out := flag.String("o", "ca-cosigner.seed", "output seed file path")
	force := flag.Bool("f", false, "overwrite existing file")
	flag.Parse()

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

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cactus-keygen: "+format+"\n", args...)
	os.Exit(1)
}
