package cert

import (
	"crypto/sha256"
	"hash"
)

// newSHA256 returns a fresh SHA-256 hash. Wrapped so cosigner_request.go
// doesn't need to import crypto/sha256 separately.
func newSHA256() hash.Hash { return sha256.New() }
