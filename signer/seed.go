package signer

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// LoadSeed reads a seed file and returns its contents, validating size.
func LoadSeed(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read seed %q: %w", path, err)
	}
	if len(data) != SeedSize {
		return nil, fmt.Errorf("seed %q must be %d bytes, got %d", path, SeedSize, len(data))
	}
	return data, nil
}

// WriteSeed creates a fresh random seed at path with 0600 perms. Refuses
// to overwrite an existing file.
func WriteSeed(path string) error {
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return fmt.Errorf("read random: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create seed %q: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(seed[:]); err != nil {
		return fmt.Errorf("write seed: %w", err)
	}
	return nil
}
