// Package storage provides the on-disk key/value abstraction the log,
// account, and order subsystems share. Cactus is a single-writer test
// server, so the implementation is just rooted-path file IO with
// atomic-rename writes.
//
// Paths are slash-separated relative paths (e.g. "log/checkpoint") and
// are validated against escape via "..".
package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// FS is the interface higher-level packages depend on. The disk-backed
// implementation is returned by New; tests can substitute their own.
type FS interface {
	// Get returns the file contents at name. Returns ErrNotExist if absent.
	Get(name string) ([]byte, error)

	// Put writes data at name atomically (temp-file + rename). Creates
	// missing parents. If exclusive is true, fails if name already
	// exists.
	Put(name string, data []byte, exclusive bool) error

	// Exists reports whether name resolves to a regular file.
	Exists(name string) (bool, error)

	// Mkdir ensures the directory at name exists.
	Mkdir(name string) error
}

// ErrNotExist is returned by Get for missing paths. fs.ErrNotExist is
// re-exported as the canonical sentinel — callers can use errors.Is.
var ErrNotExist = fs.ErrNotExist

// ErrExists is returned by Put when called with exclusive=true and the
// target already exists.
var ErrExists = errors.New("storage: file already exists")

// Disk is a filesystem-rooted FS implementation.
type Disk struct {
	root string
}

// New returns a Disk rooted at root. The directory is created if
// missing.
func New(root string) (*Disk, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("abs %q: %w", root, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %q: %w", abs, err)
	}
	return &Disk{root: abs}, nil
}

// Root returns the absolute root path.
func (d *Disk) Root() string { return d.root }

// resolve maps a slash-separated relative name to an absolute filesystem
// path within the root. Rejects paths that contain any ".." segment, to
// keep "what's allowed" trivially auditable.
func (d *Disk) resolve(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("storage: empty name")
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", fmt.Errorf("storage: escaping path %q", name)
		}
	}
	cleaned := path.Clean("/" + name)
	rel := filepath.FromSlash(strings.TrimPrefix(cleaned, "/"))
	full := filepath.Join(d.root, rel)
	if full != d.root && !strings.HasPrefix(full, d.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("storage: escaping path %q", name)
	}
	return full, nil
}

func (d *Disk) Get(name string) ([]byte, error) {
	full, err := d.resolve(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (d *Disk) Exists(name string) (bool, error) {
	full, err := d.resolve(name)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(full)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.Mode().IsRegular(), nil
}

func (d *Disk) Mkdir(name string) error {
	full, err := d.resolve(name)
	if err != nil {
		return err
	}
	return os.MkdirAll(full, 0o755)
}

func (d *Disk) Put(name string, data []byte, exclusive bool) error {
	full, err := d.resolve(name)
	if err != nil {
		return err
	}
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %q: %w", dir, err)
	}

	if exclusive {
		// Open with O_EXCL on the final path is the only race-free check.
		// We can't combine O_EXCL with rename, so we use O_EXCL on the
		// final destination. Since cactus is single-writer (per
		// PROJECT_PLAN §2 — operator must not run two instances),
		// exclusive Put does not need to be atomic w.r.t. concurrent
		// writers; we just want "fail if already there".
		f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				return ErrExists
			}
			return fmt.Errorf("open %q exclusive: %w", full, err)
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			_ = os.Remove(full)
			return fmt.Errorf("write %q: %w", full, err)
		}
		return f.Close()
	}

	// Non-exclusive: temp file + rename for atomicity vs readers.
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("tempfile in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write tmp %q: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close tmp %q: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, full); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename %q -> %q: %w", tmpName, full, err)
	}
	return nil
}
