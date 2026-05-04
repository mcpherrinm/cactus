package acme

import "os"

// readDir is a small wrapper around os.ReadDir returning just file
// names, kept in its own file so we don't have to thread os through
// persist.go.
func readDir(p string) ([]string, error) {
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
