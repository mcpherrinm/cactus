package storage

import (
	"bytes"
	"errors"
	"io/fs"
	"sync"
	"testing"
)

func TestPutGet(t *testing.T) {
	d, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Put("a/b/c", []byte("hello"), false); err != nil {
		t.Fatal(err)
	}
	got, err := d.Get("a/b/c")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Errorf("Get = %q, want hello", got)
	}
}

func TestGetMissing(t *testing.T) {
	d, _ := New(t.TempDir())
	_, err := d.Get("missing")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestPutExclusive(t *testing.T) {
	d, _ := New(t.TempDir())
	if err := d.Put("k", []byte("1"), true); err != nil {
		t.Fatal(err)
	}
	err := d.Put("k", []byte("2"), true)
	if !errors.Is(err, ErrExists) {
		t.Errorf("expected ErrExists, got %v", err)
	}
	got, _ := d.Get("k")
	if !bytes.Equal(got, []byte("1")) {
		t.Errorf("contents changed: %q", got)
	}
}

func TestPutOverwrites(t *testing.T) {
	d, _ := New(t.TempDir())
	if err := d.Put("k", []byte("v1"), false); err != nil {
		t.Fatal(err)
	}
	if err := d.Put("k", []byte("v2"), false); err != nil {
		t.Fatal(err)
	}
	got, _ := d.Get("k")
	if !bytes.Equal(got, []byte("v2")) {
		t.Errorf("Get after overwrite = %q", got)
	}
}

func TestPathEscape(t *testing.T) {
	d, _ := New(t.TempDir())
	cases := []string{"../escape", "a/../../escape", "/abs"}
	for _, p := range cases {
		// "/abs" gets cleaned to "abs" — that's *inside* root, which is
		// the intended behavior. Only ".." escapes should error.
		err := d.Put(p, []byte("x"), false)
		if p == "/abs" {
			if err != nil {
				t.Errorf("Put(%q) unexpected error: %v", p, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("Put(%q): expected escape error", p)
		}
	}
}

func TestExists(t *testing.T) {
	d, _ := New(t.TempDir())
	if ok, _ := d.Exists("nope"); ok {
		t.Error("Exists on missing returned true")
	}
	d.Put("yep", []byte("x"), false)
	if ok, _ := d.Exists("yep"); !ok {
		t.Error("Exists on present returned false")
	}
}

func TestMkdir(t *testing.T) {
	d, _ := New(t.TempDir())
	if err := d.Mkdir("a/b/c"); err != nil {
		t.Fatal(err)
	}
	// idempotent.
	if err := d.Mkdir("a/b/c"); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentPutReadVisibility(t *testing.T) {
	// Two goroutines: writer Puts a sequence of values, reader Gets and
	// checks no half-written content is observed (atomic-rename guarantee).
	d, _ := New(t.TempDir())
	d.Put("k", []byte("init"), false)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			payload := bytes.Repeat([]byte{byte('a' + (i % 26))}, 1024)
			if err := d.Put("k", payload, false); err != nil {
				t.Errorf("Put: %v", err)
				return
			}
		}
		close(stop)
	}()

	for {
		select {
		case <-stop:
			wg.Wait()
			return
		default:
		}
		got, err := d.Get("k")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 4 && len(got) != 1024 {
			t.Errorf("partial read: %d bytes", len(got))
			return
		}
		if len(got) == 1024 {
			first := got[0]
			for _, b := range got {
				if b != first {
					t.Errorf("torn read: bytes not uniform")
					return
				}
			}
		}
	}
}
