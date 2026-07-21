package mirrorpush

import (
	"bytes"
	"testing"
)

func TestParseMirrorInfo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantSize   uint64
		wantNext   uint64
		wantTicket []byte
	}{
		{
			name:     "empty ticket line",
			body:     "1024\n768\n\n",
			wantSize: 1024, wantNext: 768, wantTicket: nil,
		},
		{
			name:     "with ticket",
			body:     "1024\n768\nAAECAw==\n",
			wantSize: 1024, wantNext: 768, wantTicket: []byte{0, 1, 2, 3},
		},
		{
			name:     "zeroes",
			body:     "0\n0\n\n",
			wantSize: 0, wantNext: 0, wantTicket: nil,
		},
		{
			// A mirror ahead of us: next entry past the pending size is
			// unusual but well-formed, and the parser's job is not to
			// second-guess it.
			name:     "next entry past pending size",
			body:     "10\n99\n\n",
			wantSize: 10, wantNext: 99,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mi, err := ParseMirrorInfo([]byte(tc.body))
			if err != nil {
				t.Fatalf("ParseMirrorInfo(%q): %v", tc.body, err)
			}
			if mi.PendingSize != tc.wantSize {
				t.Errorf("PendingSize = %d, want %d", mi.PendingSize, tc.wantSize)
			}
			if mi.NextEntry != tc.wantNext {
				t.Errorf("NextEntry = %d, want %d", mi.NextEntry, tc.wantNext)
			}
			if !bytes.Equal(mi.Ticket, tc.wantTicket) {
				t.Errorf("Ticket = %x, want %x", mi.Ticket, tc.wantTicket)
			}
		})
	}
}

func TestParseMirrorInfoRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"no trailing newline", "1024\n768\n"},
		{"two lines", "1024\n768\n\n\n"},
		{"four lines", "1024\n768\n\nextra\n"},
		{"non-numeric size", "abc\n768\n\n"},
		{"non-numeric next entry", "1024\nxyz\n\n"},
		{"empty size line", "\n768\n\n"},
		{"empty next entry line", "1024\n\n\n"},
		{"negative size", "-1\n768\n\n"},
		{"size overflows uint64", "18446744073709551616\n768\n\n"},
		{"bad base64 ticket", "1024\n768\n!!!!\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if mi, err := ParseMirrorInfo([]byte(tc.body)); err == nil {
				t.Errorf("ParseMirrorInfo(%q) = %+v, want error", tc.body, mi)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	got, err := ParseSize([]byte("20852014\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != 20852014 {
		t.Errorf("ParseSize = %d, want 20852014", got)
	}
	for _, bad := range []string{"", "\n", "abc\n", "1\n2\n"} {
		if _, err := ParseSize([]byte(bad)); err == nil {
			t.Errorf("ParseSize(%q) succeeded, want error", bad)
		}
	}
}
