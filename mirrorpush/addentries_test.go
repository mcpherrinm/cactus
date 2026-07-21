package mirrorpush

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/letsencrypt/cactus/tlogx"
)

// TestCanonicalSequence pins the arithmetic every add-entries request
// depends on. Nothing about package boundaries is transmitted, so a
// sender and a mirror that disagree here disagree silently until a
// proof fails.
func TestCanonicalSequence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		start, end  uint64
		want        []Package
		wantNumPkgs int
	}{
		{
			name:  "empty interval",
			start: 500, end: 500,
			want: nil,
		},
		{
			name:  "aligned single full package",
			start: 0, end: 256,
			want: []Package{{Start: 0, End: 256, ProofStart: 0}},
		},
		{
			name:  "aligned start, short tail",
			start: 256, end: 300,
			want: []Package{{Start: 256, End: 300, ProofStart: 256}},
		},
		{
			// The interesting case: upload_start is inside a bundle, so
			// package 0 transmits only [100,256) but proves
			// [0,256) — the aligned bundle the mirror will commit.
			name:  "unaligned start proves from the aligned boundary",
			start: 100, end: 256,
			want: []Package{{Start: 100, End: 256, ProofStart: 0}},
		},
		{
			name:  "unaligned at both ends, three packages",
			start: 100, end: 600,
			want: []Package{
				{Start: 100, End: 256, ProofStart: 0},
				{Start: 256, End: 512, ProofStart: 256},
				{Start: 512, End: 600, ProofStart: 512},
			},
		},
		{
			name:  "single entry mid-bundle",
			start: 1000, end: 1001,
			want: []Package{{Start: 1000, End: 1001, ProofStart: 768}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalSequence(tc.start, tc.end)
			if err != nil {
				t.Fatalf("CanonicalSequence(%d,%d): %v", tc.start, tc.end, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("CanonicalSequence(%d,%d) =\n %+v\nwant\n %+v", tc.start, tc.end, got, tc.want)
			}
		})
	}

	if _, err := CanonicalSequence(10, 5); err == nil {
		t.Error("CanonicalSequence(10,5) succeeded, want error for start > end")
	}
}

// TestCanonicalSequenceProofSubtreesAreValid checks the property that
// makes the aligned proof range work at all: [ProofStart, End) is always
// a valid MTC §4.1 subtree, so a subtree consistency proof exists for
// it. If ProofStart were Start instead, this would fail for every
// unaligned upload.
func TestCanonicalSequenceProofSubtreesAreValid(t *testing.T) {
	for start := uint64(0); start < 600; start += 37 {
		for end := start + 1; end < start+700; end += 53 {
			seq, err := CanonicalSequence(start, end)
			if err != nil {
				t.Fatal(err)
			}
			for i, p := range seq {
				if !tlogx.IsValid(p.ProofStart, p.End) {
					t.Fatalf("[%d,%d) package %d: proof subtree [%d,%d) is not a valid subtree",
						start, end, i, p.ProofStart, p.End)
				}
				if p.ProofStart > p.Start {
					t.Fatalf("[%d,%d) package %d: ProofStart %d is past Start %d",
						start, end, i, p.ProofStart, p.Start)
				}
				if p.ProofStart%EntriesPerPackage != 0 {
					t.Fatalf("[%d,%d) package %d: ProofStart %d is not 256-aligned",
						start, end, i, p.ProofStart)
				}
			}
		}
	}
}

// makePackages produces plausible package data for the given sequence:
// distinguishable entries and a proof whose length varies per package,
// so a framing bug that mixes packages up is visible.
func makePackages(seq []Package) []PackageData {
	out := make([]PackageData, 0, len(seq))
	for i, p := range seq {
		var pd PackageData
		for j := p.Start; j < p.End; j++ {
			pd.Entries = append(pd.Entries, []byte(fmt.Sprintf("entry-%d", j)))
		}
		for k := 0; k <= i; k++ {
			var h tlogx.Hash
			h[0] = byte(i)
			h[1] = byte(k)
			pd.Proof = append(pd.Proof, h)
		}
		out = append(out, pd)
	}
	return out
}

// TestAddEntriesRoundTrip is the framing contract: a receiver that has
// only the header must be able to segment the body exactly as the
// sender did, because neither a package count nor per-package lengths
// are on the wire.
func TestAddEntriesRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name       string
		start, end uint64
		ticket     []byte
		prefixOnly int // if > 0, send only this many packages
	}{
		{name: "aligned", start: 0, end: 512},
		{name: "unaligned start", start: 100, end: 600},
		{name: "unaligned both ends", start: 300, end: 901, ticket: []byte{0x00, 0xff, 0x10}},
		{name: "empty interval", start: 512, end: 512},
		{name: "strict prefix of the sequence", start: 0, end: 1024, prefixOnly: 2},
		{name: "zero length entries", start: 0, end: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seq, err := CanonicalSequence(tc.start, tc.end)
			if err != nil {
				t.Fatal(err)
			}
			data := makePackages(seq)
			if tc.prefixOnly > 0 {
				data = data[:tc.prefixOnly]
			}
			h := Header{
				Origin:      "oid/1.3.6.1.4.1.32473.1.0.1",
				UploadStart: tc.start,
				UploadEnd:   tc.end,
				Ticket:      tc.ticket,
			}
			body, err := BuildAddEntries(h, data)
			if err != nil {
				t.Fatalf("BuildAddEntries: %v", err)
			}

			gotH, gotPkgs, gotData, err := ParseAddEntries(body)
			if err != nil {
				t.Fatalf("ParseAddEntries: %v", err)
			}
			if gotH.Origin != h.Origin || gotH.UploadStart != h.UploadStart || gotH.UploadEnd != h.UploadEnd {
				t.Errorf("header = %+v, want %+v", gotH, h)
			}
			if !bytes.Equal(gotH.Ticket, h.Ticket) {
				t.Errorf("ticket = %x, want %x", gotH.Ticket, h.Ticket)
			}
			if len(gotPkgs) != len(data) {
				t.Fatalf("parsed %d packages, sent %d", len(gotPkgs), len(data))
			}
			// The parsed package descriptors must be the prefix of the
			// sequence derived from the header alone.
			// (An empty sequence round trips to a nil slice rather than
			// an empty one; only the contents are meaningful.)
			if len(data) > 0 {
				if !reflect.DeepEqual(gotPkgs, seq[:len(data)]) {
					t.Errorf("packages =\n %+v\nwant\n %+v", gotPkgs, seq[:len(data)])
				}
				if !reflect.DeepEqual(gotData, data) {
					t.Errorf("package data round trip mismatch")
				}
			}

			// Re-encoding what we parsed must be byte-identical.
			again, err := BuildAddEntries(gotH, gotData)
			if err != nil {
				t.Fatalf("re-BuildAddEntries: %v", err)
			}
			if !bytes.Equal(again, body) {
				t.Error("re-encoded body differs from the original")
			}
		})
	}
}

// TestBuildAddEntriesRejectsBadInput covers the caller-error paths.
func TestBuildAddEntriesRejectsBadInput(t *testing.T) {
	h := Header{Origin: "oid/x", UploadStart: 0, UploadEnd: 256}
	seq, err := CanonicalSequence(h.UploadStart, h.UploadEnd)
	if err != nil {
		t.Fatal(err)
	}
	good := makePackages(seq)

	t.Run("wrong entry count", func(t *testing.T) {
		bad := []PackageData{{Entries: good[0].Entries[:10]}}
		if _, err := BuildAddEntries(h, bad); err == nil {
			t.Error("accepted a package with the wrong number of entries")
		}
	})
	t.Run("too many packages", func(t *testing.T) {
		if _, err := BuildAddEntries(h, append(good, good[0])); err == nil {
			t.Error("accepted more packages than the canonical sequence has")
		}
	})
	t.Run("empty origin", func(t *testing.T) {
		if _, err := BuildAddEntries(Header{UploadEnd: 0}, nil); err == nil {
			t.Error("accepted an empty origin")
		}
	})
	t.Run("oversized proof", func(t *testing.T) {
		bad := []PackageData{{Entries: good[0].Entries, Proof: make([]tlogx.Hash, MaxProofHashes+1)}}
		if _, err := BuildAddEntries(h, bad); err == nil {
			t.Errorf("accepted a proof with more than %d hashes", MaxProofHashes)
		}
	})
}

// TestParseAddEntriesRejectsTruncationAndTrailingBytes pins the two
// framing failures a mirror distinguishes: a body that ends mid-package
// (400) and a body with bytes past the end of the canonical sequence.
func TestParseAddEntriesRejectsTruncationAndTrailingBytes(t *testing.T) {
	h := Header{Origin: "oid/x", UploadStart: 0, UploadEnd: 300}
	seq, _ := CanonicalSequence(h.UploadStart, h.UploadEnd)
	body, err := BuildAddEntries(h, makePackages(seq))
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range []int{1, 5, 20, len(body) / 2, len(body) - 1} {
		if _, _, _, err := ParseAddEntries(body[:n]); err == nil {
			t.Errorf("ParseAddEntries accepted a body truncated to %d bytes", n)
		}
	}
	if _, _, _, err := ParseAddEntries(append(body, 0x00)); err == nil {
		t.Error("ParseAddEntries accepted trailing bytes past the canonical sequence")
	}
}
