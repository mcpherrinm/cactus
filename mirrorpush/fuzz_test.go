package mirrorpush

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"testing"
)

// FuzzParseMirrorInfo feeds random bytes to the 202/409 body parser and
// asserts it never panics. This body is attacker-adjacent — it comes
// from a remote mirror and drives our next-entry state — so a parser
// crash or an accepted-but-wrong parse both matter. Anything that parses
// must also re-encode to the same three lines, which pins the format as
// canonical rather than merely accepted.
func FuzzParseMirrorInfo(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("0\n0\n\n"))
	f.Add([]byte("1024\n768\n\n"))
	f.Add([]byte("1024\n768\nAAECAw==\n"))
	f.Add([]byte("18446744073709551615\n18446744073709551615\n\n"))
	// Malformed shapes worth keeping in the corpus.
	f.Add([]byte("1024\n768\n"))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte("1024\n768\n!!!!\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		mi, err := ParseMirrorInfo(data)
		if err != nil {
			return
		}
		// A successful parse must round trip: re-encoding the parsed
		// values reproduces a body that parses back identically.
		again := encodeMirrorInfo(mi)
		mi2, err := ParseMirrorInfo(again)
		if err != nil {
			t.Fatalf("re-parse of re-encoded mirror-info failed: %v (from %q)", err, data)
		}
		if mi2.PendingSize != mi.PendingSize || mi2.NextEntry != mi.NextEntry ||
			!bytes.Equal(mi2.Ticket, mi.Ticket) {
			t.Fatalf("mirror-info round trip changed values: %+v -> %+v", mi, mi2)
		}
	})
}

// FuzzAddEntriesFraming feeds random bytes to the add-entries body
// parser.
//
// Beyond the no-panic guarantee, this asserts the property the wire
// format actually rests on: the body carries no package count and no
// per-package lengths, so a receiver must be able to segment it from the
// header alone. Anything ParseAddEntries accepts is therefore re-built
// with BuildAddEntries and required to be byte-identical — if the two
// disagree, a sender and a mirror would disagree about where packages
// begin, which surfaces as an inscrutable 400 or 422.
func FuzzAddEntriesFraming(f *testing.F) {
	seed := func(h Header, pkgs int) {
		seq, err := CanonicalSequence(h.UploadStart, h.UploadEnd)
		if err != nil {
			return
		}
		data := makePackages(seq)
		if pkgs >= 0 && pkgs < len(data) {
			data = data[:pkgs]
		}
		body, err := BuildAddEntries(h, data)
		if err != nil {
			return
		}
		f.Add(body)
	}
	seed(Header{Origin: "oid/1.3.6.1.4.1.32473.1.0.1", UploadStart: 0, UploadEnd: 0}, -1)
	seed(Header{Origin: "oid/1.3.6.1.4.1.32473.1.0.1", UploadStart: 0, UploadEnd: 3}, -1)
	seed(Header{Origin: "oid/1.3.6.1.4.1.32473.1.0.1", UploadStart: 0, UploadEnd: 256}, -1)
	seed(Header{Origin: "oid/1.3.6.1.4.1.32473.1.0.1", UploadStart: 100, UploadEnd: 600}, -1)
	seed(Header{Origin: "oid/1.3.6.1.4.1.32473.1.0.1", UploadStart: 100, UploadEnd: 600, Ticket: []byte{1, 2, 3}}, 1)
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x61})
	// A header describing an enormous interval: the parser must not try
	// to materialise the sequence it implies.
	f.Add([]byte{
		0x00, 0x01, 0x61, // origin "a"
		0, 0, 0, 0, 0, 0, 0, 0, // upload_start
		0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // upload_end
		0x00, 0x00, // ticket
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		h, pkgs, pd, err := ParseAddEntries(data)
		if err != nil {
			return
		}
		if len(pkgs) != len(pd) {
			t.Fatalf("parsed %d package descriptors but %d payloads", len(pkgs), len(pd))
		}
		// Each parsed package must match what the header alone implies.
		for i, p := range pkgs {
			want := PackageAt(h.UploadStart, h.UploadEnd, uint64(i))
			if p != want {
				t.Fatalf("package %d = %+v, header implies %+v", i, p, want)
			}
			if uint64(len(pd[i].Entries)) != p.End-p.Start {
				t.Fatalf("package %d holds %d entries, range [%d,%d) implies %d",
					i, len(pd[i].Entries), p.Start, p.End, p.End-p.Start)
			}
		}
		again, err := BuildAddEntries(h, pd)
		if err != nil {
			t.Fatalf("BuildAddEntries rejected a body ParseAddEntries accepted: %v", err)
		}
		if !bytes.Equal(again, data) {
			t.Fatalf("add-entries framing is not canonical:\n parsed %q\nrebuilt %q", data, again)
		}
	})
}

// encodeMirrorInfo is the inverse of ParseMirrorInfo, for the round-trip
// property above. The client never sends this body — only mirrors do —
// so it lives in the test.
func encodeMirrorInfo(mi MirrorInfo) []byte {
	var b bytes.Buffer
	b.WriteString(strconv.FormatUint(mi.PendingSize, 10) + "\n")
	b.WriteString(strconv.FormatUint(mi.NextEntry, 10) + "\n")
	b.WriteString(base64.StdEncoding.EncodeToString(mi.Ticket) + "\n")
	return b.Bytes()
}
