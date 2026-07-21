package mirrorpush

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/tlogx"
)

// testCosigner builds an ML-DSA-44 cosigner from a one-byte seed fill.
func testCosigner(t *testing.T, id cert.TrustAnchorID, seedByte byte) (signer.Signer, cert.CosignerKey) {
	t.Helper()
	s, err := signer.FromSeed(signer.AlgMLDSA44, bytes.Repeat([]byte{seedByte}, signer.SeedSize))
	if err != nil {
		t.Fatalf("ML-DSA-44 signer: %v", err)
	}
	return s, cert.CosignerKey{ID: id, Algorithm: cert.AlgMLDSA44, PublicKey: s.PublicKey()}
}

// signLine produces a signed-note signature line for the given subtree
// and timestamp, as a mirror would.
func signLine(t *testing.T, s signer.Signer, key cert.CosignerKey, st *cert.MTCSubtree, timestamp uint64) string {
	t.Helper()
	msg, err := cert.MarshalSignatureInputAt(key.ID, st, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	return sigLineFor(t, key, timestamp, sig)
}

// sigLineFor assembles the wire line from an arbitrary signature blob,
// so tests can plant a signature that will not verify.
func sigLineFor(t *testing.T, key cert.CosignerKey, timestamp uint64, sig []byte) string {
	t.Helper()
	name := cert.OIDName(key.ID)
	keyID, err := cert.CosignatureKeyID(name, key.Algorithm, key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	blob := append(append([]byte(nil), keyID[:]...), cert.MarshalTimestampedSignature(timestamp, sig)...)
	return fmt.Sprintf("— %s %s", name, base64.StdEncoding.EncodeToString(blob))
}

func testSubtree() *cert.MTCSubtree {
	var h tlogx.Hash
	for i := range h {
		h[i] = byte(i)
	}
	return &cert.MTCSubtree{
		LogID: cert.TrustAnchorID("32473.1.0.1"),
		Start: 0, End: 1024, Hash: h,
	}
}

func TestVerifyCosignaturesAcceptsOwnLine(t *testing.T) {
	s, key := testCosigner(t, cert.TrustAnchorID("32473.9"), 0x11)
	st := testSubtree()
	body := signLine(t, s, key, st, 1735689600) + "\n"

	got, err := VerifyCosignatures([]byte(body), key, st, TimestampNonZero)
	if err != nil {
		t.Fatalf("VerifyCosignatures: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d cosignatures, want 1", len(got))
	}
	if got[0].Timestamp != 1735689600 {
		t.Errorf("Timestamp = %d, want 1735689600", got[0].Timestamp)
	}
	// The verbatim line is what gets appended to a checkpoint note, so
	// it must survive parsing untouched.
	if got[0].Line != strings.TrimSuffix(body, "\n") {
		t.Errorf("Line = %q, want the verbatim input line", got[0].Line)
	}
}

// TestVerifyCosignaturesIgnoresUnknownKeys covers the "MUST ignore any
// cosignatures from unknown keys" rule, in both its forms: a different
// name, and the same name with a different key ID.
func TestVerifyCosignaturesIgnoresUnknownKeys(t *testing.T) {
	ours, ourKey := testCosigner(t, cert.TrustAnchorID("32473.9"), 0x11)
	theirs, theirKey := testCosigner(t, cert.TrustAnchorID("32473.8"), 0x22)
	// Same trust anchor ID (so the same key name) but a different key,
	// hence a different key ID.
	sameNameOther, sameNameOtherKey := testCosigner(t, cert.TrustAnchorID("32473.9"), 0x33)
	st := testSubtree()

	body := strings.Join([]string{
		signLine(t, theirs, theirKey, st, 100),
		signLine(t, sameNameOther, sameNameOtherKey, st, 100),
		signLine(t, ours, ourKey, st, 100),
	}, "\n") + "\n"

	got, err := VerifyCosignatures([]byte(body), ourKey, st, TimestampNonZero)
	if err != nil {
		t.Fatalf("VerifyCosignatures: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d cosignatures, want just our own", len(got))
	}
	if got[0].Name != cert.OIDName(ourKey.ID) {
		t.Errorf("Name = %q, want %q", got[0].Name, cert.OIDName(ourKey.ID))
	}

	// With none of the lines ours, the whole thing is an error: a
	// response with no usable cosignature is not a success.
	onlyTheirs := signLine(t, theirs, theirKey, st, 100) + "\n"
	if _, err := VerifyCosignatures([]byte(onlyTheirs), ourKey, st, TimestampNonZero); err == nil {
		t.Error("VerifyCosignatures accepted a body with no cosignature of ours")
	}
}

// TestVerifyCosignaturesRejectsBadSignatureFromMatchingKey is the sharp
// edge of the matching rule. A line that matches our name AND our key
// ID claims to be from us; if it then fails to verify, the note is
// malformed and the whole response must be rejected — not silently
// skipped in favour of a good line elsewhere in the body.
func TestVerifyCosignaturesRejectsBadSignatureFromMatchingKey(t *testing.T) {
	ours, ourKey := testCosigner(t, cert.TrustAnchorID("32473.9"), 0x11)
	st := testSubtree()

	// A structurally valid ML-DSA-44 signature over the *wrong*
	// message, presented under our name and key ID.
	wrong := &cert.MTCSubtree{LogID: st.LogID, Start: 0, End: st.End + 1, Hash: st.Hash}
	msg, err := cert.MarshalSignatureInputAt(ourKey.ID, wrong, 100)
	if err != nil {
		t.Fatal(err)
	}
	badSig, err := ours.Sign(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	badLine := sigLineFor(t, ourKey, 100, badSig)
	goodLine := signLine(t, ours, ourKey, st, 100)

	// Bad line first, good line second: a "skip and keep looking"
	// implementation would return the good one and report success.
	body := badLine + "\n" + goodLine + "\n"
	got, err := VerifyCosignatures([]byte(body), ourKey, st, TimestampNonZero)
	if err == nil {
		t.Fatalf("VerifyCosignatures returned %d cosignatures, want rejection of the whole response", len(got))
	}
	if !strings.Contains(err.Error(), "failed to verify") {
		t.Errorf("error = %v, want a verification failure", err)
	}
}

// TestVerifyCosignaturesTimestampRules pins the two mutually exclusive
// timestamp requirements: zero for sign-subtree, non-zero for
// checkpoint cosignatures.
func TestVerifyCosignaturesTimestampRules(t *testing.T) {
	s, key := testCosigner(t, cert.TrustAnchorID("32473.9"), 0x11)
	st := testSubtree()
	zero := []byte(signLine(t, s, key, st, 0) + "\n")
	nonZero := []byte(signLine(t, s, key, st, 1735689600) + "\n")

	if _, err := VerifyCosignatures(zero, key, st, TimestampZero); err != nil {
		t.Errorf("zero timestamp rejected under TimestampZero: %v", err)
	}
	if _, err := VerifyCosignatures(nonZero, key, st, TimestampNonZero); err != nil {
		t.Errorf("non-zero timestamp rejected under TimestampNonZero: %v", err)
	}
	if _, err := VerifyCosignatures(nonZero, key, st, TimestampZero); err == nil {
		t.Error("a non-zero timestamp was accepted for a subtree cosignature")
	}
	if _, err := VerifyCosignatures(zero, key, st, TimestampNonZero); err == nil {
		t.Error("a zero timestamp was accepted for a checkpoint cosignature")
	}
}

// TestVerifyCosignaturesTimestampIsSigned confirms the timestamp is an
// input to the signature rather than an unauthenticated wrapper: a line
// re-labelled with a different timestamp must not verify.
func TestVerifyCosignaturesTimestampIsSigned(t *testing.T) {
	s, key := testCosigner(t, cert.TrustAnchorID("32473.9"), 0x11)
	st := testSubtree()
	msg, err := cert.MarshalSignatureInputAt(key.ID, st, 100)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	tampered := sigLineFor(t, key, 101, sig) + "\n"
	if _, err := VerifyCosignatures([]byte(tampered), key, st, TimestampNonZero); err == nil {
		t.Error("a cosignature with a rewritten timestamp verified")
	}
}

func TestParseCosignatureLinesRejects(t *testing.T) {
	_, key := testCosigner(t, cert.TrustAnchorID("32473.9"), 0x11)
	valid := sigLineFor(t, key, 1, make([]byte, 2420))

	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"only newlines", "\n\n"},
		{"hyphen instead of em dash", strings.Replace(valid, "—", "-", 1) + "\n"},
		{"en dash instead of em dash", strings.Replace(valid, "—", "–", 1) + "\n"},
		{"no space after the dash", "—" + strings.TrimPrefix(valid, "— ") + "\n"},
		{"no name", "—  AAAAAA==\n"},
		{"bad base64", "— oid/1.2.3 !!!!\n"},
		{"blob shorter than a key ID", "— oid/1.2.3 AAA=\n"},
		{"blob too short for a timestamp", "— oid/1.2.3 AAAAAAAA\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParseCosignatureLines([]byte(tc.body)); err == nil {
				t.Errorf("ParseCosignatureLines(%q) = %+v, want error", tc.body, got)
			}
		})
	}
}
