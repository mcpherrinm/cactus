package cert

import "testing"

// FuzzParseMTCProof feeds random bytes to ParseMTCProof and asserts
// the parser never panics. It's a guard against unchecked length
// overflows in the cryptobyte loop.
func FuzzParseMTCProof(f *testing.F) {
	// Seed with a few well-formed and malformed inputs.
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x02})
	// Minimal valid MTCProof: start=0, end=1, ip-len=0, sigs-len=0.
	f.Add([]byte{
		0, 0, 0, 0, 0, 0, 0, 0, // start
		0, 0, 0, 0, 0, 0, 0, 1, // end
		0, 0, // ip length
		0, 0, // sigs length
	})
	// Truncated.
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Just confirm it doesn't panic. Whether it errors or returns
		// a value is irrelevant.
		_, _ = ParseMTCProof(data)
	})
}

// FuzzSplitCertificate is an analogous guard for SplitCertificate.
func FuzzSplitCertificate(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	// Garbage.
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = SplitCertificate(data)
	})
}

// FuzzRebuildLogEntryFromTBS ensures the §7.2-step-4 reconstruction
// never panics on malformed TBS.
func FuzzRebuildLogEntryFromTBS(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x30, 0x00}, []byte{})
	f.Fuzz(func(t *testing.T, tbs, expectedIssuer []byte) {
		_, _, _ = RebuildLogEntryFromTBS(tbs, expectedIssuer)
	})
}
