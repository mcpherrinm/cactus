package cert

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// DecodeBase64 decodes standard, padded base64 (RFC 4648 §4) and
// rejects non-canonical encodings (§3.5), i.e. ones whose padding bits
// are not zero. c2sp.org/signed-note@v1.1.0 and the specs built on it
// (tlog-checkpoint, tlog-cosignature, tlog-witness, tlog-mirror) require
// decoders to reject non-canonical base64, which encoding/base64 accepts
// by default.
func DecodeBase64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		// encoding/base64 silently skips newlines; a C2SP field is a
		// single line, so one inside it is malformed.
		return nil, fmt.Errorf("cert: newline inside base64 %q", s)
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}

// ParseDecimal parses a non-negative integer encoded as an ASCII decimal
// the C2SP way (tlog-checkpoint@v1.1.0, tlog-cosignature@v1.1.0): base-10
// digits with no extra leading zeros, and "0" for zero.
func ParseDecimal(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') || strings.TrimLeft(s, "0123456789") != "" {
		return 0, fmt.Errorf("cert: %q is not a canonical ASCII decimal", s)
	}
	return strconv.ParseUint(s, 10, 64)
}
