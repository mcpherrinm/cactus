package mirrorpush

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// MirrorInfoContentType is the media type a mirror MUST use for the
// body of a 409 Conflict or 202 Accepted add-entries response.
const MirrorInfoContentType = "text/x.tlog.mirror-info"

// SizeContentType is the media type of a witness add-checkpoint 409
// body — a different, one-line format ("<size>\n"). Keeping both named
// here makes the asymmetry visible: the mirror's *add-entries* conflict
// carries three lines, its *add-checkpoint* conflict carries one.
const SizeContentType = "text/x.tlog.size"

// MirrorInfo is the parsed body of a 202/409 add-entries response: the
// mirror telling us what state it is actually in, so we can restart the
// upload from a position it will accept.
type MirrorInfo struct {
	// PendingSize is the tree size of a valid pending checkpoint, i.e.
	// a value the mirror will accept as upload_end. If it equals the
	// upload_end we just sent, our cached per-package proofs are still
	// valid and can be reused; otherwise every proof must be
	// regenerated against the new size.
	PendingSize uint64
	// NextEntry is the first index the mirror is missing. It is the
	// only value we may ever use to move our own next-entry state
	// forward short of a 200.
	NextEntry uint64
	// Ticket is the opaque resume token, decoded from the base64 on the
	// wire into the raw bytes an add-entries header wants. It is
	// legitimately empty ("possibly zero length") and an empty final
	// line is well-formed, not a truncated body.
	Ticket []byte
}

// ParseMirrorInfo parses a text/x.tlog.mirror-info body:
//
//	<pending tree size, decimal>\n
//	<next entry, decimal>\n
//	<base64 ticket, possibly empty>\n
//
// The format is fixed at exactly three newline-terminated lines, so
// anything else is rejected rather than tolerated: this body is what
// drives our next-entry state, and silently accepting a malformed one
// risks resuming an upload at the wrong index.
func ParseMirrorInfo(body []byte) (MirrorInfo, error) {
	var mi MirrorInfo
	s := string(body)
	// Every line is terminated, so a well-formed body ends in "\n" and
	// splitting yields four fields with an empty tail.
	if !strings.HasSuffix(s, "\n") {
		return mi, fmt.Errorf("mirrorpush: mirror-info body does not end in a newline")
	}
	lines := strings.Split(s[:len(s)-1], "\n")
	if len(lines) != 3 {
		return mi, fmt.Errorf("mirrorpush: mirror-info has %d lines, want 3", len(lines))
	}

	parseDecimal := func(what, in string) (uint64, error) {
		if in == "" {
			return 0, fmt.Errorf("mirrorpush: mirror-info %s line is empty", what)
		}
		v, err := strconv.ParseUint(in, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("mirrorpush: mirror-info %s %q: %w", what, in, err)
		}
		return v, nil
	}
	var err error
	if mi.PendingSize, err = parseDecimal("pending tree size", lines[0]); err != nil {
		return MirrorInfo{}, err
	}
	if mi.NextEntry, err = parseDecimal("next entry", lines[1]); err != nil {
		return MirrorInfo{}, err
	}
	// An empty ticket line is normal: base64 of the empty string is the
	// empty string, and the spec explicitly allows a zero-length ticket.
	if lines[2] != "" {
		mi.Ticket, err = base64.StdEncoding.DecodeString(lines[2])
		if err != nil {
			return MirrorInfo{}, fmt.Errorf("mirrorpush: mirror-info ticket base64: %w", err)
		}
	}
	return mi, nil
}

// ParseSize parses a text/x.tlog.size body ("<size>\n"), the format of
// a witness/mirror add-checkpoint 409 response, which reports the size
// of the latest checkpoint the peer accepted.
func ParseSize(body []byte) (uint64, error) {
	s := strings.TrimSuffix(string(body), "\n")
	if s == "" || strings.Contains(s, "\n") {
		return 0, fmt.Errorf("mirrorpush: malformed tlog.size body %q", string(body))
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("mirrorpush: tlog.size %q: %w", s, err)
	}
	return v, nil
}
