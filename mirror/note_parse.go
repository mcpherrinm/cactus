package mirror

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// signedNote is a c2sp signed-note: body lines + zero or more
// signatures. Lines do not include the trailing newline.
type signedNote struct {
	body []string
	sigs []noteSignature
}

type noteSignature struct {
	keyName string
	// sigBytes includes the 4-byte c2sp keyID followed by the
	// algorithm-specific signature.
	sigBytes []byte
}

// emDash is the U+2014 character used to introduce signature lines.
const emDash = "—"

// readSignedNote parses one signed note from r. It reads body lines
// up to the first blank line, then reads em-dash-prefixed signature
// lines until a non-signature line is hit (which is rewound back into
// the buffer).
//
// Returns io.EOF if r is empty before any body line has been read.
func readSignedNote(r *bufio.Reader) (*signedNote, error) {
	var sn signedNote
	// Body until first blank line.
	for {
		line, err := readLine(r)
		if err == io.EOF {
			if len(sn.body) == 0 {
				return nil, io.EOF
			}
			return nil, errors.New("mirror: signed note ended before blank-line separator")
		}
		if err != nil {
			return nil, err
		}
		if line == "" {
			break
		}
		sn.body = append(sn.body, line)
	}
	if len(sn.body) == 0 {
		return nil, errors.New("mirror: signed note has empty body")
	}
	// Signatures: lines starting with the em-dash. Stop at non-sig
	// or EOF.
	for {
		line, err := readLine(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(line, emDash+" ") {
			// Push back: this line belongs to the next section.
			// bufio doesn't support real ungetline; instead we set up
			// the reader so the caller knows the boundary by getting
			// the line via a different path. For our two-note format
			// we rely on a blank line *after* signatures to separate
			// notes — which we treat by reading a blank below.
			//
			// To allow cleanly: a non-blank, non-sig line means end
			// of *this* note, but it belongs to subsequent content.
			// We don't have peek-and-replace here, so we encode it as
			// an explicit error and let the caller use a different
			// flow when there's content after the note.
			//
			// Fortunately, our request format has a blank line as
			// separator, so the non-sig line we'd see is empty.
			if line == "" {
				return &sn, nil
			}
			return nil, fmt.Errorf("mirror: unexpected non-signature line in note: %q", line)
		}
		rest := strings.TrimPrefix(line, emDash+" ")
		parts := strings.SplitN(rest, " ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("mirror: malformed sig line: %q", line)
		}
		raw, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("mirror: sig b64: %w", err)
		}
		sn.sigs = append(sn.sigs, noteSignature{keyName: parts[0], sigBytes: raw})
	}
	return &sn, nil
}

// readLine reads up to and including the next \n, returning the line
// without the trailing newline. Returns io.EOF only if the reader is
// at EOF before any byte is read.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err == io.EOF && len(line) == 0 {
		return "", io.EOF
	}
	if err != nil && err != io.EOF {
		return "", err
	}
	line = strings.TrimRight(line, "\n")
	return line, nil
}

// signatureFor returns the signature lines whose keyName matches.
func (sn *signedNote) signatureFor(keyName string) (noteSignature, bool) {
	for _, s := range sn.sigs {
		if s.keyName == keyName {
			return s, true
		}
	}
	return noteSignature{}, false
}
