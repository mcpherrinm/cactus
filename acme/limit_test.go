package acme

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// TestMaxJWSBytes confirms a body over the cap is rejected with a 400.
func TestMaxJWSBytes(t *testing.T) {
	hsrv, _ := newTestStack(t)

	// Build a body that's just bigger than the limit. The content
	// doesn't have to be a valid JWS — the size cap fires first.
	huge := bytes.Repeat([]byte("a"), MaxJWSBytes+1)
	resp, err := http.Post(hsrv.URL+"/new-account", "application/jose+json",
		bytes.NewReader(huge))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	// Body should be a Problem document referencing the size limit; we
	// don't pin the wording, just sanity check that it's NOT an empty
	// body (which would suggest a panic was swallowed).
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if n == 0 {
		t.Errorf("empty problem body")
	}
	if !strings.Contains(string(buf[:n]), "malformed") &&
		!strings.Contains(string(buf[:n]), "request body too large") {
		t.Logf("problem detail: %q", buf[:n])
	}
}
