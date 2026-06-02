// Package cors provides a permissive CORS middleware so cactus's ACME
// and monitoring endpoints can be called from any web origin.
package cors

import "net/http"

// ExposeHeaders is the Access-Control-Expose-Headers value. It mirrors
// the set Boulder's WFE exposes (boulder wfe2/wfe.go setCORSHeaders), so
// browser clients reading responses via fetch() can see the ACME
// headers they need: Link (directory/order relations), Replay-Nonce
// (the next anti-replay nonce), Location (created resource URLs), and
// Retry-After (polling backoff).
const ExposeHeaders = "Link, Replay-Nonce, Location, Retry-After"

// Middleware wraps next with permissive CORS handling: every response
// carries Access-Control-Allow-Origin: * and the Boulder-compatible
// Access-Control-Expose-Headers set, and CORS preflight (OPTIONS)
// requests are answered directly so cross-origin POSTs (e.g. ACME's
// application/jose+json, which is not a CORS "simple" Content-Type) are
// permitted.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Origin "*" is fixed, so the response doesn't vary by Origin and
		// stays safe to share in caches/CDNs (no Vary needed).
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Expose-Headers", ExposeHeaders)

		// A CORS preflight is an OPTIONS request carrying
		// Access-Control-Request-Method. Answer it here rather than
		// passing it to handlers that don't register OPTIONS.
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
			// application/jose+json isn't a CORS "simple" Content-Type,
			// so the header must be explicitly allowed (see the note in
			// Boulder's setCORSHeaders).
			h.Set("Access-Control-Allow-Headers", "Content-Type")
			h.Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
