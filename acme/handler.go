package acme

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/landmark"
	cactusmetrics "github.com/letsencrypt/cactus/metrics"
	"github.com/letsencrypt/cactus/tlogx"
)

// ChallengeMode controls how challenges are validated.
type ChallengeMode string

const (
	ChallengeAutoPass ChallengeMode = "auto-pass"
	ChallengeHTTP01   ChallengeMode = "http-01"
)

// Config configures the Server.
type Config struct {
	// ExternalURL is the base URL the server is reachable at, used to
	// construct directory entries and resource URLs.
	ExternalURL string
	// Issuer drives X.509 issuance once an order is finalized.
	Issuer *ca.Issuer
	// ChallengeMode is auto-pass for tests; http-01 not yet implemented.
	ChallengeMode ChallengeMode
	// OrderLifetime bounds how long an order remains valid.
	OrderLifetime time.Duration
	// Logger receives slog records; defaults to slog.Default().
	Logger *slog.Logger
	// OrdersByStatus is the labelled counter for terminal-status
	// transitions: incremented to "valid" on successful issuance and
	// "invalid" on failure. Optional.
	OrdersByStatus cactusmetrics.CounterVec

	// Landmarks, if non-nil, enables Phase 8.4 alternate-URL
	// switchover: GET /cert/{id}/alternate returns a real
	// landmark-relative cert once a covering landmark exists.
	// Otherwise the alternate URL keeps the §9-permitted 503 stub.
	Landmarks *landmark.Sequence

	// SubtreeProof, if set, is used to compute inclusion proofs for
	// landmark-relative cert assembly. Must be set whenever
	// Landmarks is. Typically `(*log.Log).SubtreeProof`.
	SubtreeProof func(start, end, index uint64) (tlogx.Hash, []tlogx.Hash, error)

	// LogID is the issuance log's trust anchor ID (§5.2). Required
	// only when Landmarks is set (and for the standalone-cert
	// `trust_anchor_id` property emitted in
	// application/pem-certificate-chain-with-properties).
	LogID cert.TrustAnchorID

	// LandmarkBaseID is the base trust anchor ID for the landmark
	// sequence (§6.3.1's base_id). Required whenever Landmarks is
	// set, used in the landmark cert's `trust_anchor_id` and
	// `additional_trust_anchor_ranges` properties.
	LandmarkBaseID cert.TrustAnchorID
}

// Server is the ACME HTTP server.
type Server struct {
	cfg    Config
	state  *State
	logger *slog.Logger

	// certs holds DER-encoded certs by their certificate ID. Mirrored
	// to disk via certStore when storage is attached.
	certs     map[string][]byte
	certStore *CertStore
}

// New constructs a Server. The Server.SetExternalURL setter exists so
// tests using httptest.NewServer can plug in the URL after the listener
// is up.
func New(cfg Config) (*Server, error) {
	if cfg.Issuer == nil {
		return nil, fmt.Errorf("acme: Issuer required")
	}
	if cfg.OrderLifetime == 0 {
		cfg.OrderLifetime = 24 * time.Hour
	}
	if cfg.ChallengeMode == "" {
		cfg.ChallengeMode = ChallengeAutoPass
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{
		cfg:    cfg,
		state:  NewState(),
		logger: cfg.Logger,
		certs:  make(map[string][]byte),
	}, nil
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /directory", s.handleDirectory)
	mux.HandleFunc("HEAD /new-nonce", s.handleNewNonce)
	mux.HandleFunc("GET /new-nonce", s.handleNewNonce)
	mux.HandleFunc("POST /new-account", s.handleNewAccount)
	mux.HandleFunc("POST /new-order", s.handleNewOrder)
	mux.HandleFunc("POST /authz/{id}", s.handleAuthz)
	mux.HandleFunc("POST /chall/{id}", s.handleChallenge)
	mux.HandleFunc("POST /order/{id}", s.handleOrder)
	mux.HandleFunc("POST /finalize/{id}", s.handleFinalize)
	mux.HandleFunc("POST /cert/{id}", s.handleCert)
	mux.HandleFunc("POST /cert/{id}/alternate", s.handleCertAlternate)
	return mux
}

// urlFor returns a fully-qualified URL relative to the configured external URL.
func (s *Server) urlFor(path string) string {
	base := strings.TrimRight(s.cfg.ExternalURL, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

// SetExternalURL updates the base URL used in directory entries, account
// locations, etc. Tests using httptest.NewServer call this after the
// listener address is known.
func (s *Server) SetExternalURL(u string) {
	s.cfg.ExternalURL = u
}

// AttachStorage wires a storage backend so accounts, orders, and
// issued certificates are durably persisted across restarts. Nonces
// remain in-memory.
func (s *Server) AttachStorage(fs Storage) error {
	if err := s.state.LoadFromStorage(fs); err != nil {
		return err
	}
	s.certStore = NewCertStore(fs)

	// Re-hydrate the in-memory cert cache for already-issued orders.
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	for _, o := range s.state.orders {
		if o.CertificateID == "" {
			continue
		}
		der, err := s.certStore.Get(o.CertificateID)
		if err != nil {
			continue
		}
		s.certs[o.CertificateID] = der
	}
	return nil
}

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	d := Directory{
		NewNonce:   s.urlFor("/new-nonce"),
		NewAccount: s.urlFor("/new-account"),
		NewOrder:   s.urlFor("/new-order"),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(d)
}

func (s *Server) issueNonce(w http.ResponseWriter) {
	w.Header().Set("Replay-Nonce", s.state.NewNonce())
	w.Header().Set("Cache-Control", "no-store")
}

func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	s.issueNonce(w)
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

// MaxJWSBytes caps the size of an incoming JWS request body. ACME
// requests are small (a few hundred bytes plus a CSR for finalize); a
// CSR for an extreme SAN list is bounded too. 256 KiB covers anything
// reasonable and refuses the rest before allocating.
const MaxJWSBytes = 256 * 1024

// jwsError carries the ACME problem document fields readJWS wants to
// surface to the handler — distinct error types per RFC 8555 §6.
type jwsError struct {
	Status     int
	Type       string
	Detail     string
	Algorithms []string
}

func (e *jwsError) Error() string { return e.Detail }

// readJWS reads the request body, parses+verifies the JWS against either
// the embedded jwk or the looked-up account key, validates the
// protected `url` header (§6.4), consumes the nonce (§6.5), and
// returns the parsed result. Errors are *jwsError values whose Type
// is the ACME problem-document type that should be returned.
func (s *Server) readJWS(r *http.Request, expectKnownAccount bool) (*ParsedJWS, *account, error) {
	// §6.2: POST must use application/jose+json; reject with 415.
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if !strings.EqualFold(ct, "application/jose+json") {
		return nil, nil, &jwsError{
			Status: http.StatusUnsupportedMediaType,
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: fmt.Sprintf("Content-Type must be application/jose+json, got %q", ct),
		}
	}

	r.Body = http.MaxBytesReader(nil, r.Body, MaxJWSBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, &jwsError{Status: http.StatusBadRequest, Type: "urn:ietf:params:acme:error:malformed", Detail: "read body: " + err.Error()}
	}
	hdrPeek, err := peekJOSEHeader(body)
	if err != nil {
		return nil, nil, &jwsError{Status: http.StatusBadRequest, Type: "urn:ietf:params:acme:error:malformed", Detail: err.Error()}
	}

	// §6.2: if alg is unsupported, return badSignatureAlgorithm with
	// the supported `algorithms` list. We pre-check here so the error
	// type is right (otherwise jose.ParseSigned just returns "unsupported").
	if hdrPeek.Alg != "" && !algSupported(hdrPeek.Alg) {
		return nil, nil, &jwsError{
			Status:     http.StatusBadRequest,
			Type:       "urn:ietf:params:acme:error:badSignatureAlgorithm",
			Detail:     fmt.Sprintf("alg %q not supported", hdrPeek.Alg),
			Algorithms: supportedAlgsList(),
		}
	}

	var acct *account
	var key *jose.JSONWebKey
	if hdrPeek.KID != "" {
		thumb, err := s.thumbprintFromKID(hdrPeek.KID)
		if err != nil {
			return nil, nil, &jwsError{Status: http.StatusBadRequest, Type: "urn:ietf:params:acme:error:malformed", Detail: err.Error()}
		}
		s.state.mu.Lock()
		acct = s.state.accounts[thumb]
		s.state.mu.Unlock()
		if acct == nil {
			return nil, nil, &jwsError{Status: http.StatusBadRequest, Type: "urn:ietf:params:acme:error:accountDoesNotExist", Detail: "unknown account: " + thumb}
		}
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(acct.JWKBytes); err != nil {
			return nil, nil, &jwsError{Status: http.StatusInternalServerError, Type: "urn:ietf:params:acme:error:serverInternal", Detail: "parse stored jwk: " + err.Error()}
		}
		key = &jwk
	} else if expectKnownAccount {
		return nil, nil, &jwsError{Status: http.StatusBadRequest, Type: "urn:ietf:params:acme:error:malformed", Detail: "kid required"}
	}

	parsed, err := ParseAndVerify(body, key)
	if err != nil {
		return nil, nil, &jwsError{Status: http.StatusBadRequest, Type: "urn:ietf:params:acme:error:malformed", Detail: err.Error()}
	}
	// §6.4: url header must equal the request URL.
	if want := s.urlFor(r.URL.Path); parsed.URL != want {
		return nil, nil, &jwsError{
			Status: http.StatusUnauthorized,
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: fmt.Sprintf("JWS url %q does not match request URL %q", parsed.URL, want),
		}
	}
	// §6.5: nonce must validate.
	if !s.state.ConsumeNonce(parsed.Nonce) {
		return nil, nil, &jwsError{
			Status: http.StatusBadRequest,
			Type:   "urn:ietf:params:acme:error:badNonce",
			Detail: "nonce missing, replayed, or expired",
		}
	}
	return parsed, acct, nil
}

// writeJWSError converts an error returned from readJWS into the
// appropriate ACME problem document. Non-jwsError values (programmer
// bugs) fall through to a 400 malformed.
func (s *Server) writeJWSError(w http.ResponseWriter, err error) {
	var je *jwsError
	if errors.As(err, &je) {
		s.problemFull(w, je.Status, je.Type, je.Detail, je.Algorithms)
		return
	}
	s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", err.Error())
}

// algSupported reports whether `alg` is in our accepted set.
func algSupported(alg string) bool {
	for _, a := range AcceptedJWSAlgs {
		if string(a) == alg {
			return true
		}
	}
	return false
}

// supportedAlgsList returns the AcceptedJWSAlgs as plain strings, for
// the badSignatureAlgorithm `algorithms` field.
func supportedAlgsList() []string {
	out := make([]string, 0, len(AcceptedJWSAlgs))
	for _, a := range AcceptedJWSAlgs {
		out = append(out, string(a))
	}
	return out
}

// thumbprintFromKID extracts the account thumbprint from a kid URL of
// the form ${ExternalURL}/account/${thumbprint}.
func (s *Server) thumbprintFromKID(kid string) (string, error) {
	u, err := url.Parse(kid)
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[len(parts)-2] != "account" {
		return "", fmt.Errorf("kid not an account URL: %q", kid)
	}
	return parts[len(parts)-1], nil
}

// peekedHeader carries the protected-header fields cactus uses to
// route a JWS request before verifying its signature.
type peekedHeader struct {
	KID string
	Alg string
}

// peekJOSEHeader extracts kid + alg (if any) from a JWS body without
// signature verification. Used so readJWS can look up the account key
// and pre-check the signature algorithm.
func peekJOSEHeader(body []byte) (peekedHeader, error) {
	var v struct {
		Protected string `json:"protected"`
	}
	if err := json.Unmarshal(body, &v); err == nil && v.Protected != "" {
		raw, err := base64.RawURLEncoding.DecodeString(v.Protected)
		if err != nil {
			return peekedHeader{}, err
		}
		var hdr struct {
			KID string `json:"kid"`
			Alg string `json:"alg"`
		}
		if err := json.Unmarshal(raw, &hdr); err == nil {
			return peekedHeader{KID: hdr.KID, Alg: hdr.Alg}, nil
		}
	}
	// JWS Compact form: base64(header).base64(payload).base64(sig)
	parts := strings.Split(strings.TrimSpace(string(body)), ".")
	if len(parts) == 3 {
		raw, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return peekedHeader{}, err
		}
		var hdr struct {
			KID string `json:"kid"`
			Alg string `json:"alg"`
		}
		if err := json.Unmarshal(raw, &hdr); err == nil {
			return peekedHeader{KID: hdr.KID, Alg: hdr.Alg}, nil
		}
	}
	return peekedHeader{}, nil
}

func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	parsed, _, err := s.readJWS(r, false)
	if err != nil {
		s.writeJWSError(w, err)
		return
	}
	if parsed.JWK == nil {
		s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "new-account must use jwk header")
		return
	}
	var req NewAccountReq
	if len(parsed.Payload) > 0 {
		if err := json.Unmarshal(parsed.Payload, &req); err != nil {
			s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "bad payload")
			return
		}
	}
	jwkBytes, err := parsed.JWK.MarshalJSON()
	if err != nil {
		s.problem(w, http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal", err.Error())
		return
	}
	acct, created, err := s.state.GetOrCreateAccount(parsed.Thumbprint, jwkBytes, req.Contact, !req.OnlyReturnExisting)
	if err != nil {
		s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:accountDoesNotExist", err.Error())
		return
	}
	loc := s.urlFor("/account/" + acct.ID)
	w.Header().Set("Location", loc)
	s.issueNonce(w)
	if created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(AccountResp{
		Status:  acct.Status,
		Contact: acct.Contact,
	})
}

func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	parsed, acct, err := s.readJWS(r, true)
	if err != nil {
		s.writeJWSError(w, err)
		return
	}
	var req NewOrderReq
	if err := json.Unmarshal(parsed.Payload, &req); err != nil {
		s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "bad payload")
		return
	}
	if len(req.Identifiers) == 0 {
		s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "no identifiers")
		return
	}
	// Cap to a small number so a single request can't allocate
	// thousands of authz/challenge records.
	const MaxIdentifiersPerOrder = 100
	if len(req.Identifiers) > MaxIdentifiersPerOrder {
		s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed",
			fmt.Sprintf("too many identifiers (%d > %d)", len(req.Identifiers), MaxIdentifiersPerOrder))
		return
	}

	// Build the order, one authz/challenge per identifier.
	now := time.Now().UTC()
	o := &order{
		ID:          newID(),
		AccountID:   acct.ID,
		Status:      "pending",
		Expires:     now.Add(s.cfg.OrderLifetime),
		Identifiers: req.Identifiers,
	}
	if req.NotBefore != "" {
		t, err := time.Parse(time.RFC3339, req.NotBefore)
		if err == nil {
			o.NotBefore = t
		}
	}
	if req.NotAfter != "" {
		t, err := time.Parse(time.RFC3339, req.NotAfter)
		if err == nil {
			o.NotAfter = t
		}
	}

	for _, id := range req.Identifiers {
		switch id.Type {
		case "dns":
			if !validDNSName(id.Value) {
				s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:rejectedIdentifier",
					fmt.Sprintf("not a valid DNS name: %q", id.Value))
				return
			}
		case "ip":
			if net.ParseIP(id.Value) == nil {
				s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "bad IP identifier")
				return
			}
		default:
			s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:rejectedIdentifier",
				fmt.Sprintf("unsupported identifier type %q", id.Type))
			return
		}

		ch := &challenge{
			ID:     newID(),
			Type:   "http-01",
			Status: "pending",
			Token:  randomToken(),
		}
		az := &authz{
			ID:         newID(),
			OrderID:    o.ID,
			Status:     "pending",
			Identifier: id,
			ChallIDs:   []string{ch.ID},
		}
		ch.AuthzID = az.ID
		s.state.PutChallenge(ch)
		s.state.PutAuthz(az)
		o.AuthzIDs = append(o.AuthzIDs, az.ID)
	}

	// Auto-pass: instantly mark all challenges and authzs valid. Each
	// state.Update* takes the same mutex, so we must release the
	// authz lock before acquiring the challenge lock.
	if s.cfg.ChallengeMode == ChallengeAutoPass {
		for _, aid := range o.AuthzIDs {
			var challIDs []string
			s.state.UpdateAuthz(aid, func(a *authz) {
				a.Status = "valid"
				challIDs = append([]string(nil), a.ChallIDs...)
			})
			for _, cid := range challIDs {
				s.state.UpdateChallenge(cid, func(c *challenge) {
					c.Status = "valid"
				})
			}
		}
		o.Status = "ready"
	}

	s.state.PutOrder(o)

	loc := s.urlFor("/order/" + o.ID)
	w.Header().Set("Location", loc)
	s.issueNonce(w)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(s.orderJSON(o))
}

func (s *Server) orderJSON(o *order) OrderResp {
	resp := OrderResp{
		Status:      o.Status,
		Identifiers: o.Identifiers,
		Finalize:    s.urlFor("/finalize/" + o.ID),
		Expires:     o.Expires.Format(time.RFC3339),
	}
	if !o.NotBefore.IsZero() {
		resp.NotBefore = o.NotBefore.Format(time.RFC3339)
	}
	if !o.NotAfter.IsZero() {
		resp.NotAfter = o.NotAfter.Format(time.RFC3339)
	}
	for _, aid := range o.AuthzIDs {
		resp.Authorizations = append(resp.Authorizations, s.urlFor("/authz/"+aid))
	}
	if o.CertificateID != "" {
		resp.Certificate = s.urlFor("/cert/" + o.CertificateID)
	}
	return resp
}

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.readJWS(r, true); err != nil {
		s.writeJWSError(w, err)
		return
	}
	id := r.PathValue("id")
	a, ok := s.state.GetAuthz(id)
	if !ok {
		s.problem(w, http.StatusNotFound, "urn:ietf:params:acme:error:malformed", "no authz")
		return
	}
	resp := AuthzResp{
		Status:     a.Status,
		Identifier: a.Identifier,
	}
	for _, cid := range a.ChallIDs {
		c, ok := s.state.GetChallenge(cid)
		if !ok {
			continue
		}
		resp.Challenges = append(resp.Challenges, ChallengeMsg{
			Type:   c.Type,
			Status: c.Status,
			URL:    s.urlFor("/chall/" + c.ID),
			Token:  c.Token,
		})
	}
	s.issueNonce(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	_, acct, err := s.readJWS(r, true)
	if err != nil {
		s.writeJWSError(w, err)
		return
	}
	id := r.PathValue("id")
	c, ok := s.state.GetChallenge(id)
	if !ok {
		s.problem(w, http.StatusNotFound, "urn:ietf:params:acme:error:malformed", "no challenge")
		return
	}

	if s.cfg.ChallengeMode == ChallengeHTTP01 && c.Status == "pending" {
		az, ok := s.state.GetAuthz(c.AuthzID)
		if !ok {
			s.problem(w, http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal", "authz missing")
			return
		}
		if err := s.attemptHTTP01(c, az, acct); err != nil {
			s.state.UpdateChallenge(c.ID, func(ch *challenge) { ch.Status = "invalid" })
			s.problem(w, http.StatusForbidden, "urn:ietf:params:acme:error:incorrectResponse", err.Error())
			return
		}
		s.state.UpdateChallenge(c.ID, func(ch *challenge) { ch.Status = "valid" })
		// Authz is valid if any of its challenges is valid.
		s.state.UpdateAuthz(az.ID, func(a *authz) { a.Status = "valid" })
		// Order moves to ready when all authzs are valid.
		s.maybeOrderReady(az.OrderID)
		// Refresh c after the update.
		c, _ = s.state.GetChallenge(c.ID)
	}

	s.issueNonce(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ChallengeMsg{
		Type:   c.Type,
		Status: c.Status,
		URL:    s.urlFor("/chall/" + c.ID),
		Token:  c.Token,
	})
}

// attemptHTTP01 fetches http://{identifier}/.well-known/acme-challenge/{token}
// and verifies the body equals the JWS-keyAuthorization. Identifier
// values are validated by validDNSName before reaching here, so the
// host isn't attacker-controlled in a way that could inject path/query
// segments into the URL.
func (s *Server) attemptHTTP01(c *challenge, az *authz, acct *account) error {
	if az.Identifier.Type != "dns" {
		return fmt.Errorf("http-01 only supports dns identifiers, got %q", az.Identifier.Type)
	}
	if !validDNSName(az.Identifier.Value) {
		return fmt.Errorf("http-01 identifier %q is not a valid DNS name", az.Identifier.Value)
	}
	expected, err := keyAuthorization(c.Token, acct.JWKBytes)
	if err != nil {
		return err
	}
	target := (&url.URL{
		Scheme: "http",
		Host:   az.Identifier.Value,
		Path:   "/.well-known/acme-challenge/" + c.Token,
	}).String()
	client := &http.Client{
		Timeout: 5 * time.Second,
		// Refuse redirects: ACME http-01 has no need to follow
		// arbitrary 3xx, and following them is a small SSRF amplifier.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(target)
	if err != nil {
		return fmt.Errorf("fetch challenge: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("challenge URL returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	got := strings.TrimSpace(string(body))
	if got != expected {
		return fmt.Errorf("body %q != expected %q", got, expected)
	}
	return nil
}

// validDNSName reports whether name is a syntactically valid DNS name
// (RFC 1035 letters-digits-hyphen, dotted, no leading/trailing dots,
// labels 1–63 chars, total ≤253 chars). An optional ":port" suffix
// where port is all digits is allowed, so that auto-pass / http-01
// tests can bind on non-default ports without opening the door to
// path/query/fragment injection (e.g. "evil.com:80/foo?x=" is
// rejected because "80/foo?x=" isn't all digits).
func validDNSName(name string) bool {
	if len(name) == 0 {
		return false
	}
	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		port := name[i+1:]
		if len(port) == 0 || len(port) > 5 {
			return false
		}
		for j := 0; j < len(port); j++ {
			if port[j] < '0' || port[j] > '9' {
				return false
			}
		}
		name = name[:i]
	}
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if name[0] == '.' || name[len(name)-1] == '.' {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			b := label[i]
			ok := (b >= 'a' && b <= 'z') ||
				(b >= 'A' && b <= 'Z') ||
				(b >= '0' && b <= '9') ||
				b == '-' || b == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

// maybeOrderReady transitions an order to "ready" if all its authzs
// are valid.
func (s *Server) maybeOrderReady(orderID string) {
	o, ok := s.state.GetOrder(orderID)
	if !ok || o.Status != "pending" {
		return
	}
	allValid := true
	for _, aid := range o.AuthzIDs {
		az, ok := s.state.GetAuthz(aid)
		if !ok || az.Status != "valid" {
			allValid = false
			break
		}
	}
	if allValid {
		s.state.UpdateOrder(o.ID, func(o *order) { o.Status = "ready" })
	}
}

func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.readJWS(r, true); err != nil {
		s.writeJWSError(w, err)
		return
	}
	id := r.PathValue("id")
	o, ok := s.state.GetOrder(id)
	if !ok {
		s.problem(w, http.StatusNotFound, "urn:ietf:params:acme:error:malformed", "no order")
		return
	}
	s.issueNonce(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.orderJSON(o))
}

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	parsed, _, err := s.readJWS(r, true)
	if err != nil {
		s.writeJWSError(w, err)
		return
	}
	id := r.PathValue("id")
	// Atomic ready→processing claim. The loser of a finalize race
	// gets "orderNotReady"; the order remains valid because the winner
	// will produce the cert.
	o, claimed := s.state.TryClaimReadyOrder(id)
	if o == nil {
		s.problem(w, http.StatusNotFound, "urn:ietf:params:acme:error:malformed", "no order")
		return
	}
	if !claimed {
		s.problem(w, http.StatusForbidden, "urn:ietf:params:acme:error:orderNotReady",
			fmt.Sprintf("order is %s", o.Status))
		return
	}

	var req FinalizeReq
	if err := json.Unmarshal(parsed.Payload, &req); err != nil {
		s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed", "bad payload")
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:badCSR", "csr not base64url")
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:badCSR", err.Error())
		return
	}

	// Build the order input from the (already-validated) order.
	orderInput := ca.OrderInput{
		NotBefore: o.NotBefore,
		NotAfter:  o.NotAfter,
	}
	for _, idn := range o.Identifiers {
		switch idn.Type {
		case "dns":
			orderInput.AuthorizedDNSNames = append(orderInput.AuthorizedDNSNames, idn.Value)
		case "ip":
			ip := net.ParseIP(idn.Value)
			if ip != nil {
				orderInput.AuthorizedIPs = append(orderInput.AuthorizedIPs, ip)
			}
		}
	}

	// Issue (this calls log.Append + Wait).
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	der, err := s.cfg.Issuer.Issue(ctx, csr, orderInput)
	if err != nil {
		s.state.UpdateOrder(o.ID, func(o *order) { o.Status = "invalid" })
		if s.cfg.OrdersByStatus != nil {
			s.cfg.OrdersByStatus.WithLabelValues("invalid").Add(1)
		}
		// CSR/order mismatches surface as ca.ErrBadCSR; map to the
		// RFC 8555 §7.4 badCSR error type.
		if errors.Is(err, ca.ErrBadCSR) {
			s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:badCSR", err.Error())
			return
		}
		s.problem(w, http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal", err.Error())
		return
	}

	certID := newID()
	s.state.UpdateOrder(o.ID, func(o *order) {
		o.Status = "valid"
		o.CertificateID = certID
	})
	s.state.mu.Lock()
	s.certs[certID] = der
	s.state.mu.Unlock()
	if s.certStore != nil {
		if err := s.certStore.Put(certID, der); err != nil {
			s.logger.Error("persist cert", "id", certID, "err", err)
		}
	}
	if s.cfg.OrdersByStatus != nil {
		s.cfg.OrdersByStatus.WithLabelValues("valid").Add(1)
	}

	o, _ = s.state.GetOrder(o.ID)
	loc := s.urlFor("/order/" + o.ID)
	w.Header().Set("Location", loc)
	s.issueNonce(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Link", `<`+s.urlFor("/cert/"+certID+"/alternate")+`>;rel="alternate"`)
	_ = json.NewEncoder(w).Encode(s.orderJSON(o))
}

func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	parsed, acct, err := s.readJWS(r, true)
	if err != nil {
		s.writeJWSError(w, err)
		return
	}
	if !EmptyPayloadOK(parsed.Payload) {
		s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed",
			"cert download must be POST-as-GET (empty payload)")
		return
	}
	s.state.mu.Lock()
	der, ok := s.certs[id]
	s.state.mu.Unlock()
	if !ok {
		s.problem(w, http.StatusNotFound, "urn:ietf:params:acme:error:malformed", "no certificate")
		return
	}
	if !s.certBelongsToAccount(id, acct.ID) {
		s.problem(w, http.StatusForbidden, "urn:ietf:params:acme:error:unauthorized",
			"certificate does not belong to this account")
		return
	}
	s.issueNonce(w)
	accept := r.Header.Get("Accept")
	w.Header().Set("Link", `<`+s.urlFor("/cert/"+id+"/alternate")+`>;rel="alternate"`)
	if strings.Contains(accept, "application/pem-certificate-chain-with-properties") {
		w.Header().Set("Content-Type", "application/pem-certificate-chain-with-properties")
		// Standalone cert: just the trust_anchor_id property naming the log.
		props := []cert.CertificateProperty{{
			Type:          cert.PropertyTrustAnchorID,
			TrustAnchorID: s.cfg.LogID,
		}}
		// If LogID isn't configured, fall back to plain PEM rather
		// than emitting an empty list (which BuildPropertyList rejects).
		if len(s.cfg.LogID) == 0 {
			pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
			return
		}
		pl, err := cert.BuildPropertyList(props)
		if err != nil {
			http.Error(w, "build properties: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(cert.EncodePEMWithProperties(der, pl))
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// handleCertAlternate returns the landmark-relative cert (Phase 8) for
// the given cert id, falling back to 503 + Retry-After (the
// §9-permitted stub) when a covering landmark hasn't been allocated yet
// or when landmark mode is disabled.
func (s *Server) handleCertAlternate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	parsed, acct, err := s.readJWS(r, true)
	if err != nil {
		s.writeJWSError(w, err)
		return
	}
	if !EmptyPayloadOK(parsed.Payload) {
		s.problem(w, http.StatusBadRequest, "urn:ietf:params:acme:error:malformed",
			"cert download must be POST-as-GET (empty payload)")
		return
	}
	s.state.mu.Lock()
	standalone, ok := s.certs[id]
	s.state.mu.Unlock()
	if !ok {
		s.problem(w, http.StatusNotFound, "urn:ietf:params:acme:error:malformed", "no certificate")
		return
	}
	if !s.certBelongsToAccount(id, acct.ID) {
		s.problem(w, http.StatusForbidden, "urn:ietf:params:acme:error:unauthorized",
			"certificate does not belong to this account")
		return
	}
	s.issueNonce(w)

	// Pull the serial out of the standalone cert; that's the log index.
	tbs, _, _, err := cert.SplitCertificate(standalone)
	if err != nil {
		http.Error(w, "split cert: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, serial, err := cert.RebuildLogEntryFromTBS(tbs, nil)
	if err != nil {
		http.Error(w, "decode TBS: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if s.cfg.Landmarks == nil || s.cfg.SubtreeProof == nil {
		s.serveAltStub(w)
		return
	}

	lm, ok := s.cfg.Landmarks.ContainingIndex(serial)
	if !ok {
		s.serveAltStub(w)
		return
	}

	// Pick the §4.5 covering subtree of [prev_treeSize, lm.TreeSize)
	// that contains `serial`.
	subtrees := s.cfg.Landmarks.LandmarkSubtrees(lm)
	var chosen tlogx.Subtree
	for _, st := range subtrees {
		if serial >= st.Start && serial < st.End {
			chosen = st
			break
		}
	}
	if chosen.End == 0 {
		// Inconsistent state: ContainingIndex said yes but no covering
		// subtree contains the index. Treat as not-yet-available.
		s.serveAltStub(w)
		return
	}

	subtreeHash, proof, err := s.cfg.SubtreeProof(chosen.Start, chosen.End, serial)
	if err != nil {
		http.Error(w, "subtree proof: "+err.Error(), http.StatusInternalServerError)
		return
	}

	mtcSubtree := cert.MTCSubtree{
		LogID: s.cfg.LogID,
		Start: chosen.Start, End: chosen.End,
		Hash: subtreeHash,
	}
	der, err := cert.BuildLandmarkRelativeCert(standalone, s.cfg.LogID, mtcSubtree, proof)
	if err != nil {
		http.Error(w, "build landmark cert: "+err.Error(), http.StatusInternalServerError)
		return
	}

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/pem-certificate-chain-with-properties") {
		w.Header().Set("Content-Type", "application/pem-certificate-chain-with-properties")
		// Landmark-relative property list per PROJECT_PLAN §8.5:
		// trust_anchor_id = the specific landmark's TA ID; plus
		// additional_trust_anchor_ranges covering [N, N+max_active-1]
		// with base = sequence base_id.
		maxActive := uint64(s.cfg.Landmarks.MaxActive())
		if maxActive < 1 {
			maxActive = 1
		}
		base := s.cfg.LandmarkBaseID
		props := []cert.CertificateProperty{
			{Type: cert.PropertyTrustAnchorID, TrustAnchorID: lm.TrustAnchorID(base)},
			{Type: cert.PropertyAdditionalTAnchorRanges, Ranges: []cert.TrustAnchorRange{{
				Base: base,
				Min:  lm.Number,
				Max:  lm.Number + maxActive - 1,
			}}},
		}
		pl, err := cert.BuildPropertyList(props)
		if err != nil {
			http.Error(w, "build properties: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(cert.EncodePEMWithProperties(der, pl))
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// serveAltStub is the §9-permitted "not yet available" response.
func (s *Server) serveAltStub(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "3600")
	http.Error(w, "landmark-relative certificate not yet available", http.StatusServiceUnavailable)
}

// certBelongsToAccount returns true if the cert with the given id is
// the certificate produced for an order whose AccountID matches.
func (s *Server) certBelongsToAccount(certID, accountID string) bool {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	for _, o := range s.state.orders {
		if o.CertificateID == certID {
			return o.AccountID == accountID
		}
	}
	return false
}

func (s *Server) problem(w http.ResponseWriter, status int, kind, detail string) {
	s.problemFull(w, status, kind, detail, nil)
}

func (s *Server) problemFull(w http.ResponseWriter, status int, kind, detail string, algorithms []string) {
	w.Header().Set("Content-Type", "application/problem+json")
	s.issueNonce(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Problem{Type: kind, Detail: detail, Status: status, Algorithms: algorithms})
}

func randomToken() string {
	var b [32]byte
	_, _ = io.ReadFull(rand.Reader, b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
