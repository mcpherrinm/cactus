// Package acme implements a minimal RFC 8555 ACME server with the §9
// extensions of draft-ietf-plants-merkle-tree-certs-03 (PEM-with-properties
// content type, alternate URL for landmark-relative cert).
//
// This is a test-grade implementation: auto-pass challenges, in-memory
// nonces, single CA cosigner. See PROJECT_PLAN §1 Non-Goals.
package acme

import (
	"encoding/json"
	"sync"
	"time"
)

// Directory is the JSON object served at GET /directory.
type Directory struct {
	NewNonce   string   `json:"newNonce"`
	NewAccount string   `json:"newAccount"`
	NewOrder   string   `json:"newOrder"`
	RevokeCert string   `json:"revokeCert,omitempty"`
	KeyChange  string   `json:"keyChange,omitempty"`
	Meta       *DirMeta `json:"meta,omitempty"`
}

// DirMeta is the directory metadata.
type DirMeta struct {
	TermsOfService string `json:"termsOfService,omitempty"`
	Website        string `json:"website,omitempty"`
}

// Identifier is the identifier in an order or authz.
type Identifier struct {
	Type  string `json:"type"` // "dns" or "ip"
	Value string `json:"value"`
}

// NewAccountReq is the JWS payload for new-account.
type NewAccountReq struct {
	Contact              []string `json:"contact,omitempty"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitempty"`
}

// AccountResp is the body returned from new-account / GET account.
type AccountResp struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders,omitempty"`
}

// NewOrderReq is the JWS payload for new-order.
type NewOrderReq struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore,omitempty"`
	NotAfter    string       `json:"notAfter,omitempty"`
}

// OrderResp is the body returned for an order.
type OrderResp struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	NotBefore      string       `json:"notBefore,omitempty"`
	NotAfter       string       `json:"notAfter,omitempty"`
}

// AuthzResp is the body returned for an authorization.
type AuthzResp struct {
	Status     string         `json:"status"`
	Identifier Identifier     `json:"identifier"`
	Challenges []ChallengeMsg `json:"challenges"`
	Expires    string         `json:"expires,omitempty"`
}

// ChallengeMsg is a single challenge in an authz.
type ChallengeMsg struct {
	Type      string `json:"type"`
	Status    string `json:"status"`
	URL       string `json:"url"`
	Token     string `json:"token,omitempty"`
	Validated string `json:"validated,omitempty"`
}

// FinalizeReq is the payload for the finalize endpoint.
type FinalizeReq struct {
	CSR string `json:"csr"` // base64url-encoded DER
}

// Problem is the RFC 7807 problem document used for ACME errors. The
// Algorithms field is populated for badSignatureAlgorithm responses
// (RFC 8555 §6.2: "MUST include an `algorithms` field").
type Problem struct {
	Type       string   `json:"type"`
	Detail     string   `json:"detail,omitempty"`
	Status     int      `json:"status,omitempty"`
	Algorithms []string `json:"algorithms,omitempty"`
}

// MarshalJSON satisfies json.Marshaler — kept here so the type is
// trivially serialisable.
func (p Problem) MarshalJSON() ([]byte, error) {
	type alias Problem
	return json.Marshal(alias(p))
}

// State holds the in-memory + on-disk ACME state. It is goroutine-safe.
type State struct {
	mu       sync.Mutex
	nonces   map[string]time.Time
	accounts map[string]*account // key = JWK thumbprint
	orders   map[string]*order   // key = order ID
	authzs   map[string]*authz   // key = authz ID
	challs   map[string]*challenge

	// fs, if non-nil, persists every state mutation to disk.
	fs storageIface
}

// storageIface is the small subset of storage.FS that State uses,
// duplicated as an interface here to avoid import cycles in the
// types-only file.
type storageIface interface {
	Get(name string) ([]byte, error)
	Put(name string, data []byte, exclusive bool) error
	Exists(name string) (bool, error)
	Mkdir(name string) error
}

type account struct {
	ID       string // JWK thumbprint
	Status   string
	Contact  []string
	JWKBytes []byte // serialized JWK for re-loading
}

type order struct {
	ID            string
	AccountID     string
	Status        string
	Expires       time.Time
	Identifiers   []Identifier
	AuthzIDs      []string
	NotBefore     time.Time
	NotAfter      time.Time
	CertificateID string // populated after issuance
}

type authz struct {
	ID         string
	OrderID    string
	Status     string
	Identifier Identifier
	ChallIDs   []string
}

type challenge struct {
	ID      string
	AuthzID string
	Type    string
	Status  string
	Token   string
}
