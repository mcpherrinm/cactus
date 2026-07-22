// Package pollinate keeps MTC mirrors in sync with the issuance logs
// they carry. It follows the Chrome MTC cosigners list (the JSON file
// published under https://www.gstatic.com/mtcs/cosigners/v1/), watches
// every issuer's logs and every mirror's copy of them, and — when a
// mirror has been lagging the log head for longer than a configured
// delay — replays the missing entries to it over the
// c2sp.org/tlog-mirror write API.
//
// CAs are expected to push to mirrors themselves; pollinate is the
// backstop that repairs mirrors the CA is failing to reach (or that
// were added after the fact). It never needs to be trusted: everything
// it reads is authenticated against a checkpoint root hash, and the
// receiving mirror re-verifies the log signature and every subtree
// consistency proof anyway.
package pollinate

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// CosignersList is the parsed Chrome cosigners file, per
// https://www.gstatic.com/mtcs/cosigners/v1/cosigners_schema.json.
type CosignersList struct {
	Timestamp time.Time  `json:"timestamp"`
	Version   string     `json:"version"`
	Operators []Operator `json:"operators"`
	Issuers   []Signer   `json:"issuers"`
	Mirrors   []Signer   `json:"mirrors"`
}

// Operator is one cosigner operator.
type Operator struct {
	Name  string   `json:"name"`
	Email []string `json:"email"`
}

// StateChange is one entry of a signer's state history, newest first.
type StateChange struct {
	State      string    `json:"state"`
	StateStart time.Time `json:"state_start"`
}

// OperatorChange is one entry of a signer's operator history, newest
// first.
type OperatorChange struct {
	Name          string    `json:"name"`
	OperatorStart time.Time `json:"operator_start"`
}

// Signer is one issuer log or mirror from the cosigners file.
type Signer struct {
	FriendlyName           string           `json:"friendly_name"`
	BaseID                 string           `json:"base_id"`
	StateHistory           []StateChange    `json:"state_history"`
	OperatorHistory        []OperatorChange `json:"operator_history"`
	BaseURL                string           `json:"base_url"`
	Type                   string           `json:"type"`
	Realm                  string           `json:"realm"`
	MaxCertLifetimeSeconds int64            `json:"max_cert_lifetime_seconds"`
	KeySHA256              string           `json:"key_sha256"`
}

// CurrentState returns the signer's current inclusion state, or "" if
// no state history is published (issuers typically have none).
func (s Signer) CurrentState() string {
	if len(s.StateHistory) == 0 {
		return ""
	}
	return s.StateHistory[0].State
}

// ParseCosigners parses and minimally validates a cosigners file.
func ParseCosigners(data []byte) (*CosignersList, error) {
	var l CosignersList
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("pollinate: parse cosigners: %w", err)
	}
	if l.Version == "" {
		return nil, errors.New("pollinate: cosigners file has no version")
	}
	check := func(kind string, ss []Signer) error {
		for i, s := range ss {
			if s.BaseID == "" {
				return fmt.Errorf("pollinate: %s[%d] (%q) has no base_id", kind, i, s.FriendlyName)
			}
			if s.BaseURL == "" {
				return fmt.Errorf("pollinate: %s %q has no base_url", kind, s.BaseID)
			}
			if len(s.KeySHA256) != 64 {
				return fmt.Errorf("pollinate: %s %q key_sha256 %q is not 64 hex chars", kind, s.BaseID, s.KeySHA256)
			}
			if _, err := hex.DecodeString(s.KeySHA256); err != nil {
				return fmt.Errorf("pollinate: %s %q key_sha256: %w", kind, s.BaseID, err)
			}
		}
		return nil
	}
	if err := check("issuers", l.Issuers); err != nil {
		return nil, err
	}
	if err := check("mirrors", l.Mirrors); err != nil {
		return nil, err
	}
	return &l, nil
}

// ParseKeys parses the companion PEM bundle (cosigners.pem): a sequence
// of PUBLIC KEY blocks, each holding one signer's SubjectPublicKeyInfo.
// The returned map is keyed by the lowercase hex SHA-256 of the DER —
// the value the cosigners file's key_sha256 fields carry — so lookups
// need no reliance on the "# <hash>" comment lines in the file.
func ParseKeys(data []byte) (map[string][]byte, error) {
	keys := make(map[string][]byte)
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("pollinate: unexpected PEM block %q in key bundle", block.Type)
		}
		sum := sha256.Sum256(block.Bytes)
		keys[hex.EncodeToString(sum[:])] = block.Bytes
	}
	if len(keys) == 0 {
		return nil, errors.New("pollinate: no PUBLIC KEY blocks in key bundle")
	}
	return keys, nil
}

// oidMLDSA44 is id-ml-dsa-44 (NIST FIPS 204), per RFC 9881.
var oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}

// mldsa44KeyFromSPKI extracts the raw FIPS 204 ML-DSA-44 public key from
// a DER SubjectPublicKeyInfo, or reports (nil, false) when the SPKI is
// for some other algorithm (the cosigners list also carries e.g. Ed25519
// issuer keys, which pollinate cannot verify signatures from).
func mldsa44KeyFromSPKI(spki []byte) ([]byte, bool) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(spki, &seq); err != nil {
		return nil, false
	}
	var algID asn1.RawValue
	rest, err := asn1.Unmarshal(seq.Bytes, &algID)
	if err != nil {
		return nil, false
	}
	var algOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(algID.Bytes, &algOID); err != nil {
		return nil, false
	}
	if !algOID.Equal(oidMLDSA44) {
		return nil, false
	}
	var bits asn1.BitString
	if _, err := asn1.Unmarshal(rest, &bits); err != nil {
		return nil, false
	}
	if bits.BitLength%8 != 0 {
		return nil, false
	}
	return bits.RightAlign(), true
}
