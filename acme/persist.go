package acme

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/letsencrypt/cactus/storage"
)

// Storage controls where State persists its data. If nil, State is
// in-memory only.
type Storage = storage.FS

// AttachStorage wires fs into the State. After this returns, every
// mutating call (PutAccount, PutOrder, …) writes a JSON blob to disk
// before releasing the lock. Call LoadFromStorage first if there is
// existing data on disk.
func (s *State) AttachStorage(fs Storage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fs = fs
}

// LoadFromStorage reads state from fs. Account, order, authz, and
// challenge JSON blobs are loaded. Cert DERs are loaded by certID.
// Nonces are not persisted; they are ephemeral per RFC 8555 §6.5.
func (s *State) LoadFromStorage(fs Storage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fs != nil && s.fs != fs {
		return errors.New("acme: storage already attached")
	}
	s.fs = fs

	type pair struct {
		kind, prefix string
	}
	for _, p := range []pair{
		{"account", "state/accounts/"},
		{"order", "state/orders/"},
		{"authz", "state/authzs/"},
		{"chall", "state/challs/"},
	} {
		if err := s.loadKindLocked(p.kind, p.prefix); err != nil {
			return err
		}
	}
	return nil
}

// CertStore returns a small interface for storing/retrieving issued
// certificate DERs.
type CertStore struct {
	fs Storage
}

func NewCertStore(fs Storage) *CertStore {
	return &CertStore{fs: fs}
}

func (c *CertStore) Put(id string, der []byte) error {
	if c.fs == nil {
		return nil
	}
	return c.fs.Put("state/certs/"+id+".der", der, false)
}

func (c *CertStore) Get(id string) ([]byte, error) {
	if c.fs == nil {
		return nil, errors.New("no storage")
	}
	return c.fs.Get("state/certs/" + id + ".der")
}

func (s *State) saveLocked(kind, id string, v interface{}) error {
	if s.fs == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("acme: marshal %s/%s: %w", kind, id, err)
	}
	return s.fs.Put("state/"+kind+"s/"+id+".json", data, false)
}

func (s *State) loadKindLocked(kind, prefix string) error {
	// Use the storage.FS's Get on a list-like API; we don't have a List
	// in the interface. Instead, walk via os.ReadDir on the disk path.
	disk, ok := s.fs.(*storage.Disk)
	if !ok {
		return nil // unsupported; only Disk supports listing.
	}
	root := disk.Root()
	dir := path.Join(root, prefix)
	entries, err := readDirIfExists(dir)
	if err != nil {
		return fmt.Errorf("acme: list %s: %w", dir, err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e, ".json") {
			continue
		}
		id := strings.TrimSuffix(e, ".json")
		raw, err := disk.Get(prefix + e)
		if err != nil {
			return err
		}
		switch kind {
		case "account":
			var a account
			if err := json.Unmarshal(raw, &a); err != nil {
				return fmt.Errorf("decode account %s: %w", id, err)
			}
			s.accounts[a.ID] = &a
		case "order":
			var o order
			if err := json.Unmarshal(raw, &o); err != nil {
				return fmt.Errorf("decode order %s: %w", id, err)
			}
			s.orders[o.ID] = &o
		case "authz":
			var a authz
			if err := json.Unmarshal(raw, &a); err != nil {
				return fmt.Errorf("decode authz %s: %w", id, err)
			}
			s.authzs[a.ID] = &a
		case "chall":
			var c challenge
			if err := json.Unmarshal(raw, &c); err != nil {
				return fmt.Errorf("decode chall %s: %w", id, err)
			}
			s.challs[c.ID] = &c
		}
	}
	return nil
}

// readDirIfExists reads directory entries at path, returning an empty
// slice if the directory does not exist.
func readDirIfExists(p string) ([]string, error) {
	infos, err := readDir(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(infos))
	for _, name := range infos {
		out = append(out, name)
	}
	return out, nil
}

// JSON marshalling helpers — the in-package types use unexported fields
// so we add explicit Marshal helpers that emit a stable shape.

type accountJSON struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	JWK     string   `json:"jwk_hex"`
}

func (a *account) MarshalJSON() ([]byte, error) {
	return json.Marshal(accountJSON{
		ID:      a.ID,
		Status:  a.Status,
		Contact: a.Contact,
		JWK:     hex.EncodeToString(a.JWKBytes),
	})
}

func (a *account) UnmarshalJSON(b []byte) error {
	var j accountJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	jwk, err := hex.DecodeString(j.JWK)
	if err != nil {
		return err
	}
	a.ID = j.ID
	a.Status = j.Status
	a.Contact = j.Contact
	a.JWKBytes = jwk
	return nil
}

type orderJSON struct {
	ID            string       `json:"id"`
	AccountID     string       `json:"account_id"`
	Status        string       `json:"status"`
	Expires       time.Time    `json:"expires"`
	Identifiers   []Identifier `json:"identifiers"`
	AuthzIDs      []string     `json:"authz_ids"`
	NotBefore     time.Time    `json:"not_before,omitempty"`
	NotAfter      time.Time    `json:"not_after,omitempty"`
	CertificateID string       `json:"certificate_id,omitempty"`
}

func (o *order) MarshalJSON() ([]byte, error) {
	return json.Marshal(orderJSON{
		ID:            o.ID,
		AccountID:     o.AccountID,
		Status:        o.Status,
		Expires:       o.Expires,
		Identifiers:   o.Identifiers,
		AuthzIDs:      o.AuthzIDs,
		NotBefore:     o.NotBefore,
		NotAfter:      o.NotAfter,
		CertificateID: o.CertificateID,
	})
}

func (o *order) UnmarshalJSON(b []byte) error {
	var j orderJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	o.ID = j.ID
	o.AccountID = j.AccountID
	o.Status = j.Status
	o.Expires = j.Expires
	o.Identifiers = j.Identifiers
	o.AuthzIDs = j.AuthzIDs
	o.NotBefore = j.NotBefore
	o.NotAfter = j.NotAfter
	o.CertificateID = j.CertificateID
	return nil
}

type authzJSON struct {
	ID         string     `json:"id"`
	OrderID    string     `json:"order_id"`
	Status     string     `json:"status"`
	Identifier Identifier `json:"identifier"`
	ChallIDs   []string   `json:"chall_ids"`
}

func (a *authz) MarshalJSON() ([]byte, error) {
	return json.Marshal(authzJSON{
		ID: a.ID, OrderID: a.OrderID, Status: a.Status,
		Identifier: a.Identifier, ChallIDs: a.ChallIDs,
	})
}

func (a *authz) UnmarshalJSON(b []byte) error {
	var j authzJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	a.ID = j.ID
	a.OrderID = j.OrderID
	a.Status = j.Status
	a.Identifier = j.Identifier
	a.ChallIDs = j.ChallIDs
	return nil
}

type challJSON struct {
	ID      string `json:"id"`
	AuthzID string `json:"authz_id"`
	Type    string `json:"type"`
	Status  string `json:"status"`
	Token   string `json:"token"`
}

func (c *challenge) MarshalJSON() ([]byte, error) {
	return json.Marshal(challJSON{
		ID: c.ID, AuthzID: c.AuthzID, Type: c.Type,
		Status: c.Status, Token: c.Token,
	})
}

func (c *challenge) UnmarshalJSON(b []byte) error {
	var j challJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	c.ID = j.ID
	c.AuthzID = j.AuthzID
	c.Type = j.Type
	c.Status = j.Status
	c.Token = j.Token
	return nil
}
