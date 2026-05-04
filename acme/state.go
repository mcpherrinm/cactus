package acme

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// NewState returns a freshly initialized State.
func NewState() *State {
	return &State{
		nonces:   make(map[string]time.Time),
		accounts: make(map[string]*account),
		orders:   make(map[string]*order),
		authzs:   make(map[string]*authz),
		challs:   make(map[string]*challenge),
	}
}

// nonceLifetime bounds how long a nonce is accepted; 5 minutes is a
// generous upper bound for test latency.
const nonceLifetime = 5 * time.Minute

func (s *State) NewNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[id] = time.Now()
	s.gcNoncesLocked()
	return id
}

// ConsumeNonce returns true if the given nonce is valid and consumes it.
// Nonces are single-use, per RFC 8555 §6.5.
func (s *State) ConsumeNonce(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.nonces[id]
	if !ok {
		return false
	}
	delete(s.nonces, id)
	return time.Since(t) <= nonceLifetime
}

func (s *State) gcNoncesLocked() {
	cutoff := time.Now().Add(-nonceLifetime)
	for k, t := range s.nonces {
		if t.Before(cutoff) {
			delete(s.nonces, k)
		}
	}
}

// GetOrCreateAccount returns the account for the given JWK thumbprint,
// creating a new entry if `create` is true and none exists. The
// returned `created` is true if the account was created in this call.
func (s *State) GetOrCreateAccount(thumbprint string, jwkBytes []byte, contact []string, create bool) (acct *account, created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[thumbprint]
	if ok {
		return a, false, nil
	}
	if !create {
		return nil, false, fmt.Errorf("account not found")
	}
	a = &account{
		ID:       thumbprint,
		Status:   "valid",
		Contact:  contact,
		JWKBytes: jwkBytes,
	}
	s.accounts[thumbprint] = a
	if err := s.saveLocked("account", a.ID, a); err != nil {
		return nil, false, err
	}
	return a, true, nil
}

// PutOrder records a new order, returning its assigned ID.
func (s *State) PutOrder(o *order) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orders[o.ID] = o
	_ = s.saveLocked("order", o.ID, o)
}

func (s *State) GetOrder(id string) (*order, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orders[id]
	return o, ok
}

// UpdateOrder applies fn under the lock. The order must already exist.
func (s *State) UpdateOrder(id string, fn func(*order)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orders[id]
	if !ok {
		return false
	}
	fn(o)
	_ = s.saveLocked("order", o.ID, o)
	return true
}

// TryClaimReadyOrder atomically transitions an order from "ready" to
// "processing" and returns true on success. Concurrent finalize calls
// race here; only one wins.
func (s *State) TryClaimReadyOrder(id string) (*order, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orders[id]
	if !ok {
		return nil, false
	}
	if o.Status != "ready" {
		return o, false
	}
	o.Status = "processing"
	_ = s.saveLocked("order", o.ID, o)
	return o, true
}

func (s *State) PutAuthz(a *authz) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authzs[a.ID] = a
	_ = s.saveLocked("authz", a.ID, a)
}

func (s *State) GetAuthz(id string) (*authz, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.authzs[id]
	return a, ok
}

// UpdateAuthz applies fn under the lock.
func (s *State) UpdateAuthz(id string, fn func(*authz)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.authzs[id]
	if !ok {
		return false
	}
	fn(a)
	_ = s.saveLocked("authz", a.ID, a)
	return true
}

func (s *State) PutChallenge(c *challenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challs[c.ID] = c
	_ = s.saveLocked("chall", c.ID, c)
}

func (s *State) GetChallenge(id string) (*challenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challs[id]
	return c, ok
}

// UpdateChallenge applies fn under the lock.
func (s *State) UpdateChallenge(id string, fn func(*challenge)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challs[id]
	if !ok {
		return false
	}
	fn(c)
	_ = s.saveLocked("chall", c.ID, c)
	return true
}

// newID returns a 32-char hex string suitable for use as an ID.
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Compile-time assertion that the embedded sync.Mutex zero value works.
var _ sync.Locker = (*sync.Mutex)(nil)
