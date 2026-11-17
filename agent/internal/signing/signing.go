// Package signing verifies short-lived, single-use, signed URL grants.
//
// A grant is a canonical string of fields signed by the web app with an Ed25519
// private key. The Agent holds only the public key. Grants carry an expiry,
// a nonce, and the operation/file/user they authorize; the Agent rejects any
// grant that does not match the request exactly.
package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Grant is the set of fields the web app signs.
type Grant struct {
	Op      string // "upload", "download", "delete"
	FileID  string // opaque file ID, never a path
	UserID  string
	Nonce   string
	Expires int64 // unix seconds
}

// Canonical returns the exact string that is signed and verified.
func (g Grant) Canonical() string {
	return strings.Join([]string{
		"v1", g.Op, g.FileID, g.UserID, g.Nonce, strconv.FormatInt(g.Expires, 10),
	}, "\n")
}

const (
	MaxTTL      = 5 * time.Minute
	ClockSkew   = 60 * time.Second
	nonceRetain = 10 * time.Minute
)

var (
	ErrBadSignature = errors.New("invalid signature")
	ErrExpired      = errors.New("grant expired")
	ErrNotYetValid  = errors.New("grant not yet valid")
	ErrTooLong      = errors.New("grant lifetime exceeds maximum")
	ErrReplayed     = errors.New("grant already used")
	ErrMismatch     = errors.New("grant does not match request")
)

// NonceStore records used nonces so each grant is single-use.
type NonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewNonceStore() *NonceStore {
	return &NonceStore{seen: make(map[string]time.Time)}
}

// Claim marks a nonce as used. It returns ErrReplayed if the nonce was already used.
func (s *NonceStore) Claim(nonce string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.seen {
		if now.Sub(t) > nonceRetain {
			delete(s.seen, k)
		}
	}
	if _, ok := s.seen[nonce]; ok {
		return ErrReplayed
	}
	s.seen[nonce] = now
	return nil
}

// Verifier checks grants against the public key.
type Verifier struct {
	pub   ed25519.PublicKey
	nonce *NonceStore
	now   func() time.Time
}

func NewVerifier(pubKeyB64 string, nonces *NonceStore) (*Verifier, error) {
	raw, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	return &Verifier{pub: ed25519.PublicKey(raw), nonce: nonces, now: time.Now}, nil
}

// Verify checks signature, expiry (with skew tolerance), lifetime, and the
// expected operation/file/user, then claims the nonce. Each grant succeeds once.
func (v *Verifier) Verify(g Grant, sigB64 string, wantOp, wantFileID, wantUserID string) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || !ed25519.Verify(v.pub, []byte(g.Canonical()), sig) {
		return ErrBadSignature
	}
	if g.Op != wantOp || g.FileID != wantFileID || g.UserID != wantUserID {
		return ErrMismatch
	}
	now := v.now()
	exp := time.Unix(g.Expires, 0)
	if now.After(exp.Add(ClockSkew)) {
		return ErrExpired
	}
	if exp.Sub(now) > MaxTTL+ClockSkew {
		return ErrTooLong
	}
	if g.Nonce == "" {
		return ErrBadSignature
	}
	return v.nonce.Claim(g.Nonce, now)
}
