package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func setup(t *testing.T) (*Verifier, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(base64.StdEncoding.EncodeToString(pub), NewNonceStore())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	v.now = func() time.Time { return now }
	return v, priv, now
}

func sign(priv ed25519.PrivateKey, g Grant) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(g.Canonical())))
}

func grant(now time.Time, nonce string) Grant {
	return Grant{Op: "download", FileID: "f1", UserID: "u1", Nonce: nonce, Expires: now.Add(60 * time.Second).Unix()}
}

func TestValidGrantSucceedsOnce(t *testing.T) {
	v, priv, now := setup(t)
	g := grant(now, "n1")
	s := sign(priv, g)
	if err := v.Verify(g, s, "download", "f1", "u1"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if err := v.Verify(g, s, "download", "f1", "u1"); err != ErrReplayed {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestTamperedGrantRejected(t *testing.T) {
	v, priv, now := setup(t)
	g := grant(now, "n2")
	s := sign(priv, g)
	g.FileID = "other"
	if err := v.Verify(g, s, "download", "other", "u1"); err != ErrBadSignature {
		t.Fatalf("expected bad signature, got %v", err)
	}
}

func TestWrongFileOrUserOrOpRejected(t *testing.T) {
	v, priv, now := setup(t)
	g := grant(now, "n3")
	s := sign(priv, g)
	if err := v.Verify(g, s, "delete", "f1", "u1"); err != ErrMismatch {
		t.Fatalf("op mismatch: got %v", err)
	}
	if err := v.Verify(g, s, "download", "f2", "u1"); err != ErrMismatch {
		t.Fatalf("file mismatch: got %v", err)
	}
	if err := v.Verify(g, s, "download", "f1", "u2"); err != ErrMismatch {
		t.Fatalf("user mismatch: got %v", err)
	}
}

func TestExpiryAndClockSkew(t *testing.T) {
	v, priv, now := setup(t)
	g := Grant{Op: "download", FileID: "f1", UserID: "u1", Nonce: "n4", Expires: now.Add(-30 * time.Second).Unix()}
	if err := v.Verify(g, sign(priv, g), "download", "f1", "u1"); err != nil {
		t.Fatalf("within skew should pass, got %v", err)
	}
	g2 := Grant{Op: "download", FileID: "f1", UserID: "u1", Nonce: "n5", Expires: now.Add(-120 * time.Second).Unix()}
	if err := v.Verify(g2, sign(priv, g2), "download", "f1", "u1"); err != ErrExpired {
		t.Fatalf("expired grant: got %v", err)
	}
}

func TestOverlongLifetimeRejected(t *testing.T) {
	v, priv, now := setup(t)
	g := Grant{Op: "download", FileID: "f1", UserID: "u1", Nonce: "n6", Expires: now.Add(time.Hour).Unix()}
	if err := v.Verify(g, sign(priv, g), "download", "f1", "u1"); err != ErrTooLong {
		t.Fatalf("expected ErrTooLong, got %v", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	v, _, now := setup(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	g := grant(now, "n7")
	if err := v.Verify(g, sign(otherPriv, g), "download", "f1", "u1"); err != ErrBadSignature {
		t.Fatalf("expected bad signature, got %v", err)
	}
}
