package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mycloud/agent/internal/signing"
	"mycloud/agent/internal/storage"
)

const fileID = "11111111-2222-4333-8444-555555555555"
const userID = "user-1"

type fixture struct {
	srv  *httptest.Server
	priv ed25519.PrivateKey
	root string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	st, err := storage.New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	v, err := signing.NewVerifier(base64.StdEncoding.EncodeToString(pub), signing.NewNonceStore())
	if err != nil {
		t.Fatal(err)
	}
	h := New(v, st, root).Handler()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &fixture{srv: srv, priv: priv, root: root}
}

// grant returns the query string for a signed grant.
func (f *fixture) grant(t *testing.T, op, id, uid, nonce string, expires time.Time) string {
	t.Helper()
	g := signing.Grant{Op: op, FileID: id, UserID: uid, Nonce: nonce, Expires: expires.Unix()}
	sig := ed25519.Sign(f.priv, []byte(g.Canonical()))
	q := url.Values{}
	q.Set("op", op)
	q.Set("uid", uid)
	q.Set("nonce", nonce)
	q.Set("exp", strconv.FormatInt(expires.Unix(), 10))
	q.Set("sig", base64.StdEncoding.EncodeToString(sig))
	return q.Encode()
}

func (f *fixture) do(t *testing.T, method, path string, body io.Reader, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestUploadDownloadRoundTrip(t *testing.T) {
	f := newFixture(t)
	data := []byte("hello mycloud")
	exp := time.Now().Add(time.Minute)

	up := f.do(t, http.MethodPut, "/v1/files/"+fileID+"?"+f.grant(t, "upload", fileID, userID, "n-up-1", exp),
		strings.NewReader(string(data)), map[string]string{"X-Content-SHA256": sum(data)})
	if up.StatusCode != http.StatusOK {
		t.Fatalf("upload status %d", up.StatusCode)
	}

	dl := f.do(t, http.MethodGet, "/v1/files/"+fileID+"?"+f.grant(t, "download", fileID, userID, "n-dl-1", exp), nil, nil)
	got, _ := io.ReadAll(dl.Body)
	if dl.StatusCode != http.StatusOK || string(got) != string(data) {
		t.Fatalf("download status %d body %q", dl.StatusCode, got)
	}
	if dl.Header.Get("X-Content-Type-Options") != "nosniff" || dl.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("missing security headers: %v", dl.Header)
	}
}

func TestUploadRejectsChecksumMismatchAndRemovesBytes(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(time.Minute)
	res := f.do(t, http.MethodPut, "/v1/files/"+fileID+"?"+f.grant(t, "upload", fileID, userID, "n-bad-1", exp),
		strings.NewReader("tampered"), map[string]string{"X-Content-SHA256": sum([]byte("original"))})
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d", res.StatusCode)
	}
	// Nothing should remain on disk under the root.
	var found int
	_ = walk(f.root, func(string) { found++ })
	if found != 0 {
		t.Fatalf("expected corrupt upload removed, found %d files", found)
	}
}

func TestUploadRequiresValidChecksumHeader(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(time.Minute)
	res := f.do(t, http.MethodPut, "/v1/files/"+fileID+"?"+f.grant(t, "upload", fileID, userID, "n-hdr-1", exp),
		strings.NewReader("x"), nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 without checksum, got %d", res.StatusCode)
	}
}

func TestGrantIsSingleUse(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(time.Minute)
	qs := f.grant(t, "download", fileID, userID, "n-replay", exp)
	first := f.do(t, http.MethodGet, "/v1/files/"+fileID+"?"+qs, nil, nil)
	if first.StatusCode == http.StatusUnauthorized {
		t.Fatalf("first use should not be rejected")
	}
	second := f.do(t, http.MethodGet, "/v1/files/"+fileID+"?"+qs, nil, nil)
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed grant: want 401, got %d", second.StatusCode)
	}
}

func TestRejectsGrantForOtherOperationFileOrUser(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(time.Minute)
	// Create the file as userID so the owner check is what gets exercised.
	data := []byte("owned")
	up := f.do(t, http.MethodPut, "/v1/files/"+fileID+"?"+f.grant(t, "upload", fileID, userID, "n-seed", exp),
		strings.NewReader(string(data)), map[string]string{"X-Content-SHA256": sum(data)})
	if up.StatusCode != http.StatusOK {
		t.Fatalf("seed upload: %d", up.StatusCode)
	}
	// A download grant must not authorize a delete on the same file.
	qs := f.grant(t, "download", fileID, userID, "n-op", exp)
	res := f.do(t, http.MethodDelete, "/v1/files/"+fileID+"?"+qs, nil, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("op swap: want 403, got %d", res.StatusCode)
	}
	// A grant for another file ID must not work on this file.
	other := "99999999-2222-4333-8444-555555555555"
	qs2 := f.grant(t, "download", other, userID, "n-file", exp)
	res2 := f.do(t, http.MethodGet, "/v1/files/"+fileID+"?"+qs2, nil, nil)
	if res2.StatusCode != http.StatusForbidden {
		t.Fatalf("file swap: want 403, got %d", res2.StatusCode)
	}
	// A grant for another user must not work.
	qs3 := f.grant(t, "download", fileID, "someone-else", "n-user", exp)
	res3 := f.do(t, http.MethodGet, "/v1/files/"+fileID+"?"+qs3, nil, nil)
	if res3.StatusCode != http.StatusForbidden {
		t.Fatalf("user swap: want 403, got %d", res3.StatusCode)
	}
}

func TestRejectsExpiredGrant(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(-10 * time.Minute)
	res := f.do(t, http.MethodGet, "/v1/files/"+fileID+"?"+f.grant(t, "download", fileID, userID, "n-old", exp), nil, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired grant: want 401, got %d", res.StatusCode)
	}
}

func TestRejectsUnsignedRequest(t *testing.T) {
	f := newFixture(t)
	res := f.do(t, http.MethodGet, "/v1/files/"+fileID+"?op=download&uid=x&nonce=n&exp=1&sig=AAAA", nil, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("unsigned: want 403, got %d", res.StatusCode)
	}
}

func TestRejectsPathLikeFileID(t *testing.T) {
	f := newFixture(t)
	exp := time.Now().Add(time.Minute)
	bad := "..%2F..%2Fetc%2Fpasswd"
	qs := f.grant(t, "download", "../../etc/passwd", userID, "n-trav", exp)
	res := f.do(t, http.MethodGet, fmt.Sprintf("/v1/files/%s?%s", bad, qs), nil, nil)
	if res.StatusCode == http.StatusOK {
		t.Fatalf("path-like id must never be served")
	}
}

func TestHealthIsPublicAndNoPaths(t *testing.T) {
	f := newFixture(t)
	res := f.do(t, http.MethodGet, "/health", nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("health: %d", res.StatusCode)
	}
}

func walk(dir string, fn func(string)) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			fn(p)
		}
		return nil
	})
}
