// Package server exposes the Agent's signed-URL endpoints.
//
// Every endpoint requires a grant in the query string: op, file id, user id,
// nonce, expiry, and a base64 Ed25519 signature. The grant is verified
// before any file is touched. No endpoint accepts a path.
package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"mycloud/agent/internal/signing"
	"mycloud/agent/internal/storage"
)

const (
	maxUploadBytes = 5 << 30  // 5 GiB per single-request upload
	maxChunkBytes  = 64 << 20 // 64 MiB per resumable chunk
)

type Server struct {
	verifier    *signing.Verifier
	store       *storage.Store
	defaultRoot string
}

// New builds the server. defaultRoot is the storage root new files are placed in.
func New(v *signing.Verifier, s *storage.Store, defaultRoot string) *Server {
	return &Server{verifier: v, store: s, defaultRoot: defaultRoot}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("PUT /v1/files/{id}", s.upload)
	mux.HandleFunc("GET /v1/files/{id}", s.download)
	mux.HandleFunc("DELETE /v1/files/{id}", s.delete)
	mux.HandleFunc("PATCH /v1/files/{id}", s.appendChunk)
	mux.HandleFunc("POST /v1/files/{id}/finalize", s.finalize)
	return secureHeaders(mux)
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// authorize parses and verifies the grant in the query string for op on file id.
func (s *Server) authorize(r *http.Request, wantOp string) (string, error) {
	q := r.URL.Query()
	exp, err := strconv.ParseInt(q.Get("exp"), 10, 64)
	if err != nil {
		return "", errors.New("bad exp")
	}
	id := r.PathValue("id")
	g := signing.Grant{
		Op:      q.Get("op"),
		FileID:  id,
		UserID:  q.Get("uid"),
		Nonce:   q.Get("nonce"),
		Expires: exp,
	}
	if err := s.verifier.Verify(g, q.Get("sig"), wantOp, id, g.UserID); err != nil {
		return "", err
	}
	return id, nil
}

// checkOwner ensures the grant's user is the one recorded when the file was uploaded.
// A signed grant alone is not enough: it must also be for the file's owner.
func (s *Server) checkOwner(id string, r *http.Request) error {
	owner, err := s.store.Owner(id)
	if err != nil {
		return err
	}
	if owner != r.URL.Query().Get("uid") {
		return signing.ErrMismatch
	}
	return nil
}

func reject(w http.ResponseWriter, err error) {
	status := http.StatusForbidden
	switch {
	case errors.Is(err, signing.ErrReplayed), errors.Is(err, signing.ErrExpired), errors.Is(err, signing.ErrNotYetValid):
		status = http.StatusUnauthorized
	case errors.Is(err, signing.ErrMismatch):
		status = http.StatusForbidden
	case errors.Is(err, storage.ErrUnknownFile):
		status = http.StatusNotFound
	}
	http.Error(w, http.StatusText(status), status)
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	id, err := s.authorize(r, "upload")
	if err != nil {
		reject(w, err)
		return
	}
	expected := strings.ToLower(r.Header.Get("X-Content-SHA256"))
	if len(expected) != sha256.Size*2 {
		http.Error(w, "missing or invalid X-Content-SHA256", http.StatusBadRequest)
		return
	}
	if _, err := hex.DecodeString(expected); err != nil {
		http.Error(w, "missing or invalid X-Content-SHA256", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if _, err := s.store.Allocate(id, r.URL.Query().Get("uid"), s.defaultRoot); err != nil {
		if errors.Is(err, storage.ErrOwnerMismatch) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		http.Error(w, "no storage root", http.StatusInternalServerError)
		return
	}
	h := sha256.New()
	n, err := s.store.Write(id, io.TeeReader(r.Body, h))
	if errors.Is(err, storage.ErrExists) {
		http.Error(w, "file already written", http.StatusConflict)
		return
	}
	if err != nil {
		s.discard(id)
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	// The client-declared hash must match the bytes actually stored; otherwise remove them.
	if hex.EncodeToString(h.Sum(nil)) != expected {
		s.discard(id)
		http.Error(w, "checksum mismatch", http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"bytes": n, "sha256": expected})
}

// appendChunk writes one chunk at ?offset=N. Each chunk carries its own
// X-Content-SHA256 so corruption is caught per chunk, and the offset must equal
// the stored size, which makes client retries idempotent.
func (s *Server) appendChunk(w http.ResponseWriter, r *http.Request) {
	id, err := s.authorize(r, "upload")
	if err != nil {
		reject(w, err)
		return
	}
	if _, err := s.store.Allocate(id, r.URL.Query().Get("uid"), s.defaultRoot); err != nil {
		if errors.Is(err, storage.ErrOwnerMismatch) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		http.Error(w, "no storage root", http.StatusInternalServerError)
		return
	}
	off, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	if err != nil || off < 0 {
		http.Error(w, "bad offset", http.StatusBadRequest)
		return
	}
	expected := strings.ToLower(r.Header.Get("X-Content-SHA256"))
	if _, err := hex.DecodeString(expected); err != nil || len(expected) != sha256.Size*2 {
		http.Error(w, "missing or invalid X-Content-SHA256", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxChunkBytes)
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "chunk too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	sum := sha256.Sum256(buf)
	if hex.EncodeToString(sum[:]) != expected {
		http.Error(w, "chunk checksum mismatch", http.StatusUnprocessableEntity)
		return
	}
	size, err := s.store.Append(id, off, bytes.NewReader(buf))
	if err != nil {
		if errors.Is(err, storage.ErrOffsetMismatch) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"size": size})
			return
		}
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"size": size})
}

// finalize verifies the whole file's SHA-256 against X-Content-SHA256. On mismatch
// the file is removed, so only fully verified content is ever kept.
func (s *Server) finalize(w http.ResponseWriter, r *http.Request) {
	id, err := s.authorize(r, "finalize")
	if err != nil {
		reject(w, err)
		return
	}
	if err := s.checkOwner(id, r); err != nil {
		reject(w, err)
		return
	}
	expected := strings.ToLower(r.Header.Get("X-Content-SHA256"))
	if _, err := hex.DecodeString(expected); err != nil || len(expected) != sha256.Size*2 {
		http.Error(w, "missing or invalid X-Content-SHA256", http.StatusBadRequest)
		return
	}
	p, err := s.store.Resolve(id)
	if err != nil {
		reject(w, err)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	f.Close()
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		s.discard(id)
		http.Error(w, "checksum mismatch", http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"bytes": n, "sha256": expected})
}

// discard removes a partially written or corrupt file and forgets its ID.
func (s *Server) discard(id string) {
	if p, err := s.store.Resolve(id); err == nil {
		_ = os.Remove(p)
	}
	s.store.Forget(id)
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	id, err := s.authorize(r, "download")
	if err != nil {
		reject(w, err)
		return
	}
	if err := s.checkOwner(id, r); err != nil {
		reject(w, err)
		return
	}
	p, err := s.store.Resolve(id)
	if err != nil {
		reject(w, err)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.Error(w, "stat failed", http.StatusInternalServerError)
		return
	}
	// http.ServeContent handles Range requests and conditional headers.
	w.Header().Set("Content-Disposition", "attachment")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", st.ModTime(), f)
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	id, err := s.authorize(r, "delete")
	if err != nil {
		reject(w, err)
		return
	}
	if err := s.checkOwner(id, r); err != nil {
		reject(w, err)
		return
	}
	p, err := s.store.Resolve(id)
	if err != nil {
		reject(w, err)
		return
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	s.store.Forget(id)
	w.WriteHeader(http.StatusNoContent)
}
