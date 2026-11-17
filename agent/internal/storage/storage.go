// Package storage maps opaque file IDs to paths under configured roots.
//
// The Agent never accepts a path from the network. Callers pass only a file ID;
// the path is derived from a registry the Agent owns, and every resolved path
// must stay inside one of the configured roots.
package storage

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

var (
	ErrUnknownFile    = errors.New("unknown file id")
	ErrOutsideRoot    = errors.New("path escapes configured root")
	ErrBadID          = errors.New("invalid file id")
	ErrOwnerMismatch  = errors.New("file owned by another user")
	ErrOffsetMismatch = errors.New("chunk offset does not match stored size")
	ErrExists         = errors.New("file already written")
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type entry struct {
	path  string
	owner string
}

type Store struct {
	mu    sync.RWMutex
	roots []string
	files map[string]entry // file id -> path and owner
}

// New creates a store confined to the given roots. Roots are made absolute and cleaned.
func New(roots []string) (*Store, error) {
	clean := make([]string, 0, len(roots))
	for _, r := range roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(abs, 0o750); err != nil {
			return nil, err
		}
		clean = append(clean, filepath.Clean(abs))
	}
	return &Store{roots: clean, files: make(map[string]entry)}, nil
}

// Within reports whether path is inside root (after cleaning). Both must be absolute.
func Within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !filepath.IsAbs(rel) && (len(rel) < 3 || rel[:3] != ".."+string(filepath.Separator))
}

// Allocate chooses a path for a new file ID under the given root and records its owner.
// An existing ID can only be re-allocated by its original owner.
func (s *Store) Allocate(id, owner, root string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", ErrBadID
	}
	if !s.isRoot(root) {
		return "", ErrOutsideRoot
	}
	p := filepath.Join(root, id[:2], id)
	if !Within(root, p) {
		return "", ErrOutsideRoot
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.files[id]; ok && prev.owner != owner {
		return "", ErrOwnerMismatch
	}
	s.files[id] = entry{path: p, owner: owner}
	return p, nil
}

// Owner returns the owner recorded for a file ID.
func (s *Store) Owner(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", ErrBadID
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.files[id]
	if !ok {
		return "", ErrUnknownFile
	}
	return e.owner, nil
}

// Resolve returns the path for a known file ID, re-checking it is inside a root.
func (s *Store) Resolve(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", ErrBadID
	}
	s.mu.RLock()
	e, ok := s.files[id]
	s.mu.RUnlock()
	if !ok {
		return "", ErrUnknownFile
	}
	for _, r := range s.roots {
		if Within(r, e.path) {
			return e.path, nil
		}
	}
	return "", ErrOutsideRoot
}

// Forget removes an ID from the registry (used after a verified delete).
func (s *Store) Forget(id string) {
	s.mu.Lock()
	delete(s.files, id)
	s.mu.Unlock()
}

// Write copies r into the file for id, returning the bytes written.
// The file must have been allocated first; writes never create registry entries.
func (s *Store) Write(id string, r io.Reader) (int64, error) {
	p, err := s.Resolve(id)
	if err != nil {
		return 0, err
	}
	// O_EXCL: a finished file is never silently replaced by a second write.
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if errors.Is(err, fs.ErrExist) {
		return 0, ErrExists
	}
	if err != nil {
		return 0, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	return io.Copy(f, r)
}

// Append writes r at byte offset off. The current size must equal off, so a
// retried or out-of-order chunk can never corrupt earlier bytes. It returns the new size.
func (s *Store) Append(id string, off int64, r io.Reader) (int64, error) {
	p, err := s.Resolve(id)
	if err != nil {
		return 0, err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return 0, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if st.Size() != off {
		return st.Size(), ErrOffsetMismatch
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	return off + n, err
}

// Size returns the current stored size of a file ID.
func (s *Store) Size(id string) (int64, error) {
	p, err := s.Resolve(id)
	if err != nil {
		return 0, err
	}
	st, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

func (s *Store) isRoot(root string) bool {
	clean := filepath.Clean(root)
	for _, r := range s.roots {
		if r == clean {
			return true
		}
	}
	return false
}
