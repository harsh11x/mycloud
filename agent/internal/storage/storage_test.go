package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validID = "123e4567-e89b-12d3-a456-426614174000"

func TestRejectsPathLikeIDs(t *testing.T) {
	root := t.TempDir()
	s, err := New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../etc/passwd", "a/b", "..", "", "123e4567-e89b-12d3-a456-42661417400z"} {
		if _, err := s.Allocate(bad, "u1", root); err != ErrBadID {
			t.Fatalf("Allocate(%q): want ErrBadID, got %v", bad, err)
		}
		if _, err := s.Resolve(bad); err != ErrBadID {
			t.Fatalf("Resolve(%q): want ErrBadID, got %v", bad, err)
		}
	}
}

func TestRejectsRootsNotConfigured(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	s, _ := New([]string{root})
	if _, err := s.Allocate(validID, "u1", other); err != ErrOutsideRoot {
		t.Fatalf("want ErrOutsideRoot, got %v", err)
	}
}

func TestAllocateWriteResolve(t *testing.T) {
	root := t.TempDir()
	s, _ := New([]string{root})
	p, err := s.Allocate(validID, "u1", root)
	if err != nil {
		t.Fatal(err)
	}
	if owner, _ := s.Owner(validID); owner != "u1" {
		t.Fatalf("owner = %q", owner)
	}
	if !strings.HasPrefix(p, root) {
		t.Fatalf("path %s not under root", p)
	}
	n, err := s.Write(validID, strings.NewReader("hello"))
	if err != nil || n != 5 {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	got, _ := s.Resolve(validID)
	data, _ := os.ReadFile(filepath.Clean(got))
	if string(data) != "hello" {
		t.Fatalf("content = %q", data)
	}
}

func TestOtherOwnerCannotReallocate(t *testing.T) {
	root := t.TempDir()
	s, _ := New([]string{root})
	if _, err := s.Allocate(validID, "u1", root); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Allocate(validID, "u2", root); err != ErrOwnerMismatch {
		t.Fatalf("want ErrOwnerMismatch, got %v", err)
	}
}

func TestUnknownIDNotResolved(t *testing.T) {
	s, _ := New([]string{t.TempDir()})
	if _, err := s.Resolve(validID); err != ErrUnknownFile {
		t.Fatalf("want ErrUnknownFile, got %v", err)
	}
}

func TestWithinBlocksTraversal(t *testing.T) {
	root := "/data/root"
	if Within(root, "/data/root/../secret") {
		t.Fatal("traversal escaped root")
	}
	if !Within(root, "/data/root/ab/file") {
		t.Fatal("valid path rejected")
	}
	if Within(root, "/data/rootsibling/file") {
		t.Fatal("sibling prefix accepted")
	}
}
