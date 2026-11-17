package storage

import (
	"errors"
	"strings"
	"testing"
)

func TestWriteRefusesToReplaceFinishedFile(t *testing.T) {
	root := t.TempDir()
	st, err := New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	const id = "11111111-2222-4333-8444-555555555555"
	if _, err := st.Allocate(id, "u1", root); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write(id, strings.NewReader("first")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := st.Write(id, strings.NewReader("second")); !errors.Is(err, ErrExists) {
		t.Fatalf("second write: want ErrExists, got %v", err)
	}
}
