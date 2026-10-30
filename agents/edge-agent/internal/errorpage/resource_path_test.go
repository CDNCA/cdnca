package errorpage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadOwnerOnlyFileRejectsSymlinkedRootAncestor(t *testing.T) {
	base := t.TempDir()
	base, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	realParent := filepath.Join(base, "real")
	realRoot := filepath.Join(realParent, "resources")
	if err := os.MkdirAll(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("safe error page")
	if err := os.WriteFile(filepath.Join(realRoot, "page.txt"), body, 0o400); err != nil {
		t.Fatal(err)
	}

	got, err := readOwnerOnlyFile(realRoot, "page.txt")
	if err != nil {
		t.Fatalf("read through resolved root: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("body = %q, want %q", got, body)
	}

	linkedParent := filepath.Join(base, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	_, err = readOwnerOnlyFile(filepath.Join(linkedParent, "resources"), "page.txt")
	if !errors.Is(err, ErrUnsafeResource) {
		t.Fatalf("symlinked root ancestor error = %v, want %v", err, ErrUnsafeResource)
	}
}
