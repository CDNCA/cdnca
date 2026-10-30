package challenge

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadSecureKeyAtPinsAncestorAcrossReplacement(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(base, "keys")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	const name = "challenge.key"
	originalSecret := []byte("original-challenge-key-material-0001")
	replacementSecret := []byte("replacement-challenge-key-material-1")
	if err := os.WriteFile(filepath.Join(parent, name), originalSecret, 0o600); err != nil {
		t.Fatal(err)
	}

	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentDirectory := os.NewFile(uintptr(parentFD), parent)
	if parentDirectory == nil {
		_ = unix.Close(parentFD)
		t.Fatal("wrap parent directory descriptor")
	}
	ownedByReader := false
	defer func() {
		if !ownedByReader {
			_ = parentDirectory.Close()
		}
	}()

	originalParent := filepath.Join(base, "original-keys")
	if err := os.Rename(parent, originalParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, name), replacementSecret, 0o600); err != nil {
		t.Fatal(err)
	}

	ownedByReader = true
	secret, err := readSecureKeyAt(parentDirectory, []string{name})
	if err != nil {
		t.Fatalf("read descriptor-pinned key: %v", err)
	}
	if !bytes.Equal(secret, originalSecret) {
		t.Fatalf("read replacement key: got %q", secret)
	}
	for _, expected := range []struct {
		path    string
		content []byte
	}{
		{path: filepath.Join(originalParent, name), content: originalSecret},
		{path: filepath.Join(parent, name), content: replacementSecret},
	} {
		content, err := os.ReadFile(expected.path)
		if err != nil {
			t.Fatalf("read %q: %v", expected.path, err)
		}
		if !bytes.Equal(content, expected.content) {
			t.Fatalf("key %q was mutated: got %q", expected.path, content)
		}
	}
}
