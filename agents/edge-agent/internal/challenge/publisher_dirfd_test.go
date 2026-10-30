package challenge

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPublisherPinsRootAcrossReplacement(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	policy := validPolicy(makeKeys(t))
	fallbackRaw := marshalPolicy(t, policy)
	fallbackCanonical, _, err := CompileJSON(fallbackRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(fallbackRaw); err != nil {
		t.Fatalf("PublishJSON(v1) error = %v", err)
	}
	policy.PolicyVersion = 2
	raw := marshalPolicy(t, policy)
	canonical, _, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(raw); err != nil {
		t.Fatalf("PublishJSON(v2) error = %v", err)
	}
	for _, expected := range []struct {
		name    string
		content []byte
	}{
		{name: filepath.Join("versions", versionFilename(1)), content: fallbackCanonical},
		{name: filepath.Join("versions", versionFilename(2)), content: canonical},
		{name: "current.json", content: canonical},
	} {
		content, err := os.ReadFile(filepath.Join(root, expected.name))
		if err != nil {
			t.Fatalf("read original publication %q: %v", expected.name, err)
		}
		if !bytes.Equal(content, expected.content) {
			t.Fatalf("original publication %q does not match canonical policy", expected.name)
		}
	}

	lockFD, err := unix.Open(filepath.Join(root, ".publish.lock"), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(lockFD)
	if err := unix.Flock(lockFD, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_ = unix.Flock(lockFD, unix.LOCK_UN)
		}
	}()

	type result struct {
		publication Publication
		err         error
	}
	resultChannel := make(chan result, 1)
	go func() {
		publication, publishErr := publisher.PublishJSON(raw)
		resultChannel <- result{publication: publication, err: publishErr}
	}()
	select {
	case result := <-resultChannel:
		t.Fatalf("PublishJSON() returned before the held lock was released: %v", result.err)
	case <-time.After(time.Second):
	}

	originalRoot := filepath.Join(base, "original-state")
	if err := os.Rename(root, originalRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(lockFD, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	locked = false

	var publishResult result
	select {
	case publishResult = <-resultChannel:
	case <-time.After(5 * time.Second):
		t.Fatal("PublishJSON() did not finish after the lock was released")
	}
	if publishResult.err != nil {
		t.Fatalf("descriptor-pinned PublishJSON() error = %v", publishResult.err)
	}
	if publishResult.publication.CurrentPath != filepath.Join(root, "current.json") {
		t.Fatalf("CurrentPath = %q", publishResult.publication.CurrentPath)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("replacement root was mutated: %v", entries)
	}
	for _, expected := range []struct {
		name    string
		content []byte
	}{
		{name: filepath.Join("versions", versionFilename(1)), content: fallbackCanonical},
		{name: filepath.Join("versions", versionFilename(2)), content: canonical},
		{name: "current.json", content: canonical},
	} {
		content, err := os.ReadFile(filepath.Join(originalRoot, expected.name))
		if err != nil {
			t.Fatalf("read descriptor-pinned publication %q: %v", expected.name, err)
		}
		if !bytes.Equal(content, expected.content) {
			t.Fatalf("descriptor-pinned publication %q does not match canonical policy", expected.name)
		}
	}
}
