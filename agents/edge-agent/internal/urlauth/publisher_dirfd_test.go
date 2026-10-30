package urlauth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPublisherPinsRootAcrossDirectoryReplacement(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "state")
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	keys := makeKeys(t)
	firstPolicy := validPolicy(keys)
	firstCanonical, _, err := CompileJSON(marshalPolicy(t, firstPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(marshalPolicy(t, firstPolicy)); err != nil {
		t.Fatalf("publish initial policy: %v", err)
	}
	secondPolicy := firstPolicy
	secondPolicy.PolicyVersion++
	secondCanonical, _, err := CompileJSON(marshalPolicy(t, secondPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(marshalPolicy(t, secondPolicy)); err != nil {
		t.Fatalf("publish second policy: %v", err)
	}
	for _, expected := range []struct {
		name      string
		canonical []byte
	}{
		{name: filepath.Join("versions", versionFilename(firstPolicy.PolicyVersion)), canonical: firstCanonical},
		{name: filepath.Join("versions", versionFilename(secondPolicy.PolicyVersion)), canonical: secondCanonical},
		{name: "current.json", canonical: secondCanonical},
	} {
		content, err := os.ReadFile(filepath.Join(root, expected.name))
		if err != nil {
			t.Fatalf("read pre-swap %q: %v", expected.name, err)
		}
		if !bytes.Equal(content, expected.canonical) {
			t.Fatalf("pre-swap %q differs from canonical policy", expected.name)
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

	thirdPolicy := secondPolicy
	thirdPolicy.PolicyVersion++
	thirdCanonical, _, err := CompileJSON(marshalPolicy(t, thirdPolicy))
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		publication Publication
		err         error
	}
	resultChannel := make(chan result, 1)
	go func() {
		publication, publishErr := publisher.PublishJSON(marshalPolicy(t, thirdPolicy))
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
		t.Fatalf("descriptor-pinned publication failed: %v", publishResult.err)
	}
	for _, expected := range []struct {
		name      string
		canonical []byte
	}{
		{name: filepath.Join("versions", versionFilename(firstPolicy.PolicyVersion)), canonical: firstCanonical},
		{name: filepath.Join("versions", versionFilename(secondPolicy.PolicyVersion)), canonical: secondCanonical},
		{name: filepath.Join("versions", versionFilename(thirdPolicy.PolicyVersion)), canonical: thirdCanonical},
		{name: "current.json", canonical: thirdCanonical},
	} {
		content, err := os.ReadFile(filepath.Join(originalRoot, expected.name))
		if err != nil {
			t.Fatalf("read descriptor-pinned %q: %v", expected.name, err)
		}
		if !bytes.Equal(content, expected.canonical) {
			t.Fatalf("descriptor-pinned %q differs from canonical policy", expected.name)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("replacement root mutated with %d entries", len(entries))
	}
	if publishResult.publication.CurrentPath != filepath.Join(root, "current.json") {
		t.Fatalf("CurrentPath = %q", publishResult.publication.CurrentPath)
	}
}
