package cc

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPublisherPinsRootAcrossAncestorReplacement(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scope := filepath.Join(base, "scope")
	root := filepath.Join(scope, "state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	lockFD, err := unix.Open(filepath.Join(root, ".publish.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
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

	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	policy := policyVersion(t, 1, "/dirfd")
	canonical, _, err := CompileJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		publication Publication
		err         error
	}
	resultChannel := make(chan result, 1)
	go func() {
		publication, publishErr := publisher.PublishJSON(policy)
		resultChannel <- result{publication: publication, err: publishErr}
	}()

	select {
	case result := <-resultChannel:
		t.Fatalf("PublishJSON() returned before the held lock was released: %v", result.err)
	case <-time.After(time.Second):
	}

	originalScope := filepath.Join(base, "original-scope")
	if err := os.Rename(scope, originalScope); err != nil {
		t.Fatal(err)
	}
	attackerScope := filepath.Join(base, "attacker-scope")
	if err := os.Mkdir(attackerScope, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(attackerScope, scope); err != nil {
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
	attackerRoot := filepath.Join(attackerScope, "state")
	if _, err := os.Lstat(attackerRoot); !os.IsNotExist(err) {
		t.Fatalf("publication escaped through the replaced ancestor: %v", err)
	}
	if publishResult.err != nil {
		t.Fatalf("descriptor-pinned publication failed: %v", publishResult.err)
	}
	originalRoot := filepath.Join(originalScope, "state")
	for _, name := range []string{
		filepath.Join("versions", versionFilename(1)),
		"fallback.json",
		"current.json",
	} {
		content, err := os.ReadFile(filepath.Join(originalRoot, name))
		if err != nil {
			t.Fatalf("descriptor-pinned publication %q: %v", name, err)
		}
		if !bytes.Equal(content, canonical) {
			t.Fatalf("descriptor-pinned publication %q content mismatch", name)
		}
	}
	if publishResult.publication.CurrentPath != filepath.Join(root, "current.json") {
		t.Fatalf("CurrentPath = %q", publishResult.publication.CurrentPath)
	}
}
