package ccadaptive

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
	policy := Policy{
		SchemaVersion: SchemaVersion,
		Revision:      1,
		Enabled:       true,
		Mode:          ModeSimple,
		Static:        Limit{RatePerSecond: 10, Burst: 2},
	}
	candidate := mustJSON(t, policy)
	canonical, _, err := CompileJSON(candidate)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		publication Publication
		err         error
	}
	resultChannel := make(chan result, 1)
	go func() {
		publication, publishErr := publisher.PublishJSON(candidate)
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
	for _, path := range []string{
		filepath.Join(originalScope, "state", "versions", versionName(1)),
		filepath.Join(originalScope, "state", "fallback.json"),
		filepath.Join(originalScope, "state", "current.json"),
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("descriptor-pinned publication %s: %v", path, err)
		}
		if !bytes.Equal(got, canonical) {
			t.Fatalf("descriptor-pinned publication %s = %q, want %q", path, got, canonical)
		}
	}
	if publishResult.publication.Path != filepath.Join(root, "versions", versionName(1)) {
		t.Fatalf("publication path = %q", publishResult.publication.Path)
	}
}

func TestPublisherRejectsExistingSymlinkAncestorWithoutMutation(t *testing.T) {
	base := canonicalTempDir(t)
	target := filepath.Join(base, "target")
	targetRoot := filepath.Join(target, "state")
	if err := os.MkdirAll(targetRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}

	if _, err := NewPublisher(filepath.Join(alias, "state")); err == nil {
		t.Fatal("publication root with an existing symlink ancestor was accepted")
	}
	for _, name := range []string{".publish.lock", "versions", "current.json", "fallback.json"} {
		if _, err := os.Lstat(filepath.Join(targetRoot, name)); !os.IsNotExist(err) {
			t.Fatalf("rejected root mutated %s: %v", name, err)
		}
	}
}
