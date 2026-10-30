package errorpage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPublisherPinsStateRootAcrossAncestorReplacement(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	scope := filepath.Join(base, "scope")
	root := filepath.Join(scope, "state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(root, "", &fakeRuntime{})
	if err != nil {
		t.Fatal(err)
	}

	baselinePolicy := publisherPolicy(1, "v1", "baseline\n")
	baseline, err := Compile(baselinePolicy, "")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := publisher.Apply(context.Background(), baselinePolicy); err != nil || !result.Changed {
		t.Fatalf("publish baseline: result=%+v err=%v", result, err)
	}
	assertErrorPagePublication(t, root, baseline)

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

	candidatePolicy := publisherPolicy(2, "v2", "candidate\n")
	candidate, err := Compile(candidatePolicy, "")
	if err != nil {
		t.Fatal(err)
	}
	type applyOutcome struct {
		result ApplyResult
		err    error
	}
	outcomes := make(chan applyOutcome, 1)
	go func() {
		result, applyErr := publisher.Apply(context.Background(), candidatePolicy)
		outcomes <- applyOutcome{result: result, err: applyErr}
	}()

	select {
	case outcome := <-outcomes:
		t.Fatalf("Apply returned before the held publication lock was released: %v", outcome.err)
	case <-time.After(time.Second):
	}

	originalScope := filepath.Join(base, "original-scope")
	if err := os.Rename(scope, originalScope); err != nil {
		t.Fatal(err)
	}
	replacementRoot := filepath.Join(scope, "state")
	if err := os.MkdirAll(replacementRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(lockFD, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	locked = false

	var outcome applyOutcome
	select {
	case outcome = <-outcomes:
	case <-time.After(5 * time.Second):
		t.Fatal("Apply did not finish after the publication lock was released")
	}
	if outcome.err != nil || !outcome.result.Changed || outcome.result.Digest != candidate.Digest {
		t.Fatalf("descriptor-pinned publication: result=%+v err=%v", outcome.result, outcome.err)
	}
	entries, err := os.ReadDir(replacementRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("replacement tree was mutated: %v", entries)
	}
	assertErrorPagePublication(t, filepath.Join(originalScope, "state"), candidate)
}

func assertErrorPagePublication(t *testing.T, root string, artifact Artifact) {
	t.Helper()
	target := filepath.ToSlash(filepath.Join("versions", artifact.Digest))
	for _, name := range []string{"current", "lkg"} {
		actual, err := os.Readlink(filepath.Join(root, name))
		if err != nil || actual != target {
			t.Fatalf("%s pointer = %q err=%v, want %q", name, actual, err, target)
		}
		content, err := os.ReadFile(filepath.Join(root, name, "policy.json"))
		if err != nil || !bytes.Equal(content, artifact.CanonicalJSON) {
			t.Fatalf("%s policy bytes mismatch: err=%v", name, err)
		}
	}
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(target), "policy.json"))
	if err != nil || !bytes.Equal(content, artifact.CanonicalJSON) {
		t.Fatalf("sealed version policy bytes mismatch: err=%v", err)
	}
}
