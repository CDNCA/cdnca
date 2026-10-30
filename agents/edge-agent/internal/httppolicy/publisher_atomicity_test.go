package httppolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var errInjectedPublicationIO = errors.New("injected publication I/O failure")

type faultingPublicationIO struct {
	root  string
	point string
	once  sync.Once
}

func (faults *faultingPublicationIO) Write(file *os.File, content []byte) (int, error) {
	point := "commit-write"
	if filepath.Dir(file.Name()) == filepath.Join(faults.root, "versions") {
		point = "version-write"
	}
	if faults.shouldFail(point) {
		return 0, errInjectedPublicationIO
	}
	return file.Write(content)
}

func (faults *faultingPublicationIO) Sync(file *os.File) error {
	point := "commit-file-sync"
	switch file.Name() {
	case faults.root:
		point = "root-dir-sync"
	case filepath.Join(faults.root, "versions"):
		point = "versions-dir-sync"
	default:
		if filepath.Dir(file.Name()) == filepath.Join(faults.root, "versions") {
			point = "version-file-sync"
		}
	}
	if faults.shouldFail(point) {
		return errInjectedPublicationIO
	}
	return file.Sync()
}

func (faults *faultingPublicationIO) Rename(oldPath, newPath string) error {
	if newPath == filepath.Join(faults.root, commitFilename) && faults.shouldFail("commit-rename") {
		return errInjectedPublicationIO
	}
	return os.Rename(oldPath, newPath)
}

func (faults *faultingPublicationIO) shouldFail(point string) bool {
	if faults.point != point {
		return false
	}
	failed := false
	faults.once.Do(func() { failed = true })
	return failed
}

func TestPublisherFailureBeforeCommitKeepsConfirmedVersionAcrossRestart(t *testing.T) {
	for _, point := range []string{
		"version-write",
		"version-file-sync",
		"versions-dir-sync",
		"commit-write",
		"commit-file-sync",
		"commit-rename",
	} {
		t.Run(point, func(t *testing.T) {
			root := privateTempDir(t)
			publishVersion(t, root, 1)
			faults := &faultingPublicationIO{root: resolvedPath(t, root), point: point}
			publisher, err := newPublisherWithIO(root, faults)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := publisher.PublishJSON(policyJSON(t, validPolicy(2))); !errors.Is(err, errInjectedPublicationIO) {
				t.Fatalf("fault %s returned %v", point, err)
			}
			assertCommittedVersion(t, root, 1)

			restarted, err := NewPublisher(root)
			if err != nil {
				t.Fatal(err)
			}
			result, err := restarted.PublishJSON(policyJSON(t, validPolicy(2)))
			if err != nil {
				t.Fatal(err)
			}
			if !result.Changed || !result.DurabilityConfirmed {
				t.Fatalf("retry result=%+v", result)
			}
			assertCommittedVersion(t, root, 2)
		})
	}
}

func TestPublisherPostCommitSyncFailureReturnsCommittedSuccess(t *testing.T) {
	root := privateTempDir(t)
	publishVersion(t, root, 1)
	faults := &faultingPublicationIO{root: resolvedPath(t, root), point: "root-dir-sync"}
	publisher, err := newPublisherWithIO(root, faults)
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.PublishJSON(policyJSON(t, validPolicy(2)))
	if err != nil {
		t.Fatalf("commit-point success was reported as failure: %v", err)
	}
	if !result.Changed || result.DurabilityConfirmed {
		t.Fatalf("post-commit sync result=%+v", result)
	}
	assertCommittedVersion(t, root, 2)

	restarted, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := restarted.PublishJSON(policyJSON(t, validPolicy(2)))
	if err != nil {
		t.Fatal(err)
	}
	if retry.Changed || !retry.DurabilityConfirmed {
		t.Fatalf("durability retry result=%+v", retry)
	}
}

func TestPublisherSerializesAcrossPublisherInstances(t *testing.T) {
	root := privateTempDir(t)
	raw := policyJSON(t, validPolicy(1))
	var wait sync.WaitGroup
	results := make(chan Publication, 8)
	errorsFound := make(chan error, 8)
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			publisher, err := NewPublisher(root)
			if err == nil {
				var result Publication
				result, err = publisher.PublishJSON(raw)
				results <- result
			}
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	changed := 0
	for result := range results {
		if result.Changed {
			changed++
		}
		if !result.DurabilityConfirmed {
			t.Fatalf("publication durability not confirmed: %+v", result)
		}
	}
	if changed != 1 {
		t.Fatalf("changed publications=%d, want 1", changed)
	}
	assertCommittedVersion(t, root, 1)
}

func TestPublisherRejectsUnverifiableCommitUnknownVersionEntryAndHardlinkedLock(t *testing.T) {
	t.Run("unverifiable-commit", func(t *testing.T) {
		root := privateTempDir(t)
		publishVersion(t, root, 1)
		path := filepath.Join(root, commitFilename)
		manifest := readCommitManifest(t, root)
		manifest.SHA256 = strings.Repeat("0", sha256.Size*2)
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewPublisher(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.PublishJSON(policyJSON(t, validPolicy(2))); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("unverifiable commit error=%v", err)
		}
	})

	t.Run("unknown-version-entry", func(t *testing.T) {
		root := privateTempDir(t)
		publishVersion(t, root, 1)
		if err := os.WriteFile(filepath.Join(root, "versions", "unexpected"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewPublisher(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.PublishJSON(policyJSON(t, validPolicy(2))); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("unknown version entry error=%v", err)
		}
	})

	t.Run("hardlinked-lock", func(t *testing.T) {
		root := privateTempDir(t)
		publishVersion(t, root, 1)
		if err := os.Link(filepath.Join(root, ".publish.lock"), filepath.Join(root, "lock-link")); err != nil {
			t.Fatal(err)
		}
		publisher, err := NewPublisher(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.PublishJSON(policyJSON(t, validPolicy(2))); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("hardlinked lock error=%v", err)
		}
	})
}

func TestPublisherPinsResolvedParentAgainstSymlinkRetarget(t *testing.T) {
	base := privateTempDir(t)
	firstParent := filepath.Join(base, "first")
	secondParent := filepath.Join(base, "second")
	for _, path := range []string{firstParent, secondParent} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(base, "parent")
	if err := os.Symlink(firstParent, link); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(filepath.Join(link, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secondParent, link); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(policyJSON(t, validPolicy(1))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(firstParent, "state", commitFilename)); err != nil {
		t.Fatalf("resolved parent was not pinned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(secondParent, "state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retargeted symlink received publication: %v", err)
	}
}

func publishVersion(t *testing.T, root string, version uint64) Publication {
	t.Helper()
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.PublishJSON(policyJSON(t, validPolicy(version)))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertCommittedVersion(t *testing.T, root string, version uint64) {
	t.Helper()
	manifest := readCommitManifest(t, root)
	if manifest.PolicyVersion != version {
		t.Fatalf("committed version=%d, want %d", manifest.PolicyVersion, version)
	}
	artifactPath := filepath.Join(root, filepath.FromSlash(manifest.Artifact))
	content, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != manifest.SHA256 {
		t.Fatal("committed manifest digest does not match immutable artifact")
	}
	artifact, err := CompileJSON(content)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.PolicyVersion != version || !strings.HasSuffix(manifest.Artifact, versionFilename(version)) {
		t.Fatalf("manifest=%+v artifact_version=%d", manifest, artifact.PolicyVersion)
	}
}

func readCommitManifest(t *testing.T, root string) commitManifest {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, commitFilename))
	if err != nil {
		t.Fatal(err)
	}
	var manifest commitManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func resolvedPath(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
