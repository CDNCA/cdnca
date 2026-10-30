package httppolicy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPublisherKeepsCommittedVersionForInvalidOlderAndSameVersionCandidates(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	v1 := policyJSON(t, validPolicy(1))
	first, err := publisher.PublishJSON(v1)
	if err != nil {
		t.Fatal(err)
	}
	assertPublished(t, first, v1)

	invalid := validPolicy(2)
	invalid.Sites[0].RequestHeaders = []HeaderAction{{Kind: HeaderSet, Name: "Host", Values: []string{"evil.test"}}}
	if _, err := publisher.PublishJSON(policyJSON(t, invalid)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid candidate error=%v", err)
	}
	assertPublished(t, first, v1)

	v2 := policyJSON(t, validPolicy(2))
	second, err := publisher.PublishJSON(v2)
	if err != nil {
		t.Fatal(err)
	}
	assertPublished(t, second, v2)
	if _, err := publisher.PublishJSON(v1); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("older candidate error=%v", err)
	}
	mutated := validPolicy(2)
	mutated.Sites[0].MaxUploadBytes = 17
	if _, err := publisher.PublishJSON(policyJSON(t, mutated)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("same-version mutation error=%v", err)
	}
	assertPublished(t, second, v2)
}

func TestPublisherSerializesConcurrentIdempotentPublication(t *testing.T) {
	publisher, err := NewPublisher(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	raw := policyJSON(t, validPolicy(1))
	var wait sync.WaitGroup
	results := make(chan Publication, 8)
	errorsFound := make(chan error, 8)
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, publishErr := publisher.PublishJSON(raw)
			results <- result
			errorsFound <- publishErr
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
	}
	if changed != 1 {
		t.Fatalf("changed publications=%d, want 1", changed)
	}
}

func TestPublisherRejectsUnsafeRootAndVersionFile(t *testing.T) {
	if _, err := NewPublisher("relative"); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("relative root error=%v", err)
	}
	root := privateTempDir(t)
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublisher(root); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("public root error=%v", err)
	}
}

func assertPublished(t *testing.T, publication Publication, raw []byte) {
	t.Helper()
	artifact, err := CompileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !publication.DurabilityConfirmed {
		t.Fatal("successful publication did not confirm directory durability")
	}
	manifest := readCommitManifest(t, filepath.Dir(publication.CommitPath))
	if manifest.PolicyVersion != artifact.PolicyVersion || manifest.SHA256 != hex.EncodeToString(artifact.Digest[:]) {
		t.Fatalf("commit manifest=%+v", manifest)
	}
	content, err := os.ReadFile(publication.VersionPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, artifact.Canonical) {
		t.Fatalf("%s does not contain canonical policy", publication.VersionPath)
	}
	for _, path := range []string{publication.CommitPath, publication.VersionPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%v err=%v", path, info.Mode().Perm(), err)
		}
	}
}

func policyJSON(t *testing.T, policy Policy) []byte {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}
