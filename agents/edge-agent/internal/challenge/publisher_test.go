package challenge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func TestPublisherKeepsLastKnownGood(t *testing.T) {
	keys := makeKeys(t)
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	policy := validPolicy(keys)
	first, err := publisher.PublishJSON(marshalPolicy(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(first.CurrentPath)
	if err != nil {
		t.Fatal(err)
	}
	bad := policy
	bad.PolicyVersion = 2
	bad.Algorithm = "sha1"
	if _, err := publisher.PublishJSON(marshalPolicy(t, bad)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("bad candidate error = %v", err)
	}
	reused := policy
	reused.Rules[0].Mode = ModeClick
	reused.Rules[0].MinDelaySeconds = 0
	if _, err := publisher.PublishJSON(marshalPolicy(t, reused)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("reused version error = %v", err)
	}
	after, err := os.ReadFile(first.CurrentPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("rejected policy changed LKG: %v", err)
	}
	policy.PolicyVersion = 2
	if _, err := publisher.PublishJSON(marshalPolicy(t, policy)); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(marshalPolicy(t, policy)); err != nil {
		t.Fatalf("idempotent publish failed: %v", err)
	}
}

func TestPublisherAtomicReadersAndIndependentLocking(t *testing.T) {
	keys := makeKeys(t)
	root := privateTempDir(t)
	first, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	policy := validPolicy(keys)
	publication, err := first.PublishJSON(marshalPolicy(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	readerErrors := make(chan error, 4)
	var readers sync.WaitGroup
	for index := 0; index < 4; index++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				raw, err := os.ReadFile(publication.CurrentPath)
				var current CompiledPolicy
				if err != nil || json.Unmarshal(raw, &current) != nil || current.PolicyVersion == 0 {
					readerErrors <- fmt.Errorf("reader observed invalid current policy: %w", err)
					return
				}
			}
		}()
	}
	for version := uint64(2); version <= 20; version++ {
		policy.PolicyVersion = version
		publisher := first
		if version%2 == 0 {
			publisher = second
		}
		if _, err := publisher.PublishJSON(marshalPolicy(t, policy)); err != nil {
			close(done)
			readers.Wait()
			t.Fatal(err)
		}
	}
	close(done)
	readers.Wait()
	close(readerErrors)
	for err := range readerErrors {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "versions"))
	if err != nil || len(entries) != 20 {
		t.Fatalf("versions = %d, error = %v", len(entries), err)
	}
}

func TestPublisherRecoversDamagedCurrentOnlyFromValidSealedPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "corrupt current",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("{damaged\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing current",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keys := makeKeys(t)
			root := privateTempDir(t)
			publisher, err := NewPublisher(root)
			if err != nil {
				t.Fatal(err)
			}
			policy := validPolicy(keys)
			first, err := publisher.PublishJSON(marshalPolicy(t, policy))
			if err != nil {
				t.Fatal(err)
			}
			sealedPath := filepath.Join(root, "versions", versionFilename(1))
			sealedBefore, err := os.ReadFile(sealedPath)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(t, first.CurrentPath)

			policy.PolicyVersion = 2
			second, err := publisher.PublishJSON(marshalPolicy(t, policy))
			if err != nil {
				t.Fatalf("recover from valid sealed policy: %v", err)
			}
			sealedAfter, err := os.ReadFile(sealedPath)
			if err != nil || !bytes.Equal(sealedBefore, sealedAfter) {
				t.Fatalf("sealed v1 changed: %v", err)
			}
			current, err := os.ReadFile(second.CurrentPath)
			if err != nil {
				t.Fatal(err)
			}
			var compiled CompiledPolicy
			if err := json.Unmarshal(current, &compiled); err != nil || compiled.PolicyVersion != 2 {
				t.Fatalf("recovered current policy = %+v, %v", compiled, err)
			}

			if err := os.WriteFile(second.CurrentPath, []byte("{damaged-current\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			latestPath := filepath.Join(root, "versions", versionFilename(2))
			if err := os.WriteFile(latestPath, []byte("{damaged-sealed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			currentBefore, _ := os.ReadFile(second.CurrentPath)
			latestBefore, _ := os.ReadFile(latestPath)
			policy.PolicyVersion = 3
			if _, err := publisher.PublishJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("damaged current and sealed error = %v", err)
			}
			if _, err := os.Lstat(filepath.Join(root, "versions", versionFilename(3))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed publication created v3: %v", err)
			}
			currentAfter, _ := os.ReadFile(second.CurrentPath)
			latestAfter, _ := os.ReadFile(latestPath)
			if !bytes.Equal(currentBefore, currentAfter) || !bytes.Equal(latestBefore, latestAfter) {
				t.Fatal("failed recovery mutated current or sealed policy")
			}
		})
	}
}

func TestPublisherRepairsSameVersionAfterSealedWriteCrash(t *testing.T) {
	keys := makeKeys(t)
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	policy := validPolicy(keys)
	first, err := publisher.PublishJSON(marshalPolicy(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	policy.PolicyVersion = 2
	canonical, _, err := CompileJSON(marshalPolicy(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	sealedPath := filepath.Join(root, "versions", versionFilename(2))
	if err := os.WriteFile(sealedPath, canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(marshalPolicy(t, policy)); err != nil {
		t.Fatalf("repair same-version crash: %v", err)
	}
	current, err := os.ReadFile(first.CurrentPath)
	if err != nil || !bytes.Equal(current, canonical) {
		t.Fatalf("current was not repaired from sealed v2: %v", err)
	}
}

func TestPublisherRejectsUnsafeCurrentAndSealedPolicyFiles(t *testing.T) {
	tests := []struct {
		name   string
		target string
		mutate func(*testing.T, string)
	}{
		{name: "current symlink", target: "current", mutate: replaceChallengePolicyWithSymlink},
		{name: "current hardlink", target: "current", mutate: addChallengePolicyHardlink},
		{name: "current permissions", target: "current", mutate: makeChallengePolicyPublic},
		{name: "current oversized", target: "current", mutate: makeChallengePolicyOversized},
		{name: "sealed symlink", target: "sealed", mutate: replaceChallengePolicyWithSymlink},
		{name: "sealed hardlink", target: "sealed", mutate: addChallengePolicyHardlink},
		{name: "sealed permissions", target: "sealed", mutate: makeChallengePolicyPublic},
		{name: "sealed oversized", target: "sealed", mutate: makeChallengePolicyOversized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keys := makeKeys(t)
			root := privateTempDir(t)
			publisher, err := NewPublisher(root)
			if err != nil {
				t.Fatal(err)
			}
			policy := validPolicy(keys)
			publication, err := publisher.PublishJSON(marshalPolicy(t, policy))
			if err != nil {
				t.Fatal(err)
			}
			target := publication.CurrentPath
			if test.target == "sealed" {
				target = filepath.Join(root, "versions", versionFilename(1))
			}
			test.mutate(t, target)
			policy.PolicyVersion = 2
			if _, err := publisher.PublishJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("unsafe %s error = %v", test.target, err)
			}
			if _, err := os.Lstat(filepath.Join(root, "versions", versionFilename(2))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe state created v2: %v", err)
			}
		})
	}
}

func TestNewPublisherRejectsUnsafeRoot(t *testing.T) {
	if _, err := NewPublisher("relative"); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("relative root error = %v", err)
	}
	parent := t.TempDir()
	public := filepath.Join(parent, "public")
	if err := os.Mkdir(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublisher(public); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("public root error = %v", err)
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	// macOS 的 TempDir 位于 /var -> /private/var 软链之下；发布根目录禁止软链祖先，先解析成真实路径。
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func replaceChallengePolicyWithSymlink(t *testing.T, path string) {
	t.Helper()
	target := path + ".target"
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func addChallengePolicyHardlink(t *testing.T, path string) {
	t.Helper()
	if err := os.Link(path, path+".link"); err != nil {
		t.Fatal(err)
	}
}

func makeChallengePolicyPublic(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

func makeChallengePolicyOversized(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, MaxPolicyBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertChallengePolicyFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("policy file %q identity = %v, %v", path, info, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		t.Fatalf("policy file %q link count is not one", path)
	}
}
