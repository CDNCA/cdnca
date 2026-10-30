package ccadaptive

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPublisherValidateBeforePublishLKGAndRollback(t *testing.T) {
	root := canonicalTempDir(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	first := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 10, Burst: 2}}
	publication, err := publisher.PublishJSON(mustJSON(t, first))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON([]byte(`{"schema_version":"bad"}`)); err == nil {
		t.Fatal("invalid candidate published")
	}
	after, err := os.ReadFile(filepath.Join(root, "current.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("LKG changed after rejected candidate: %v", err)
	}
	second := first
	second.Revision = 2
	if _, err := publisher.PublishJSON(mustJSON(t, second)); err != nil {
		t.Fatal(err)
	}
	rolled, err := publisher.Rollback(1)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Revision != publication.Revision || rolled.Digest != publication.Digest {
		t.Fatalf("rollback = %+v, want %+v", rolled, publication)
	}
}

func TestPublisherMaintainsValidatedDurableFallback(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	first := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 10, Burst: 2}}
	canonicalFirst, _, err := CompileJSON(mustJSON(t, first))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(mustJSON(t, first)); err != nil {
		t.Fatal(err)
	}
	assertPrivateFileEquals(t, filepath.Join(root, "fallback.json"), canonicalFirst)

	second := first
	second.Revision = 2
	canonicalSecond, _, err := CompileJSON(mustJSON(t, second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(mustJSON(t, second)); err != nil {
		t.Fatal(err)
	}
	assertPrivateFileEquals(t, filepath.Join(root, "fallback.json"), canonicalFirst)
	if _, err := publisher.PublishJSON([]byte(`{"schema_version":"bad"}`)); err == nil {
		t.Fatal("invalid candidate published")
	}
	assertPrivateFileEquals(t, filepath.Join(root, "fallback.json"), canonicalFirst)

	if _, err := publisher.Rollback(1); err != nil {
		t.Fatal(err)
	}
	assertPrivateFileEquals(t, filepath.Join(root, "current.json"), canonicalFirst)
	assertPrivateFileEquals(t, filepath.Join(root, "fallback.json"), canonicalSecond)
}

func TestPublisherInvalidCurrentCannotAdvanceAndSameRevisionRestores(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	base := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 10, Burst: 2}}
	if _, err := publisher.PublishJSON(mustJSON(t, base)); err != nil {
		t.Fatal(err)
	}
	base.Revision = 2
	canonicalTwo, _, err := CompileJSON(mustJSON(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(mustJSON(t, base)); err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(root, "fallback.json")
	wantFallback, err := os.ReadFile(fallback)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "current.json"), []byte(`{"schema_version":`), 0o600); err != nil {
		t.Fatal(err)
	}
	newer := base
	newer.Revision = 3
	if _, err := publisher.PublishJSON(mustJSON(t, newer)); err == nil {
		t.Fatal("new revision advanced from invalid current")
	}
	assertPrivateFileEquals(t, fallback, wantFallback)
	if _, err := os.Lstat(filepath.Join(root, "versions", versionName(3))); !os.IsNotExist(err) {
		t.Fatalf("rejected revision persisted: %v", err)
	}
	if _, err := publisher.PublishJSON(mustJSON(t, base)); err != nil {
		t.Fatalf("same revision recovery: %v", err)
	}
	assertPrivateFileEquals(t, filepath.Join(root, "current.json"), canonicalTwo)
	assertPrivateFileEquals(t, fallback, wantFallback)
}

func TestPublisherFallbackFailureDoesNotCommitCurrentAndCanRetry(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(root, "fallback.json")
	if err := os.Mkdir(fallback, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 10, Burst: 2}}
	if _, err := publisher.PublishJSON(mustJSON(t, policy)); err == nil {
		t.Fatal("publication succeeded without durable fallback")
	}
	if _, err := os.Lstat(filepath.Join(root, "current.json")); !os.IsNotExist(err) {
		t.Fatalf("failed publication committed current: %v", err)
	}
	if err := os.Remove(fallback); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(mustJSON(t, policy)); err != nil {
		t.Fatalf("same revision retry: %v", err)
	}
	canonical, _, err := CompileJSON(mustJSON(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	assertPrivateFileEquals(t, fallback, canonical)
}

func TestOpenRestyColdStartFallbackContract(t *testing.T) {
	engine, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "ccadaptive", "engine.lua"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"local fallback_path",
		`fallback_path = type(policy_path) == "string" and policy_path:match("^(.*)/[^/]+$") or nil`,
		`fallback_path = fallback_path and fallback_path .. "/fallback.json" or nil`,
		"if not revision and not active and fallback_path then",
		"_M.load(fallback_path)",
	} {
		if !strings.Contains(string(engine), required) {
			t.Errorf("engine is missing cold-start fallback contract %q", required)
		}
	}
	smoke, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "ccadaptive", "smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(smoke)
	markers := []string{
		`cp "${workdir}/policy/current.json" "${workdir}/policy/fallback.json"`,
		"# Cold-start recovery must use the sealed fallback while current is invalid.",
		`cp "${workdir}/policy/bad.json" "${workdir}/policy/current.json"`,
		`test "$(curl --fail --silent --show-error "${base_url}/revision")" = 7`,
		`cp "${workdir}/policy/current-copy.json" "${workdir}/policy/current.json"`,
	}
	searchFrom := 0
	for _, marker := range markers {
		relative := strings.Index(text[searchFrom:], marker)
		if relative < 0 {
			t.Fatalf("smoke cold-start fallback marker %q missing or out of order", marker)
		}
		searchFrom += relative + len(marker)
	}
}

func TestPublisherHistoricalHeadCannotRegressAfterRollback(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	base := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 10, Burst: 2}}
	for _, revision := range []uint64{1, 3} {
		candidate := base
		candidate.Revision = revision
		if _, err := publisher.PublishJSON(mustJSON(t, candidate)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := publisher.Rollback(1); err != nil {
		t.Fatal(err)
	}
	base.Revision = 2
	if _, err := publisher.PublishJSON(mustJSON(t, base)); err == nil {
		t.Fatal("revision below historical head accepted after rollback")
	}
}

func TestPublisherRejectsHardlinkedVersionAndSymlinkLock(t *testing.T) {
	t.Run("hardlinked version", func(t *testing.T) {
		root := privateTempDir(t)
		publisher, err := NewPublisher(root)
		if err != nil {
			t.Fatal(err)
		}
		policy := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 10, Burst: 2}}
		if _, err := publisher.PublishJSON(mustJSON(t, policy)); err != nil {
			t.Fatal(err)
		}
		version := filepath.Join(root, "versions", versionName(1))
		if err := os.Link(version, filepath.Join(root, "outside-link.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.Rollback(1); err == nil {
			t.Fatal("hardlinked immutable version accepted")
		}
	})

	t.Run("symlink lock", func(t *testing.T) {
		root := privateTempDir(t)
		publisher, err := NewPublisher(root)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "lock-target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, ".publish.lock")); err != nil {
			t.Fatal(err)
		}
		policy := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 10, Burst: 2}}
		if _, err := publisher.PublishJSON(mustJSON(t, policy)); err == nil {
			t.Fatal("symlink publication lock accepted")
		}
	})
}

func TestPublisherRecoversUnactivatedPartialRevision(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	base := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 10, Burst: 2}}
	if _, err := publisher.PublishJSON(mustJSON(t, base)); err != nil {
		t.Fatal(err)
	}
	partialPath := filepath.Join(root, "versions", versionName(2))
	if err := os.WriteFile(partialPath, []byte(`{"schema_version":`), 0o600); err != nil {
		t.Fatal(err)
	}
	base.Revision = 2
	publication, err := publisher.PublishJSON(mustJSON(t, base))
	if err != nil {
		t.Fatalf("partial retry: %v", err)
	}
	if publication.Revision != 2 {
		t.Fatalf("publication = %+v", publication)
	}
	want, _, err := CompileJSON(mustJSON(t, base))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(partialPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("recovered revision = %q error=%v", got, err)
	}
}

func TestPublisherActivationFailureCanRetrySameRevision(t *testing.T) {
	root := privateTempDir(t)
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "current.json")
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 10, Burst: 2}}
	if _, err := publisher.PublishJSON(mustJSON(t, policy)); err == nil {
		t.Fatal("activation unexpectedly succeeded over directory")
	}
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishJSON(mustJSON(t, policy)); err != nil {
		t.Fatalf("same revision retry: %v", err)
	}
	entries, err := filepath.Glob(filepath.Join(root, ".current-*"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary activation files = %v error=%v", entries, err)
	}
}

func TestPublisherRejectsSymlinkRootBeforeCreatingContent(t *testing.T) {
	parent := canonicalTempDir(t)
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublisher(link); err == nil {
		t.Fatal("symlink publication root accepted")
	}
	if _, err := os.Lstat(filepath.Join(target, "versions")); !os.IsNotExist(err) {
		t.Fatalf("content was created through rejected symlink: %v", err)
	}
}

func TestIndependentPublishersCannotRegressCurrentRevision(t *testing.T) {
	root := canonicalTempDir(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	base := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 10, Burst: 2}}
	if _, err := first.PublishJSON(mustJSON(t, base)); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	start := make(chan struct{})
	for index, publisher := range []*Publisher{first, second} {
		wait.Add(1)
		go func(offset int, publisher *Publisher) {
			defer wait.Done()
			<-start
			candidate := base
			candidate.Revision = uint64(offset + 2)
			_, _ = publisher.PublishJSON(mustJSON(t, candidate))
		}(index, publisher)
	}
	close(start)
	wait.Wait()
	revision, _, err := first.current()
	if err != nil {
		t.Fatal(err)
	}
	if revision != 3 {
		t.Fatalf("current revision = %d, want 3", revision)
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	root := canonicalTempDir(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(fmt.Errorf("secure temp dir: %w", err))
	}
	return root
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func assertPrivateFileEquals(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !bytes.Equal(got, want) {
		t.Fatalf("%s mode/content mismatch: mode=%o got=%q want=%q", path, info.Mode().Perm(), got, want)
	}
}
