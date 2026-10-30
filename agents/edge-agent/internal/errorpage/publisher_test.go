package errorpage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type fakeRuntime struct {
	mu                sync.Mutex
	precheckFail      bool
	activateFailOnce  bool
	healthFailOnce    bool
	prechecks         int
	activations       int
	healthChecks      int
	stops             int
	activeRevision    uint64
	rollbackCtxUsable bool
}

func (runtime *fakeRuntime) Precheck(_ context.Context, release string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.prechecks++
	for _, name := range []string{"manifest.json", "policy.json", "policy.lua"} {
		info, err := os.Lstat(filepath.Join(release, name))
		if err != nil || info.Mode().Perm() != 0o400 || !info.Mode().IsRegular() {
			return errors.New("unsafe release file")
		}
	}
	if runtime.precheckFail {
		return errors.New("injected precheck failure")
	}
	return nil
}

func (runtime *fakeRuntime) Activate(ctx context.Context, _ string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.activations++
	if runtime.activateFailOnce {
		runtime.activateFailOnce = false
		return errors.New("injected activation failure")
	}
	runtime.rollbackCtxUsable = ctx.Err() == nil
	return nil
}

func (runtime *fakeRuntime) Health(ctx context.Context, _ string, artifact Artifact) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.healthChecks++
	if runtime.healthFailOnce {
		runtime.healthFailOnce = false
		return errors.New("injected health failure")
	}
	runtime.rollbackCtxUsable = ctx.Err() == nil
	runtime.activeRevision = artifact.Revision
	return nil
}

func (runtime *fakeRuntime) Stop(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.stops++
	runtime.rollbackCtxUsable = ctx.Err() == nil
	runtime.activeRevision = 0
	return nil
}

func TestPublisherBadPolicyAndPrecheckKeepLKG(t *testing.T) {
	publisher, runtime := testPublisher(t)
	first := publisherPolicy(1, "v1", "healthy\n")
	result, err := publisher.Apply(context.Background(), first)
	if err != nil || !result.Changed {
		t.Fatalf("initial apply: result=%+v err=%v", result, err)
	}

	bad := publisherPolicy(2, "v2", "bad digest\n")
	bad.Global.Rules[0].Resource.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := publisher.Apply(context.Background(), bad); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("bad policy was not rejected: %v", err)
	}
	assertPointers(t, publisher, 1, result.Digest)

	runtime.precheckFail = true
	if _, err := publisher.Apply(context.Background(), publisherPolicy(2, "v2", "candidate\n")); !errors.Is(err, ErrPrecheck) {
		t.Fatalf("precheck failure not reported: %v", err)
	}
	assertPointers(t, publisher, 1, result.Digest)
	if runtime.activations != 1 || runtime.healthChecks != 1 {
		t.Fatalf("bad candidates reached activation: activations=%d health=%d", runtime.activations, runtime.healthChecks)
	}
}

func TestPublisherActivationAndHealthFailureRollback(t *testing.T) {
	publisher, runtime := testPublisher(t)
	first, err := publisher.Apply(context.Background(), publisherPolicy(1, "v1", "healthy\n"))
	if err != nil {
		t.Fatal(err)
	}

	runtime.activateFailOnce = true
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := publisher.Apply(cancelled, publisherPolicy(2, "v2", "activation fail\n")); !errors.Is(err, ErrActivate) {
		t.Fatalf("activation failure not reported: %v", err)
	}
	assertPointers(t, publisher, 1, first.Digest)
	if !runtime.rollbackCtxUsable || runtime.activeRevision != 1 {
		t.Fatalf("rollback did not use an independent context: %+v", runtime)
	}

	runtime.healthFailOnce = true
	if _, err := publisher.Apply(context.Background(), publisherPolicy(3, "v3", "health fail\n")); !errors.Is(err, ErrHealth) {
		t.Fatalf("health failure not reported: %v", err)
	}
	assertPointers(t, publisher, 1, first.Digest)
	if runtime.activeRevision != 1 {
		t.Fatalf("health rollback left revision %d active", runtime.activeRevision)
	}
}

func TestPublisherFirstActivationFailureStopsAndClearsPointers(t *testing.T) {
	publisher, runtime := testPublisher(t)
	runtime.healthFailOnce = true
	if _, err := publisher.Apply(context.Background(), publisherPolicy(1, "v1", "candidate\n")); !errors.Is(err, ErrHealth) {
		t.Fatalf("health failure not reported: %v", err)
	}
	if _, found, err := publisher.Current(); err != nil || found {
		t.Fatalf("current remains after first failure: found=%t err=%v", found, err)
	}
	if _, found, err := publisher.LKG(); err != nil || found {
		t.Fatalf("LKG remains after first failure: found=%t err=%v", found, err)
	}
	if runtime.stops != 1 || !runtime.rollbackCtxUsable {
		t.Fatalf("candidate runtime was not stopped: %+v", runtime)
	}
}

func TestPublisherRevisionAndConcurrentIdempotency(t *testing.T) {
	publisher, runtime := testPublisher(t)
	policy := publisherPolicy(1, "v1", "stable\n")
	first, err := publisher.Apply(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 24
	var wait sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := publisher.Apply(context.Background(), policy)
			if err == nil && (result.Changed || result.Digest != first.Digest) {
				err = errors.New("idempotent apply changed state")
			}
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if runtime.activations != 1 || runtime.healthChecks != 1 {
		t.Fatalf("concurrent idempotent apply reloaded: activations=%d health=%d", runtime.activations, runtime.healthChecks)
	}

	conflict := publisherPolicy(1, "v1-conflict", "different\n")
	if _, err := publisher.Apply(context.Background(), conflict); !errors.Is(err, ErrRevision) {
		t.Fatalf("same-revision conflict accepted: %v", err)
	}
	if _, err := publisher.Apply(context.Background(), publisherPolicy(0, "older", "old\n")); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("zero revision accepted: %v", err)
	}
	assertPointers(t, publisher, 1, first.Digest)
}

func TestNewPublisherRejectsSymlinkAncestors(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realRoot := filepath.Join(root, "real")
	resourceRoot := filepath.Join(realRoot, "resources")
	if err := os.MkdirAll(resourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(root, "linked")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		stateRoot    string
		resourceRoot string
	}{
		{name: "state root", stateRoot: filepath.Join(linkedRoot, "state")},
		{name: "resource root", stateRoot: filepath.Join(root, "state"), resourceRoot: filepath.Join(linkedRoot, "resources")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewPublisher(test.stateRoot, test.resourceRoot, &fakeRuntime{}); err == nil {
				t.Fatal("publisher accepted a symlinked path ancestor")
			}
		})
	}

	directState := filepath.Join(root, "direct-state")
	if _, err := NewPublisher(directState, resourceRoot, &fakeRuntime{}); err != nil {
		t.Fatalf("publisher rejected resolved roots with an absent state leaf: %v", err)
	}
	if _, err := os.Lstat(directState); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("constructor created absent state leaf: %v", err)
	}
}

func testPublisher(t *testing.T) (*Publisher, *fakeRuntime) {
	t.Helper()
	temporary, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(temporary, "state")
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	runtime := &fakeRuntime{}
	publisher, err := NewPublisher(root, "", runtime)
	if err != nil {
		t.Fatal(err)
	}
	return publisher, runtime
}

func publisherPolicy(revision uint64, version, body string) Policy {
	policy := testPolicy(testRule("route", CategoryEdgeRoute, StatusMatch{Codes: []int{404}}, "text/plain", body))
	policy.Revision = revision
	policy.Version = version
	return policy
}

func assertPointers(t *testing.T, publisher *Publisher, revision uint64, digest string) {
	t.Helper()
	current, found, err := publisher.Current()
	if err != nil || !found || current.Revision != revision || current.Digest != digest {
		t.Fatalf("current=%+v found=%t err=%v", current, found, err)
	}
	lkg, found, err := publisher.LKG()
	if err != nil || !found || lkg.Revision != revision || lkg.Digest != digest {
		t.Fatalf("lkg=%+v found=%t err=%v", lkg, found, err)
	}
}
