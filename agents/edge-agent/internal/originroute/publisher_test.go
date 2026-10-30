package originroute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type publisherRuntime struct {
	mu            sync.Mutex
	precheckError error
	reloadError   error
	stopError     error
	healthErrors  map[string]error
	prechecks     []string
	reloads       []string
	healths       []string
	stops         int
	delay         time.Duration
}

type recoveryPublisherRuntime struct {
	mu          sync.Mutex
	serving     string
	failReloads int
	reloads     []string
	healths     []string
}

func (runtime *recoveryPublisherRuntime) Precheck(context.Context, string) error { return nil }

func (runtime *recoveryPublisherRuntime) Reload(_ context.Context, release string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.reloads = append(runtime.reloads, release)
	if runtime.failReloads > 0 {
		runtime.failReloads--
		return errors.New("injected recovery reload failure")
	}
	raw, err := os.ReadFile(filepath.Join(release, "policy.json"))
	if err != nil {
		return err
	}
	var policy struct {
		VersionID string `json:"version_id"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return err
	}
	runtime.serving = policy.VersionID
	return nil
}

func (runtime *recoveryPublisherRuntime) Healthy(_ context.Context, version string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.healths = append(runtime.healths, version)
	if runtime.serving != version {
		return fmt.Errorf("runtime serves %q, expected %q", runtime.serving, version)
	}
	return nil
}

func (runtime *recoveryPublisherRuntime) Stop(context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.serving = ""
	return nil
}

type blockingPublisherRuntime struct {
	reloadEntered chan struct{}
	release       chan struct{}
	mu            sync.Mutex
	reloads       int
	healths       int
}

func (runtime *blockingPublisherRuntime) Precheck(context.Context, string) error { return nil }

func (runtime *blockingPublisherRuntime) Reload(ctx context.Context, _ string) error {
	runtime.mu.Lock()
	runtime.reloads++
	runtime.mu.Unlock()
	runtime.reloadEntered <- struct{}{}
	select {
	case <-runtime.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runtime *blockingPublisherRuntime) Healthy(context.Context, string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.healths++
	return nil
}

func (runtime *blockingPublisherRuntime) Stop(context.Context) error { return nil }

type processPublisherRuntime struct {
	entered string
	release string
}

func (runtime processPublisherRuntime) Precheck(context.Context, string) error { return nil }

func (runtime processPublisherRuntime) Reload(ctx context.Context, _ string) error {
	if err := os.WriteFile(runtime.entered, []byte("entered\n"), 0o600); err != nil {
		return err
	}
	for {
		if _, err := os.Stat(runtime.release); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (processPublisherRuntime) Healthy(context.Context, string) error { return nil }
func (processPublisherRuntime) Stop(context.Context) error            { return nil }

func (runtime *publisherRuntime) Precheck(_ context.Context, release string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.prechecks = append(runtime.prechecks, release)
	return runtime.precheckError
}

func (runtime *publisherRuntime) Reload(_ context.Context, release string) error {
	if runtime.delay > 0 {
		time.Sleep(runtime.delay)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.reloads = append(runtime.reloads, release)
	return runtime.reloadError
}

func (runtime *publisherRuntime) Healthy(_ context.Context, version string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.healths = append(runtime.healths, version)
	return runtime.healthErrors[version]
}

func (runtime *publisherRuntime) Stop(_ context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.stops++
	return runtime.stopError
}

func allPublisherAddresses(policy Policy) testAddressInspector {
	addresses := make(map[netip.Addr]bool)
	for _, listener := range policy.Listeners {
		for _, raw := range []string{listener.IngressSourceIPv4, listener.IngressSourceIPv6} {
			if raw != "" {
				addresses[netip.MustParseAddr(raw)] = true
			}
		}
	}
	return testAddressInspector{addresses: addresses}
}

func policyJSON(t *testing.T, policy Policy) []byte {
	t.Helper()
	value, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func newTestPublisher(t *testing.T, policy Policy, runtime *publisherRuntime) (*Publisher, string) {
	t.Helper()
	base := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	root := filepath.Join(base, "state")
	publisher, err := NewPublisher(root, "/opt/cdnca/originroute", allPublisherAddresses(policy), runtime)
	if err != nil {
		t.Fatal(err)
	}
	return publisher, root
}

func publisherTestBase(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				if info.IsDir() {
					_ = os.Chmod(path, 0o700)
				} else {
					_ = os.Chmod(path, 0o600)
				}
			}
			return nil
		})
	})
	return base
}

func TestPublisherAppliesIdempotentlyAndRejectsRevisionConflicts(t *testing.T) {
	policy := testPolicy()
	runtime := &publisherRuntime{healthErrors: make(map[string]error)}
	publisher, root := newTestPublisher(t, policy, runtime)

	first, err := publisher.Apply(context.Background(), policyJSON(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || first.PreviousDigest != "" {
		t.Fatalf("first result=%+v", first)
	}
	for _, pointer := range []string{"current", "lkg"} {
		target, err := os.Readlink(filepath.Join(root, pointer))
		if err != nil {
			t.Fatal(err)
		}
		if target != filepath.Join("versions", first.Digest) {
			t.Fatalf("%s target=%q", pointer, target)
		}
	}

	second, err := publisher.Apply(context.Background(), policyJSON(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed || second.Digest != first.Digest {
		t.Fatalf("idempotent result=%+v", second)
	}

	older := policy
	older.Revision = 0
	older.VersionID = "older"
	if _, err := publisher.Apply(context.Background(), policyJSON(t, older)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("zero revision error=%v", err)
	}
	conflict := policy
	conflict.VersionID = "same-revision-other-content"
	if _, err := publisher.Apply(context.Background(), policyJSON(t, conflict)); !errors.Is(err, ErrConflict) {
		t.Fatalf("same revision conflict error=%v", err)
	}

	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.prechecks) != 1 || len(runtime.reloads) != 1 || runtime.stops != 0 {
		t.Fatalf("runtime calls precheck=%d reload=%d stop=%d", len(runtime.prechecks), len(runtime.reloads), runtime.stops)
	}
}

func TestPublisherRejectsHardlinkedReleaseFiles(t *testing.T) {
	for _, name := range []string{"nginx.conf", "policy.json"} {
		t.Run(name, func(t *testing.T) {
			policy := testPolicy()
			runtime := &publisherRuntime{healthErrors: make(map[string]error)}
			publisher, root := newTestPublisher(t, policy, runtime)
			result, err := publisher.Apply(context.Background(), policyJSON(t, policy))
			if err != nil {
				t.Fatal(err)
			}
			releaseFile := filepath.Join(root, "versions", result.Digest, name)
			outside := filepath.Join(filepath.Dir(root), "linked-"+name)
			if err := os.Link(releaseFile, outside); err != nil {
				t.Fatal(err)
			}
			if _, err := publisher.Apply(context.Background(), policyJSON(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("hardlinked %s replay error=%v, expected %v", name, err, ErrInvalidPolicy)
			}
		})
	}
}

func TestPublisherFailurePreservesLastKnownGood(t *testing.T) {
	policy := testPolicy()
	runtime := &publisherRuntime{healthErrors: make(map[string]error)}
	publisher, root := newTestPublisher(t, policy, runtime)
	first, err := publisher.Apply(context.Background(), policyJSON(t, policy))
	if err != nil {
		t.Fatal(err)
	}

	candidate := policy
	candidate.Revision = 2
	candidate.VersionID = "route-v2-bad"
	runtime.healthErrors[candidate.VersionID] = errors.New("candidate unhealthy")
	if _, err := publisher.Apply(context.Background(), policyJSON(t, candidate)); !errors.Is(err, ErrHealth) {
		t.Fatalf("candidate health error=%v", err)
	}
	for _, pointer := range []string{"current", "lkg"} {
		target, err := os.Readlink(filepath.Join(root, pointer))
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(target) != first.Digest {
			t.Fatalf("%s moved after failure: %q", pointer, target)
		}
	}

	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.reloads) != 3 || runtime.healths[len(runtime.healths)-1] != policy.VersionID {
		t.Fatalf("rollback calls reload=%v health=%v", runtime.reloads, runtime.healths)
	}
}

func TestPublisherInitialHealthFailureStopsCandidateAndClearsPointers(t *testing.T) {
	policy := testPolicy()
	runtime := &publisherRuntime{healthErrors: map[string]error{policy.VersionID: errors.New("not healthy")}}
	publisher, root := newTestPublisher(t, policy, runtime)
	if _, err := publisher.Apply(context.Background(), policyJSON(t, policy)); !errors.Is(err, ErrHealth) {
		t.Fatalf("initial health error=%v", err)
	}
	for _, pointer := range []string{"current", "lkg"} {
		if _, err := os.Lstat(filepath.Join(root, pointer)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists after initial failure: %v", pointer, err)
		}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.stops != 1 {
		t.Fatalf("candidate stop calls=%d, expected 1", runtime.stops)
	}
}

func TestPublisherSerializesConcurrentApply(t *testing.T) {
	policy := testPolicy()
	runtime := &publisherRuntime{healthErrors: make(map[string]error), delay: 5 * time.Millisecond}
	publisher, _ := newTestPublisher(t, policy, runtime)
	raw := policyJSON(t, policy)

	const workers = 24
	results := make(chan ApplyResult, workers)
	errorsFound := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := publisher.Apply(context.Background(), raw)
			if err != nil {
				errorsFound <- err
				return
			}
			results <- result
		}()
	}
	group.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("concurrent Apply error=%v", err)
	}
	changed := 0
	for result := range results {
		if result.Changed {
			changed++
		}
	}
	if changed != 1 {
		t.Fatalf("changed results=%d, expected 1", changed)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.reloads) != 1 {
		t.Fatalf("reload calls=%d, expected 1", len(runtime.reloads))
	}
}

func TestPublisherSerializesSeparateInstances(t *testing.T) {
	policy := testPolicy()
	runtime := &blockingPublisherRuntime{
		reloadEntered: make(chan struct{}, 2),
		release:       make(chan struct{}),
	}
	base := publisherTestBase(t)
	root := filepath.Join(base, "state")
	first, err := NewPublisher(root, "/opt/cdnca/originroute", allPublisherAddresses(policy), runtime)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPublisher(root, "/opt/cdnca/originroute", allPublisherAddresses(policy), runtime)
	if err != nil {
		t.Fatal(err)
	}
	raw := policyJSON(t, policy)
	results := make(chan ApplyResult, 2)
	errorsFound := make(chan error, 2)
	finished := make(chan struct{}, 2)
	apply := func(publisher *Publisher) {
		result, applyErr := publisher.Apply(context.Background(), raw)
		results <- result
		errorsFound <- applyErr
		finished <- struct{}{}
	}
	go apply(first)
	select {
	case <-runtime.reloadEntered:
	case <-time.After(time.Second):
		t.Fatal("first publisher did not enter reload")
	}
	go apply(second)
	select {
	case <-runtime.reloadEntered:
		t.Fatal("second publisher entered reload before the first released the state lock")
	case <-finished:
		t.Fatal("second publisher completed while the first held an unverified current release")
	case <-time.After(100 * time.Millisecond):
	}
	close(runtime.release)
	changed := 0
	for range 2 {
		if err := <-errorsFound; err != nil {
			t.Fatal(err)
		}
		if (<-results).Changed {
			changed++
		}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if changed != 1 || runtime.reloads != 1 || runtime.healths != 2 {
		t.Fatalf("changed=%d reloads=%d healths=%d", changed, runtime.reloads, runtime.healths)
	}
}

func TestPublisherCrossProcessLockHelper(t *testing.T) {
	if os.Getenv("CDNCA_ORIGINROUTE_PUBLISH_HELPER") != "1" {
		return
	}
	policy := testPolicy()
	runtime := processPublisherRuntime{
		entered: os.Getenv("CDNCA_ORIGINROUTE_PUBLISH_ENTERED"),
		release: os.Getenv("CDNCA_ORIGINROUTE_PUBLISH_RELEASE"),
	}
	publisher, err := NewPublisher(
		os.Getenv("CDNCA_ORIGINROUTE_PUBLISH_ROOT"),
		"/opt/cdnca/originroute", allPublisherAddresses(policy), runtime,
	)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("CDNCA_ORIGINROUTE_PUBLISH_CANDIDATE") == "1" {
		policy.Revision++
		policy.VersionID = "route-v2-crash-candidate"
	}
	if _, err := publisher.Apply(context.Background(), policyJSON(t, policy)); err != nil {
		t.Fatal(err)
	}
}

func TestPublisherSerializesAcrossProcesses(t *testing.T) {
	policy := testPolicy()
	base := publisherTestBase(t)
	root := filepath.Join(base, "state")
	entered := filepath.Join(base, "entered")
	release := filepath.Join(base, "release")
	runtime := &publisherRuntime{healthErrors: make(map[string]error)}
	publisher, err := NewPublisher(root, "/opt/cdnca/originroute", allPublisherAddresses(policy), runtime)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestPublisherCrossProcessLockHelper$")
	command.Env = append(os.Environ(),
		"CDNCA_ORIGINROUTE_PUBLISH_HELPER=1",
		"CDNCA_ORIGINROUTE_PUBLISH_ROOT="+root,
		"CDNCA_ORIGINROUTE_PUBLISH_ENTERED="+entered,
		"CDNCA_ORIGINROUTE_PUBLISH_RELEASE="+release,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = os.WriteFile(release, []byte("release\n"), 0o600)
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(entered); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper publisher did not enter reload")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := publisher.Apply(ctx, policyJSON(t, policy)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrent process apply error=%v, expected context deadline", err)
	}
	if err := os.WriteFile(release, []byte("release\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	if result, err := publisher.Apply(context.Background(), policyJSON(t, policy)); err != nil || result.Changed {
		t.Fatalf("post-lock replay result=%+v error=%v", result, err)
	}
}

func TestPublisherStartupReconcilesUnverifiedCurrentToLKG(t *testing.T) {
	for _, withJournal := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing journal", true: "pending journal"}[withJournal], func(t *testing.T) {
			policy := testPolicy()
			runtime := &publisherRuntime{healthErrors: make(map[string]error)}
			publisher, root := newTestPublisher(t, policy, runtime)
			first, err := publisher.Apply(context.Background(), policyJSON(t, policy))
			if err != nil {
				t.Fatal(err)
			}
			candidate := policy
			candidate.Revision++
			candidate.VersionID = "unverified-candidate"
			artifact, err := Compile(candidate, root, "/opt/cdnca/originroute")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := publisher.ensureRelease(artifact); err != nil {
				t.Fatal(err)
			}
			if err := publisher.setPointer("current", artifact.Digest); err != nil {
				t.Fatal(err)
			}
			if withJournal {
				journal := []byte(`{"schema":1,"candidate_digest":"` + artifact.Digest + `","previous_digest":"` + first.Digest + `"}` + "\n")
				if err := os.WriteFile(filepath.Join(root, "apply-journal.json"), journal, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			runtime.mu.Lock()
			runtime.reloads, runtime.healths = nil, nil
			runtime.mu.Unlock()
			if _, err := NewPublisher(root, "/opt/cdnca/originroute", allPublisherAddresses(policy), runtime); err != nil {
				t.Fatal(err)
			}
			current, err := publisher.pointer("current")
			if err != nil || current != first.Digest {
				t.Fatalf("reconciled current=%q error=%v, want %q", current, err, first.Digest)
			}
			if _, err := os.Lstat(filepath.Join(root, "apply-journal.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("journal remains after reconciliation: %v", err)
			}
			runtime.mu.Lock()
			defer runtime.mu.Unlock()
			if len(runtime.reloads) != 1 || len(runtime.healths) != 1 || runtime.healths[0] != policy.VersionID {
				t.Fatalf("recovery reloads=%v healths=%v", runtime.reloads, runtime.healths)
			}
		})
	}
}

func TestPublisherRecoveryRetainsJournalUntilLKGIsServing(t *testing.T) {
	policy := testPolicy()
	setupRuntime := &publisherRuntime{healthErrors: make(map[string]error)}
	publisher, root := newTestPublisher(t, policy, setupRuntime)
	first, err := publisher.Apply(context.Background(), policyJSON(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	candidate := policy
	candidate.Revision++
	candidate.VersionID = "route-v2-rejected"
	artifact, err := Compile(candidate, root, "/opt/cdnca/originroute")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.ensureRelease(artifact); err != nil {
		t.Fatal(err)
	}
	if err := publisher.writeJournal(publicationJournal{
		Schema: publicationJournalSchema, CandidateDigest: artifact.Digest, PreviousDigest: first.Digest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := publisher.setPointer("current", artifact.Digest); err != nil {
		t.Fatal(err)
	}

	recovery := &recoveryPublisherRuntime{serving: candidate.VersionID, failReloads: 1}
	if _, err := NewPublisher(root, "/opt/cdnca/originroute", allPublisherAddresses(policy), recovery); !errors.Is(err, ErrRollback) {
		t.Fatalf("first recovery error=%v, expected rollback failure", err)
	}
	current, err := publisher.pointer("current")
	if err != nil || current != first.Digest {
		t.Fatalf("failed recovery current=%q error=%v, want LKG %q", current, err, first.Digest)
	}
	if _, err := os.Lstat(filepath.Join(root, publicationJournalName)); err != nil {
		t.Fatalf("failed recovery lost journal: %v", err)
	}
	if _, err := NewPublisher(root, "/opt/cdnca/originroute", allPublisherAddresses(policy), recovery); err != nil {
		t.Fatal(err)
	}
	recovery.mu.Lock()
	defer recovery.mu.Unlock()
	if recovery.serving != policy.VersionID || len(recovery.reloads) != 2 || len(recovery.healths) != 1 {
		t.Fatalf("recovery serving=%q reloads=%v healths=%v",
			recovery.serving, recovery.reloads, recovery.healths)
	}
	if _, err := os.Lstat(filepath.Join(root, publicationJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verified recovery retained journal: %v", err)
	}
}

func TestPublisherJournalsUnexpectedCurrentBeforeRollback(t *testing.T) {
	policy := testPolicy()
	setupRuntime := &publisherRuntime{healthErrors: make(map[string]error)}
	publisher, root := newTestPublisher(t, policy, setupRuntime)
	first, err := publisher.Apply(context.Background(), policyJSON(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	candidate := policy
	candidate.Revision++
	candidate.VersionID = "route-v2-unexpected-current"
	artifact, err := Compile(candidate, root, "/opt/cdnca/originroute")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.ensureRelease(artifact); err != nil {
		t.Fatal(err)
	}
	if err := publisher.setPointer("current", artifact.Digest); err != nil {
		t.Fatal(err)
	}

	recovery := &recoveryPublisherRuntime{serving: candidate.VersionID, failReloads: 1}
	if _, err := NewPublisher(root, "/opt/cdnca/originroute", allPublisherAddresses(policy), recovery); !errors.Is(err, ErrRollback) {
		t.Fatalf("unexpected-current recovery error=%v", err)
	}
	journal, err := publisher.readJournal()
	if err != nil || journal == nil || journal.CandidateDigest != artifact.Digest || journal.PreviousDigest != first.Digest {
		t.Fatalf("durable recovery journal=%+v error=%v", journal, err)
	}
	if _, err := NewPublisher(root, "/opt/cdnca/originroute", allPublisherAddresses(policy), recovery); err != nil {
		t.Fatal(err)
	}
	recovery.mu.Lock()
	defer recovery.mu.Unlock()
	if recovery.serving != policy.VersionID || len(recovery.reloads) != 2 || len(recovery.healths) != 1 {
		t.Fatalf("unexpected-current serving=%q reloads=%v healths=%v",
			recovery.serving, recovery.reloads, recovery.healths)
	}
}

func TestPublisherRecoversAfterProcessDiesWithCandidateCurrent(t *testing.T) {
	policy := testPolicy()
	base := publisherTestBase(t)
	root := filepath.Join(base, "state")
	entered := filepath.Join(base, "crash-entered")
	release := filepath.Join(base, "never-release")
	setupRuntime := &publisherRuntime{healthErrors: make(map[string]error)}
	publisher, err := NewPublisher(root, "/opt/cdnca/originroute", allPublisherAddresses(policy), setupRuntime)
	if err != nil {
		t.Fatal(err)
	}
	first, err := publisher.Apply(context.Background(), policyJSON(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestPublisherCrossProcessLockHelper$")
	command.Env = append(os.Environ(),
		"CDNCA_ORIGINROUTE_PUBLISH_HELPER=1",
		"CDNCA_ORIGINROUTE_PUBLISH_CANDIDATE=1",
		"CDNCA_ORIGINROUTE_PUBLISH_ROOT="+root,
		"CDNCA_ORIGINROUTE_PUBLISH_ENTERED="+entered,
		"CDNCA_ORIGINROUTE_PUBLISH_RELEASE="+release,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(entered); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal("crash helper did not enter candidate reload")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("crash helper exited successfully after SIGKILL")
	}
	current, err := publisher.pointer("current")
	if err != nil || current == "" || current == first.Digest {
		t.Fatalf("crash boundary current=%q error=%v, expected candidate", current, err)
	}
	if _, err := os.Lstat(filepath.Join(root, publicationJournalName)); err != nil {
		t.Fatalf("crash boundary journal missing: %v", err)
	}
	recovery := &recoveryPublisherRuntime{serving: "route-v2-crash-candidate"}
	if _, err := NewPublisher(root, "/opt/cdnca/originroute", allPublisherAddresses(policy), recovery); err != nil {
		t.Fatal(err)
	}
	recovery.mu.Lock()
	defer recovery.mu.Unlock()
	if recovery.serving != policy.VersionID || len(recovery.reloads) != 1 || len(recovery.healths) != 1 {
		t.Fatalf("crash recovery serving=%q reloads=%v healths=%v",
			recovery.serving, recovery.reloads, recovery.healths)
	}
}

func TestPublisherRejectsUnsafePublicationJournal(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		build func(t *testing.T, path string)
	}{
		{name: "mode", build: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink", build: func(t *testing.T, path string) {
			target := filepath.Join(filepath.Dir(filepath.Dir(path)), "outside-journal")
			if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory", build: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink", build: func(t *testing.T, path string) {
			target := filepath.Join(filepath.Dir(filepath.Dir(path)), "linked-journal")
			if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(target, path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			policy := testPolicy()
			runtime := &publisherRuntime{healthErrors: make(map[string]error)}
			publisher, root := newTestPublisher(t, policy, runtime)
			path := filepath.Join(root, publicationJournalName)
			testCase.build(t, path)
			if _, err := publisher.readJournal(); err == nil {
				t.Fatal("unsafe publication journal was accepted")
			}
		})
	}
}

func TestCompileIsDeterministicAndInjectionSafe(t *testing.T) {
	policy := testPolicy()
	first, err := Compile(policy, "/var/lib/cdnca-originroute", "/opt/cdnca/originroute")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(policy, "/var/lib/cdnca-originroute", "/opt/cdnca/originroute")
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || string(first.Nginx) != string(second.Nginx) {
		t.Fatal("compile output is not deterministic")
	}
	if _, err := Compile(policy, "/tmp/origin;return", "/opt/cdnca/originroute"); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unsafe root error=%v", err)
	}
	if _, err := Compile(policy, "relative", "/opt/cdnca/originroute"); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("relative root error=%v", err)
	}
}
