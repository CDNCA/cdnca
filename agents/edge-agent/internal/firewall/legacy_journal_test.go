package firewall

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Legacy (unscoped) applies must have the same crash boundary as scoped applies:
// the durable journal determines whether the candidate or the previous LKG won.
func TestLegacyApplyCrashAfterKernelApplyRecoversCandidateWithoutReplay(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{}
	manager := newTestManager(t, root, runner, fixedTime)
	baseline := validVersion("legacy-task-v1", "legacy-fw-v1")
	if result, err := manager.Apply(context.Background(), baseline); err != nil || result.State != StateApplied {
		t.Fatalf("Apply(baseline) result=%+v error=%v", result, err)
	}

	candidate := validVersion("legacy-task-v2", "legacy-fw-v2")
	candidate.Entries[0].Network = "203.0.113.8"
	manager.afterKernelApply = func() error { return errInjected }
	if _, err := manager.Apply(context.Background(), candidate); !errors.Is(err, errInjected) {
		t.Fatalf("Apply(candidate) error=%v, want injected crash", err)
	}
	if _, err := os.Stat(manager.store.inflightPath); err != nil {
		t.Fatalf("candidate journal missing after post-apply crash: %v", err)
	}
	_, appliesBeforeRecovery, _ := runner.counts()

	restarted := newTestManager(t, root, runner, fixedTime)
	_, appliesAfterRecovery, _ := runner.counts()
	if appliesAfterRecovery != appliesBeforeRecovery {
		t.Fatalf("recovery replayed nft apply: before=%d after=%d", appliesBeforeRecovery, appliesAfterRecovery)
	}
	status, err := restarted.Status(context.Background())
	if err != nil || !status.Healthy || status.VersionID != candidate.VersionID {
		t.Fatalf("recovered status=%+v error=%v, want candidate active", status, err)
	}
	if _, err := os.Stat(restarted.store.inflightPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate journal remained after recovery: %v", err)
	}
	result, err := restarted.Apply(context.Background(), candidate)
	if err != nil || result.State != StateApplied || result.ActiveVersionID != candidate.VersionID {
		t.Fatalf("replayed candidate result=%+v error=%v", result, err)
	}
	if _, appliesAfterReplay, _ := runner.counts(); appliesAfterReplay != appliesAfterRecovery {
		t.Fatalf("idempotent replay reran nft apply: before=%d after=%d", appliesAfterRecovery, appliesAfterReplay)
	}
}

func TestLegacyApplyCrashBeforeKernelApplyKeepsLKG(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{}
	manager := newTestManager(t, root, runner, fixedTime)
	baseline := validVersion("legacy-task-v1", "legacy-fw-v1")
	if result, err := manager.Apply(context.Background(), baseline); err != nil || result.State != StateApplied {
		t.Fatalf("Apply(baseline) result=%+v error=%v", result, err)
	}
	candidate := validVersion("legacy-task-v2", "legacy-fw-v2")
	candidate.Entries[0].Network = "203.0.113.9"
	manager.afterJournalSync = func() error { return errInjected }
	if _, err := manager.Apply(context.Background(), candidate); !errors.Is(err, errInjected) {
		t.Fatalf("Apply(candidate) error=%v, want injected crash", err)
	}
	if _, err := os.Stat(manager.store.inflightPath); err != nil {
		t.Fatalf("candidate journal missing before kernel apply: %v", err)
	}
	_, appliesBeforeRecovery, _ := runner.counts()

	restarted := newTestManager(t, root, runner, fixedTime)
	_, appliesAfterRecovery, _ := runner.counts()
	if appliesAfterRecovery != appliesBeforeRecovery {
		t.Fatalf("unapplied recovery invoked nft apply: before=%d after=%d", appliesBeforeRecovery, appliesAfterRecovery)
	}
	status, err := restarted.Status(context.Background())
	if err != nil || !status.Healthy || status.VersionID != baseline.VersionID {
		t.Fatalf("recovered status=%+v error=%v, want baseline LKG", status, err)
	}
	if _, err := os.Stat(restarted.store.inflightPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unapplied journal remained after recovery: %v", err)
	}
	result, err := restarted.Apply(context.Background(), candidate)
	if err != nil || result.State != StateFailed || result.ErrorCode != "RECOVERY_NOT_APPLIED" || !result.RunningVersionUnchanged {
		t.Fatalf("recovered candidate result=%+v error=%v", result, err)
	}
	if _, appliesAfterReplay, _ := runner.counts(); appliesAfterReplay != appliesAfterRecovery {
		t.Fatalf("recovered candidate replay reran nft apply: before=%d after=%d", appliesAfterRecovery, appliesAfterReplay)
	}
	if !reflect.DeepEqual(result, func() Result {
		replayed, replayErr := restarted.Apply(context.Background(), candidate)
		if replayErr != nil {
			t.Fatalf("failed candidate replay error=%v", replayErr)
		}
		return replayed
	}()) {
		t.Fatalf("failed candidate replay changed durable result")
	}
}

func TestAggregateScopeMetadataFailsClosedBeforeNft(t *testing.T) {
	runner := &fakeRunner{}
	manager := newTestManager(t, testStateRoot(t), runner, fixedTime)
	version := scopedVersion(
		"aggregate-scope", "11111111-1111-4111-8111-111111111111",
		"77777777-7777-4777-8777-777777777777", "44444444-4444-4444-8444-444444444444", 1, 0,
		"198.51.100.0/24",
	)
	version.Aggregate = true
	if _, err := manager.Apply(context.Background(), version); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("Aggregate scoped metadata error=%v, want ErrInvalidVersion", err)
	}
	if checks, applies, statuses := runner.counts(); checks != 0 || applies != 0 || statuses != 0 {
		t.Fatalf("invalid aggregate metadata reached nft: checks=%d applies=%d statuses=%d", checks, applies, statuses)
	}
}

func TestCorruptLegacyJournalFailsClosed(t *testing.T) {
	root := testStateRoot(t)
	runner := &fakeRunner{}
	manager := newTestManager(t, root, runner, fixedTime)
	if err := os.WriteFile(manager.store.inflightPath, []byte(`{"schema_version":999,"digest":"`+strings.Repeat("a", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManagerWithDependencies(root, runner, fixedTime); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("NewManagerWithDependencies() error=%v, want ErrCorruptState", err)
	}
	if checks, applies, statuses := runner.counts(); checks != 0 || applies != 0 || statuses != 0 {
		t.Fatalf("corrupt journal reached nft: checks=%d applies=%d statuses=%d", checks, applies, statuses)
	}
}
