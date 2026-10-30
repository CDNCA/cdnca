package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestUpgradeActiveProbeEvidenceSurvivesReplayAndRestart(t *testing.T) {
	artifact := []byte("active-probe-agent-v2")
	environment := newTestEnvironment(t, artifact)
	environment.probe.evidence = ConfigProbeEvidence{
		ActiveConfigSHA256:        repeatedDigest(0x41),
		LastKnownGoodConfigSHA256: repeatedDigest(0x42),
	}
	plan := environment.plan(t, "upgrade-active-probe", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)

	result, err := environment.manager.Process(context.Background(), plan)
	if err != nil || result.State != StateSucceeded {
		t.Fatalf("upgrade result = (%#v, %v)", result, err)
	}
	artifactDigest := sha256.Sum256(artifact)
	baselineDigest := sha256.Sum256([]byte("baseline-v1"))
	if result.ActiveEvidence.ActiveArtifactSHA256 != hex.EncodeToString(artifactDigest[:]) ||
		result.ActiveEvidence.LastKnownGoodArtifactSHA256 != hex.EncodeToString(baselineDigest[:]) ||
		result.ActiveEvidence.ActiveConfigSHA256 != environment.probe.evidence.ActiveConfigSHA256 ||
		result.ActiveEvidence.LastKnownGoodConfigSHA256 != environment.probe.evidence.LastKnownGoodConfigSHA256 ||
		validateActiveProbeEvidence(result.InstallerTransactionID, result.ActiveEvidence) != nil {
		t.Fatalf("active evidence = %#v", result.ActiveEvidence)
	}

	replayed, err := environment.manager.Process(context.Background(), plan)
	if err != nil || !replayed.Duplicate || !reflect.DeepEqual(replayed.ActiveEvidence, result.ActiveEvidence) {
		t.Fatalf("replayed result = (%#v, %v)", replayed, err)
	}
	restarted, err := environment.newManager(t).Process(context.Background(), plan)
	if err != nil || !restarted.Duplicate || !reflect.DeepEqual(restarted.ActiveEvidence, result.ActiveEvidence) {
		t.Fatalf("restarted result = (%#v, %v)", restarted, err)
	}
}

func TestAutomaticRollbackProvesRestoredLastKnownGood(t *testing.T) {
	artifact := []byte("active-probe-unhealthy-v2")
	environment := newTestEnvironment(t, artifact)
	environment.probe.evidence = ConfigProbeEvidence{
		ActiveConfigSHA256:        repeatedDigest(0x51),
		LastKnownGoodConfigSHA256: repeatedDigest(0x52),
	}
	environment.probe.errors = []error{nil, errors.New("unhealthy")}
	plan := environment.plan(t, "upgrade-active-probe-rollback", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)

	result, err := environment.manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrHealth) || result.State != StateRolledBack {
		t.Fatalf("rollback result = (%#v, %v)", result, err)
	}
	baselineDigest := sha256.Sum256([]byte("baseline-v1"))
	failedDigest := sha256.Sum256(artifact)
	if result.ActiveEvidence.ActiveArtifactSHA256 != hex.EncodeToString(baselineDigest[:]) ||
		result.ActiveEvidence.LastKnownGoodArtifactSHA256 != hex.EncodeToString(failedDigest[:]) ||
		validateActiveProbeEvidence(result.InstallerTransactionID, result.ActiveEvidence) != nil {
		t.Fatalf("rollback evidence = %#v", result.ActiveEvidence)
	}
}

func TestUpgradeActiveProbeUsesLastRealProbeTimeWhenSleepOvershoots(t *testing.T) {
	artifact := []byte("active-probe-real-timer-overshoot")
	environment := newTestEnvironment(t, artifact)
	clock := &overshootingClock{now: environment.now.Now(), overshoot: time.Nanosecond}
	config := DefaultConfig(
		environment.root, "1.0.0", map[string]ed25519.PublicKey{"release-2026": environment.planPublicKey},
		map[string]ed25519.PublicKey{"sandbox-helper": environment.receiptPublicKey},
		environment.downloader, environment.installer, environment.probe,
	)
	config.NodeID = "node-test-1"
	config.Clock = clock
	config.DiskReserveBytes = 0
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	plan := environment.plan(t, "upgrade-active-probe-overshoot", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)

	result, err := manager.Process(context.Background(), plan)
	if err != nil || result.State != StateSucceeded || result.ActiveEvidence == nil {
		t.Fatalf("overshooting clock result = (%#v, %v)", result, err)
	}
	if result.ActiveEvidence.ProbeObservedAt.After(result.ActiveEvidence.ProbeDeadline) {
		t.Fatalf("probe observed after deadline: observed=%s deadline=%s",
			result.ActiveEvidence.ProbeObservedAt, result.ActiveEvidence.ProbeDeadline)
	}
}

func TestUpgradeActiveProbeRestartAfterMidWindowCrashCannotSkipObservation(t *testing.T) {
	artifact := []byte("active-probe-mid-window-crash")
	environment := newTestEnvironment(t, artifact)
	ctx, cancel := context.WithCancel(context.Background())
	probe := &crashingActiveProbe{
		cancel: cancel, crashAt: 2,
		evidence: ConfigProbeEvidence{
			ActiveConfigSHA256:        repeatedDigest(0x43),
			LastKnownGoodConfigSHA256: repeatedDigest(0x44),
		},
	}
	newManager := func() *Manager {
		config := DefaultConfig(
			environment.root, "1.0.0", map[string]ed25519.PublicKey{"release-2026": environment.planPublicKey},
			map[string]ed25519.PublicKey{"sandbox-helper": environment.receiptPublicKey},
			environment.downloader, environment.installer, probe,
		)
		config.NodeID = "node-test-1"
		config.Clock = environment.now
		config.DiskReserveBytes = 0
		manager, err := NewManager(config)
		if err != nil {
			t.Fatal(err)
		}
		return manager
	}
	plan := environment.plan(t, "upgrade-active-probe-mid-window-crash", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	manager := newManager()

	if result, err := manager.Process(ctx, plan); !errors.Is(err, context.Canceled) || result.State == StateSucceeded {
		t.Fatalf("mid-window crash result = (%#v, %v)", result, err)
	}
	journal, err := manager.fs.loadTransaction()
	if err != nil || journal == nil || journal.Phase != phaseObserve || journal.Result.ActiveEvidence == nil ||
		journal.Result.ActiveEvidence.ProbeObservedAt.IsZero() || journal.Result.ActiveEvidence.ProbeDeadline.IsZero() {
		t.Fatalf("mid-window durable state = (%#v, %v)", journal, err)
	}
	environment.now.mu.Lock()
	environment.now.now = journal.Result.ActiveEvidence.ProbeDeadline.Add(time.Second)
	environment.now.mu.Unlock()

	result, found, err := newManager().Recover(context.Background())
	if !found || !errors.Is(err, ErrHealth) || result.State != StateRolledBack {
		t.Fatalf("cross-deadline recovery = (%#v, %t, %v)", result, found, err)
	}
	baselineDigest := sha256.Sum256([]byte("baseline-v1"))
	failedDigest := sha256.Sum256(artifact)
	if result.ActiveEvidence == nil ||
		result.ActiveEvidence.ActiveArtifactSHA256 != hex.EncodeToString(baselineDigest[:]) ||
		result.ActiveEvidence.LastKnownGoodArtifactSHA256 != hex.EncodeToString(failedDigest[:]) ||
		validateActiveProbeEvidence(result.InstallerTransactionID, result.ActiveEvidence) != nil {
		t.Fatalf("recovered LKG evidence = %#v", result.ActiveEvidence)
	}
}

func TestUpgradeRuntimeEmitsMicrosecondStatusTime(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Date(2026, 8, 6, 2, 0, 0, 123456789, time.UTC)
	runtime := &UpgradeRuntime{store: store, now: func() time.Time { return observed }}
	if err := runtime.emitStatus(context.Background(), accepted, EdgeUpgradeStateAccepted, Result{}, ""); err != nil {
		t.Fatal(err)
	}
	status, found, err := store.LastStatus(context.Background(), accepted.Command.CommandID)
	if err != nil || !found {
		t.Fatalf("last status = (%#v, %t, %v)", status, found, err)
	}
	if want := observed.Truncate(time.Microsecond); !status.ObservedAt.Equal(want) {
		t.Fatalf("status observed_at = %s, want %s", status.ObservedAt, want)
	}
}

func TestEdgeUpgradeStatusV2RejectsStateOnlyOrExpiredEvidence(t *testing.T) {
	commandID := "00000000-0000-4000-8000-000000000021"
	observed := time.Date(2026, 8, 6, 2, 0, 0, 0, time.UTC)
	status := EdgeUpgradeStatus{
		Schema:   EdgeUpgradeStatusSchemaV2,
		StatusID: mustUpgradeStatusID(t, commandID, 3), StatusRevision: 3,
		CommandID: commandID, PlanID: "00000000-0000-4000-8000-000000000011", PlanRevision: 2,
		InstallationID: "00000000-0000-4000-8000-000000000004",
		NodeID:         "00000000-0000-4000-8000-000000000022", CommandSHA256: repeatedDigest(0x61),
		State: EdgeUpgradeStateHealthy, CurrentVersion: "2.0.0", PreviousVersion: "1.0.0",
		InstallerTransactionID: "txn-active-probe-v2", ObservedAt: observed,
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEdgeUpgradeStatus(encoded); !errors.Is(err, ErrInvalidUpgradeStatus) {
		t.Fatalf("state-only v2 error = %v", err)
	}

	status.ActiveEvidence = &ActiveProbeEvidence{
		Schema:               ActiveProbeEvidenceSchema,
		ActiveArtifactSHA256: repeatedDigest(0x62), ActiveConfigSHA256: repeatedDigest(0x63),
		LastKnownGoodArtifactSHA256: repeatedDigest(0x64), LastKnownGoodConfigSHA256: repeatedDigest(0x65),
		ProbeObservedAt: observed.Add(-time.Second), ProbeDeadline: observed.Add(time.Second),
	}
	status.ActiveEvidence.EvidenceSHA256 = activeProbeEvidenceDigest(status.InstallerTransactionID, *status.ActiveEvidence)
	encoded, _ = json.Marshal(status)
	if decoded, err := decodeEdgeUpgradeStatus(encoded); err != nil || decoded.ActiveEvidence == nil {
		t.Fatalf("v2 evidence decode = (%#v, %v)", decoded, err)
	}

	expired := status
	expired.ActiveEvidence = cloneActiveProbeEvidence(status.ActiveEvidence)
	expired.ActiveEvidence.ProbeDeadline = expired.ActiveEvidence.ProbeObservedAt.Add(-time.Nanosecond)
	expired.ActiveEvidence.EvidenceSHA256 = activeProbeEvidenceDigest(expired.InstallerTransactionID, *expired.ActiveEvidence)
	encoded, _ = json.Marshal(expired)
	if _, err := decodeEdgeUpgradeStatus(encoded); !errors.Is(err, ErrInvalidUpgradeStatus) {
		t.Fatalf("expired evidence error = %v", err)
	}

	tampered := status
	tampered.ActiveEvidence = cloneActiveProbeEvidence(status.ActiveEvidence)
	tampered.ActiveEvidence.ActiveConfigSHA256 = repeatedDigest(0x66)
	encoded, _ = json.Marshal(tampered)
	if _, err := decodeEdgeUpgradeStatus(encoded); !errors.Is(err, ErrInvalidUpgradeStatus) {
		t.Fatalf("tampered evidence error = %v", err)
	}
}

func repeatedDigest(value byte) string {
	return hex.EncodeToString(makeRepeatedBytes(value, sha256.Size))
}

func makeRepeatedBytes(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

type overshootingClock struct {
	now       time.Time
	overshoot time.Duration
}

type crashingActiveProbe struct {
	cancel   context.CancelFunc
	crashAt  int
	checks   int
	evidence ConfigProbeEvidence
}

func (probe *crashingActiveProbe) Check(context.Context, ActivationReceipt, []string) error {
	probe.checks++
	if probe.checks == probe.crashAt {
		probe.cancel()
		return context.Canceled
	}
	return nil
}

func (probe *crashingActiveProbe) Evidence(context.Context, ActivationReceipt, []string) (ConfigProbeEvidence, error) {
	return probe.evidence, nil
}

func (clock *overshootingClock) Now() time.Time { return clock.now }

func (clock *overshootingClock) Sleep(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clock.now = clock.now.Add(duration + clock.overshoot)
	return nil
}
