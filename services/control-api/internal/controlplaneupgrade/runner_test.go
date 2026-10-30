package controlplaneupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

func TestRunnerExecutesDurableControlPlaneUpgradeInSafeOrder(t *testing.T) {
	fixture := newRunnerFixture(t)
	receipt, err := fixture.runner.Run(t.Context(), fixture.encoded)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"facts", "expand", "preflight", "drain", "activate", "health:target", "contract", "resume"}
	if !reflect.DeepEqual(fixture.executor.calls, want) {
		t.Fatalf("calls = %v, want %v", fixture.executor.calls, want)
	}
	if receipt.Result != ResultApplied || receipt.Sequence != 42 || receipt.TargetVersion != "1.5.0" || receipt.Replayed {
		t.Fatalf("receipt = %#v", receipt)
	}
	stored, err := fixture.store.Load()
	if err != nil || stored.Phase != PhaseCompleted || stored.Receipt == nil || stored.Receipt.Result != ResultApplied {
		t.Fatalf("stored = (%#v, %v)", stored, err)
	}
}

func TestRunnerRejectsTamperTargetMismatchAndStaleSequenceBeforeMutation(t *testing.T) {
	fixture := newRunnerFixture(t)
	tampered := append([]byte(nil), fixture.encoded...)
	tampered[len(tampered)-2] ^= 1
	if _, err := fixture.runner.Run(t.Context(), tampered); err == nil {
		t.Fatal("tampered bundle was accepted")
	}
	if len(fixture.executor.calls) != 0 {
		t.Fatalf("tampered calls = %v", fixture.executor.calls)
	}

	fixture = newRunnerFixture(t)
	fixture.executor.facts.CurrentVersion = "1.3.0"
	if _, err := fixture.runner.Run(t.Context(), fixture.encoded); !errors.Is(err, ErrTargetMismatch) {
		t.Fatalf("current-version mismatch error = %v", err)
	}
	if len(fixture.executor.calls) != 1 {
		t.Fatalf("mismatch calls = %v", fixture.executor.calls)
	}

	fixture = newRunnerFixture(t)
	if err := fixture.store.Save(State{Schema: StateSchema, PlanID: "00000000-0000-4000-8000-000000000099",
		BundleSHA256: digestBytes([]byte("newer")), Sequence: 43, Phase: PhaseCompleted}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runner.Run(t.Context(), fixture.encoded); !errors.Is(err, ErrStalePlan) {
		t.Fatalf("stale sequence error = %v", err)
	}
	if len(fixture.executor.calls) != 0 {
		t.Fatalf("stale calls = %v", fixture.executor.calls)
	}
}

func TestRunnerReplaysTerminalReceiptAndResumesCheckpoint(t *testing.T) {
	fixture := newRunnerFixture(t)
	first, err := fixture.runner.Run(t.Context(), fixture.encoded)
	if err != nil {
		t.Fatal(err)
	}
	fixture.executor.calls = nil
	replayed, err := fixture.runner.Run(t.Context(), fixture.encoded)
	if err != nil || !replayed.Replayed || replayed.ID != first.ID || len(fixture.executor.calls) != 0 {
		t.Fatalf("replay = (%#v, %v), calls=%v", replayed, err, fixture.executor.calls)
	}

	fixture = newRunnerFixture(t)
	plan, err := fixture.runner.verify(fixture.encoded, fixture.executor.facts)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Save(State{Schema: StateSchema, PlanID: plan.ID, BundleSHA256: plan.BundleSHA256,
		Sequence: plan.Sequence, Phase: PhaseActivated, PreviousDigest: fixture.executor.facts.CurrentDigest,
		TargetDigest: plan.Target.Digest}); err != nil {
		t.Fatal(err)
	}
	receipt, err := fixture.runner.Run(t.Context(), fixture.encoded)
	if err != nil || receipt.Result != ResultApplied {
		t.Fatalf("resumed Run() = (%#v, %v)", receipt, err)
	}
	want := []string{"facts", "health:target", "contract", "resume"}
	if !reflect.DeepEqual(fixture.executor.calls, want) {
		t.Fatalf("resume calls = %v, want %v", fixture.executor.calls, want)
	}
}

func TestRunnerResumesWhenActivationCompletedBeforeCheckpoint(t *testing.T) {
	fixture := newRunnerFixture(t)
	plan, err := fixture.runner.verify(fixture.encoded, fixture.executor.facts)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Save(State{Schema: StateSchema, PlanID: plan.ID, BundleSHA256: plan.BundleSHA256,
		Sequence: plan.Sequence, Phase: PhaseDrained, PreviousDigest: fixture.executor.facts.CurrentDigest,
		TargetDigest: plan.Target.Digest}); err != nil {
		t.Fatal(err)
	}
	fixture.executor.facts.CurrentVersion = plan.Target.Version
	fixture.executor.facts.CurrentDigest = plan.Target.Digest

	receipt, err := fixture.runner.Run(t.Context(), fixture.encoded)
	if err != nil || receipt.Result != ResultApplied {
		t.Fatalf("resumed Run() = (%#v, %v)", receipt, err)
	}
	want := []string{"facts", "activate", "health:target", "contract", "resume"}
	if !reflect.DeepEqual(fixture.executor.calls, want) {
		t.Fatalf("resume calls = %v, want %v", fixture.executor.calls, want)
	}
}

func TestRunnerAutomaticallyRollsBackAndPersistsReceipt(t *testing.T) {
	fixture := newRunnerFixture(t)
	fixture.executor.failHealthTarget = errors.New("readiness timeout")
	receipt, err := fixture.runner.Run(t.Context(), fixture.encoded)
	if !errors.Is(err, ErrRolledBack) || receipt.Result != ResultRolledBack || receipt.ErrorCode != "target_health_failed" {
		t.Fatalf("Run() = (%#v, %v)", receipt, err)
	}
	want := []string{"facts", "expand", "preflight", "drain", "activate", "health:target", "rollback", "health:rollback", "resume"}
	if !reflect.DeepEqual(fixture.executor.calls, want) {
		t.Fatalf("rollback calls = %v, want %v", fixture.executor.calls, want)
	}
	stored, err := fixture.store.Load()
	if err != nil || stored.Phase != PhaseRolledBack || stored.Receipt == nil || stored.Receipt.Result != ResultRolledBack {
		t.Fatalf("stored rollback = (%#v, %v)", stored, err)
	}
}

func TestRunnerRetriesTransientFailureBeforeActivation(t *testing.T) {
	fixture := newRunnerFixture(t)
	fixture.executor.failDrain = errors.New("drain unavailable")
	if receipt, err := fixture.runner.Run(t.Context(), fixture.encoded); err == nil || receipt.ID != "" {
		t.Fatalf("first Run() = (%#v, %v)", receipt, err)
	}
	stored, err := fixture.store.Load()
	if err != nil || stored.Phase != PhasePreflighted || stored.ErrorCode != "drain_failed" || stored.Receipt != nil {
		t.Fatalf("stored retry checkpoint = (%#v, %v)", stored, err)
	}
	fixture.executor.failDrain = nil
	fixture.executor.calls = nil
	receipt, err := fixture.runner.Run(t.Context(), fixture.encoded)
	if err != nil || receipt.Result != ResultApplied {
		t.Fatalf("retry Run() = (%#v, %v)", receipt, err)
	}
	want := []string{"facts", "drain", "activate", "health:target", "contract", "resume"}
	if !reflect.DeepEqual(fixture.executor.calls, want) {
		t.Fatalf("retry calls = %v, want %v", fixture.executor.calls, want)
	}
}

func TestRunnerTerminallyFailsRejectedCandidateBeforeDrain(t *testing.T) {
	fixture := newRunnerFixture(t)
	fixture.executor.failExpand = fmt.Errorf("%w: %w", ErrCandidateRejected, ErrTargetMismatch)
	receipt, err := fixture.runner.Run(t.Context(), fixture.encoded)
	if !errors.Is(err, ErrTargetMismatch) || receipt.Result != ResultFailed || receipt.ErrorCode != "expand_failed" {
		t.Fatalf("Run() = (%#v, %v)", receipt, err)
	}
	stored, err := fixture.store.Load()
	if err != nil || stored.Phase != PhaseFailed || stored.Receipt == nil || stored.Receipt.Result != ResultFailed {
		t.Fatalf("stored = (%#v, %v)", stored, err)
	}
	fixture.executor.calls = nil
	replayed, err := fixture.runner.Run(t.Context(), fixture.encoded)
	if err != nil || !replayed.Replayed || replayed.Result != ResultFailed || len(fixture.executor.calls) != 0 {
		t.Fatalf("replay = (%#v, %v), calls=%v", replayed, err, fixture.executor.calls)
	}
}

func TestRunnerSupersedesFailedCheckpointOnlyBeforeDrain(t *testing.T) {
	for _, tc := range []struct {
		name      string
		phase     Phase
		errorCode string
		sequence  uint64
		want      error
	}{
		{"failed verified checkpoint", PhaseVerified, "expand_failed", 41, nil},
		{"failed preflighted same sequence", PhasePreflighted, "drain_failed", 42, nil},
		{"in-flight verified checkpoint", PhaseVerified, "", 41, ErrPlanInProgress},
		{"drained checkpoint", PhaseDrained, "activation_failed", 41, ErrPlanInProgress},
		{"failed checkpoint with newer sequence", PhaseVerified, "expand_failed", 43, ErrStalePlan},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRunnerFixture(t)
			if err := fixture.store.Save(State{Schema: StateSchema, PlanID: "00000000-0000-4000-8000-000000000099",
				BundleSHA256: digestBytes([]byte("older")), Sequence: tc.sequence, Phase: tc.phase, ErrorCode: tc.errorCode,
				PreviousDigest: fixture.executor.facts.CurrentDigest}); err != nil {
				t.Fatal(err)
			}
			receipt, err := fixture.runner.Run(t.Context(), fixture.encoded)
			if tc.want != nil {
				if !errors.Is(err, tc.want) || len(fixture.executor.calls) != 0 {
					t.Fatalf("Run() = (%#v, %v), calls=%v", receipt, err, fixture.executor.calls)
				}
				return
			}
			if err != nil || receipt.Result != ResultApplied {
				t.Fatalf("Run() = (%#v, %v)", receipt, err)
			}
		})
	}
}

func TestRunnerRejectsOversizedBundleBeforeExecutor(t *testing.T) {
	fixture := newRunnerFixture(t)
	if _, err := fixture.runner.Run(t.Context(), bytes.Repeat([]byte{'x'}, (1<<20)+1)); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("oversized bundle error = %v", err)
	}
	if len(fixture.executor.calls) != 0 {
		t.Fatalf("oversized bundle calls = %v", fixture.executor.calls)
	}
}

type runnerFixture struct {
	runner   *Runner
	store    *FileStore
	executor *fakeExecutor
	encoded  []byte
}

func newRunnerFixture(t *testing.T) runnerFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	signer := runnerTestSigner{privateKey: privateKey}
	encoded := signedRunnerTestBundle(t, now, signer)
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: signer.KeyID(), PublicKey: privateKey.Public().(ed25519.PublicKey),
	}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(filepath.Join(t.TempDir(), "runner-state"))
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeExecutor{facts: Facts{InstallationID: "00000000-0000-4000-8000-000000000005",
		CurrentVersion: "1.4.0", CurrentDigest: "5252525252525252525252525252525252525252525252525252525252525252", ProtocolVersion: 2}}
	runner, err := New(Config{InstallationID: executor.facts.InstallationID, Component: "control-api",
		Target: TargetKubernetes}, trust, store, executor, func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	return runnerFixture{runner: runner, store: store, executor: executor, encoded: encoded}
}

type fakeExecutor struct {
	facts            Facts
	calls            []string
	failHealthTarget error
	failDrain        error
	failExpand       error
}

func (executor *fakeExecutor) Target() Target { return TargetKubernetes }
func (executor *fakeExecutor) Facts(context.Context) (Facts, error) {
	executor.calls = append(executor.calls, "facts")
	return executor.facts, nil
}
func (executor *fakeExecutor) Expand(context.Context, Plan) error {
	executor.calls = append(executor.calls, "expand")
	return executor.failExpand
}
func (executor *fakeExecutor) Preflight(context.Context, Plan) error {
	executor.calls = append(executor.calls, "preflight")
	return nil
}
func (executor *fakeExecutor) Drain(context.Context, Plan) error {
	executor.calls = append(executor.calls, "drain")
	return executor.failDrain
}
func (executor *fakeExecutor) Activate(context.Context, Plan) error {
	executor.calls = append(executor.calls, "activate")
	return nil
}
func (executor *fakeExecutor) Health(_ context.Context, _ Plan, artifact Artifact) error {
	if artifact.Version == "1.5.0" {
		executor.calls = append(executor.calls, "health:target")
		return executor.failHealthTarget
	}
	executor.calls = append(executor.calls, "health:rollback")
	return nil
}
func (executor *fakeExecutor) Contract(context.Context, Plan) error {
	executor.calls = append(executor.calls, "contract")
	return nil
}
func (executor *fakeExecutor) Rollback(context.Context, Plan) error {
	executor.calls = append(executor.calls, "rollback")
	return nil
}
func (executor *fakeExecutor) Resume(context.Context, Plan) error {
	executor.calls = append(executor.calls, "resume")
	return nil
}

type runnerTestSigner struct{ privateKey ed25519.PrivateKey }

func (runnerTestSigner) KeyID() string { return "license-release-1" }
func (signer runnerTestSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.privateKey, payload), nil
}

func signedRunnerTestBundle(t *testing.T, now time.Time, signer runnerTestSigner) []byte {
	t.Helper()
	artifact := func(id, version string, fill byte, sequence uint64) entitlement.UpgradePlanArtifact {
		manifest := entitlement.ArtifactManifestV2{Schema: entitlement.ArtifactManifestV3Schema,
			Audience: entitlement.ArtifactManifestAudience, Purpose: entitlement.ArtifactManifestPurpose,
			ArtifactID: id, Component: "control-api", Version: version, ProtocolMin: 1, ProtocolMax: 3,
			ArtifactSizeBytes: 4096, ReleaseSequence: sequence, DigestAlgorithm: "sha256",
			SHA256Digest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32)),
			DownloadURL:  "https://releases.example.invalid/control-api/" + version}
		signature, err := entitlement.SignArtifactManifestV3(t.Context(), manifest, signer)
		if err != nil {
			t.Fatal(err)
		}
		return entitlement.UpgradePlanArtifact{Manifest: manifest, SignatureAlgorithm: entitlement.Algorithm,
			SignatureKeyID: signer.KeyID(), ManifestSignature: base64.RawURLEncoding.EncodeToString(signature)}
	}
	bundle := entitlement.UpgradePlanArtifactBundle{Schema: entitlement.UpgradePlanArtifactBundleV2Schema,
		Audience: entitlement.UpgradePlanArtifactBundleAudience, Purpose: entitlement.UpgradePlanArtifactBundlePurpose,
		BundleID: "00000000-0000-4000-8000-000000000001", PlanID: "00000000-0000-4000-8000-000000000002",
		InitialPlanRevision: 1, ParentGrantID: "00000000-0000-4000-8000-000000000003",
		ParentGrantSHA256:   base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32)),
		ParentGrantIssuedAt: now.Add(-time.Minute).Unix(), ParentGrantExpiresAt: now.Add(48 * time.Hour).Unix(),
		CustomerID: "00000000-0000-4000-8000-000000000004", InstallationID: "00000000-0000-4000-8000-000000000005",
		LicenseID: "00000000-0000-4000-8000-000000000006", Channel: "stable", ChannelRevision: 7,
		Component: "control-api", CurrentVersion: "1.4.0", Version: "1.5.0", ProtocolVersion: 2,
		Forward:  artifact("00000000-0000-4000-8000-000000000007", "1.5.0", 0x51, 42),
		Rollback: artifact("00000000-0000-4000-8000-000000000008", "1.4.0", 0x52, 41),
		IssuedAt: now.Unix(), CommandIssuanceNotAfter: now.Add(24 * time.Hour).Unix()}
	signed, err := entitlement.SignUpgradePlanArtifactBundle(t.Context(), bundle, signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestRunnerJournalsEveryCheckpointForTheUpgradeLog(t *testing.T) {
	fixture := newRunnerFixture(t)
	if _, err := fixture.runner.Run(t.Context(), fixture.encoded); err != nil {
		t.Fatal(err)
	}
	history, err := fixture.store.LoadHistory()
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := fixture.store.Load()
	phases := make([]Phase, 0, len(history.Entries))
	for _, entry := range history.Entries {
		phases = append(phases, entry.Phase)
		if entry.At != time.Unix(1_800_000_060, 0).Unix() || entry.ErrorCode != "" {
			t.Fatalf("entry = %#v", entry)
		}
	}
	want := []Phase{PhaseVerified, PhaseExpanded, PhasePreflighted, PhaseDrained, PhaseActivated, PhaseHealthy, PhaseContracted, PhaseCompleted}
	if history.PlanID != stored.PlanID || history.Sequence != stored.Sequence || !reflect.DeepEqual(phases, want) {
		t.Fatalf("history = %#v", history)
	}
	// Replaying a terminal receipt does not repeat the journal.
	if _, err := fixture.runner.Run(t.Context(), fixture.encoded); err != nil {
		t.Fatal(err)
	}
	if replayed, _ := fixture.store.LoadHistory(); len(replayed.Entries) != len(want) {
		t.Fatalf("replayed history = %#v", replayed)
	}
	// A later plan starts a new journal instead of extending the old one.
	if err := fixture.store.appendHistory(State{Schema: StateSchema, PlanID: "00000000-0000-4000-8000-000000000099",
		BundleSHA256: digestBytes([]byte("newer")), Sequence: 43, Phase: PhaseVerified}, time.Unix(1_800_000_100, 0)); err != nil {
		t.Fatal(err)
	}
	if next, err := fixture.store.LoadHistory(); err != nil || next.Sequence != 43 || len(next.Entries) != 1 {
		t.Fatalf("next history = (%#v, %v)", next, err)
	}
}

func TestRunnerJournalsRollbackWithItsFailureCode(t *testing.T) {
	fixture := newRunnerFixture(t)
	fixture.executor.failHealthTarget = errors.New("readiness timeout")
	if _, err := fixture.runner.Run(t.Context(), fixture.encoded); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("Run() error = %v", err)
	}
	history, err := fixture.store.LoadHistory()
	if err != nil || len(history.Entries) < 3 {
		t.Fatalf("history = (%#v, %v)", history, err)
	}
	tail := history.Entries[len(history.Entries)-2:]
	if tail[0].Phase != PhaseRollingBack || tail[0].ErrorCode != "target_health_failed" ||
		tail[1].Phase != PhaseRolledBack || tail[1].ErrorCode != "target_health_failed" {
		t.Fatalf("rollback tail = %#v", tail)
	}
}

func TestFileStoreRejectsCorruptHistory(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadHistory(); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("missing history error = %v", err)
	}
	for _, body := range []string{`{}`, `{"schema":"` + HistorySchema + `","plan_id":"p","sequence":1,"entries":[{"phase":"bogus","at":1}]}`,
		`{"schema":"` + HistorySchema + `","plan_id":"p","sequence":1,"entries":[{"phase":"verified","at":2},{"phase":"expanded","at":1}]}`,
		`{"schema":"` + HistorySchema + `","plan_id":"p","sequence":1,"entries":[{"phase":"verified","at":1}],"extra":1}`} {
		if err := os.WriteFile(filepath.Join(store.root, historyFilename), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadHistory(); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("history %s error = %v", body, err)
		}
	}
}
