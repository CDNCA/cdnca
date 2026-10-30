package securityreleaseruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/securityrelease"
)

const (
	testNodeID       = "00000000-0000-4000-8000-000000000001"
	otherNodeID      = "00000000-0000-4000-8000-000000000003"
	testReleaseID    = "00000000-0000-4000-8000-000000000101"
	testDigest       = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testOtherDigest  = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testCurrentImage = "sha256:" + testDigest
	testTargetImage  = "sha256:" + testOtherDigest
)

type testFactsSource struct {
	facts RuntimeFacts
	err   error
	calls int
}

func (source *testFactsSource) Current(context.Context) (RuntimeFacts, error) {
	source.calls++
	return source.facts, source.err
}

type testUpdaterAdapter struct {
	requests []ExecutionRequest
	failures int
	mutate   func(*ExecutionReceipt)
}

func (*testUpdaterAdapter) Version() uint32 { return SignedUpdaterAdapterVersion }

func (adapter *testUpdaterAdapter) Execute(_ context.Context, request ExecutionRequest) (ExecutionReceipt, error) {
	request.SignedCommand = append([]byte(nil), request.SignedCommand...)
	adapter.requests = append(adapter.requests, request)
	if adapter.failures > 0 {
		adapter.failures--
		return ExecutionReceipt{}, errors.New("updater interrupted")
	}
	receipt := ExecutionReceipt{
		Version:                SignedUpdaterAdapterVersion,
		ExecutionID:            request.ExecutionID,
		NodeID:                 request.NodeID,
		ReleaseID:              request.ReleaseID,
		ReleaseSequence:        request.ReleaseSequence,
		ManifestSHA256:         request.ManifestSHA256,
		Action:                 request.Action,
		InstallerTransactionID: "txn-security-release-101",
		PreviousRuntimeVersion: request.CurrentRuntimeVersion,
		ResultRuntimeVersion:   request.TargetRuntimeVersion,
		LKGRuntimeVersion:      request.LKGRuntimeVersion,
		LKGImageDigest:         request.LKGImageDigest,
	}
	if request.Action == securityrelease.ActionRollback {
		receipt.RollbackReceiptSHA256 = testOtherDigest
	} else {
		receipt.ActiveReceiptSHA256 = testOtherDigest
	}
	if adapter.mutate != nil {
		adapter.mutate(&receipt)
	}
	return receipt, nil
}

func TestOPS15DeployPersistsExactReceiptAndReplaysAfterRestart(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	encoded, keys := signedSecurityManifest(t, now, 101, securityrelease.PhaseCanary)
	facts := &testFactsSource{facts: runtimeFacts(testNodeID, "1.27.1.2", testCurrentImage)}
	adapter := &testUpdaterAdapter{}
	root := t.TempDir()
	runtime := newTestRuntime(t, root, now, keys, facts, adapter)

	record, err := runtime.Apply(t.Context(), encoded, []byte("signed-updater-command-v1"))
	if err != nil || record.State != StateActive || record.DecisionReason != securityrelease.ReasonCanaryEligible ||
		record.CurrentRuntimeVersion != "1.27.1.2" || record.TargetRuntimeVersion != "1.31.3.1" ||
		record.LKGRuntimeVersion != "1.27.1.2" || record.LKGImageDigest != testCurrentImage ||
		record.InstallerTransactionID == "" || record.ActiveReceiptSHA256 != testOtherDigest ||
		record.RollbackReceiptSHA256 != "" || len(adapter.requests) != 1 {
		t.Fatalf("Apply(deploy) = (%+v, %v), requests=%+v", record, err, adapter.requests)
	}
	request := adapter.requests[0]
	if request.Action != securityrelease.ActionDeploy || request.ManifestSHA256 != record.ManifestSHA256 ||
		request.ReleaseSequence != 101 || request.ExecutionID != record.ExecutionID ||
		request.SignedCommandSHA256 != record.SignedCommandSHA256 {
		t.Fatalf("updater request = %+v", request)
	}

	facts.err = errors.New("runtime facts unavailable after activation")
	restarted := newTestRuntime(t, root, now.Add(time.Minute), keys, facts, adapter)
	replayed, err := restarted.Apply(t.Context(), encoded, []byte("signed-updater-command-v1"))
	if err != nil || replayed != record || len(adapter.requests) != 1 || facts.calls != 1 {
		t.Fatalf("exact restart replay = (%+v, %v), requests=%d facts=%d", replayed, err, len(adapter.requests), facts.calls)
	}
	current, found, err := restarted.Current(t.Context())
	if err != nil || !found || current != record {
		t.Fatalf("Current() = (%+v, %t, %v)", current, found, err)
	}
}

func TestOPS15HoldDecisionsNeverInvokeUpdater(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		phase  securityrelease.Phase
		nodeID string
		reason securityrelease.ReasonCode
	}{
		{name: "paused", phase: securityrelease.PhasePaused, nodeID: testNodeID, reason: securityrelease.ReasonPaused},
		{name: "canary not selected", phase: securityrelease.PhaseCanary, nodeID: otherNodeID, reason: securityrelease.ReasonCanaryNotSelected},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, keys := signedSecurityManifest(t, now, 101, test.phase)
			facts := &testFactsSource{facts: runtimeFacts(test.nodeID, "1.27.1.2", testCurrentImage)}
			adapter := &testUpdaterAdapter{}
			runtime := newTestRuntimeForNode(t, t.TempDir(), now, keys, facts, adapter, test.nodeID)
			record, err := runtime.Apply(t.Context(), encoded, []byte("must-not-run"))
			if err != nil || record.State != StateHeld || record.DecisionAction != securityrelease.ActionHold ||
				record.DecisionReason != test.reason || record.SignedCommandSHA256 != "" ||
				record.InstallerTransactionID != "" || len(adapter.requests) != 0 {
				t.Fatalf("hold decision = (%+v, %v), requests=%+v", record, err, adapter.requests)
			}
		})
	}
}

func TestOPS15MissingCommandAndAdapterFailureRemainPendingThenRecoverExactly(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	encoded, keys := signedSecurityManifest(t, now, 101, securityrelease.PhaseCanary)
	facts := &testFactsSource{facts: runtimeFacts(testNodeID, "1.27.1.2", testCurrentImage)}
	adapter := &testUpdaterAdapter{failures: 1}
	root := t.TempDir()
	runtime := newTestRuntime(t, root, now, keys, facts, adapter)

	pending, err := runtime.Apply(t.Context(), encoded, nil)
	if !errors.Is(err, ErrSignedCommandRequired) || pending.State != StatePending ||
		pending.SignedCommandSHA256 != "" || len(adapter.requests) != 0 {
		t.Fatalf("missing signed command = (%+v, %v), requests=%d", pending, err, len(adapter.requests))
	}
	failed, err := runtime.Apply(t.Context(), encoded, []byte("signed-updater-command-v1"))
	if !errors.Is(err, ErrUpdaterExecution) || failed.State != StatePending ||
		failed.ExecutionID != pending.ExecutionID || failed.SignedCommandSHA256 == "" || len(adapter.requests) != 1 {
		t.Fatalf("failed execution = (%+v, %v), requests=%d", failed, err, len(adapter.requests))
	}

	restarted := newTestRuntime(t, root, now.Add(time.Minute), keys, facts, adapter)
	recovered, err := restarted.Apply(t.Context(), encoded, []byte("signed-updater-command-v1"))
	if err != nil || recovered.State != StateActive || recovered.ExecutionID != pending.ExecutionID ||
		len(adapter.requests) != 2 || adapter.requests[0].ExecutionID != adapter.requests[1].ExecutionID {
		t.Fatalf("recovered execution = (%+v, %v), requests=%+v", recovered, err, adapter.requests)
	}
}

func TestOPS15RollbackUsesSignedUpdaterAdapterAndPersistsLKGReceipt(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	encoded, keys := signedSecurityManifest(t, now, 102, securityrelease.PhaseRollback)
	facts := &testFactsSource{facts: runtimeFacts(testNodeID, "1.31.3.1", testTargetImage)}
	adapter := &testUpdaterAdapter{}
	runtime := newTestRuntime(t, t.TempDir(), now, keys, facts, adapter)

	record, err := runtime.Apply(t.Context(), encoded, []byte("signed-updater-rollback-command-v1"))
	if err != nil || record.State != StateRolledBack || record.DecisionAction != securityrelease.ActionRollback ||
		record.DecisionReason != securityrelease.ReasonRollbackRequired || record.TargetRuntimeVersion != "1.27.1.2" ||
		record.LKGRuntimeVersion != "1.27.1.2" || record.LKGImageDigest != testCurrentImage ||
		record.RollbackReceiptSHA256 != testOtherDigest || record.ActiveReceiptSHA256 != "" || len(adapter.requests) != 1 {
		t.Fatalf("rollback = (%+v, %v), requests=%+v", record, err, adapter.requests)
	}
	if request := adapter.requests[0]; request.Action != securityrelease.ActionRollback ||
		request.CurrentRuntimeVersion != "1.31.3.1" || request.TargetRuntimeVersion != "1.27.1.2" {
		t.Fatalf("rollback updater request = %+v", request)
	}
}

func TestOPS15SequenceAndReceiptConflictsFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	encoded, keys := signedSecurityManifest(t, now, 101, securityrelease.PhasePaused)
	facts := &testFactsSource{facts: runtimeFacts(testNodeID, "1.27.1.2", testCurrentImage)}
	adapter := &testUpdaterAdapter{}
	runtime := newTestRuntime(t, t.TempDir(), now, keys, facts, adapter)
	first, err := runtime.Apply(t.Context(), encoded, nil)
	if err != nil || first.State != StateHeld {
		t.Fatalf("first hold = (%+v, %v)", first, err)
	}

	conflict, _ := signedSecurityManifestWithTarget(t, now, 101, securityrelease.PhasePaused, "1.31.3.2")
	if record, err := runtime.Apply(t.Context(), conflict, nil); !errors.Is(err, ErrSequenceConflict) || record != first {
		t.Fatalf("same-sequence conflict = (%+v, %v)", record, err)
	}
	stale, _ := signedSecurityManifest(t, now, 100, securityrelease.PhasePaused)
	if record, err := runtime.Apply(t.Context(), stale, nil); !errors.Is(err, ErrStaleSequence) || record != first {
		t.Fatalf("stale sequence = (%+v, %v)", record, err)
	}

	encodedDeploy, deployKeys := signedSecurityManifest(t, now, 102, securityrelease.PhaseCanary)
	badAdapter := &testUpdaterAdapter{mutate: func(receipt *ExecutionReceipt) { receipt.ManifestSHA256 = testDigest }}
	badRuntime := newTestRuntime(t, t.TempDir(), now, deployKeys, facts, badAdapter)
	pending, err := badRuntime.Apply(t.Context(), encodedDeploy, []byte("signed-updater-command-v1"))
	if !errors.Is(err, ErrReceiptMismatch) || pending.State != StatePending ||
		pending.ActiveReceiptSHA256 != "" || pending.InstallerTransactionID != "" {
		t.Fatalf("forged receipt = (%+v, %v)", pending, err)
	}
}

func newTestRuntime(t *testing.T, root string, now time.Time, keys map[string]ed25519.PublicKey,
	facts RuntimeFactsSource, adapter SignedUpdaterAdapter,
) *Runtime {
	t.Helper()
	return newTestRuntimeForNode(t, root, now, keys, facts, adapter, testNodeID)
}

func newTestRuntimeForNode(t *testing.T, root string, now time.Time, keys map[string]ed25519.PublicKey,
	facts RuntimeFactsSource, adapter SignedUpdaterAdapter, nodeID string,
) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(Config{
		Root: root, NodeID: nodeID, ManifestKeys: keys, Facts: facts, Updater: adapter,
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func runtimeFacts(nodeID, runtimeVersion, imageDigest string) RuntimeFacts {
	return RuntimeFacts{NodeID: nodeID, AgentVersion: "1.8.0", RuntimeVersion: runtimeVersion, RuntimeImageDigest: imageDigest}
}

func signedSecurityManifest(t *testing.T, now time.Time, sequence uint64,
	phase securityrelease.Phase,
) ([]byte, map[string]ed25519.PublicKey) {
	t.Helper()
	return signedSecurityManifestWithTarget(t, now, sequence, phase, "1.31.3.1")
}

func signedSecurityManifestWithTarget(t *testing.T, now time.Time, sequence uint64,
	phase securityrelease.Phase, target string,
) ([]byte, map[string]ed25519.PublicKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	manifest := securityrelease.Manifest{
		Schema: securityrelease.Schema, ReleaseID: testReleaseID, ReleaseSequence: sequence,
		Channel: securityrelease.ChannelSecurityHotfix, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		CurrentRuntimeVersion: "1.27.1.2", TargetRuntimeVersion: target,
		Compatibility: securityrelease.Compatibility{MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0"},
		Evidence: securityrelease.Evidence{
			SourceSHA256: testDigest, BaseImageDigest: testCurrentImage, RuntimeImageDigest: testTargetImage,
			PatchManifestSHA256: testDigest, SBOMSHA256: testDigest, ProvenanceSHA256: testDigest,
			AdvisorySnapshotSHA256: testDigest, SignatureBundleSHA256: testDigest,
		},
		Advisories: []securityrelease.Advisory{{
			ID: "CVE-2026-0001", Status: securityrelease.AdvisoryPatched,
			UpstreamURL: "https://security.example.test/CVE-2026-0001", FixedVersion: target,
			PatchReference: "0123456789abcdef0123456789abcdef01234567", RegressionTest: "cve-2026-0001",
			EvidenceSHA256: testDigest,
		}},
		ProtocolRegressions: []securityrelease.ProtocolRegression{
			{Name: "cache-refresh", Status: securityrelease.RegressionPassed, EvidenceSHA256: testDigest},
			{Name: "http1", Status: securityrelease.RegressionPassed, EvidenceSHA256: testDigest},
			{Name: "http2", Status: securityrelease.RegressionPassed, EvidenceSHA256: testDigest},
			{Name: "http3", Status: securityrelease.RegressionPassed, EvidenceSHA256: testDigest},
			{Name: "range206", Status: securityrelease.RegressionPassed, EvidenceSHA256: testDigest},
			{Name: "rewrite", Status: securityrelease.RegressionPassed, EvidenceSHA256: testDigest},
			{Name: "websocket", Status: securityrelease.RegressionPassed, EvidenceSHA256: testDigest},
		},
		Rollout: securityrelease.RolloutPolicy{
			Phase: phase, CanaryNodeIDs: []string{testNodeID}, AutomaticRollback: true,
		},
	}
	switch phase {
	case securityrelease.PhasePaused:
		manifest.Rollout.ExpansionPercentage = 25
		manifest.Rollout.CanaryEvidenceSHA256 = testDigest
	case securityrelease.PhaseRollback:
		manifest.Rollout.CanaryEvidenceSHA256 = testDigest
		manifest.Rollout.LastKnownGoodVersion = "1.27.1.2"
		manifest.Rollout.LastKnownGoodImageDigest = testCurrentImage
	}
	if err := securityrelease.Sign(&manifest, "security-2026", privateKey); err != nil {
		t.Fatal(err)
	}
	encoded, err := securityrelease.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, map[string]ed25519.PublicKey{"security-2026": publicKey}
}
