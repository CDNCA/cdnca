package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestDurableUpgradeStoreAcceptsExactCommandBeforeReturning(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	encoded := encodeUpgradeCommandFixture(t, fixture)
	root := filepath.Join(t.TempDir(), "updater")
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}

	accepted, err := store.AcceptCommand(context.Background(), encoded)
	if err != nil {
		t.Fatalf("AcceptCommand() error = %v", err)
	}
	if accepted.Duplicate || !bytes.Equal(accepted.Encoded, encoded) || accepted.Command.CommandID != fixture.execution.CommandID {
		t.Fatalf("accepted = %#v", accepted)
	}
	wantDigest := sha256Hex(encoded)
	if accepted.SHA256 != wantDigest {
		t.Fatalf("command sha256 = %s, want %s", accepted.SHA256, wantDigest)
	}

	restarted, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	commands, err := restarted.PendingCommands(context.Background())
	if err != nil || len(commands) != 1 || !bytes.Equal(commands[0].Encoded, encoded) {
		t.Fatalf("restarted PendingCommands() = (%#v, %v)", commands, err)
	}
	duplicate, err := restarted.AcceptCommand(context.Background(), encoded)
	if err != nil || !duplicate.Duplicate || duplicate.SHA256 != wantDigest {
		t.Fatalf("duplicate AcceptCommand() = (%#v, %v)", duplicate, err)
	}

	changedFixture := fixture
	changedFixture.execution.PlanRevision++
	resignExecutionFixture(t, &changedFixture)
	changedWire := encodeUpgradeCommandFixture(t, changedFixture)
	if _, err := restarted.AcceptCommand(context.Background(), changedWire); !errors.Is(err, ErrUpgradeCommandConflict) {
		t.Fatalf("changed command error = %v", err)
	}
	commands, err = restarted.PendingCommands(context.Background())
	if err != nil || len(commands) != 1 || !bytes.Equal(commands[0].Encoded, encoded) {
		t.Fatalf("command overwritten = (%#v, %v)", commands, err)
	}
}

func TestDurableUpgradeStoreClaimsVerifiedSignedExecutionAndReplaysAfterRestart(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	encoded := encodeUpgradeCommandFixture(t, fixture)
	root := filepath.Join(t.TempDir(), "updater")
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptCommand(context.Background(), encoded); err != nil {
		t.Fatal(err)
	}

	claimed, err := store.ClaimCommand(context.Background(), fixture.execution.CommandID, fixture.options())
	if err != nil {
		t.Fatalf("ClaimCommand() error = %v", err)
	}
	if claimed.Plan.PlanID != fixture.execution.PlanID || claimed.Plan.Revision != fixture.execution.PlanRevision ||
		claimed.Plan.BatchID != fixture.execution.BatchID || claimed.Plan.TargetVersion != fixture.execution.TargetVersion ||
		claimed.Plan.ArtifactBundleID != fixture.execution.ArtifactBundleID ||
		claimed.Plan.ArtifactBundleSHA256 != fixture.execution.ArtifactBundleSHA256 ||
		claimed.Plan.CommandIssuanceNotAfter != fixture.execution.CommandIssuanceNotAfter ||
		claimed.Command.SignedExecutionSHA256 != sha256Hex(fixture.encoded) {
		t.Fatalf("claimed = %#v", claimed)
	}
	var durable durableUpgradeClaim
	found, err := readJSONFile(filepath.Join(root, "state", "upgrade-wire-v1", "claims",
		fixture.execution.CommandID+".json"), &durable)
	if err != nil || !found || durable.PlanID != fixture.execution.PlanID ||
		durable.PlanRevision != fixture.execution.PlanRevision || durable.BatchID != fixture.execution.BatchID ||
		durable.ArtifactBundleID != fixture.execution.ArtifactBundleID ||
		durable.ArtifactBundleSHA256 != fixture.execution.ArtifactBundleSHA256 ||
		durable.CommandIssuanceNotAfter != fixture.execution.CommandIssuanceNotAfter {
		t.Fatalf("durable claim = (%#v, %t, %v)", durable, found, err)
	}

	restarted, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := restarted.ClaimedCommands(context.Background())
	if err != nil || len(claims) != 1 || !bytes.Equal(claims[0].Encoded, encoded) {
		t.Fatalf("ClaimedCommands() = (%#v, %v)", claims, err)
	}
	if _, err := restarted.ClaimCommand(context.Background(), fixture.execution.CommandID, fixture.options()); !errors.Is(err, ErrUpgradeExecutionReplay) {
		t.Fatalf("duplicate claim error = %v", err)
	}

	claimFiles, err := filepath.Glob(filepath.Join(root, "state", "upgrade-wire-v1", "claims", "*.json"))
	if err != nil || len(claimFiles) != 1 {
		t.Fatalf("claim files = (%v, %v)", claimFiles, err)
	}
	info, err := os.Stat(claimFiles[0])
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("claim mode = (%v, %v)", info, err)
	}
}

func TestDurableUpgradeStorePersistsAndResumesV3SequenceFacts(t *testing.T) {
	fixture := newExecutionV3Fixture(t)
	encoded := encodeUpgradeCommandFixture(t, fixture)
	root := filepath.Join(t.TempDir(), "updater")
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptCommand(context.Background(), encoded); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimCommand(context.Background(), fixture.execution.CommandID, fixture.options())
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Plan.ExecutionSequence != fixture.execution.ExecutionSequence ||
		claimed.Plan.ReleaseSequence != fixture.execution.ReleaseSequence {
		t.Fatalf("claimed sequence facts = (%d, %d), want (%d, %d)",
			claimed.Plan.ExecutionSequence, claimed.Plan.ReleaseSequence,
			fixture.execution.ExecutionSequence, fixture.execution.ReleaseSequence)
	}
	var durable durableUpgradeClaim
	found, err := readJSONFile(filepath.Join(root, "state", "upgrade-wire-v1", "claims",
		fixture.execution.CommandID+".json"), &durable)
	if err != nil || !found || durable.Schema != upgradeExecutionV3Schema ||
		durable.ExecutionSequence != fixture.execution.ExecutionSequence ||
		durable.ReleaseSequence != fixture.execution.ReleaseSequence ||
		durable.Component != fixture.execution.Component {
		t.Fatalf("durable v3 claim = (%#v, %t, %v)", durable, found, err)
	}

	restarted, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := restarted.ResumeClaimedCommand(context.Background(), fixture.execution.CommandID, fixture.options())
	if err != nil || resumed.Plan.ExecutionSequence != fixture.execution.ExecutionSequence ||
		resumed.Plan.ReleaseSequence != fixture.execution.ReleaseSequence {
		t.Fatalf("resumed v3 claim = (%#v, %v)", resumed, err)
	}
}

func TestDurableUpgradeStoreRejectsV1ExecutionBeforeInboxWrite(t *testing.T) {
	fixture := newExecutionFixture(t)
	root := filepath.Join(t.TempDir(), "updater")
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); !errors.Is(err, ErrInvalidUpgradeCommand) {
		t.Fatalf("v1 execution error = %v", err)
	}
	commands, err := store.PendingCommands(context.Background())
	if err != nil || len(commands) != 0 {
		t.Fatalf("v1 execution reached inbox = (%#v, %v)", commands, err)
	}
}

func TestDurableUpgradeStoreResumesClaimBeforeProcessAfterRestart(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	encoded := encodeUpgradeCommandFixture(t, fixture)
	root := filepath.Join(t.TempDir(), "updater")
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptCommand(context.Background(), encoded); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimCommand(context.Background(), fixture.execution.CommandID, fixture.options())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "state", "transaction.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("manager transaction exists before Process: %v", err)
	}
	claimPath := filepath.Join(root, "state", "upgrade-wire-v1", "claims", fixture.execution.CommandID+".json")
	claimMTime := fixture.now.Add(-time.Hour)
	if err := os.Chtimes(claimPath, claimMTime, claimMTime); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := restarted.ResumeClaimedCommand(context.Background(), fixture.execution.CommandID, fixture.options())
	if err != nil {
		t.Fatalf("ResumeClaimedCommand() error = %v", err)
	}
	if !bytes.Equal(resumed.Encoded, claimed.Encoded) || resumed.SHA256 != claimed.SHA256 ||
		resumed.Plan.PlanID != claimed.Plan.PlanID || resumed.Plan.TargetVersion != claimed.Plan.TargetVersion {
		t.Fatalf("resumed = %#v, claimed = %#v", resumed, claimed)
	}
	if _, err := os.Stat(filepath.Join(root, "state", "transaction.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resume created manager transaction: %v", err)
	}
	claimInfo, err := os.Stat(claimPath)
	if err != nil || !claimInfo.ModTime().Equal(claimMTime) {
		t.Fatalf("resume rewrote durable claim = (%v, %v)", claimInfo, err)
	}
}

func TestDurableUpgradeStoreResumeRejectsUnclaimedTamperedStateAndOptions(t *testing.T) {
	t.Run("unclaimed", func(t *testing.T) {
		fixture := newExecutionV2Fixture(t)
		store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ResumeClaimedCommand(context.Background(), fixture.execution.CommandID, fixture.options()); !errors.Is(err, ErrUpgradeCommandNotClaimed) {
			t.Fatalf("unclaimed resume error = %v", err)
		}
	})

	t.Run("claim", func(t *testing.T) {
		fixture := newExecutionV2Fixture(t)
		root := filepath.Join(t.TempDir(), "updater")
		store, err := NewDurableUpgradeStore(root)
		if err != nil {
			t.Fatal(err)
		}
		encoded := encodeUpgradeCommandFixture(t, fixture)
		if _, err := store.AcceptCommand(context.Background(), encoded); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ClaimCommand(context.Background(), fixture.execution.CommandID, fixture.options()); err != nil {
			t.Fatal(err)
		}

		badOptions := fixture.options()
		badOptions.ExpectedArchitecture = "arm64"
		if _, err := store.ResumeClaimedCommand(context.Background(), fixture.execution.CommandID, badOptions); !errors.Is(err, ErrUpgradeExecutionTargetMismatch) {
			t.Fatalf("mismatched options error = %v", err)
		}

		claimPath := filepath.Join(root, "state", "upgrade-wire-v1", "claims", fixture.execution.CommandID+".json")
		var claim durableUpgradeClaim
		found, err := readJSONFile(claimPath, &claim)
		if err != nil || !found {
			t.Fatalf("read claim = (%t, %v)", found, err)
		}
		claim.Nonce = "00000000-0000-4000-8000-000000000099"
		if err := writeJSONAtomic(claimPath, claim); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ResumeClaimedCommand(context.Background(), fixture.execution.CommandID, fixture.options()); !errors.Is(err, ErrUpgradeCommandConflict) {
			t.Fatalf("tampered claim error = %v", err)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*durableUpgradeClaim)
	}{
		{name: "plan id", mutate: func(claim *durableUpgradeClaim) {
			claim.PlanID = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "plan revision", mutate: func(claim *durableUpgradeClaim) { claim.PlanRevision++ }},
		{name: "batch id", mutate: func(claim *durableUpgradeClaim) {
			claim.BatchID = "00000000-0000-4000-8000-000000000098"
		}},
		{name: "bundle id", mutate: func(claim *durableUpgradeClaim) {
			claim.ArtifactBundleID = "00000000-0000-4000-8000-000000000097"
		}},
		{name: "bundle digest", mutate: func(claim *durableUpgradeClaim) {
			claim.ArtifactBundleSHA256 = fixtureDigest(0x99)
		}},
		{name: "issuance deadline", mutate: func(claim *durableUpgradeClaim) { claim.CommandIssuanceNotAfter++ }},
	} {
		t.Run("claim "+test.name, func(t *testing.T) {
			fixture := newExecutionV2Fixture(t)
			root := filepath.Join(t.TempDir(), "updater")
			store, err := NewDurableUpgradeStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ClaimCommand(context.Background(), fixture.execution.CommandID, fixture.options()); err != nil {
				t.Fatal(err)
			}
			claimPath := filepath.Join(root, "state", "upgrade-wire-v1", "claims", fixture.execution.CommandID+".json")
			var claim durableUpgradeClaim
			found, err := readJSONFile(claimPath, &claim)
			if err != nil || !found {
				t.Fatalf("read claim = (%t, %v)", found, err)
			}
			test.mutate(&claim)
			if err := writeJSONAtomic(claimPath, claim); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewDurableUpgradeStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.ResumeClaimedCommand(context.Background(), fixture.execution.CommandID, fixture.options()); !errors.Is(err, ErrUpgradeCommandConflict) {
				t.Fatalf("tampered %s error = %v", test.name, err)
			}
		})
	}

	t.Run("inbox", func(t *testing.T) {
		fixture := newExecutionV2Fixture(t)
		root := filepath.Join(t.TempDir(), "updater")
		store, err := NewDurableUpgradeStore(root)
		if err != nil {
			t.Fatal(err)
		}
		encoded := encodeUpgradeCommandFixture(t, fixture)
		if _, err := store.AcceptCommand(context.Background(), encoded); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ClaimCommand(context.Background(), fixture.execution.CommandID, fixture.options()); err != nil {
			t.Fatal(err)
		}
		var changed EdgeUpgradeCommand
		if err := json.Unmarshal(encoded, &changed); err != nil {
			t.Fatal(err)
		}
		changed.PlanRevision++
		changedWire, _ := json.Marshal(changed)
		commandPath := filepath.Join(root, "state", "upgrade-wire-v1", "inbox", fixture.execution.CommandID+".json")
		if err := writeDurableBytes(commandPath, changedWire); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ResumeClaimedCommand(context.Background(), fixture.execution.CommandID, fixture.options()); !errors.Is(err, ErrUpgradeCommandConflict) && !errors.Is(err, ErrCorruptState) {
			t.Fatalf("tampered inbox error = %v", err)
		}
	})
}

func TestDurableUpgradeStoreRejectsTamperedGrantBeforeClaim(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	tamperedEnvelope := fixture.envelope
	tamperedEnvelope.Execution.Rollback.Automatic = false
	tamperedExecution, _ := json.Marshal(tamperedEnvelope)
	encoded := encodeUpgradeCommand(t, fixture, tamperedExecution)
	root := filepath.Join(t.TempDir(), "updater")
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptCommand(context.Background(), encoded); !errors.Is(err, ErrInvalidUpgradeCommand) {
		t.Fatalf("AcceptCommand() tampered error = %v", err)
	}

	encoded = encodeUpgradeCommandFixture(t, fixture)
	if _, err := store.AcceptCommand(context.Background(), encoded); err != nil {
		t.Fatal(err)
	}
	var command EdgeUpgradeCommand
	if err := json.Unmarshal(encoded, &command); err != nil {
		t.Fatal(err)
	}
	tamperedEnvelope = fixture.envelope
	tamperedEnvelope.Execution.TargetVersion = "2.0.1"
	tamperedExecution, _ = json.Marshal(tamperedEnvelope)
	command.SignedExecution = tamperedExecution
	command.SignedExecutionSHA256 = sha256Hex(tamperedExecution)
	tamperedCommand, _ := json.Marshal(command)
	otherRoot := filepath.Join(t.TempDir(), "updater")
	other, err := NewDurableUpgradeStore(otherRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.AcceptCommand(context.Background(), tamperedCommand); err != nil {
		t.Fatalf("durable inbox should accept structurally valid bytes before signature verification: %v", err)
	}
	options := fixture.options()
	options.ExpectedTargetVersion = "2.0.1"
	if _, err := other.ClaimCommand(context.Background(), fixture.execution.CommandID, options); !errors.Is(err, ErrInvalidUpgradeExecutionControlSignature) {
		t.Fatalf("ClaimCommand() tampered signature error = %v", err)
	}
	claims, err := other.ClaimedCommands(context.Background())
	if err != nil || len(claims) != 0 {
		t.Fatalf("tampered execution became visible as claimed = (%#v, %v)", claims, err)
	}
}

func TestDurableUpgradeStoreSerializesConcurrentClaim(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	root := filepath.Join(t.TempDir(), "updater")
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); err != nil {
		t.Fatal(err)
	}

	const attempts = 8
	var wait sync.WaitGroup
	wait.Add(attempts)
	results := make(chan error, attempts)
	for range attempts {
		go func() {
			defer wait.Done()
			_, err := store.ClaimCommand(context.Background(), fixture.execution.CommandID, fixture.options())
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	succeeded := 0
	replayed := 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrUpgradeExecutionReplay):
			replayed++
		default:
			t.Fatalf("concurrent claim error = %v", err)
		}
	}
	if succeeded != 1 || replayed != attempts-1 {
		t.Fatalf("claims = %d success, %d replay", succeeded, replayed)
	}
}

func TestDurableUpgradeStoreReplaysAndAcknowledgesExactStatuses(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	commandWire := encodeUpgradeCommandFixture(t, fixture)
	root := filepath.Join(t.TempDir(), "updater")
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.AcceptCommand(context.Background(), commandWire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimCommand(context.Background(), fixture.execution.CommandID, fixture.options()); err != nil {
		t.Fatal(err)
	}
	status := EdgeUpgradeStatus{
		Schema: EdgeUpgradeStatusSchema, StatusID: mustUpgradeStatusID(t, fixture.execution.CommandID, 1), StatusRevision: 1,
		CommandID: fixture.execution.CommandID, PlanID: accepted.Command.PlanID, PlanRevision: accepted.Command.PlanRevision,
		InstallationID: fixture.execution.InstallationID, NodeID: fixture.execution.NodeID,
		CommandSHA256: accepted.SHA256, State: EdgeUpgradeStateClaimed,
		ObservedAt: fixture.now.Add(time.Minute),
	}
	for _, state := range []EdgeUpgradeStatus{
		status,
		func() EdgeUpgradeStatus {
			value := status
			value.StatusID = mustUpgradeStatusID(t, fixture.execution.CommandID, 2)
			value.StatusRevision = 2
			value.State = EdgeUpgradeStateInstalling
			value.InstallerTransactionID = "txn-unknown-1"
			value.ObservedAt = fixture.now.Add(2 * time.Minute)
			return value
		}(),
	} {
		stateWire, _ := json.Marshal(state)
		queued, err := store.EnqueueStatus(context.Background(), stateWire)
		if err != nil {
			t.Fatalf("EnqueueStatus(%s) error = %v", state.State, err)
		}
		if acknowledged, err := store.AcknowledgeStatus(context.Background(), state.StatusID, queued.SHA256); err != nil || !acknowledged {
			t.Fatalf("AcknowledgeStatus(%s) = (%t, %v)", state.State, acknowledged, err)
		}
	}
	status.StatusID = mustUpgradeStatusID(t, fixture.execution.CommandID, 3)
	status.StatusRevision = 3
	status.State = EdgeUpgradeStateUncertain
	status.CurrentVersion = "2.0.0"
	status.PreviousVersion = "1.0.0"
	status.InstallerTransactionID = "txn-unknown-1"
	status.ErrorCode = "INSTALLER_OUTCOME_UNKNOWN"
	status.AlertRequired = true
	status.ObservedAt = fixture.now.Add(3 * time.Minute)
	statusWire, _ := json.Marshal(status)
	queued, err := store.EnqueueStatus(context.Background(), statusWire)
	if err != nil || queued.Duplicate || queued.SHA256 != sha256Hex(statusWire) {
		t.Fatalf("EnqueueStatus() = (%#v, %v)", queued, err)
	}

	restarted, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := restarted.PendingStatuses(context.Background())
	if err != nil || len(pending) != 1 || !bytes.Equal(pending[0].Encoded, statusWire) {
		t.Fatalf("PendingStatuses() = (%#v, %v)", pending, err)
	}
	if _, err := restarted.AcknowledgeStatus(context.Background(), status.StatusID, sha256Hex([]byte("wrong"))); !errors.Is(err, ErrUpgradeStatusAckMismatch) {
		t.Fatalf("wrong ACK error = %v", err)
	}
	acknowledged, err := restarted.AcknowledgeStatus(context.Background(), status.StatusID, queued.SHA256)
	if err != nil || !acknowledged {
		t.Fatalf("AcknowledgeStatus() = (%t, %v)", acknowledged, err)
	}
	pending, err = restarted.PendingStatuses(context.Background())
	if err != nil || len(pending) != 0 {
		t.Fatalf("acked status replayed = (%#v, %v)", pending, err)
	}
	acknowledged, err = restarted.AcknowledgeStatus(context.Background(), status.StatusID, queued.SHA256)
	if err != nil || !acknowledged {
		t.Fatalf("duplicate ACK = (%t, %v)", acknowledged, err)
	}
	duplicate, err := restarted.EnqueueStatus(context.Background(), statusWire)
	if err != nil || !duplicate.Duplicate {
		t.Fatalf("acked duplicate enqueue = (%#v, %v)", duplicate, err)
	}
	status.AlertRequired = false
	changedStatus, _ := json.Marshal(status)
	if _, err := restarted.EnqueueStatus(context.Background(), changedStatus); !errors.Is(err, ErrUpgradeStatusConflict) &&
		!errors.Is(err, ErrInvalidUpgradeStatus) {
		t.Fatalf("changed status error = %v", err)
	}
}

func TestDurableUpgradeStoreLegacyAcknowledgeStatusPreservesLegacyPath(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	status := EdgeUpgradeStatus{
		Schema: EdgeUpgradeStatusSchema, StatusID: mustUpgradeStatusID(t, fixture.execution.CommandID, 1), StatusRevision: 1,
		CommandID: fixture.execution.CommandID, PlanID: accepted.Command.PlanID, PlanRevision: accepted.Command.PlanRevision,
		InstallationID: fixture.execution.InstallationID, NodeID: fixture.execution.NodeID,
		CommandSHA256: accepted.SHA256, State: EdgeUpgradeStateAccepted, ObservedAt: fixture.now,
	}
	wire, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	queued, err := store.EnqueueStatus(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	if acknowledged, err := store.AcknowledgeStatus(context.Background(), status.StatusID, queued.SHA256); err != nil || !acknowledged {
		t.Fatalf("legacy AcknowledgeStatus() = (%t, %v)", acknowledged, err)
	}
	pending, err := store.PendingStatuses(context.Background())
	if err != nil || len(pending) != 0 {
		t.Fatalf("legacy acknowledgement left pending outbox = (%#v, %v)", pending, err)
	}
	unlock, err := store.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ack, found, err := store.loadStatusAckLocked(status.StatusID)
	unlock()
	if err != nil || !found || ack.PublishedStream != "" || ack.PublishedSequence != 0 || ack.ReceiptRequired {
		t.Fatalf("legacy acknowledgement identity = (%#v, %t, %v)", ack, found, err)
	}
}

func TestDurableUpgradeStoreAcknowledgeStatusWithPublicationPersistsExactSequence(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	status := EdgeUpgradeStatus{
		Schema: EdgeUpgradeStatusSchema, StatusID: mustUpgradeStatusID(t, fixture.execution.CommandID, 1), StatusRevision: 1,
		CommandID: fixture.execution.CommandID, PlanID: accepted.Command.PlanID, PlanRevision: accepted.Command.PlanRevision,
		InstallationID: fixture.execution.InstallationID, NodeID: fixture.execution.NodeID,
		CommandSHA256: accepted.SHA256, State: EdgeUpgradeStateAccepted, ObservedAt: fixture.now,
	}
	wire, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	queued, err := store.EnqueueStatus(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	ackWire := []byte("verified-status-puback")
	acknowledged, err := store.AcknowledgeStatusWithPublication(context.Background(), UpgradeStatusAcknowledgement{
		StatusID: status.StatusID, CommandID: status.CommandID, StatusRevision: status.StatusRevision,
		StatusSHA256: queued.SHA256, PersistedAt: fixture.now, PublishedStream: "AGENT_DEPLOYMENT_STATUS",
		PublishedSequence: 41, Encoded: ackWire, SHA256: sha256String(ackWire),
	})
	if err != nil || !acknowledged {
		t.Fatalf("publication acknowledgement = (%t, %v)", acknowledged, err)
	}
	unlock, err := store.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ack, found, err := store.loadStatusAckLocked(status.StatusID)
	unlock()
	if err != nil || !found || ack.PublishedStream != "AGENT_DEPLOYMENT_STATUS" || ack.PublishedSequence != 41 || ack.ReceiptRequired || len(ack.Encoded) != 0 {
		t.Fatalf("publication acknowledgement identity = (%#v, %t, %v)", ack, found, err)
	}
}

func TestDurableUpgradeStatusAcknowledgementReceiptReplaysExactlyUntilConfirmed(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	root := filepath.Join(t.TempDir(), "updater")
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	status := EdgeUpgradeStatus{
		Schema: EdgeUpgradeStatusSchema, StatusID: mustUpgradeStatusID(t, fixture.execution.CommandID, 1), StatusRevision: 1,
		CommandID: fixture.execution.CommandID, PlanID: accepted.Command.PlanID, PlanRevision: accepted.Command.PlanRevision,
		InstallationID: fixture.execution.InstallationID, NodeID: fixture.execution.NodeID,
		CommandSHA256: accepted.SHA256, State: EdgeUpgradeStateAccepted, ObservedAt: fixture.now.Add(time.Minute),
	}
	statusWire, _ := json.Marshal(status)
	queued, err := store.EnqueueStatus(context.Background(), statusWire)
	if err != nil {
		t.Fatal(err)
	}
	ackWire := []byte("exact deterministic UpgradeStatusAck protobuf")
	acknowledgement := UpgradeStatusAcknowledgement{
		StatusID: status.StatusID, CommandID: status.CommandID, StatusRevision: status.StatusRevision,
		StatusSHA256: queued.SHA256, PersistedAt: fixture.now.Add(2 * time.Minute),
		PublishedStream: "AGENT_DEPLOYMENT_STATUS", PublishedSequence: 41,
		Encoded: ackWire, SHA256: sha256String(ackWire),
	}
	acceptedState, err := store.PersistStatusAcknowledgement(context.Background(), acknowledgement)
	if err != nil || !acceptedState {
		t.Fatalf("PersistStatusAcknowledgement() = (%t, %v)", acceptedState, err)
	}
	if pending, err := store.PendingStatuses(context.Background()); err != nil || len(pending) != 0 {
		t.Fatalf("status was republished after durable ACK = (%#v, %v)", pending, err)
	}

	restarted, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := restarted.PendingStatusAcknowledgements(context.Background())
	if err != nil || len(receipts) != 1 || !sameUpgradeStatusAcknowledgement(receipts[0], acknowledgement) ||
		!bytes.Equal(receipts[0].Encoded, ackWire) {
		t.Fatalf("pending ACK receipts = (%#v, %v)", receipts, err)
	}
	if _, err := os.Stat(restarted.statusPath(status.StatusID)); err != nil {
		t.Fatalf("original status was discarded before confirmation: %v", err)
	}
	if _, err := os.Stat(restarted.ackPath(status.StatusID)); err != nil {
		t.Fatalf("exact ACK was not durable before confirmation: %v", err)
	}

	wrong := acknowledgement
	wrong.PublishedSequence++
	if confirmed, err := restarted.ConfirmStatusAcknowledgement(context.Background(), wrong); !errors.Is(err, ErrUpgradeStatusAckMismatch) || confirmed {
		t.Fatalf("wrong receipt confirmation = (%t, %v)", confirmed, err)
	}
	receipts, err = restarted.PendingStatusAcknowledgements(context.Background())
	if err != nil || len(receipts) != 1 || !sameUpgradeStatusAcknowledgement(receipts[0], acknowledgement) {
		t.Fatalf("wrong confirmation changed replay = (%#v, %v)", receipts, err)
	}
	confirmed, err := restarted.ConfirmStatusAcknowledgement(context.Background(), acknowledgement)
	if err != nil || !confirmed {
		t.Fatalf("exact receipt confirmation = (%t, %v)", confirmed, err)
	}
	receipts, err = restarted.PendingStatusAcknowledgements(context.Background())
	if err != nil || len(receipts) != 0 {
		t.Fatalf("confirmed receipt replayed = (%#v, %v)", receipts, err)
	}
	if _, err := os.Stat(restarted.statusPath(status.StatusID)); err != nil {
		t.Fatalf("status ledger was not retained after confirmation: %v", err)
	}
}

func TestDurableUpgradeStatusAcknowledgementRejectsWrongExactReplay(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	status := EdgeUpgradeStatus{
		Schema: EdgeUpgradeStatusSchema, StatusID: mustUpgradeStatusID(t, fixture.execution.CommandID, 1), StatusRevision: 1,
		CommandID: fixture.execution.CommandID, PlanID: accepted.Command.PlanID, PlanRevision: accepted.Command.PlanRevision,
		InstallationID: fixture.execution.InstallationID, NodeID: fixture.execution.NodeID,
		CommandSHA256: accepted.SHA256, State: EdgeUpgradeStateAccepted, ObservedAt: fixture.now.Add(time.Minute),
	}
	wire, _ := json.Marshal(status)
	queued, err := store.EnqueueStatus(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	ackWire := []byte("ack-one")
	acknowledgement := UpgradeStatusAcknowledgement{
		StatusID: status.StatusID, CommandID: status.CommandID, StatusRevision: 1, StatusSHA256: queued.SHA256,
		PersistedAt: fixture.now.Add(2 * time.Minute), PublishedStream: "AGENT_DEPLOYMENT_STATUS", PublishedSequence: 9,
		Encoded: ackWire, SHA256: sha256String(ackWire),
	}
	if _, err := store.PersistStatusAcknowledgement(context.Background(), acknowledgement); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*UpgradeStatusAcknowledgement){
		func(value *UpgradeStatusAcknowledgement) { value.CommandID = "00000000-0000-4000-8000-000000000099" },
		func(value *UpgradeStatusAcknowledgement) { value.StatusRevision++ },
		func(value *UpgradeStatusAcknowledgement) { value.PersistedAt = value.PersistedAt.Add(time.Second) },
		func(value *UpgradeStatusAcknowledgement) { value.PublishedSequence++ },
		func(value *UpgradeStatusAcknowledgement) {
			value.Encoded = []byte("ack-two")
			value.SHA256 = sha256String(value.Encoded)
		},
	} {
		changed := acknowledgement
		mutate(&changed)
		if _, err := store.PersistStatusAcknowledgement(context.Background(), changed); !errors.Is(err, ErrUpgradeStatusAckMismatch) {
			t.Fatalf("changed exact ACK error = %v for %#v", err, changed)
		}
	}
}

func TestPendingUpgradeStatusesUseCommandRevisionOrderAcrossRestartAndPartialAck(t *testing.T) {
	later := newExecutionV2Fixture(t)
	earlier := later
	earlier.execution.CommandID = "00000000-0000-4000-8000-000000000020"
	earlier.execution.Nonce = "00000000-0000-4000-8000-000000000030"
	earlier.execution.PlanID = "00000000-0000-4000-8000-000000000031"
	earlier.execution.BatchID = "00000000-0000-4000-8000-000000000032"
	earlier.execution.ArtifactBundleID = "00000000-0000-4000-8000-000000000033"
	resignExecutionFixture(t, &earlier)
	root := filepath.Join(t.TempDir(), "updater")
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	manager := &recordingUpgradeManager{result: Result{
		State: StateRolledBack, CurrentVersion: "1.0.0", PreviousVersion: "2.0.0",
		InstallerTransactionID: "txn-runtime-test", ErrorCode: "HEALTH_FAILED",
	}}
	upgradeRuntime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: manager, Options: later.options(),
		Now: func() time.Time { return later.now.Add(2 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	acceptAndAcknowledgeRuntimeCommand(t, upgradeRuntime, later)
	acceptAndAcknowledgeRuntimeCommand(t, upgradeRuntime, earlier)
	if err := upgradeRuntime.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	statuses, err := upgradeRuntime.PendingStatuses(context.Background())
	if err != nil || len(statuses) != 8 {
		t.Fatalf("pending statuses = (%#v, %v)", statuses, err)
	}
	assertPendingStatusOrder(t, statuses, earlier.execution.CommandID, 2, 3, 4, 5)
	assertPendingStatusOrder(t, statuses[4:], later.execution.CommandID, 2, 3, 4, 5)
	if acknowledged, err := upgradeRuntime.AcknowledgeStatus(context.Background(), statuses[1].Status.StatusID,
		statuses[1].Status.CommandID, statuses[1].SHA256); err != nil || !acknowledged {
		t.Fatalf("partial ACK = (%t, %v)", acknowledged, err)
	}
	if acknowledged, err := upgradeRuntime.AcknowledgeStatus(context.Background(), statuses[6].Status.StatusID,
		statuses[6].Status.CommandID, statuses[6].SHA256); err != nil || !acknowledged {
		t.Fatalf("second partial ACK = (%t, %v)", acknowledged, err)
	}
	restartedStore, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: restartedStore, Manager: manager, Options: later.options(),
		Now: func() time.Time { return later.now.Add(3 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	statuses, err = restarted.PendingStatuses(context.Background())
	if err != nil || len(statuses) != 6 {
		t.Fatalf("restarted pending statuses = (%#v, %v)", statuses, err)
	}
	assertPendingStatusOrder(t, statuses, earlier.execution.CommandID, 2, 4, 5)
	assertPendingStatusOrder(t, statuses[3:], later.execution.CommandID, 2, 3, 5)
}

func TestPendingUpgradeStatusesRejectCorruptCompleteHistory(t *testing.T) {
	fixture := newExecutionV2Fixture(t)

	t.Run("missing intermediate revision", func(t *testing.T) {
		store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
		if err != nil {
			t.Fatal(err)
		}
		accepted := seedRuntimeInstalling(t, store, fixture)
		statusID, err := upgradeStatusID(accepted.Command.CommandID, 2)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(store.statusPath(statusID)); err != nil {
			t.Fatal(err)
		}
		if statuses, err := store.PendingStatuses(context.Background()); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("PendingStatuses() = (%#v, %v), want corrupt state", statuses, err)
		}
	})

	t.Run("terminal successor", func(t *testing.T) {
		store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
		if err != nil {
			t.Fatal(err)
		}
		accepted := seedRuntimeInstalling(t, store, fixture)
		healthy := runtimeStatus(t, accepted, fixture, 4, EdgeUpgradeStateHealthy, Result{
			CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
		})
		healthyWire, _ := json.Marshal(healthy)
		if _, err := store.EnqueueStatus(context.Background(), healthyWire); err != nil {
			t.Fatal(err)
		}
		failed := runtimeStatus(t, accepted, fixture, 5, EdgeUpgradeStateFailed, Result{
			CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
			ErrorCode: "HEALTH_FAILED", AlertRequired: true,
		})
		failedWire, _ := json.Marshal(failed)
		if err := writeDurableBytes(store.statusPath(failed.StatusID), failedWire); err != nil {
			t.Fatal(err)
		}
		if statuses, err := store.PendingStatuses(context.Background()); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("PendingStatuses() = (%#v, %v), want corrupt state", statuses, err)
		}
	})

	t.Run("installer transaction drift", func(t *testing.T) {
		store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
		if err != nil {
			t.Fatal(err)
		}
		accepted := seedRuntimeInstalling(t, store, fixture)
		healthy := runtimeStatus(t, accepted, fixture, 4, EdgeUpgradeStateHealthy, Result{
			CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-drifted",
		})
		wire, _ := json.Marshal(healthy)
		if err := writeDurableBytes(store.statusPath(healthy.StatusID), wire); err != nil {
			t.Fatal(err)
		}
		if statuses, err := store.PendingStatuses(context.Background()); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("PendingStatuses() = (%#v, %v), want corrupt state", statuses, err)
		}
	})

	for _, test := range []struct {
		name       string
		uncertain  bool
		finalState EdgeUpgradeState
	}{
		{name: "rollback failure cause drift", finalState: EdgeUpgradeStateFailed},
		{name: "reconciled rollback failure cause drift", uncertain: true, finalState: EdgeUpgradeStateFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
			if err != nil {
				t.Fatal(err)
			}
			accepted := seedRuntimeInstalling(t, store, fixture)
			rollingBack := runtimeStatus(t, accepted, fixture, 4, EdgeUpgradeStateRollingBack, Result{
				CurrentVersion: "1.0.0", PreviousVersion: "2.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "HEALTH_FAILED",
			})
			wire, err := json.Marshal(rollingBack)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
				t.Fatalf("enqueue rolling_back: %v", err)
			}

			revision := uint64(5)
			if test.uncertain {
				uncertain := runtimeStatus(t, accepted, fixture, revision, EdgeUpgradeStateUncertain, Result{
					InstallerTransactionID: "txn-runtime-test", ErrorCode: "INSTALLER_OUTCOME_UNKNOWN", AlertRequired: true,
				})
				wire, err = json.Marshal(uncertain)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
					t.Fatalf("enqueue uncertain: %v", err)
				}
				revision++
			}

			terminal := runtimeStatus(t, accepted, fixture, revision, test.finalState, Result{
				CurrentVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "ROLLBACK_DIFFERENT_FAILURE", AlertRequired: true,
			})
			wire, err = json.Marshal(terminal)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeDurableBytes(store.statusPath(terminal.StatusID), wire); err != nil {
				t.Fatal(err)
			}
			if statuses, err := store.PendingStatuses(context.Background()); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("PendingStatuses() = (%#v, %v), want corrupt state", statuses, err)
			}
		})
	}
}

func TestDurableUpgradeStoreRejectsRollbackCauseDriftBeforeWrite(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	for _, test := range []struct {
		name      string
		reconcile bool
		state     EdgeUpgradeState
	}{
		{name: "failed", state: EdgeUpgradeStateFailed},
		{name: "rolled back", state: EdgeUpgradeStateRolledBack},
		{name: "reconciled failed", reconcile: true, state: EdgeUpgradeStateFailed},
		{name: "reconciled rolled back", reconcile: true, state: EdgeUpgradeStateRolledBack},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
			if err != nil {
				t.Fatal(err)
			}
			accepted := seedRuntimeInstalling(t, store, fixture)
			rollingBack := runtimeStatus(t, accepted, fixture, 4, EdgeUpgradeStateRollingBack, Result{
				CurrentVersion: "1.0.0", PreviousVersion: "2.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "HEALTH_FAILED",
			})
			wire, _ := json.Marshal(rollingBack)
			if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
				t.Fatal(err)
			}
			previousRevision := uint64(4)
			if test.reconcile {
				uncertain := runtimeStatus(t, accepted, fixture, 5, EdgeUpgradeStateUncertain, Result{
					InstallerTransactionID: "txn-runtime-test", ErrorCode: "INSTALLER_OUTCOME_UNKNOWN", AlertRequired: true,
				})
				wire, _ = json.Marshal(uncertain)
				if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
					t.Fatal(err)
				}
				previousRevision = 5
			}
			result := Result{
				CurrentVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "DIFFERENT_CAUSE", AlertRequired: test.state == EdgeUpgradeStateFailed,
			}
			if test.state == EdgeUpgradeStateRolledBack {
				result.PreviousVersion = "2.0.0"
			}
			candidate := runtimeStatus(t, accepted, fixture, previousRevision+1, test.state, result)
			wire, _ = json.Marshal(candidate)
			if test.reconcile {
				_, err = store.ReconcileStatus(context.Background(), wire)
			} else {
				_, err = store.EnqueueStatus(context.Background(), wire)
			}
			if !errors.Is(err, ErrUpgradeStatusConflict) {
				t.Fatalf("rollback cause drift error = %v", err)
			}
			if _, statErr := os.Stat(store.statusPath(candidate.StatusID)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("rejected candidate persisted: %v", statErr)
			}
		})
	}
}

func TestDurableUpgradeStoreBindsCommandAndClaimBasenames(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	for _, test := range []struct {
		name  string
		claim bool
	}{
		{name: "inbox"},
		{name: "claim", claim: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); err != nil {
				t.Fatal(err)
			}
			source := store.commandPath(fixture.execution.CommandID)
			if test.claim {
				if _, err := store.ClaimCommand(context.Background(), fixture.execution.CommandID, fixture.options()); err != nil {
					t.Fatal(err)
				}
				source = store.claimPath(fixture.execution.CommandID)
			}
			replacementID := "00000000-0000-4000-8000-000000000099"
			destination := filepath.Join(filepath.Dir(source), replacementID+".json")
			if err := os.Rename(source, destination); err != nil {
				t.Fatal(err)
			}
			if test.claim {
				if commands, err := store.ClaimedCommands(context.Background()); !errors.Is(err, ErrCorruptState) {
					t.Fatalf("ClaimedCommands() = (%#v, %v)", commands, err)
				}
			} else if commands, err := store.PendingCommands(context.Background()); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("PendingCommands() = (%#v, %v)", commands, err)
			}
		})
	}
}

func TestDurableUpgradeStatusRequiresDerivedIDAndExactLedgerBasename(t *testing.T) {
	fixture := newExecutionV2Fixture(t)

	t.Run("arbitrary status id", func(t *testing.T) {
		store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
		if err != nil {
			t.Fatal(err)
		}
		accepted := seedRuntimeInstalling(t, store, fixture)
		status := runtimeStatus(t, accepted, fixture, 4, EdgeUpgradeStateHealthy, Result{
			CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
		})
		status.StatusID = "00000000-0000-4000-8000-000000000099"
		wire, _ := json.Marshal(status)
		if _, err := store.EnqueueStatus(context.Background(), wire); !errors.Is(err, ErrInvalidUpgradeStatus) {
			t.Fatalf("arbitrary status ID error = %v", err)
		}
	})

	t.Run("renamed ledger", func(t *testing.T) {
		store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
		if err != nil {
			t.Fatal(err)
		}
		accepted := seedRuntimeInstalling(t, store, fixture)
		status := runtimeStatus(t, accepted, fixture, 4, EdgeUpgradeStateHealthy, Result{
			CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
		})
		wire, _ := json.Marshal(status)
		if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
			t.Fatal(err)
		}
		renamed := store.statusPath("00000000-0000-4000-8000-000000000099")
		if err := os.Rename(store.statusPath(status.StatusID), renamed); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PendingStatuses(context.Background()); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("renamed ledger error = %v", err)
		}
	})

	t.Run("renamed acknowledgement", func(t *testing.T) {
		store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
		if err != nil {
			t.Fatal(err)
		}
		accepted := seedRuntimeInstalling(t, store, fixture)
		status := runtimeStatus(t, accepted, fixture, 4, EdgeUpgradeStateHealthy, Result{
			CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
		})
		wire, _ := json.Marshal(status)
		queued, err := store.EnqueueStatus(context.Background(), wire)
		if err != nil {
			t.Fatal(err)
		}
		if acknowledged, err := store.AcknowledgeStatus(context.Background(), status.StatusID, queued.SHA256); err != nil || !acknowledged {
			t.Fatalf("ACK = (%t, %v)", acknowledged, err)
		}
		renamed := store.ackPath("00000000-0000-4000-8000-000000000099")
		if err := os.Rename(store.ackPath(status.StatusID), renamed); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PendingStatuses(context.Background()); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("renamed ACK error = %v", err)
		}
	})
}

func assertPendingStatusOrder(t *testing.T, statuses []QueuedUpgradeStatus, commandID string, revisions ...uint64) {
	t.Helper()
	if len(statuses) < len(revisions) {
		t.Fatalf("pending statuses = %#v, want command %s revisions %v", statuses, commandID, revisions)
	}
	for index, revision := range revisions {
		status := statuses[index].Status
		if status.CommandID != commandID || status.StatusRevision != revision {
			t.Fatalf("pending status[%d] = (%s,%d), want (%s,%d)",
				index, status.CommandID, status.StatusRevision, commandID, revision)
		}
	}
}

func TestDurableUpgradeStoreAcceptsOnlyFrozenStatusStates(t *testing.T) {
	allowed := []EdgeUpgradeState{
		EdgeUpgradeStateAccepted, EdgeUpgradeStateClaimed, EdgeUpgradeStateInstalling,
		EdgeUpgradeStateHealthy, EdgeUpgradeStateFailed, EdgeUpgradeStateRollingBack,
		EdgeUpgradeStateRolledBack, EdgeUpgradeStateUncertain,
	}
	for _, state := range allowed {
		if !validEdgeUpgradeState(state) {
			t.Fatalf("state %q rejected", state)
		}
	}
	if validEdgeUpgradeState("succeeded") || validEdgeUpgradeState("") {
		t.Fatal("non-contract state accepted")
	}
}

func TestDurableUpgradeStoreRejectsInvalidEarlyStatusFields(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	for _, test := range []struct {
		name   string
		state  EdgeUpgradeState
		mutate func(*EdgeUpgradeStatus)
	}{
		{"accepted current version", EdgeUpgradeStateAccepted, func(value *EdgeUpgradeStatus) { value.CurrentVersion = "1.0.0" }},
		{"accepted previous version", EdgeUpgradeStateAccepted, func(value *EdgeUpgradeStatus) { value.PreviousVersion = "0.9.0" }},
		{"accepted transaction", EdgeUpgradeStateAccepted, func(value *EdgeUpgradeStatus) { value.InstallerTransactionID = "txn-accepted" }},
		{"accepted error", EdgeUpgradeStateAccepted, func(value *EdgeUpgradeStatus) { value.ErrorCode = "INVALID" }},
		{"accepted alert", EdgeUpgradeStateAccepted, func(value *EdgeUpgradeStatus) { value.AlertRequired = true }},
		{"claimed current version", EdgeUpgradeStateClaimed, func(value *EdgeUpgradeStatus) { value.CurrentVersion = "1.0.0" }},
		{"claimed previous version", EdgeUpgradeStateClaimed, func(value *EdgeUpgradeStatus) { value.PreviousVersion = "0.9.0" }},
		{"claimed transaction", EdgeUpgradeStateClaimed, func(value *EdgeUpgradeStatus) { value.InstallerTransactionID = "txn-claimed" }},
		{"claimed error", EdgeUpgradeStateClaimed, func(value *EdgeUpgradeStatus) { value.ErrorCode = "INVALID" }},
		{"claimed alert", EdgeUpgradeStateClaimed, func(value *EdgeUpgradeStatus) { value.AlertRequired = true }},
		{"installing missing transaction", EdgeUpgradeStateInstalling, func(value *EdgeUpgradeStatus) {}},
		{"installing current version", EdgeUpgradeStateInstalling, func(value *EdgeUpgradeStatus) {
			value.InstallerTransactionID, value.CurrentVersion = "txn-installing", "1.0.0"
		}},
		{"installing previous version", EdgeUpgradeStateInstalling, func(value *EdgeUpgradeStatus) {
			value.InstallerTransactionID, value.PreviousVersion = "txn-installing", "0.9.0"
		}},
		{"installing error", EdgeUpgradeStateInstalling, func(value *EdgeUpgradeStatus) {
			value.InstallerTransactionID, value.ErrorCode = "txn-installing", "INVALID"
		}},
		{"installing alert", EdgeUpgradeStateInstalling, func(value *EdgeUpgradeStatus) {
			value.InstallerTransactionID, value.AlertRequired = "txn-installing", true
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
			if err != nil {
				t.Fatal(err)
			}
			accepted, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.ClaimCommand(context.Background(), fixture.execution.CommandID, fixture.options()); err != nil {
				t.Fatal(err)
			}
			base := EdgeUpgradeStatus{
				Schema: EdgeUpgradeStatusSchema, StatusID: mustUpgradeStatusID(t, fixture.execution.CommandID, 1), StatusRevision: 1,
				CommandID: fixture.execution.CommandID, PlanID: accepted.Command.PlanID,
				PlanRevision: accepted.Command.PlanRevision, InstallationID: fixture.execution.InstallationID,
				NodeID: fixture.execution.NodeID, CommandSHA256: accepted.SHA256, State: EdgeUpgradeStateClaimed,
				ObservedAt: fixture.now.Add(time.Minute),
			}
			if test.state == EdgeUpgradeStateInstalling {
				wire, marshalErr := json.Marshal(base)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
					t.Fatal(err)
				}
				base.StatusID = mustUpgradeStatusID(t, fixture.execution.CommandID, 2)
				base.StatusRevision = 2
			}
			base.State = test.state
			test.mutate(&base)
			wire, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.EnqueueStatus(context.Background(), wire); !errors.Is(err, ErrInvalidUpgradeStatus) {
				t.Fatalf("invalid %s fields error = %v", test.state, err)
			}
		})
	}
}

func encodeUpgradeCommandFixture(t *testing.T, fixture executionFixture) []byte {
	t.Helper()
	return encodeUpgradeCommand(t, fixture, fixture.encoded)
}

func mustUpgradeStatusID(t *testing.T, commandID string, revision uint64) string {
	t.Helper()
	statusID, err := upgradeStatusID(commandID, revision)
	if err != nil {
		t.Fatal(err)
	}
	return statusID
}

func encodeUpgradeCommand(t *testing.T, fixture executionFixture, signedExecution []byte) []byte {
	t.Helper()
	command := EdgeUpgradeCommand{
		Schema: EdgeUpgradeCommandSchema, CommandID: fixture.execution.CommandID,
		PlanID: "00000000-0000-4000-8000-000000000024", PlanRevision: fixture.execution.ReleaseSequence,
		BatchID: "canary-0001", InstallationID: fixture.execution.InstallationID, NodeID: fixture.execution.NodeID,
		Action: fixture.execution.Operation, SignedExecution: append([]byte(nil), signedExecution...),
		SignedExecutionSHA256: sha256Hex(signedExecution),
	}
	if fixture.execution.Schema == upgradeExecutionV2Schema || fixture.execution.Schema == upgradeExecutionV3Schema {
		command.PlanID = fixture.execution.PlanID
		command.PlanRevision = fixture.execution.PlanRevision
		command.BatchID = fixture.execution.BatchID
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
