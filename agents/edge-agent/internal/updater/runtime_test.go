package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	stdruntime "runtime"
	"sync/atomic"
	"testing"
	"time"
)

type recordingUpgradeManager struct {
	process        atomic.Int32
	helperPrepared atomic.Bool
	durableInstall *bool
	beforeProcess  func()
	prepared       preparedUpgrade
	result         Result
	processErr     error
	pending        bool
	pendingID      string
}

func (manager *recordingUpgradeManager) prepare(_ context.Context, plan Plan) (preparedUpgrade, error) {
	manager.helperPrepared.Store(true)
	if manager.prepared.InstallerTransactionID != "" || manager.prepared.Complete {
		prepared := manager.prepared
		prepared.Result = recordingResultEvidence(plan, prepared.Result)
		return prepared, nil
	}
	return preparedUpgrade{InstallerTransactionID: "txn-runtime-test"}, nil
}

func (manager *recordingUpgradeManager) beginInstall(context.Context, string) (bool, error) {
	if manager.durableInstall != nil {
		return *manager.durableInstall, nil
	}
	return true, nil
}

func (manager *recordingUpgradeManager) processPrepared(_ context.Context, plan Plan, transactionID string) (Result, error) {
	if transactionID != "txn-runtime-test" {
		return Result{}, ErrReplay
	}
	manager.process.Add(1)
	if manager.beforeProcess != nil {
		manager.beforeProcess()
	}
	if manager.result.State != "" || manager.processErr != nil {
		return recordingResultEvidence(plan, manager.result), manager.processErr
	}
	return recordingResultEvidence(plan, Result{
		PlanID: plan.PlanID, Revision: plan.Revision, ReleaseSequence: plan.ReleaseSequence,
		State: StateSucceeded, CurrentVersion: plan.TargetVersion, PreviousVersion: plan.CurrentVersion,
		InstallerTransactionID: "txn-runtime-test",
	}), nil
}

func recordingResultEvidence(plan Plan, result Result) Result {
	if result.ActiveEvidence != nil || result.State != StateSucceeded && result.State != StateRolledBack ||
		result.InstallerTransactionID == "" {
		return result
	}
	evidence := &ActiveProbeEvidence{Schema: ActiveProbeEvidenceSchema,
		ActiveArtifactSHA256: plan.Artifact.SHA256, ActiveConfigSHA256: plan.Artifact.SHA256,
		LastKnownGoodArtifactSHA256: plan.Artifact.SHA256,
		LastKnownGoodConfigSHA256:   plan.Artifact.SHA256,
		ProbeObservedAt:             plan.IssuedAt.UTC(), ProbeDeadline: plan.ExpiresAt.UTC()}
	evidence.EvidenceSHA256 = activeProbeEvidenceDigest(result.InstallerTransactionID, *evidence)
	result.ActiveEvidence = evidence
	return result
}

func (manager *recordingUpgradeManager) pendingTransaction(context.Context) (Plan, string, bool, error) {
	return Plan{}, manager.pendingID, manager.pending, nil
}

func TestUpgradeStatusIDIsDeterministicAndRevisionBound(t *testing.T) {
	commandID := "00000000-0000-4000-8000-000000000011"
	first, err := upgradeStatusID(commandID, 1)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := upgradeStatusID(commandID, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := upgradeStatusID(commandID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first != replay || first == second {
		t.Fatalf("first=%q replay=%q second=%q", first, replay, second)
	}
}

func TestUpgradeRuntimeRejectsV1BeforeDurableAccept(t *testing.T) {
	fixture := newExecutionFixture(t)
	store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
	if err != nil {
		t.Fatal(err)
	}
	manager := &recordingUpgradeManager{}
	runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: manager, Options: fixture.options(),
		Now: func() time.Time { return fixture.now.Add(2 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); !errors.Is(err, ErrInvalidUpgradeCommand) {
		t.Fatalf("v1 execution error = %v", err)
	}
	commands, err := store.PendingCommands(context.Background())
	if err != nil || len(commands) != 0 || manager.process.Load() != 0 {
		t.Fatalf("v1 durable effects = (commands=%#v process=%d err=%v)", commands, manager.process.Load(), err)
	}
}

func TestUpgradeRuntimeRefusesInstallingWithoutDurableHelperProof(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
	if err != nil {
		t.Fatal(err)
	}
	durableInstall := false
	manager := &recordingUpgradeManager{durableInstall: &durableInstall}
	runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: manager, Options: fixture.options(),
		Now: func() time.Time { return fixture.now.Add(2 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); err != nil {
		t.Fatal(err)
	}
	statuses, err := runtime.PendingStatuses(context.Background())
	if err != nil || len(statuses) != 1 || statuses[0].Status.State != EdgeUpgradeStateAccepted {
		t.Fatalf("accepted status = (%#v, %v)", statuses, err)
	}
	accepted := statuses[0]
	if acknowledged, err := runtime.AcknowledgeStatus(context.Background(), accepted.Status.StatusID,
		accepted.Status.CommandID, accepted.SHA256); err != nil || !acknowledged {
		t.Fatalf("accepted ACK = (%t, %v)", acknowledged, err)
	}
	if err := runtime.Recover(context.Background()); !errors.Is(err, ErrInstallerUncertain) {
		t.Fatalf("Recover() error = %v, want %v", err, ErrInstallerUncertain)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateClaimed {
		t.Fatalf("status after missing helper proof = (%+v, %t, %v)", last, found, err)
	}
	if manager.process.Load() != 0 {
		t.Fatalf("process ran without helper proof: %d", manager.process.Load())
	}
}

func TestUpgradeRuntimeReadyRejectsStoreDriftBeforeAndAfterWiring(t *testing.T) {
	newStore := func(t *testing.T) (*DurableUpgradeStore, string) {
		t.Helper()
		root := filepath.Join(t.TempDir(), "updater")
		store, err := NewDurableUpgradeStore(root)
		if err != nil {
			t.Fatal(err)
		}
		return store, root
	}
	replaceWire := func(t *testing.T, store *DurableUpgradeStore) {
		t.Helper()
		original := store.wireDir + "-original"
		if err := os.Rename(store.wireDir, original); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(store.wireDir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"inbox", "claims", "outbox", "acked"} {
			if err := os.Mkdir(filepath.Join(store.wireDir, name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	fixture := newExecutionV2Fixture(t)
	manager := &recordingUpgradeManager{}

	t.Run("before wiring", func(t *testing.T) {
		store, _ := newStore(t)
		replaceWire(t, store)
		if runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
			Store: store, Manager: manager, Options: fixture.options(), Now: func() time.Time { return fixture.now },
		}); !errors.Is(err, ErrInvalidUpgradeCommand) || runtime != nil {
			t.Fatalf("NewUpgradeRuntime() = (%#v, %v)", runtime, err)
		}
	})

	t.Run("after wiring", func(t *testing.T) {
		store, _ := newStore(t)
		runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
			Store: store, Manager: manager, Options: fixture.options(), Now: func() time.Time { return fixture.now },
		})
		if err != nil || !runtime.Ready() {
			t.Fatalf("initial runtime = (%#v, %v)", runtime, err)
		}
		replaceWire(t, store)
		if runtime.Ready() {
			t.Fatal("Ready() accepted replaced durable store")
		}
	})
}

func TestUpgradeRuntimeReportsCapabilitiesFromConcreteDurableRuntimeAndManager(t *testing.T) {
	artifact := []byte("runtime-capability-authority")
	environment := newTestEnvironment(t, artifact)
	installer := newV2SandboxInstaller(environment.installer)
	manager := v2ManagerForEnvironment(t, environment, installer)
	store, err := NewDurableUpgradeStore(environment.root)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newExecutionV2Fixture(t)
	runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: manager, Options: fixture.options(), Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	receipts, ok := any(runtime).(interface{ StatusAcknowledgementReceiptsEnabled() bool })
	if !ok || !receipts.StatusAcknowledgementReceiptsEnabled() || runtime.InstallerProtocolVersion() != InstallerProtocolV2 {
		t.Fatalf("actual runtime capabilities = (receipt-interface=%t receipt=%t protocol=%d)",
			ok, ok && receipts.StatusAcknowledgementReceiptsEnabled(), runtime.InstallerProtocolVersion())
	}

	markerRuntime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: &recordingUpgradeManager{}, Options: fixture.options(), Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if markerRuntime.InstallerProtocolVersion() != 0 {
		t.Fatalf("non-concrete manager advertised installer protocol %d", markerRuntime.InstallerProtocolVersion())
	}
}

func TestUpgradeRuntimeVerifiesBothV2SignaturesBeforeDurableAccept(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*fixtureEnvelope)
		want   error
	}{
		{name: "control", mutate: func(envelope *fixtureEnvelope) {
			envelope.Execution.ArtifactBundleSHA256 = fixtureDigest(0x73)
		}, want: ErrInvalidUpgradeExecutionControlSignature},
		{name: "edge", mutate: func(envelope *fixtureEnvelope) {
			envelope.EdgeSignature = envelope.ControlSignature
		}, want: ErrInvalidUpgradeExecutionEdgeSignature},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
			if err != nil {
				t.Fatal(err)
			}
			manager := &recordingUpgradeManager{}
			runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
				Store: store, Manager: manager, Options: fixture.options(),
				Now: func() time.Time { return fixture.now.Add(2 * time.Minute) },
			})
			if err != nil {
				t.Fatal(err)
			}
			envelope := fixture.envelope
			test.mutate(&envelope)
			signedExecution, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if err := runtime.AcceptCommand(context.Background(), encodeUpgradeCommand(t, fixture, signedExecution)); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			commands, commandErr := store.PendingCommands(context.Background())
			statuses, statusErr := store.PendingStatuses(context.Background())
			if commandErr != nil || statusErr != nil || len(commands) != 0 || len(statuses) != 0 || manager.process.Load() != 0 {
				t.Fatalf("durable effects = (commands=%#v statuses=%#v process=%d errors=%v/%v)",
					commands, statuses, manager.process.Load(), commandErr, statusErr)
			}
		})
	}
}

func TestUpgradeStatusAcknowledgementReplayRemainsCommandBound(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
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
	status := EdgeUpgradeStatus{
		Schema: EdgeUpgradeStatusSchema, StatusID: mustUpgradeStatusID(t, fixture.execution.CommandID, 1), StatusRevision: 1,
		CommandID: fixture.execution.CommandID, PlanID: accepted.Command.PlanID,
		PlanRevision: accepted.Command.PlanRevision, InstallationID: fixture.execution.InstallationID,
		NodeID: fixture.execution.NodeID, CommandSHA256: accepted.SHA256, State: EdgeUpgradeStateClaimed,
		ObservedAt: fixture.now.Add(3),
	}
	wire, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingStatuses(context.Background())
	if err != nil || len(pending) != 1 {
		t.Fatalf("PendingStatuses() = (%d, %v)", len(pending), err)
	}
	if acknowledged, err := store.acknowledgeStatus(context.Background(), status.StatusID,
		status.CommandID, pending[0].SHA256); err != nil || !acknowledged {
		t.Fatalf("acknowledgeStatus() = (%t, %v)", acknowledged, err)
	}
	if _, err := store.acknowledgeStatus(context.Background(), status.StatusID,
		"00000000-0000-4000-8000-000000000099", pending[0].SHA256); !errors.Is(err, ErrUpgradeStatusAckMismatch) {
		t.Fatalf("cross-command replay error = %v", err)
	}
}

func TestUpgradeRuntimeRequiresDurableAcceptedAckBeforeProcessAndRecovery(t *testing.T) {
	root := filepath.Join(t.TempDir(), "updater")
	fixture := newExecutionV2Fixture(t)
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	manager := &recordingUpgradeManager{}
	runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: manager, Options: fixture.options(), Now: func() time.Time { return fixture.now.Add(2 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	command := encodeUpgradeCommandFixture(t, fixture)
	if err := runtime.AcceptCommand(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if manager.process.Load() != 0 {
		t.Fatal("Process ran before accepted status acknowledgement")
	}

	restartedStore, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	restartedManager := &recordingUpgradeManager{}
	restarted, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: restartedStore, Manager: restartedManager, Options: fixture.options(), Now: func() time.Time { return fixture.now.Add(2 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restartedManager.process.Load() != 0 {
		t.Fatal("recovery processed a command without accepted status acknowledgement")
	}

	statuses, err := restarted.PendingStatuses(context.Background())
	if err != nil || len(statuses) != 1 || statuses[0].Status.State != EdgeUpgradeStateAccepted {
		t.Fatalf("accepted outbox = (%d, %v)", len(statuses), err)
	}
	accepted := statuses[0]
	if _, err := restarted.AcknowledgeStatus(context.Background(), accepted.Status.StatusID,
		accepted.Status.CommandID, sha256String([]byte("wrong"))); !errors.Is(err, ErrUpgradeStatusAckMismatch) {
		t.Fatalf("wrong accepted ACK error = %v", err)
	}
	if err := restarted.Recover(context.Background()); err != nil || restartedManager.process.Load() != 0 {
		t.Fatalf("recovery after rejected ACK = (%d, %v)", restartedManager.process.Load(), err)
	}

	restartedManager.beforeProcess = func() {
		if !restartedManager.helperPrepared.Load() {
			t.Fatal("installing status was emitted before the helper prepared journal")
		}
		acknowledged, err := restartedStore.acceptedStatusAcknowledged(context.Background(), accepted.Status.CommandID)
		if err != nil || !acknowledged {
			t.Fatalf("accepted ACK was not durable before Process: (%t, %v)", acknowledged, err)
		}
		last, found, err := restartedStore.LastStatus(context.Background(), accepted.Status.CommandID)
		if err != nil || !found || last.State != EdgeUpgradeStateInstalling ||
			last.CurrentVersion != "" || last.PreviousVersion != "" ||
			last.InstallerTransactionID != "txn-runtime-test" || last.ErrorCode != "" || last.AlertRequired {
			t.Fatalf("installing status before Process = (%#v, %t, %v)", last, found, err)
		}
	}
	if acknowledged, err := restarted.AcknowledgeStatus(context.Background(), accepted.Status.StatusID,
		accepted.Status.CommandID, accepted.SHA256); err != nil || !acknowledged {
		t.Fatalf("accepted ACK = (%t, %v)", acknowledged, err)
	}
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restartedManager.process.Load() != 1 {
		t.Fatalf("Process calls = %d, want 1", restartedManager.process.Load())
	}
}

func TestUpgradeRuntimeProcessesV3CommandAndDoesNotRepeatAfterRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "updater")
	fixture := newExecutionV3Fixture(t)
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	manager := &recordingUpgradeManager{}
	runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: manager, Options: fixture.options(),
		Now: func() time.Time { return fixture.now.Add(2 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); err != nil {
		t.Fatal(err)
	}
	statuses, err := runtime.PendingStatuses(context.Background())
	if err != nil || len(statuses) != 1 || statuses[0].Status.State != EdgeUpgradeStateAccepted {
		t.Fatalf("accepted v3 status = (%#v, %v)", statuses, err)
	}
	accepted := statuses[0]
	if acknowledged, err := runtime.AcknowledgeStatus(context.Background(), accepted.Status.StatusID,
		accepted.Status.CommandID, accepted.SHA256); err != nil || !acknowledged {
		t.Fatalf("accepted v3 ACK = (%t, %v)", acknowledged, err)
	}
	if err := runtime.Recover(context.Background()); err != nil || manager.process.Load() != 1 {
		t.Fatalf("v3 process = (%d, %v)", manager.process.Load(), err)
	}

	restartedStore, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	restartedManager := &recordingUpgradeManager{}
	restarted, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: restartedStore, Manager: restartedManager, Options: fixture.options(),
		Now: func() time.Time { return fixture.now.Add(2 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Recover(context.Background()); err != nil || restartedManager.process.Load() != 0 {
		t.Fatalf("v3 restart = (%d, %v)", restartedManager.process.Load(), err)
	}
}

func TestUpgradeRuntimeDoesNotEmitInstallingForCompletedJournal(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
	if err != nil {
		t.Fatal(err)
	}
	manager := &recordingUpgradeManager{prepared: preparedUpgrade{
		InstallerTransactionID: "txn-runtime-test", Complete: true,
		Result: Result{State: StateSucceeded, InstallerTransactionID: "txn-runtime-test"},
	}}
	runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: manager, Options: fixture.options(),
		Now: func() time.Time { return fixture.now.Add(2 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); err != nil {
		t.Fatal(err)
	}
	statuses, err := runtime.PendingStatuses(context.Background())
	if err != nil || len(statuses) != 1 {
		t.Fatalf("accepted statuses = (%d, %v)", len(statuses), err)
	}
	accepted := statuses[0]
	if acknowledged, err := runtime.AcknowledgeStatus(context.Background(), accepted.Status.StatusID,
		accepted.Status.CommandID, accepted.SHA256); err != nil || !acknowledged {
		t.Fatalf("accepted ACK = (%t, %v)", acknowledged, err)
	}
	if err := runtime.Recover(context.Background()); !errors.Is(err, ErrUpgradeStatusConflict) {
		t.Fatalf("completed journal recovery error = %v", err)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateClaimed || last.InstallerTransactionID != "" || manager.process.Load() != 0 {
		t.Fatalf("completed journal status = (%#v, %t, %v), process calls = %d", last, found, err, manager.process.Load())
	}
}

func TestUpgradeResultStateMapping(t *testing.T) {
	for _, test := range []struct {
		action string
		result Result
		want   []EdgeUpgradeState
	}{
		{string(ActionUpgrade), Result{State: StateSucceeded}, []EdgeUpgradeState{EdgeUpgradeStateHealthy}},
		{string(ActionRollback), Result{State: StateSucceeded}, []EdgeUpgradeState{EdgeUpgradeStateRolledBack}},
		{string(ActionUpgrade), Result{State: StateRolledBack}, []EdgeUpgradeState{EdgeUpgradeStateRollingBack, EdgeUpgradeStateRolledBack}},
		{string(ActionRollback), Result{State: StateRolledBack}, []EdgeUpgradeState{EdgeUpgradeStateFailed}},
		{string(ActionUpgrade), Result{State: StateFailed}, []EdgeUpgradeState{EdgeUpgradeStateFailed}},
		{string(ActionUpgrade), Result{State: StateFailed, ErrorCode: "ROLLBACK_FAILED"}, []EdgeUpgradeState{EdgeUpgradeStateUncertain}},
	} {
		got := upgradeResultStates(test.action, test.result, false)
		if len(got) != len(test.want) {
			t.Fatalf("states=%v want=%v", got, test.want)
		}
		for index := range got {
			if got[index] != test.want[index] {
				t.Fatalf("states=%v want=%v", got, test.want)
			}
		}
	}
}

func TestUpgradeRuntimeEmitsExactStatusTupleMatrix(t *testing.T) {
	upgrade := newExecutionV2Fixture(t)
	rollback := newRollbackExecutionFixture(t)
	for _, test := range []struct {
		name      string
		fixture   executionFixture
		manager   *recordingUpgradeManager
		terminal  []EdgeUpgradeState
		current   string
		previous  string
		errorCode string
		alert     bool
	}{
		{
			name: "upgrade healthy", fixture: upgrade,
			manager: &recordingUpgradeManager{result: Result{
				State: StateSucceeded, CurrentVersion: "2.0.0", PreviousVersion: "1.0.0",
				InstallerTransactionID: "txn-runtime-test",
			}},
			terminal: []EdgeUpgradeState{EdgeUpgradeStateHealthy}, current: "2.0.0", previous: "1.0.0",
		},
		{
			name: "explicit rollback", fixture: rollback,
			manager: &recordingUpgradeManager{result: Result{
				State: StateSucceeded, CurrentVersion: "1.0.0", PreviousVersion: "2.0.0",
				InstallerTransactionID: "txn-runtime-test",
			}},
			terminal: []EdgeUpgradeState{EdgeUpgradeStateRolledBack}, current: "1.0.0", previous: "2.0.0",
		},
		{
			name: "explicit rollback target restoration", fixture: rollback,
			manager: &recordingUpgradeManager{result: Result{
				State: StateRolledBack, CurrentVersion: "2.0.0", PreviousVersion: "1.0.0",
				InstallerTransactionID: "txn-runtime-test", ErrorCode: "HEALTH_FAILED",
			}, processErr: ErrHealth},
			terminal: []EdgeUpgradeState{EdgeUpgradeStateFailed}, current: "2.0.0", previous: "1.0.0",
			errorCode: "HEALTH_FAILED", alert: true,
		},
		{
			name: "explicit rollback preactivation failed", fixture: rollback,
			manager: &recordingUpgradeManager{result: Result{
				State: StateFailed, CurrentVersion: "2.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "ARTIFACT_INTEGRITY_FAILED", AlertRequired: true,
			}, processErr: ErrArtifactIntegrity},
			terminal: []EdgeUpgradeState{EdgeUpgradeStateFailed}, current: "2.0.0",
			errorCode: "ARTIFACT_INTEGRITY_FAILED", alert: true,
		},
		{
			name: "automatic rollback", fixture: upgrade,
			manager: &recordingUpgradeManager{result: Result{
				State: StateRolledBack, CurrentVersion: "1.0.0", PreviousVersion: "2.0.0",
				InstallerTransactionID: "txn-runtime-test", ErrorCode: "HEALTH_FAILED",
			}},
			terminal: []EdgeUpgradeState{EdgeUpgradeStateRollingBack, EdgeUpgradeStateRolledBack},
			current:  "1.0.0", previous: "2.0.0", errorCode: "HEALTH_FAILED",
		},
		{
			name: "preactivation failed", fixture: upgrade,
			manager: &recordingUpgradeManager{result: Result{
				State: StateFailed, CurrentVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "ARTIFACT_INTEGRITY_FAILED", AlertRequired: true,
			}, processErr: ErrArtifactIntegrity},
			terminal: []EdgeUpgradeState{EdgeUpgradeStateFailed}, current: "1.0.0",
			errorCode: "ARTIFACT_INTEGRITY_FAILED", alert: true,
		},
		{
			name: "rollback failure with known active candidate", fixture: upgrade,
			manager: &recordingUpgradeManager{result: Result{
				State: StateFailed, CurrentVersion: "2.0.0", PreviousVersion: "1.0.0",
				InstallerTransactionID: "txn-runtime-test", ErrorCode: "ROLLBACK_FAILED", AlertRequired: true,
			}, processErr: ErrRollback},
			terminal: []EdgeUpgradeState{EdgeUpgradeStateUncertain}, current: "2.0.0", previous: "1.0.0",
			errorCode: "ROLLBACK_FAILED", alert: true,
		},
		{
			name: "unknown installed state", fixture: upgrade,
			manager:  &recordingUpgradeManager{processErr: ErrInstallerUncertain, pending: true, pendingID: "txn-runtime-test"},
			terminal: []EdgeUpgradeState{EdgeUpgradeStateUncertain}, errorCode: "INSTALLER_UNCERTAIN", alert: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
			if err != nil {
				t.Fatal(err)
			}
			runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
				Store: store, Manager: test.manager, Options: test.fixture.options(),
				Now: func() time.Time { return test.fixture.now.Add(2 * time.Minute) },
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := runtime.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, test.fixture)); err != nil {
				t.Fatal(err)
			}
			statuses, err := runtime.PendingStatuses(context.Background())
			if err != nil || len(statuses) != 1 {
				t.Fatalf("accepted statuses = (%d, %v)", len(statuses), err)
			}
			accepted := statuses[0]
			assertEarlyUpgradeStatus(t, accepted.Status, EdgeUpgradeStateAccepted, "")
			if acknowledged, err := runtime.AcknowledgeStatus(context.Background(), accepted.Status.StatusID,
				accepted.Status.CommandID, accepted.SHA256); err != nil || !acknowledged {
				t.Fatalf("accepted ACK = (%t, %v)", acknowledged, err)
			}
			processErr := runtime.Recover(context.Background())
			if test.manager.processErr == nil && processErr != nil || test.manager.processErr != nil && !errors.Is(processErr, test.manager.processErr) {
				t.Fatalf("Recover() error = %v, want %v", processErr, test.manager.processErr)
			}
			statuses, err = runtime.PendingStatuses(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(statuses) != 2+len(test.terminal) {
				t.Fatalf("status count = %d, want %d: %#v", len(statuses), 2+len(test.terminal), statuses)
			}
			assertEarlyUpgradeStatus(t, statuses[0].Status, EdgeUpgradeStateClaimed, "")
			assertEarlyUpgradeStatus(t, statuses[1].Status, EdgeUpgradeStateInstalling, "txn-runtime-test")
			for index, state := range test.terminal {
				status := statuses[index+2].Status
				if status.State != state || status.CurrentVersion != test.current || status.PreviousVersion != test.previous ||
					status.InstallerTransactionID != "txn-runtime-test" || status.ErrorCode != test.errorCode ||
					status.AlertRequired != test.alert {
					t.Fatalf("terminal status = %#v, want state=%s current=%q previous=%q error=%q alert=%t",
						status, state, test.current, test.previous, test.errorCode, test.alert)
				}
			}
		})
	}
}

func TestActualManagerRuntimeReconcilesRollbackOutcomesAcrossRestart(t *testing.T) {
	t.Run("explicit rollback health failure restores original and reports failed", func(t *testing.T) {
		fixture, environment, storeRoot := newActualRuntimeEnvironment(t, newRollbackExecutionFixture(t))
		environment.probe.errors = []error{errors.New("unhealthy")}
		store, upgradeRuntime := newActualRuntime(t, environment, fixture, storeRoot)
		accepted := acceptAndAcknowledgeRuntimeCommand(t, upgradeRuntime, fixture)

		if err := upgradeRuntime.Recover(context.Background()); !errors.Is(err, ErrHealth) {
			t.Fatalf("explicit rollback Recover() error = %v", err)
		}
		last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
		if err != nil || !found || last.State != EdgeUpgradeStateFailed || last.CurrentVersion != "2.0.0" ||
			last.PreviousVersion != "1.0.0" || last.ErrorCode != "HEALTH_FAILED" || !last.AlertRequired {
			t.Fatalf("explicit rollback terminal = (%+v, %t, %v)", last, found, err)
		}
		_, restarted := newActualRuntime(t, environment, fixture, storeRoot)
		if err := restarted.Recover(context.Background()); err != nil || environment.installer.rollbackCalls != 1 {
			t.Fatalf("explicit rollback restart = (%d, %v)", environment.installer.rollbackCalls, err)
		}
	})

	t.Run("uncertain resolves directly to rolled back", func(t *testing.T) {
		fixture, environment, storeRoot := newActualRuntimeEnvironment(t, newExecutionV2Fixture(t))
		environment.probe.errors = []error{errors.New("unhealthy")}
		environment.installer.rollbackFailure = true
		environment.installer.queryError = errors.New("installer query unavailable")
		store, upgradeRuntime := newActualRuntime(t, environment, fixture, storeRoot)
		accepted := acceptAndAcknowledgeRuntimeCommand(t, upgradeRuntime, fixture)

		if err := upgradeRuntime.Recover(context.Background()); !errors.Is(err, ErrRollback) {
			t.Fatalf("initial uncertain Recover() error = %v", err)
		}
		last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
		if err != nil || !found || last.State != EdgeUpgradeStateUncertain || last.ErrorCode != "ROLLBACK_FAILED" {
			t.Fatalf("initial uncertain status = (%+v, %t, %v)", last, found, err)
		}
		journal, err := environment.manager.store.loadTransaction()
		if err != nil || journal == nil || journal.Phase != phaseRollback || journal.ErrorCode != "HEALTH_FAILED" {
			t.Fatalf("recoverable journal = (%+v, %v)", journal, err)
		}
		installExternalRollbackReceipt(t, environment, journal)
		environment.installer.queryError = nil
		_, restarted := newActualRuntime(t, environment, fixture, storeRoot)
		if err := restarted.Recover(context.Background()); !errors.Is(err, ErrHealth) {
			t.Fatalf("reconciled Recover() error = %v", err)
		}
		statuses, err := restarted.PendingStatuses(context.Background())
		if err != nil || len(statuses) != 4 {
			t.Fatalf("reconciled statuses = (%#v, %v)", statuses, err)
		}
		want := []EdgeUpgradeState{EdgeUpgradeStateClaimed, EdgeUpgradeStateInstalling, EdgeUpgradeStateUncertain, EdgeUpgradeStateRolledBack}
		for index, status := range statuses {
			if status.Status.State != want[index] || status.Status.StatusRevision != uint64(index+2) {
				t.Fatalf("reconciled status[%d] = %+v, want %s revision %d", index, status.Status, want[index], index+2)
			}
		}
		_, terminalRestart := newActualRuntime(t, environment, fixture, storeRoot)
		if err := terminalRestart.Recover(context.Background()); err != nil || environment.installer.rollbackCalls != 1 {
			t.Fatalf("terminal restart = (%d, %v)", environment.installer.rollbackCalls, err)
		}
	})

	t.Run("uncertain resolves to exact failed tuple once", func(t *testing.T) {
		fixture, environment, storeRoot := newActualRuntimeEnvironment(t, newExecutionV2Fixture(t))
		environment.probe.errors = []error{errors.New("unhealthy")}
		environment.installer.rollbackFailure = true
		environment.installer.queryError = errors.New("installer query unavailable")
		store, upgradeRuntime := newActualRuntime(t, environment, fixture, storeRoot)
		accepted := acceptAndAcknowledgeRuntimeCommand(t, upgradeRuntime, fixture)

		if err := upgradeRuntime.Recover(context.Background()); !errors.Is(err, ErrRollback) {
			t.Fatalf("initial uncertain Recover() error = %v", err)
		}
		journal, err := environment.manager.store.loadTransaction()
		if err != nil || journal == nil || journal.Phase != phaseRollback || journal.ErrorCode != "HEALTH_FAILED" {
			t.Fatalf("recoverable journal = (%+v, %v)", journal, err)
		}
		environment.installer.queryError = nil
		_, restarted := newActualRuntime(t, environment, fixture, storeRoot)
		if err := restarted.Recover(context.Background()); !errors.Is(err, ErrRollback) {
			t.Fatalf("reconciled Recover() error = %v", err)
		}
		last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
		if err != nil || !found || last.State != EdgeUpgradeStateFailed || last.CurrentVersion != "2.0.0" ||
			last.PreviousVersion != "1.0.0" || last.ErrorCode != "HEALTH_FAILED" || !last.AlertRequired {
			t.Fatalf("reconciled failed status = (%+v, %t, %v)", last, found, err)
		}
		before, err := restarted.PendingStatuses(context.Background())
		if err != nil || len(before) != 4 {
			t.Fatalf("reconciled statuses = (%#v, %v)", before, err)
		}
		_, duplicate := newActualRuntime(t, environment, fixture, storeRoot)
		if err := duplicate.Recover(context.Background()); err != nil {
			t.Fatalf("duplicate Recover() error = %v", err)
		}
		after, err := duplicate.PendingStatuses(context.Background())
		if err != nil || len(after) != len(before) {
			t.Fatalf("duplicate statuses = (%#v, %v)", after, err)
		}
		for index := range before {
			if before[index].SHA256 != after[index].SHA256 || !bytes.Equal(before[index].Encoded, after[index].Encoded) {
				t.Fatalf("duplicate status[%d] changed", index)
			}
		}
		if environment.installer.rollbackCalls != 1 {
			t.Fatalf("duplicate rollback calls = %d", environment.installer.rollbackCalls)
		}
	})

	t.Run("crash after rolling back write resumes exact terminal", func(t *testing.T) {
		fixture, environment, storeRoot := newActualRuntimeEnvironment(t, newExecutionV2Fixture(t))
		environment.probe.errors = []error{errors.New("unhealthy")}
		store, upgradeRuntime := newActualRuntime(t, environment, fixture, storeRoot)
		acceptAndAcknowledgeRuntimeCommand(t, upgradeRuntime, fixture)
		commands, err := store.PendingCommands(context.Background())
		if err != nil || len(commands) != 1 {
			t.Fatalf("pending commands = (%#v, %v)", commands, err)
		}
		command := commands[0]
		options, err := upgradeRuntime.verificationOptions(command.Command)
		if err != nil {
			t.Fatal(err)
		}
		options.Now = environment.now.Now()
		claimed, err := store.ClaimCommand(context.Background(), command.Command.CommandID, options)
		if err != nil {
			t.Fatal(err)
		}
		if err := upgradeRuntime.emitStatus(context.Background(), command, EdgeUpgradeStateClaimed, Result{}, ""); err != nil {
			t.Fatal(err)
		}
		prepared, err := environment.manager.prepare(context.Background(), claimed.Plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := upgradeRuntime.emitStatus(context.Background(), command, EdgeUpgradeStateInstalling,
			Result{InstallerTransactionID: prepared.InstallerTransactionID}, ""); err != nil {
			t.Fatal(err)
		}
		result, processErr := environment.manager.processPrepared(context.Background(), claimed.Plan, prepared.InstallerTransactionID)
		if !errors.Is(processErr, ErrHealth) || result.State != StateRolledBack {
			t.Fatalf("rollback result = (%+v, %v)", result, processErr)
		}
		if err := upgradeRuntime.emitStatus(context.Background(), command, EdgeUpgradeStateRollingBack, result, result.ErrorCode); err != nil {
			t.Fatal(err)
		}
		journal, err := environment.manager.store.loadTransaction()
		if err != nil || journal == nil || journal.Phase != phaseDone || journal.Result.State != StateRolledBack {
			t.Fatalf("completed rollback journal = (%+v, %v)", journal, err)
		}
		_, restarted := newActualRuntime(t, environment, fixture, storeRoot)
		if err := restarted.Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		statuses, err := restarted.PendingStatuses(context.Background())
		if err != nil || len(statuses) != 4 {
			t.Fatalf("resumed statuses = (%#v, %v)", statuses, err)
		}
		want := []EdgeUpgradeState{EdgeUpgradeStateClaimed, EdgeUpgradeStateInstalling, EdgeUpgradeStateRollingBack, EdgeUpgradeStateRolledBack}
		for index, status := range statuses {
			if status.Status.State != want[index] || status.Status.StatusRevision != uint64(index+2) {
				t.Fatalf("resumed status[%d] = %+v, want %s revision %d", index, status.Status, want[index], index+2)
			}
		}
	})
}

func newActualRuntimeEnvironment(t *testing.T, fixture executionFixture) (executionFixture, *testEnvironment, string) {
	t.Helper()
	artifact := bytes.Repeat([]byte{0x5a}, 1024)
	digest := sha256.Sum256(artifact)
	fixture.execution.SHA256Digest = base64.RawURLEncoding.EncodeToString(digest[:])
	fixture.execution.ArtifactSizeBytes = int64(len(artifact))
	fixture.execution.Platform = stdruntime.GOOS
	fixture.execution.Architecture = stdruntime.GOARCH
	fixture.execution.Health.ActivationTimeoutNanoseconds = int64(time.Second)
	fixture.execution.Health.ObservationWindowNanoseconds = int64(time.Second)
	fixture.execution.Health.IntervalNanoseconds = int64(time.Second)
	fixture.execution.Health.ProbeTimeoutNanoseconds = int64(time.Second)
	fixture.execution.Health.RequiredConsecutiveSuccesses = 1
	resignExecutionFixture(t, &fixture)

	environment := newTestEnvironment(t, artifact)
	environment.now.now = fixture.now.Add(2 * time.Minute)
	current := environment.installer.sign(ActivationReceipt{
		SchemaVersion: receiptSchemaVersion, InstallerTransactionID: "bootstrap-actual-runtime",
		ReleaseSequence: fixture.execution.ReleaseSequence - 1,
		ArtifactSHA256:  sha256Hex([]byte("baseline-" + fixture.execution.CurrentVersion)),
		CurrentVersion:  fixture.execution.CurrentVersion, Status: ReceiptStatusActive, IssuedAt: environment.now.Now(),
	})
	environment.installer.current = current
	return fixture, environment, filepath.Join(environment.root, "runtime-wire")
}

func newActualRuntime(t *testing.T, environment *testEnvironment, fixture executionFixture,
	storeRoot string) (*DurableUpgradeStore, *UpgradeRuntime) {
	t.Helper()
	config := DefaultConfig(
		environment.root, fixture.execution.CurrentVersion,
		map[string]ed25519.PublicKey{fixture.envelope.EdgeKeyID: fixture.edgePublic},
		map[string]ed25519.PublicKey{"sandbox-helper": environment.receiptPublicKey},
		environment.downloader, environment.installer, environment.probe,
	)
	config.NodeID = fixture.execution.NodeID
	config.Clock = environment.now
	config.DiskReserveBytes = 0
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	environment.manager = manager
	store, err := NewDurableUpgradeStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	upgradeRuntime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: manager, Options: fixture.options(), Now: environment.now.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, upgradeRuntime
}

func acceptAndAcknowledgeRuntimeCommand(t *testing.T, upgradeRuntime *UpgradeRuntime,
	fixture executionFixture) QueuedUpgradeStatus {
	t.Helper()
	if err := upgradeRuntime.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); err != nil {
		t.Fatal(err)
	}
	statuses, err := upgradeRuntime.PendingStatuses(context.Background())
	if err != nil || len(statuses) != 1 || statuses[0].Status.State != EdgeUpgradeStateAccepted {
		t.Fatalf("accepted statuses = (%#v, %v)", statuses, err)
	}
	accepted := statuses[0]
	if acknowledged, err := upgradeRuntime.AcknowledgeStatus(context.Background(), accepted.Status.StatusID,
		accepted.Status.CommandID, accepted.SHA256); err != nil || !acknowledged {
		t.Fatalf("accepted ACK = (%t, %v)", acknowledged, err)
	}
	return accepted
}

func installExternalRollbackReceipt(t *testing.T, environment *testEnvironment, journal *transaction) {
	t.Helper()
	environment.installer.mu.Lock()
	defer environment.installer.mu.Unlock()
	receipt := environment.installer.sign(ActivationReceipt{
		SchemaVersion: receiptSchemaVersion, InstallerTransactionID: journal.InstallerTransactionID,
		ReleaseSequence: journal.Plan.ReleaseSequence, ArtifactSHA256: journal.Plan.Artifact.SHA256,
		CurrentVersion: journal.Before.CurrentVersion, PreviousVersion: journal.Plan.TargetVersion,
		Status: ReceiptStatusRolledBack, IssuedAt: environment.now.Now(),
	})
	environment.installer.records[journal.InstallerTransactionID] = receipt
	environment.installer.current = environment.installer.restoredCurrent(
		journal.InstallerTransactionID, journal.Plan.ReleaseSequence, journal.Before, journal.Plan.TargetVersion,
	)
}

func TestUpgradeStatusDirectRolledBackTransitionIsRollbackActionOnly(t *testing.T) {
	for _, test := range []struct {
		name    string
		fixture executionFixture
		wantErr error
	}{
		{name: "explicit rollback", fixture: newRollbackExecutionFixture(t)},
		{name: "upgrade", fixture: newExecutionV2Fixture(t), wantErr: ErrUpgradeStatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
			if err != nil {
				t.Fatal(err)
			}
			accepted, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, test.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.ClaimCommand(context.Background(), accepted.Command.CommandID, test.fixture.options()); err != nil {
				t.Fatal(err)
			}
			claimed := runtimeStatus(t, accepted, test.fixture, 1, EdgeUpgradeStateClaimed, Result{})
			installing := runtimeStatus(t, accepted, test.fixture, 2, EdgeUpgradeStateInstalling,
				Result{InstallerTransactionID: "txn-runtime-test"})
			rolledBack := runtimeStatus(t, accepted, test.fixture, 3, EdgeUpgradeStateRolledBack, Result{
				CurrentVersion:  test.fixture.execution.TargetVersion,
				PreviousVersion: test.fixture.execution.CurrentVersion, InstallerTransactionID: "txn-runtime-test",
			})
			for _, status := range []EdgeUpgradeStatus{claimed, installing} {
				wire, _ := json.Marshal(status)
				if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
					t.Fatal(err)
				}
			}
			wire, _ := json.Marshal(rolledBack)
			_, err = store.EnqueueStatus(context.Background(), wire)
			if !errors.Is(err, test.wantErr) &&
				!(test.wantErr == ErrUpgradeStatusConflict && errors.Is(err, ErrInvalidUpgradeStatus)) {
				t.Fatalf("direct rolled_back error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestExplicitRollbackTerminalSurvivesLastStatusAndRuntimeRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "updater")
	fixture := newRollbackExecutionFixture(t)
	store, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	manager := &recordingUpgradeManager{result: Result{
		State: StateSucceeded, CurrentVersion: "1.0.0", PreviousVersion: "2.0.0",
		InstallerTransactionID: "txn-runtime-test",
	}}
	runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: manager, Options: fixture.options(),
		Now: func() time.Time { return fixture.now.Add(2 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); err != nil {
		t.Fatal(err)
	}
	statuses, err := runtime.PendingStatuses(context.Background())
	if err != nil || len(statuses) != 1 {
		t.Fatalf("accepted statuses = (%d, %v)", len(statuses), err)
	}
	accepted := statuses[0]
	if acknowledged, err := runtime.AcknowledgeStatus(context.Background(), accepted.Status.StatusID,
		accepted.Status.CommandID, accepted.SHA256); err != nil || !acknowledged {
		t.Fatalf("accepted ACK = (%t, %v)", acknowledged, err)
	}
	if err := runtime.Recover(context.Background()); err != nil || manager.process.Load() != 1 {
		t.Fatalf("initial rollback processing = (%d, %v)", manager.process.Load(), err)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateRolledBack {
		t.Fatalf("LastStatus() = (%#v, %t, %v)", last, found, err)
	}

	restartedStore, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	restartedManager := &recordingUpgradeManager{}
	restarted, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: restartedStore, Manager: restartedManager, Options: fixture.options(),
		Now: func() time.Time { return fixture.now.Add(3 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Recover(context.Background()); err != nil || restartedManager.process.Load() != 0 {
		t.Fatalf("restarted rollback recovery = (%d, %v)", restartedManager.process.Load(), err)
	}
}

func TestUpgradeRuntimeRecoversCompletedRollbackFailureAsUncertain(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
	if err != nil {
		t.Fatal(err)
	}
	manager := &recordingUpgradeManager{prepared: preparedUpgrade{
		InstallerTransactionID: "txn-runtime-test", Complete: true,
		Result: Result{
			State: StateFailed, CurrentVersion: "2.0.0", PreviousVersion: "1.0.0",
			InstallerTransactionID: "txn-runtime-test", ErrorCode: "ROLLBACK_FAILED", AlertRequired: true,
		},
	}}
	runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: manager, Options: fixture.options(),
		Now: func() time.Time { return fixture.now.Add(2 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture)); err != nil {
		t.Fatal(err)
	}
	statuses, err := runtime.PendingStatuses(context.Background())
	if err != nil || len(statuses) != 1 {
		t.Fatalf("accepted statuses = (%d, %v)", len(statuses), err)
	}
	acceptedStatus := statuses[0]
	if acknowledged, err := runtime.AcknowledgeStatus(context.Background(), acceptedStatus.Status.StatusID,
		acceptedStatus.Status.CommandID, acceptedStatus.SHA256); err != nil || !acknowledged {
		t.Fatalf("accepted ACK = (%t, %v)", acknowledged, err)
	}
	commands, err := store.PendingCommands(context.Background())
	if err != nil || len(commands) != 1 {
		t.Fatalf("pending commands = (%d, %v)", len(commands), err)
	}
	accepted := commands[0]
	if _, err := store.ClaimCommand(context.Background(), accepted.Command.CommandID, fixture.options()); err != nil {
		t.Fatal(err)
	}
	for _, status := range []EdgeUpgradeStatus{
		runtimeStatus(t, accepted, fixture, 2, EdgeUpgradeStateClaimed, Result{}),
		runtimeStatus(t, accepted, fixture, 3, EdgeUpgradeStateInstalling,
			Result{InstallerTransactionID: "txn-runtime-test"}),
	} {
		wire, _ := json.Marshal(status)
		if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
			t.Fatal(err)
		}
	}
	if err := runtime.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Command.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateUncertain || last.CurrentVersion != "2.0.0" ||
		last.PreviousVersion != "1.0.0" || last.InstallerTransactionID != "txn-runtime-test" ||
		last.ErrorCode != "ROLLBACK_FAILED" || !last.AlertRequired || manager.process.Load() != 0 {
		t.Fatalf("completed rollback recovery = (%#v, %t, %v), process calls = %d", last, found, err, manager.process.Load())
	}
}

func TestUpgradeRuntimeReconcilesUncertainStatusMatrix(t *testing.T) {
	upgrade := newExecutionV2Fixture(t)
	rollback := newRollbackExecutionFixture(t)
	for _, test := range []struct {
		name         string
		fixture      executionFixture
		rollingCause string
		initial      Result
		completed    Result
		wantState    EdgeUpgradeState
		want         Result
		wantNew      bool
	}{
		{
			name: "upgrade healthy", fixture: upgrade,
			initial: Result{InstallerTransactionID: "txn-runtime-test", ErrorCode: "INSTALLER_UNCERTAIN", AlertRequired: true},
			completed: Result{State: StateSucceeded, CurrentVersion: "2.0.0", PreviousVersion: "1.0.0",
				InstallerTransactionID: "txn-runtime-test"},
			wantState: EdgeUpgradeStateHealthy,
			want:      Result{CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test"},
			wantNew:   true,
		},
		{
			name: "upgrade automatic rollback restores original cause", fixture: upgrade, rollingCause: "HEALTH_FAILED",
			initial: Result{InstallerTransactionID: "txn-runtime-test", ErrorCode: "INSTALLER_UNCERTAIN", AlertRequired: true},
			completed: Result{State: StateRolledBack, CurrentVersion: "1.0.0", PreviousVersion: "2.0.0",
				InstallerTransactionID: "txn-runtime-test", ErrorCode: "HEALTH_FAILED"},
			wantState: EdgeUpgradeStateRolledBack,
			want: Result{CurrentVersion: "1.0.0", PreviousVersion: "2.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "HEALTH_FAILED"},
			wantNew: true,
		},
		{
			name: "explicit rollback success", fixture: rollback,
			initial: Result{InstallerTransactionID: "txn-runtime-test", ErrorCode: "INSTALLER_UNCERTAIN", AlertRequired: true},
			completed: Result{State: StateSucceeded, CurrentVersion: "1.0.0", PreviousVersion: "2.0.0",
				InstallerTransactionID: "txn-runtime-test"},
			wantState: EdgeUpgradeStateRolledBack,
			want:      Result{CurrentVersion: "1.0.0", PreviousVersion: "2.0.0", InstallerTransactionID: "txn-runtime-test"},
			wantNew:   true,
		},
		{
			name: "explicit rollback restoration", fixture: rollback,
			initial: Result{InstallerTransactionID: "txn-runtime-test", ErrorCode: "INSTALLER_UNCERTAIN", AlertRequired: true},
			completed: Result{State: StateRolledBack, CurrentVersion: "2.0.0", PreviousVersion: "1.0.0",
				InstallerTransactionID: "txn-runtime-test", ErrorCode: "HEALTH_FAILED"},
			wantState: EdgeUpgradeStateFailed,
			want: Result{CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "HEALTH_FAILED", AlertRequired: true},
			wantNew: true,
		},
		{
			name: "proved preactivation failure", fixture: upgrade,
			initial: Result{InstallerTransactionID: "txn-runtime-test", ErrorCode: "INSTALLER_UNCERTAIN", AlertRequired: true},
			completed: Result{State: StateFailed, CurrentVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "ARTIFACT_INTEGRITY_FAILED", AlertRequired: true},
			wantState: EdgeUpgradeStateFailed,
			want: Result{CurrentVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "ARTIFACT_INTEGRITY_FAILED", AlertRequired: true},
			wantNew: true,
		},
		{
			name: "uncertain facts evolve", fixture: upgrade,
			initial: Result{InstallerTransactionID: "txn-runtime-test", ErrorCode: "INSTALLER_UNCERTAIN", AlertRequired: true},
			completed: Result{State: StateFailed, CurrentVersion: "2.0.0", PreviousVersion: "1.0.0",
				InstallerTransactionID: "txn-runtime-test", ErrorCode: "ROLLBACK_FAILED", AlertRequired: true},
			wantState: EdgeUpgradeStateUncertain,
			want: Result{CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "ROLLBACK_FAILED", AlertRequired: true},
			wantNew: true,
		},
		{
			name: "exact uncertain duplicate", fixture: upgrade,
			initial: Result{CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "ROLLBACK_FAILED", AlertRequired: true},
			completed: Result{State: StateFailed, CurrentVersion: "2.0.0", PreviousVersion: "1.0.0",
				InstallerTransactionID: "txn-runtime-test", ErrorCode: "ROLLBACK_FAILED", AlertRequired: true},
			wantState: EdgeUpgradeStateUncertain,
			want: Result{CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test",
				ErrorCode: "ROLLBACK_FAILED", AlertRequired: true},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "updater")
			store, err := NewDurableUpgradeStore(root)
			if err != nil {
				t.Fatal(err)
			}
			accepted := seedRuntimeInstalling(t, store, test.fixture)
			revision := uint64(4)
			if test.rollingCause != "" {
				rollingBack := runtimeStatus(t, accepted, test.fixture, revision, EdgeUpgradeStateRollingBack, Result{
					CurrentVersion:  test.fixture.execution.CurrentVersion,
					PreviousVersion: test.fixture.execution.TargetVersion, InstallerTransactionID: "txn-runtime-test",
					ErrorCode: test.rollingCause,
				})
				wire, _ := json.Marshal(rollingBack)
				if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
					t.Fatal(err)
				}
				revision++
			}
			uncertain := runtimeStatus(t, accepted, test.fixture, revision, EdgeUpgradeStateUncertain, test.initial)
			wire, _ := json.Marshal(uncertain)
			if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
				t.Fatal(err)
			}

			manager := &recordingUpgradeManager{prepared: preparedUpgrade{
				InstallerTransactionID: "txn-runtime-test", Complete: true, Result: test.completed,
			}}
			runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
				Store: store, Manager: manager, Options: test.fixture.options(),
				Now: func() time.Time { return test.fixture.now.Add(2 * time.Minute) },
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := runtime.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			last, found, err := store.LastStatus(context.Background(), accepted.Command.CommandID)
			wantRevision := revision
			if test.wantNew {
				wantRevision++
			}
			if err != nil || !found || last.StatusRevision != wantRevision || last.State != test.wantState ||
				last.CurrentVersion != test.want.CurrentVersion || last.PreviousVersion != test.want.PreviousVersion ||
				last.InstallerTransactionID != test.want.InstallerTransactionID || last.ErrorCode != test.want.ErrorCode ||
				last.AlertRequired != test.want.AlertRequired || manager.process.Load() != 0 {
				t.Fatalf("reconciled status = (%#v, %t, %v), process=%d want revision=%d state=%s result=%+v",
					last, found, err, manager.process.Load(), wantRevision, test.wantState, test.want)
			}

			restartedStore, err := NewDurableUpgradeStore(root)
			if err != nil {
				t.Fatal(err)
			}
			restartedManager := &recordingUpgradeManager{prepared: manager.prepared}
			restarted, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
				Store: restartedStore, Manager: restartedManager, Options: test.fixture.options(),
				Now: func() time.Time { return test.fixture.now.Add(3 * time.Minute) },
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := restarted.Recover(context.Background()); err != nil || restartedManager.process.Load() != 0 {
				t.Fatalf("restart recovery = (%d, %v)", restartedManager.process.Load(), err)
			}
		})
	}
}

func TestDurableUpgradeStatusRejectsForgedActionTuplesAndDrift(t *testing.T) {
	upgrade := newExecutionV2Fixture(t)
	rollback := newRollbackExecutionFixture(t)
	for _, test := range []struct {
		name    string
		fixture executionFixture
		state   EdgeUpgradeState
		result  Result
	}{
		{name: "rollback healthy", fixture: rollback, state: EdgeUpgradeStateHealthy,
			result: Result{CurrentVersion: "1.0.0", PreviousVersion: "2.0.0", InstallerTransactionID: "txn-runtime-test"}},
		{name: "rollback rolling back", fixture: rollback, state: EdgeUpgradeStateRollingBack,
			result: Result{CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test", ErrorCode: "HEALTH_FAILED"}},
		{name: "upgrade direct rolled back", fixture: upgrade, state: EdgeUpgradeStateRolledBack,
			result: Result{CurrentVersion: "1.0.0", PreviousVersion: "2.0.0", InstallerTransactionID: "txn-runtime-test", ErrorCode: "HEALTH_FAILED"}},
		{name: "upgrade healthy wrong tuple", fixture: upgrade, state: EdgeUpgradeStateHealthy,
			result: Result{CurrentVersion: "1.0.0", PreviousVersion: "2.0.0", InstallerTransactionID: "txn-runtime-test"}},
		{name: "failed without alert", fixture: upgrade, state: EdgeUpgradeStateFailed,
			result: Result{CurrentVersion: "1.0.0", InstallerTransactionID: "txn-runtime-test", ErrorCode: "DOWNLOAD_FAILED"}},
		{name: "uncertain without error", fixture: upgrade, state: EdgeUpgradeStateUncertain,
			result: Result{InstallerTransactionID: "txn-runtime-test", AlertRequired: true}},
		{name: "transaction drift", fixture: upgrade, state: EdgeUpgradeStateHealthy,
			result: Result{CurrentVersion: "2.0.0", PreviousVersion: "1.0.0", InstallerTransactionID: "txn-other"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
			if err != nil {
				t.Fatal(err)
			}
			accepted := seedRuntimeInstalling(t, store, test.fixture)
			candidate := runtimeStatus(t, accepted, test.fixture, 4, test.state, test.result)
			wire, _ := json.Marshal(candidate)
			if _, err := store.EnqueueStatus(context.Background(), wire); !errors.Is(err, ErrInvalidUpgradeStatus) && !errors.Is(err, ErrUpgradeStatusConflict) {
				t.Fatalf("forged status error = %v", err)
			}
		})
	}

	store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
	if err != nil {
		t.Fatal(err)
	}
	accepted := seedRuntimeInstalling(t, store, upgrade)
	rollingBack := runtimeStatus(t, accepted, upgrade, 4, EdgeUpgradeStateRollingBack, Result{
		CurrentVersion: "1.0.0", PreviousVersion: "2.0.0", InstallerTransactionID: "txn-runtime-test",
		ErrorCode: "HEALTH_FAILED",
	})
	rolledBack := runtimeStatus(t, accepted, upgrade, 5, EdgeUpgradeStateRolledBack, Result{
		CurrentVersion: "1.0.0", PreviousVersion: "2.0.0", InstallerTransactionID: "txn-runtime-test",
		ErrorCode: "HEALTH_FAILED",
	})
	for _, status := range []EdgeUpgradeStatus{rollingBack, rolledBack} {
		wire, _ := json.Marshal(status)
		if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
			t.Fatal(err)
		}
	}
	rolledBack.ErrorCode = "PLAN_EXPIRED"
	tampered, _ := json.Marshal(rolledBack)
	if err := writeDurableBytes(store.statusPath(rolledBack.StatusID), tampered); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LastStatus(context.Background(), accepted.Command.CommandID); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("tampered rollback cause error = %v", err)
	}
}

func seedRuntimeInstalling(t *testing.T, store *DurableUpgradeStore, fixture executionFixture) AcceptedUpgradeCommand {
	t.Helper()
	accepted, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	acceptedStatus := runtimeStatus(t, accepted, fixture, 1, EdgeUpgradeStateAccepted, Result{})
	wire, _ := json.Marshal(acceptedStatus)
	queued, err := store.EnqueueStatus(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	if acknowledged, err := store.AcknowledgeStatus(context.Background(), acceptedStatus.StatusID, queued.SHA256); err != nil || !acknowledged {
		t.Fatalf("accepted ACK = (%t, %v)", acknowledged, err)
	}
	if _, err := store.ClaimCommand(context.Background(), accepted.Command.CommandID, fixture.options()); err != nil {
		t.Fatal(err)
	}
	for _, status := range []EdgeUpgradeStatus{
		runtimeStatus(t, accepted, fixture, 2, EdgeUpgradeStateClaimed, Result{}),
		runtimeStatus(t, accepted, fixture, 3, EdgeUpgradeStateInstalling,
			Result{InstallerTransactionID: "txn-runtime-test"}),
	} {
		wire, _ := json.Marshal(status)
		if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
			t.Fatal(err)
		}
	}
	return accepted
}

func runtimeStatus(t *testing.T, accepted AcceptedUpgradeCommand, fixture executionFixture,
	revision uint64, state EdgeUpgradeState, result Result) EdgeUpgradeStatus {
	t.Helper()
	statusID, err := upgradeStatusID(accepted.Command.CommandID, revision)
	if err != nil {
		t.Fatal(err)
	}
	return EdgeUpgradeStatus{
		Schema: EdgeUpgradeStatusSchema, StatusID: statusID, StatusRevision: revision,
		CommandID: accepted.Command.CommandID, PlanID: accepted.Command.PlanID,
		PlanRevision: accepted.Command.PlanRevision, InstallationID: accepted.Command.InstallationID,
		NodeID: accepted.Command.NodeID, CommandSHA256: accepted.SHA256, State: state,
		CurrentVersion: result.CurrentVersion, PreviousVersion: result.PreviousVersion,
		InstallerTransactionID: result.InstallerTransactionID, ErrorCode: result.ErrorCode,
		AlertRequired: result.AlertRequired, ObservedAt: fixture.now.Add(time.Duration(revision) * time.Second),
	}
}

func assertEarlyUpgradeStatus(t *testing.T, status EdgeUpgradeStatus, state EdgeUpgradeState, transactionID string) {
	t.Helper()
	if status.State != state || status.CurrentVersion != "" || status.PreviousVersion != "" ||
		status.InstallerTransactionID != transactionID || status.ErrorCode != "" || status.AlertRequired {
		t.Fatalf("early status = %#v, want state=%s transaction=%q", status, state, transactionID)
	}
}
