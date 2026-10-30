//go:build integration

package updater

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUpgradeStatusRevisionUniquenessIntegrationRED(t *testing.T) {
	for _, test := range []struct {
		name      string
		preceding func(EdgeUpgradeStatus) []EdgeUpgradeStatus
		candidate func(EdgeUpgradeStatus) EdgeUpgradeStatus
	}{
		{
			name: "same revision conflicting identity and state",
			preceding: func(base EdgeUpgradeStatus) []EdgeUpgradeStatus {
				return []EdgeUpgradeStatus{base}
			},
			candidate: func(base EdgeUpgradeStatus) EdgeUpgradeStatus {
				base.StatusID = "00000000-0000-4000-8000-000000000032"
				base.State = EdgeUpgradeStateFailed
				base.ErrorCode = "CONFLICTING_TERMINAL_STATE"
				return base
			},
		},
		{
			name: "revision regression",
			preceding: func(base EdgeUpgradeStatus) []EdgeUpgradeStatus {
				return []EdgeUpgradeStatus{base, nextUpgradeStatus(base,
					"00000000-0000-4000-8000-000000000032", 2, EdgeUpgradeStateInstalling)}
			},
			candidate: func(base EdgeUpgradeStatus) EdgeUpgradeStatus {
				base.StatusID = "00000000-0000-4000-8000-000000000033"
				return base
			},
		},
		{
			name:      "revision gap",
			preceding: func(base EdgeUpgradeStatus) []EdgeUpgradeStatus { return []EdgeUpgradeStatus{base} },
			candidate: func(base EdgeUpgradeStatus) EdgeUpgradeStatus {
				return nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000033", 3, EdgeUpgradeStateInstalling)
			},
		},
		{
			name:      "claim directly to healthy",
			preceding: func(EdgeUpgradeStatus) []EdgeUpgradeStatus { return nil },
			candidate: func(base EdgeUpgradeStatus) EdgeUpgradeStatus {
				base.State = EdgeUpgradeStateHealthy
				return base
			},
		},
		{
			name: "healthy regresses to installing",
			preceding: func(base EdgeUpgradeStatus) []EdgeUpgradeStatus {
				return []EdgeUpgradeStatus{
					base,
					nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000032", 2, EdgeUpgradeStateInstalling),
					nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000033", 3, EdgeUpgradeStateHealthy),
				}
			},
			candidate: func(base EdgeUpgradeStatus) EdgeUpgradeStatus {
				base.StatusID = "00000000-0000-4000-8000-000000000034"
				base.StatusRevision = 4
				base.State = EdgeUpgradeStateInstalling
				return base
			},
		},
		{
			name: "failed is terminal",
			preceding: func(base EdgeUpgradeStatus) []EdgeUpgradeStatus {
				return []EdgeUpgradeStatus{
					base,
					nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000032", 2, EdgeUpgradeStateInstalling),
					nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000033", 3, EdgeUpgradeStateFailed),
				}
			},
			candidate: func(base EdgeUpgradeStatus) EdgeUpgradeStatus {
				return nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000034", 4, EdgeUpgradeStateRollingBack)
			},
		},
		{
			name: "rolled back is terminal",
			preceding: func(base EdgeUpgradeStatus) []EdgeUpgradeStatus {
				return []EdgeUpgradeStatus{
					base,
					nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000032", 2, EdgeUpgradeStateInstalling),
					nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000033", 3, EdgeUpgradeStateRollingBack),
					nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000034", 4, EdgeUpgradeStateRolledBack),
				}
			},
			candidate: func(base EdgeUpgradeStatus) EdgeUpgradeStatus {
				return nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000035", 5, EdgeUpgradeStateInstalling)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, base := newClaimedUpgradeStatusStore(t, filepath.Join(t.TempDir(), "updater"))
			for _, status := range test.preceding(base) {
				wire, _ := json.Marshal(status)
				if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
					t.Fatalf("enqueue preceding status: %v", err)
				}
			}
			candidateWire, _ := json.Marshal(test.candidate(base))
			if _, err := store.EnqueueStatus(context.Background(), candidateWire); !errors.Is(err, ErrUpgradeStatusConflict) && !errors.Is(err, ErrInvalidUpgradeStatus) {
				t.Fatalf("invalid status revision/state transition was accepted: %v", err)
			}
		})
	}
}

func TestUpgradeStatusLegalProgressionIntegration(t *testing.T) {
	store, base := newClaimedUpgradeStatusStore(t, filepath.Join(t.TempDir(), "updater"))
	statuses := []EdgeUpgradeStatus{
		base,
		nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000032", 2, EdgeUpgradeStateInstalling),
		nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000033", 3, EdgeUpgradeStateHealthy),
	}
	for _, status := range statuses {
		wire, _ := json.Marshal(status)
		if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
			t.Fatalf("enqueue %s: %v", status.State, err)
		}
	}
}

func TestUpgradeStatusHeadSurvivesAcknowledgementAndRestartIntegrationRED(t *testing.T) {
	root := filepath.Join(t.TempDir(), "updater")
	store, base := newClaimedUpgradeStatusStore(t, root)
	for _, status := range []EdgeUpgradeStatus{
		base,
		nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000032", 2, EdgeUpgradeStateInstalling),
	} {
		wire, _ := json.Marshal(status)
		queued, err := store.EnqueueStatus(context.Background(), wire)
		if err != nil {
			t.Fatal(err)
		}
		if acknowledged, err := store.AcknowledgeStatus(context.Background(), status.StatusID, queued.SHA256); err != nil || !acknowledged {
			t.Fatalf("acknowledge %s = (%t, %v)", status.State, acknowledged, err)
		}
		store, err = NewDurableUpgradeStore(root)
		if err != nil {
			t.Fatal(err)
		}
	}
	gap := nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000034", 4, EdgeUpgradeStateHealthy)
	wire, _ := json.Marshal(gap)
	if _, err := store.EnqueueStatus(context.Background(), wire); !errors.Is(err, ErrUpgradeStatusConflict) {
		t.Fatalf("gap after acknowledged restart error = %v", err)
	}
}

func TestAcknowledgedStatusPayloadIsImmutableLedgerIntegrationRED(t *testing.T) {
	acknowledge := func(t *testing.T, store *DurableUpgradeStore, status EdgeUpgradeStatus) {
		t.Helper()
		wire, _ := json.Marshal(status)
		queued, err := store.EnqueueStatus(context.Background(), wire)
		if err != nil {
			t.Fatal(err)
		}
		if acknowledged, err := store.AcknowledgeStatus(context.Background(), status.StatusID, queued.SHA256); err != nil || !acknowledged {
			t.Fatalf("AcknowledgeStatus() = (%t, %v)", acknowledged, err)
		}
	}
	replayRevisionOne := func(t *testing.T, store *DurableUpgradeStore, base EdgeUpgradeStatus) {
		t.Helper()
		base.StatusID = "00000000-0000-4000-8000-000000000032"
		wire, _ := json.Marshal(base)
		if _, err := store.EnqueueStatus(context.Background(), wire); !errors.Is(err, ErrUpgradeStatusConflict) &&
			!errors.Is(err, ErrCorruptState) && !errors.Is(err, ErrInvalidUpgradeStatus) {
			t.Fatalf("acknowledged revision replay error = %v", err)
		}
	}

	t.Run("deleted ack tombstone", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "updater")
		store, base := newClaimedUpgradeStatusStore(t, root)
		acknowledge(t, store, base)
		if err := os.Remove(store.ackPath(base.StatusID)); err != nil {
			t.Fatal(err)
		}
		restarted, err := NewDurableUpgradeStore(root)
		if err != nil {
			t.Fatal(err)
		}
		replayRevisionOne(t, restarted, base)
	})

	t.Run("ack tombstone rebound to another command", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "updater")
		store, base := newClaimedUpgradeStatusStore(t, root)
		acknowledge(t, store, base)
		var ack durableStatusAck
		found, err := readJSONFile(store.ackPath(base.StatusID), &ack)
		if err != nil || !found {
			t.Fatalf("read ack = (%t, %v)", found, err)
		}
		ack.CommandID = "00000000-0000-4000-8000-000000000099"
		if err := writeJSONAtomic(store.ackPath(base.StatusID), ack); err != nil {
			t.Fatal(err)
		}
		restarted, err := NewDurableUpgradeStore(root)
		if err != nil {
			t.Fatal(err)
		}
		if pending, err := restarted.PendingStatuses(context.Background()); !errors.Is(err, ErrCorruptState) {
			t.Errorf("rebound ack PendingStatuses() = (%#v, %v)", pending, err)
		}
		replayRevisionOne(t, restarted, base)
	})

	t.Run("exact ack hides immutable ledger", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "updater")
		store, base := newClaimedUpgradeStatusStore(t, root)
		acknowledge(t, store, base)
		restarted, err := NewDurableUpgradeStore(root)
		if err != nil {
			t.Fatal(err)
		}
		pending, err := restarted.PendingStatuses(context.Background())
		if err != nil || len(pending) != 0 {
			t.Fatalf("PendingStatuses() = (%#v, %v)", pending, err)
		}
		replayRevisionOne(t, restarted, base)
	})
}

func TestOrphanAcknowledgementFailsClosedIntegrationRED(t *testing.T) {
	root := filepath.Join(t.TempDir(), "updater")
	store, base := newClaimedUpgradeStatusStore(t, root)
	wire, _ := json.Marshal(base)
	queued, err := store.EnqueueStatus(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	if acknowledged, err := store.AcknowledgeStatus(context.Background(), base.StatusID, queued.SHA256); err != nil || !acknowledged {
		t.Fatalf("AcknowledgeStatus() = (%t, %v)", acknowledged, err)
	}
	if err := os.Remove(store.statusPath(base.StatusID)); err != nil {
		t.Fatal(err)
	}
	if err := syncDirectory(store.outboxDir); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewDurableUpgradeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := restarted.EnqueueStatus(context.Background(), wire); !errors.Is(err, ErrCorruptState) {
		t.Errorf("orphan ack exact EnqueueStatus() = (%#v, %v)", result, err)
	}
	if pending, err := restarted.PendingStatuses(context.Background()); !errors.Is(err, ErrCorruptState) {
		t.Errorf("orphan ack PendingStatuses() = (%#v, %v)", pending, err)
	}
	replay := base
	replay.StatusID = "00000000-0000-4000-8000-000000000032"
	replayWire, _ := json.Marshal(replay)
	if _, err := restarted.EnqueueStatus(context.Background(), replayWire); !errors.Is(err, ErrCorruptState) &&
		!errors.Is(err, ErrUpgradeStatusConflict) && !errors.Is(err, ErrInvalidUpgradeStatus) {
		t.Errorf("orphan ack revision replay error = %v", err)
	}
	if _, err := os.Stat(restarted.statusPath(replay.StatusID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("revision replay was written before failure: %v", err)
	}
}

func TestUncertainStatusRequiresExplicitQueryReconciliationIntegrationRED(t *testing.T) {
	setup := func(t *testing.T, transactionID string) (*DurableUpgradeStore, EdgeUpgradeStatus) {
		t.Helper()
		store, base := newClaimedUpgradeStatusStore(t, filepath.Join(t.TempDir(), "updater"))
		installing := nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000032", 2, EdgeUpgradeStateInstalling)
		installing.InstallerTransactionID = transactionID
		uncertain := nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000033", 3, EdgeUpgradeStateUncertain)
		uncertain.InstallerTransactionID = transactionID
		uncertain.ErrorCode = "INSTALLER_OUTCOME_UNKNOWN"
		uncertain.AlertRequired = true
		for _, status := range []EdgeUpgradeStatus{base, installing, uncertain} {
			wire, _ := json.Marshal(status)
			if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
				t.Fatalf("enqueue %s: %v", status.State, err)
			}
		}
		return store, uncertain
	}

	t.Run("no uncertain head", func(t *testing.T) {
		store, base := newClaimedUpgradeStatusStore(t, filepath.Join(t.TempDir(), "updater"))
		wire, _ := json.Marshal(nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000032", 2, EdgeUpgradeStateHealthy))
		if _, err := store.ReconcileStatus(context.Background(), wire); !errors.Is(err, ErrUpgradeStatusConflict) {
			t.Fatalf("reconcile without uncertain head error = %v", err)
		}
	})

	for _, test := range []struct {
		name   string
		txn    string
		mutate func(*EdgeUpgradeStatus)
	}{
		{name: "empty transaction", txn: ""},
		{name: "transaction mismatch", txn: "txn-query-1", mutate: func(status *EdgeUpgradeStatus) {
			status.InstallerTransactionID = "txn-query-2"
		}},
		{name: "rolling back is not query result", txn: "txn-query-1", mutate: func(status *EdgeUpgradeStatus) {
			status.State = EdgeUpgradeStateRollingBack
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			transactionID := test.txn
			if transactionID == "" {
				transactionID = "txn-query-1"
			}
			store, uncertain := setup(t, transactionID)
			candidate := nextUpgradeStatus(uncertain, "00000000-0000-4000-8000-000000000034", 4, EdgeUpgradeStateHealthy)
			if test.txn == "" {
				candidate.InstallerTransactionID = ""
			}
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			wire, _ := json.Marshal(candidate)
			if _, err := store.ReconcileStatus(context.Background(), wire); !errors.Is(err, ErrUpgradeStatusConflict) &&
				!errors.Is(err, ErrInvalidUpgradeStatus) {
				t.Fatalf("invalid reconciliation error = %v", err)
			}
		})
	}

	t.Run("normal enqueue cannot reconcile", func(t *testing.T) {
		store, uncertain := setup(t, "txn-query-1")
		candidate := nextUpgradeStatus(uncertain, "00000000-0000-4000-8000-000000000034", 4, EdgeUpgradeStateHealthy)
		wire, _ := json.Marshal(candidate)
		if _, err := store.EnqueueStatus(context.Background(), wire); !errors.Is(err, ErrUpgradeStatusConflict) {
			t.Fatalf("normal enqueue reconciliation error = %v", err)
		}
	})

	t.Run("query result and exact replay", func(t *testing.T) {
		store, uncertain := setup(t, "txn-query-1")
		candidate := nextUpgradeStatus(uncertain, "00000000-0000-4000-8000-000000000034", 4, EdgeUpgradeStateHealthy)
		wire, _ := json.Marshal(candidate)
		queued, err := store.ReconcileStatus(context.Background(), wire)
		if err != nil || queued.Duplicate {
			t.Fatalf("ReconcileStatus() = (%#v, %v)", queued, err)
		}
		duplicate, err := store.ReconcileStatus(context.Background(), wire)
		if err != nil || !duplicate.Duplicate {
			t.Fatalf("duplicate ReconcileStatus() = (%#v, %v)", duplicate, err)
		}
		candidate.AlertRequired = !candidate.AlertRequired
		changed, _ := json.Marshal(candidate)
		if _, err := store.ReconcileStatus(context.Background(), changed); !errors.Is(err, ErrUpgradeStatusConflict) &&
			!errors.Is(err, ErrInvalidUpgradeStatus) {
			t.Fatalf("changed reconciliation error = %v", err)
		}
	})
}

func TestRollbackCommandRequiresMatchingSignedExecutionContract(t *testing.T) {
	rollback := newRollbackExecutionFixture(t)
	store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, rollback))
	if err != nil {
		t.Fatalf("AcceptCommand(rollback) error = %v", err)
	}
	claimed, err := store.ClaimCommand(context.Background(), rollback.execution.CommandID, rollback.options())
	if err != nil {
		t.Fatalf("ClaimCommand(rollback) error = %v", err)
	}
	if accepted.Command.Action != string(ActionRollback) || claimed.Plan.Action != ActionRollback ||
		claimed.Plan.ReleaseSequence != rollback.execution.ReleaseSequence ||
		claimed.Plan.CurrentVersion != "2.0.0" || claimed.Plan.TargetVersion != "1.0.0" {
		t.Fatalf("rollback binding = (%#v, %#v)", accepted.Command, claimed.Plan)
	}

	t.Run("reused upgrade execution", func(t *testing.T) {
		upgrade := newExecutionV2Fixture(t)
		var command EdgeUpgradeCommand
		if err := json.Unmarshal(encodeUpgradeCommandFixture(t, upgrade), &command); err != nil {
			t.Fatal(err)
		}
		command.Action = string(ActionRollback)
		wire, _ := json.Marshal(command)
		candidate, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := candidate.AcceptCommand(context.Background(), wire); !errors.Is(err, ErrInvalidUpgradeCommand) {
			t.Fatalf("reused upgrade execution error = %v", err)
		}
	})

	t.Run("rollback direction", func(t *testing.T) {
		invalid := newRollbackExecutionFixture(t)
		invalid.execution.CurrentVersion = "1.0.0"
		invalid.execution.TargetVersion = "2.0.0"
		resignExecutionFixture(t, &invalid)
		candidate, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := candidate.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, invalid)); !errors.Is(err, ErrInvalidUpgradeCommand) {
			t.Fatalf("ascending rollback error = %v", err)
		}
	})

	t.Run("release sequence", func(t *testing.T) {
		invalid := newRollbackExecutionFixture(t)
		invalid.execution.ReleaseSequence = 0
		resignExecutionFixture(t, &invalid)
		var command EdgeUpgradeCommand
		if err := json.Unmarshal(encodeUpgradeCommandFixture(t, invalid), &command); err != nil {
			t.Fatal(err)
		}
		command.PlanRevision = 1
		wire, _ := json.Marshal(command)
		candidate, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := candidate.AcceptCommand(context.Background(), wire); !errors.Is(err, ErrInvalidUpgradeCommand) {
			t.Fatalf("zero release sequence error = %v", err)
		}
	})
}

func TestEdgeUpgradeStatusV1CanonicalFieldSetContract(t *testing.T) {
	store, status := newClaimedUpgradeStatusStore(t, filepath.Join(t.TempDir(), "updater"))
	_ = store
	status.State = EdgeUpgradeStateFailed
	status.PreviousVersion = "0.9.0"
	status.InstallerTransactionID = "txn-status-contract-1"
	status.ErrorCode = "STATUS_CONTRACT"
	status.AlertRequired = true
	wire, _ := json.Marshal(status)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{}{
		"schema": {}, "status_id": {}, "status_revision": {}, "command_id": {}, "plan_id": {},
		"plan_revision": {}, "installation_id": {}, "node_id": {}, "command_sha256": {}, "state": {},
		"current_version": {}, "previous_version": {}, "installer_transaction_id": {}, "error_code": {},
		"alert_required": {}, "observed_at": {},
	}
	if len(fields) != len(want) {
		t.Fatalf("status fields = %v, want exactly %v", fields, want)
	}
	for name := range want {
		if _, found := fields[name]; !found {
			t.Fatalf("status field %q missing", name)
		}
	}
	if _, found := fields["batch_id"]; found {
		t.Fatal("status unexpectedly includes batch_id")
	}
	if _, found := fields["action"]; found {
		t.Fatal("status unexpectedly includes action")
	}
	decoded, err := decodeEdgeUpgradeStatus(wire)
	if err != nil || decoded.CurrentVersion != status.CurrentVersion || decoded.PreviousVersion != status.PreviousVersion ||
		decoded.InstallerTransactionID != status.InstallerTransactionID || decoded.ErrorCode != status.ErrorCode ||
		decoded.AlertRequired != status.AlertRequired {
		t.Fatalf("decoded status = (%#v, %v)", decoded, err)
	}
	for _, field := range []string{"batch_id", "action"} {
		fields[field] = json.RawMessage(`"unexpected"`)
		changed, _ := json.Marshal(fields)
		if _, err := decodeEdgeUpgradeStatus(changed); !errors.Is(err, ErrInvalidUpgradeStatus) {
			t.Fatalf("extra %s error = %v", field, err)
		}
		delete(fields, field)
	}
}

func TestStatusProgressionIsActionIndependentContract(t *testing.T) {
	for _, test := range []struct {
		name    string
		fixture func(*testing.T) executionFixture
	}{
		{name: "upgrade", fixture: newExecutionV2Fixture},
		{name: "rollback", fixture: newRollbackExecutionFixture},
	} {
		t.Run(test.name+" rollback progression", func(t *testing.T) {
			fixture := test.fixture(t)
			store, base := newClaimedUpgradeStatusStoreForFixture(t, filepath.Join(t.TempDir(), "updater"), fixture)
			installing := nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000032", 2, EdgeUpgradeStateInstalling)
			installing.InstallerTransactionID = "txn-action-contract-1"
			statuses := []EdgeUpgradeStatus{base, installing}
			if fixture.execution.Operation == string(ActionUpgrade) {
				rollingBack := nextUpgradeStatus(installing, "00000000-0000-4000-8000-000000000033", 3, EdgeUpgradeStateRollingBack)
				statuses = append(statuses, rollingBack,
					nextUpgradeStatus(rollingBack, "00000000-0000-4000-8000-000000000034", 4, EdgeUpgradeStateRolledBack))
			} else {
				rolledBack := nextUpgradeStatus(installing, "00000000-0000-4000-8000-000000000033", 3, EdgeUpgradeStateRolledBack)
				rolledBack.CurrentVersion = fixture.execution.TargetVersion
				rolledBack.PreviousVersion = fixture.execution.CurrentVersion
				rolledBack.ErrorCode = ""
				statuses = append(statuses, rolledBack)
			}
			for _, status := range statuses {
				wire, _ := json.Marshal(status)
				if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
					t.Fatalf("enqueue %s: %v", status.State, err)
				}
			}
		})

		t.Run(test.name+" uncertain reconciliation", func(t *testing.T) {
			fixture := test.fixture(t)
			store, base := newClaimedUpgradeStatusStoreForFixture(t, filepath.Join(t.TempDir(), "updater"), fixture)
			installing := nextUpgradeStatus(base, "00000000-0000-4000-8000-000000000032", 2, EdgeUpgradeStateInstalling)
			installing.InstallerTransactionID = "txn-action-contract-2"
			uncertain := nextUpgradeStatus(installing, "00000000-0000-4000-8000-000000000033", 3, EdgeUpgradeStateUncertain)
			uncertain.ErrorCode = "INSTALLER_OUTCOME_UNKNOWN"
			uncertain.AlertRequired = true
			for _, status := range []EdgeUpgradeStatus{base, installing, uncertain} {
				wire, _ := json.Marshal(status)
				if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
					t.Fatalf("enqueue %s: %v", status.State, err)
				}
			}
			reconciled := nextUpgradeStatus(uncertain, "00000000-0000-4000-8000-000000000034", 4, EdgeUpgradeStateRolledBack)
			if fixture.execution.Operation == string(ActionRollback) {
				reconciled.CurrentVersion = fixture.execution.TargetVersion
				reconciled.PreviousVersion = fixture.execution.CurrentVersion
				reconciled.ErrorCode = ""
			}
			wire, _ := json.Marshal(reconciled)
			if _, err := store.ReconcileStatus(context.Background(), wire); err != nil {
				t.Fatalf("ReconcileStatus() error = %v", err)
			}
		})
	}
}

func TestOuterRolloutMetadataRequiresSignedCommitmentIntegration(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	encoded := encodeUpgradeCommandFixture(t, fixture)
	for _, test := range []struct {
		name   string
		mutate func(*EdgeUpgradeCommand)
	}{
		{name: "plan id", mutate: func(command *EdgeUpgradeCommand) {
			command.PlanID = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "plan revision", mutate: func(command *EdgeUpgradeCommand) { command.PlanRevision++ }},
		{name: "batch id", mutate: func(command *EdgeUpgradeCommand) { command.BatchID = "fixed-batch-999" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var command EdgeUpgradeCommand
			if err := json.Unmarshal(encoded, &command); err != nil {
				t.Fatal(err)
			}
			test.mutate(&command)
			changed, _ := json.Marshal(command)
			store, err := NewDurableUpgradeStore(filepath.Join(t.TempDir(), "updater"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.AcceptCommand(context.Background(), changed); !errors.Is(err, ErrInvalidUpgradeCommand) {
				t.Fatalf("unsigned outer rollout metadata mutation was accepted: %v", err)
			}
		})
	}
}

func TestDurableUpgradeStoreOperationsRejectReplacedWireDirectoryIntegrationRED(t *testing.T) {
	operations := []struct {
		name string
		run  func(*testing.T, *DurableUpgradeStore, EdgeUpgradeStatus) error
	}{
		{name: "AcceptCommand", run: func(t *testing.T, store *DurableUpgradeStore, _ EdgeUpgradeStatus) error {
			fixture := newExecutionV2Fixture(t)
			_, err := store.AcceptCommand(context.Background(), encodeUpgradeCommandFixture(t, fixture))
			return err
		}},
		{name: "PendingCommands", run: func(_ *testing.T, store *DurableUpgradeStore, _ EdgeUpgradeStatus) error {
			_, err := store.PendingCommands(context.Background())
			return err
		}},
		{name: "ClaimCommand", run: func(t *testing.T, store *DurableUpgradeStore, base EdgeUpgradeStatus) error {
			fixture := newExecutionV2Fixture(t)
			_, err := store.ClaimCommand(context.Background(), base.CommandID, fixture.options())
			return err
		}},
		{name: "ResumeClaimedCommand", run: func(t *testing.T, store *DurableUpgradeStore, base EdgeUpgradeStatus) error {
			fixture := newExecutionV2Fixture(t)
			_, err := store.ResumeClaimedCommand(context.Background(), base.CommandID, fixture.options())
			return err
		}},
		{name: "ClaimedCommands", run: func(_ *testing.T, store *DurableUpgradeStore, _ EdgeUpgradeStatus) error {
			_, err := store.ClaimedCommands(context.Background())
			return err
		}},
		{name: "EnqueueStatus", run: func(t *testing.T, store *DurableUpgradeStore, base EdgeUpgradeStatus) error {
			status := nextUpgradeStatus(base, "", 2, EdgeUpgradeStateInstalling)
			wire, err := json.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.EnqueueStatus(context.Background(), wire)
			return err
		}},
		{name: "ReconcileStatus", run: func(t *testing.T, store *DurableUpgradeStore, base EdgeUpgradeStatus) error {
			status := nextUpgradeStatus(base, "", base.StatusRevision+1, EdgeUpgradeStateFailed)
			wire, err := json.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.ReconcileStatus(context.Background(), wire)
			return err
		}},
		{name: "PendingStatuses", run: func(_ *testing.T, store *DurableUpgradeStore, _ EdgeUpgradeStatus) error {
			_, err := store.PendingStatuses(context.Background())
			return err
		}},
		{name: "AcknowledgeStatus", run: func(t *testing.T, store *DurableUpgradeStore, base EdgeUpgradeStatus) error {
			wire, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.AcknowledgeStatus(context.Background(), base.StatusID, sha256String(wire))
			return err
		}},
		{name: "LastStatus", run: func(_ *testing.T, store *DurableUpgradeStore, base EdgeUpgradeStatus) error {
			_, _, err := store.LastStatus(context.Background(), base.CommandID)
			return err
		}},
	}

	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "updater")
			store, base := newClaimedUpgradeStatusStore(t, root)
			wire, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
				t.Fatal(err)
			}
			if operation.name == "ReconcileStatus" {
				installing := nextUpgradeStatus(base, "", 2, EdgeUpgradeStateInstalling)
				wire, err := json.Marshal(installing)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
					t.Fatal(err)
				}
				uncertain := nextUpgradeStatus(installing, "", 3, EdgeUpgradeStateUncertain)
				uncertain.ErrorCode = "INSTALLER_OUTCOME_UNKNOWN"
				uncertain.AlertRequired = true
				wire, err = json.Marshal(uncertain)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.EnqueueStatus(context.Background(), wire); err != nil {
					t.Fatal(err)
				}
				base = uncertain
			}
			replacement := store.wireDir + "-original"
			if err := os.Rename(store.wireDir, replacement); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(replacement, store.wireDir); err != nil {
				t.Fatal(err)
			}
			if err := operation.run(t, store, base); !errors.Is(err, ErrCorruptState) && !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("operation accepted replaced wire directory: %v", err)
			}
		})
	}
}

func TestDurableUpgradeStoreRejectsReplacedDurablePathChainIntegrationRED(t *testing.T) {
	for _, test := range []struct {
		name    string
		path    func(string, *DurableUpgradeStore) string
		symlink bool
	}{
		{name: "root symlink", path: func(root string, _ *DurableUpgradeStore) string { return root }, symlink: true},
		{name: "state inode", path: func(_ string, store *DurableUpgradeStore) string { return store.disk.stateDir }},
		{name: "lock inode", path: func(_ string, store *DurableUpgradeStore) string { return store.disk.lockPath }},
		{name: "wire inode", path: func(_ string, store *DurableUpgradeStore) string { return store.wireDir }},
		{name: "inbox symlink", path: func(_ string, store *DurableUpgradeStore) string { return store.inboxDir }, symlink: true},
		{name: "claims inode", path: func(_ string, store *DurableUpgradeStore) string { return store.claimsDir }},
		{name: "outbox symlink", path: func(_ string, store *DurableUpgradeStore) string { return store.outboxDir }, symlink: true},
		{name: "acked inode", path: func(_ string, store *DurableUpgradeStore) string { return store.ackedDir }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "updater")
			store, err := NewDurableUpgradeStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.PendingCommands(context.Background()); err != nil {
				t.Fatal(err)
			}
			path := test.path(root, store)
			replacement := path + "-original"
			if err := os.Rename(path, replacement); err != nil {
				t.Fatal(err)
			}
			if test.symlink {
				if err := os.Symlink(replacement, path); err != nil {
					t.Fatal(err)
				}
			} else {
				info, err := os.Stat(replacement)
				if err != nil {
					t.Fatal(err)
				}
				if info.IsDir() {
					err = os.Mkdir(path, 0o700)
				} else {
					err = os.WriteFile(path, nil, 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
				if path == root {
					if err := os.Mkdir(filepath.Join(path, "state"), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if path == store.disk.stateDir {
					if err := os.WriteFile(filepath.Join(path, "upgrade.lock"), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := store.PendingCommands(context.Background()); !errors.Is(err, ErrCorruptState) && !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("replaced durable path error = %v", err)
			}
		})
	}
}

func newClaimedUpgradeStatusStore(t *testing.T, root string) (*DurableUpgradeStore, EdgeUpgradeStatus) {
	t.Helper()
	fixture := newExecutionV2Fixture(t)
	store, err := NewDurableUpgradeStore(root)
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
	return store, EdgeUpgradeStatus{
		Schema: EdgeUpgradeStatusSchema, StatusID: mustUpgradeStatusID(t, fixture.execution.CommandID, 1), StatusRevision: 1,
		CommandID: fixture.execution.CommandID, PlanID: accepted.Command.PlanID,
		PlanRevision: accepted.Command.PlanRevision, InstallationID: fixture.execution.InstallationID,
		NodeID: fixture.execution.NodeID, CommandSHA256: accepted.SHA256, State: EdgeUpgradeStateClaimed,
		ObservedAt: fixture.now.Add(3),
	}
}

func nextUpgradeStatus(base EdgeUpgradeStatus, _ string, revision uint64, state EdgeUpgradeState) EdgeUpgradeStatus {
	base.StatusID, _ = upgradeStatusID(base.CommandID, revision)
	base.StatusRevision = revision
	base.State = state
	base.ObservedAt = base.ObservedAt.Add(1)
	if state != EdgeUpgradeStateAccepted && state != EdgeUpgradeStateClaimed && base.InstallerTransactionID == "" {
		base.InstallerTransactionID = "txn-status-contract"
	}
	switch state {
	case EdgeUpgradeStateInstalling:
		base.CurrentVersion, base.PreviousVersion, base.ErrorCode, base.AlertRequired = "", "", "", false
	case EdgeUpgradeStateHealthy:
		base.CurrentVersion, base.PreviousVersion, base.ErrorCode, base.AlertRequired = "2.0.0", "1.0.0", "", false
	case EdgeUpgradeStateFailed:
		base.CurrentVersion, base.PreviousVersion = "1.0.0", ""
		base.ErrorCode, base.AlertRequired = "UPGRADE_FAILED", true
	case EdgeUpgradeStateRollingBack, EdgeUpgradeStateRolledBack:
		base.CurrentVersion, base.PreviousVersion = "1.0.0", "2.0.0"
		base.ErrorCode, base.AlertRequired = "HEALTH_FAILED", false
	case EdgeUpgradeStateUncertain:
		base.CurrentVersion, base.PreviousVersion = "", ""
		base.ErrorCode, base.AlertRequired = "INSTALLER_OUTCOME_UNKNOWN", true
	}
	return base
}

func newClaimedUpgradeStatusStoreForFixture(t *testing.T, root string,
	fixture executionFixture) (*DurableUpgradeStore, EdgeUpgradeStatus) {
	t.Helper()
	store, err := NewDurableUpgradeStore(root)
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
	return store, EdgeUpgradeStatus{
		Schema: EdgeUpgradeStatusSchema, StatusID: mustUpgradeStatusID(t, fixture.execution.CommandID, 1), StatusRevision: 1,
		CommandID: fixture.execution.CommandID, PlanID: accepted.Command.PlanID,
		PlanRevision: accepted.Command.PlanRevision, InstallationID: fixture.execution.InstallationID,
		NodeID: fixture.execution.NodeID, CommandSHA256: accepted.SHA256, State: EdgeUpgradeStateClaimed,
		ObservedAt: fixture.now.Add(3),
	}
}
