//go:build integration

package controlupgrade

import (
	"errors"
	"testing"
	"time"
)

func TestRolloutStatusDeliveryIdentityIsAtomicAndReplaySafe(t *testing.T) {
	pool := openRolloutPersistenceIntegrationPool(t)
	identity := seedRolloutPersistenceIdentity(t, pool)
	plan := mustRolloutPlan(t)
	insertRolloutPersistencePlan(t, pool, identity, &plan)
	store := NewStore(pool, nil, nil, time.Now)
	cause, _ := rolloutCause(t, planCommand(PlanStart, plan.Revision, "start_requested"))
	commit, err := store.TransactLocked(t.Context(), identity, plan.ID, cause,
		func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
			return rolloutStartMutation(t, locked, cause, time.Now()), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	command := commit.NodeCommands[0]
	publishedAt := time.Now().UTC().Truncate(time.Microsecond)
	claims, err := store.ClaimOutbox(t.Context(), "status-puback-test", publishedAt, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim = (%#v,%v)", claims, err)
	}
	if err := store.SettleOutbox(t.Context(), RolloutOutboxSettlement{
		OutboxID: command.ID, ClaimToken: claims[0].ClaimToken, PayloadSHA256: claims[0].Message.PayloadSHA256,
		Disposition: RolloutOutboxPublished, PublishedStream: upgradeCommandStream,
		PublishedSequence: 501, SettledAt: publishedAt,
	}); err != nil {
		t.Fatal(err)
	}

	receipt := rolloutStatus(t, command, 1, "claimed", nodeID(941), publishedAt.Add(time.Second))
	receipt.DeliveryStream = upgradeStatusStream
	receipt.DeliveryConsumer = "control_api_upgrade_status"
	receipt.DeliverySequence = 601
	if replayed, err := store.RecordStatus(t.Context(), identity, receipt); err != nil || replayed {
		t.Fatalf("initial status = (%v,%v)", replayed, err)
	}
	var stream, consumer, commandState string
	var sequence uint64
	if err := pool.QueryRow(t.Context(), `SELECT receipt.delivery_stream,receipt.delivery_consumer,
		receipt.delivery_sequence,command.state FROM control_upgrade_status_receipts receipt
		JOIN control_upgrade_node_commands command ON command.command_id=receipt.command_id
		WHERE receipt.status_id=$1`, receipt.StatusID).Scan(&stream, &consumer, &sequence, &commandState); err != nil ||
		stream != receipt.DeliveryStream || consumer != receipt.DeliveryConsumer ||
		sequence != receipt.DeliverySequence || commandState != "acknowledged" {
		t.Fatalf("atomic status broker fact = %q/%q/%d state=%q err=%v", stream, consumer, sequence, commandState, err)
	}
	if replayed, err := store.RecordStatus(t.Context(), identity, receipt); err != nil || !replayed {
		t.Fatalf("same tuple replay = (%v,%v)", replayed, err)
	}

	var auditBefore int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events`).Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RolloutStatusReceipt){
		"consumer": func(value *RolloutStatusReceipt) { value.DeliveryConsumer = "other_consumer" },
		"stream":   func(value *RolloutStatusReceipt) { value.DeliveryStream = "OTHER" },
		"sequence": func(value *RolloutStatusReceipt) { value.DeliverySequence++ },
		"command":  func(value *RolloutStatusReceipt) { value.CommandID = nodeID(942) },
		"node":     func(value *RolloutStatusReceipt) { value.NodeID = nodeID(943) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := receipt
			mutate(&candidate)
			if _, err := store.RecordStatus(t.Context(), identity, candidate); err == nil {
				t.Fatal("mismatched broker/status tuple was accepted")
			}
		})
	}
	collision := rolloutStatus(t, command, 2, "installing", nodeID(944), publishedAt.Add(2*time.Second))
	collision.DeliveryStream = receipt.DeliveryStream
	collision.DeliveryConsumer = receipt.DeliveryConsumer
	collision.DeliverySequence = receipt.DeliverySequence
	if _, err := store.RecordStatus(t.Context(), identity, collision); !errors.Is(err, ErrPlanIdempotencyConflict) {
		t.Fatalf("cross-status sequence collision = %v", err)
	}
	var receipts, auditAfter int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM control_upgrade_status_receipts WHERE plan_id=$1`, plan.ID).
		Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events`).Scan(&auditAfter); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 || auditAfter != auditBefore {
		t.Fatalf("rejected tuple durable facts receipts/audit = %d/%d, want 1/%d", receipts, auditAfter, auditBefore)
	}
}
