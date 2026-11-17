//go:build integration

package controlupgrade

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// The status processor against the real 676 head. A node observed its command 27 ms before
// the outbox settlement; with the strict 105 trigger the status was NAKed forever on P9302. Now a status
// trigger refusal is stored as a rejection and terminated, while a not-yet-published command stays a
// retryable NAK with a growing delay.
func TestStatusProcessorObservedSkewAndDatabaseRefusalPostgres(t *testing.T) {
	t.Run("accepted 27ms before published_at is recorded", func(t *testing.T) {
		pool, store, command, publishedAt := seedStatusProcessorCommand(t, true)
		receipt := rolloutStatus(t, command, 1, "accepted", nodeID(951), publishedAt.Add(-27*time.Millisecond))
		delivery := statusDeliveryForReceipt(receipt, 701)
		if disposition, err := mustStatusProcessor(t, store, delivery).ProcessOnce(t.Context()); disposition != StatusDispositionAck || err != nil {
			t.Fatalf("ProcessOnce() = (%q,%v)", disposition, err)
		}
		var commandState string
		if err := pool.QueryRow(t.Context(), `SELECT command.state FROM control_upgrade_status_receipts receipt
			JOIN control_upgrade_node_commands command ON command.command_id=receipt.command_id
			WHERE receipt.status_id=$1`, receipt.StatusID).Scan(&commandState); err != nil || commandState != "acknowledged" {
			t.Fatalf("recorded status command state = %q, %v", commandState, err)
		}
		assertStatusOutcome(t, pool, delivery, 0, 0, "")
	})

	t.Run("accepted beyond the 30s skew is rejected and terminated", func(t *testing.T) {
		pool, store, command, publishedAt := seedStatusProcessorCommand(t, true)
		receipt := rolloutStatus(t, command, 1, "accepted", nodeID(952), publishedAt.Add(-31*time.Second))
		delivery := statusDeliveryForReceipt(receipt, 702)
		if disposition, err := mustStatusProcessor(t, store, delivery).ProcessOnce(t.Context()); disposition != StatusDispositionTerm || err != nil {
			t.Fatalf("ProcessOnce() = (%q,%v)", disposition, err)
		}
		assertStatusOutcome(t, pool, delivery, 0, 1, "status_rejected")
	})

	t.Run("strict 105 trigger refusal is rejected instead of redelivered", func(t *testing.T) {
		pool, store, command, publishedAt := seedStatusProcessorCommand(t, true)
		restoreStrict105StatusTrigger(t, pool)
		receipt := rolloutStatus(t, command, 1, "accepted", nodeID(953), publishedAt.Add(-27*time.Millisecond))
		delivery := statusDeliveryForReceipt(receipt, 703)
		delivery.delivered = 9
		if disposition, err := mustStatusProcessor(t, store, delivery).ProcessOnce(t.Context()); disposition != StatusDispositionTerm || err != nil {
			t.Fatalf("ProcessOnce() = (%q,%v)", disposition, err)
		}
		assertStatusOutcome(t, pool, delivery, 0, 1, "status_database_rejected")
	})

	t.Run("status for an unpublished command naks with backoff", func(t *testing.T) {
		pool, store, command, publishedAt := seedStatusProcessorCommand(t, false)
		receipt := rolloutStatus(t, command, 1, "accepted", nodeID(954), publishedAt)
		delivery := statusDeliveryForReceipt(receipt, 704)
		delivery.delivered = 3
		if disposition, err := mustStatusProcessor(t, store, delivery).ProcessOnce(t.Context()); disposition != StatusDispositionNak ||
			!errors.Is(err, ErrResourceUnavailable) {
			t.Fatalf("ProcessOnce() = (%q,%v)", disposition, err)
		}
		if delivery.nakDelay != 4*time.Second {
			t.Fatalf("nak delay = %v, want 4s", delivery.nakDelay)
		}
		assertStatusOutcome(t, pool, delivery, 1, 0, "")
	})
}

func seedStatusProcessorCommand(t *testing.T, publish bool) (*pgxpool.Pool, *Store, RolloutNodeCommand, time.Time) {
	t.Helper()
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
	if !publish {
		return pool, store, command, publishedAt
	}
	claims, err := store.ClaimOutbox(t.Context(), "status-processor-test", publishedAt, time.Minute, 1)
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
	return pool, store, command, publishedAt
}

// statusDeliveryForReceipt is the delivery the Gateway's legacy status subject produces for receipt.
func statusDeliveryForReceipt(receipt RolloutStatusReceipt, sequence uint64) *fakeStatusDelivery {
	header := nats.Header{}
	header.Set(nats.MsgIdHdr, receipt.StatusID)
	header.Set(nats.ExpectedStreamHdr, upgradeStatusStream)
	header.Set(upgradePayloadSHA256Header, rolloutWireDigest(receipt.StatusBytes))
	header.Set(upgradeMessageKeyHeader, receipt.StatusID)
	return &fakeStatusDelivery{subject: upgradeStatusSubjectPrefix + "." + receipt.NodeID, data: receipt.StatusBytes,
		header: header, stream: upgradeStatusStream, consumer: upgradeStatusConsumer, sequence: sequence, delivered: 1}
}

// restoreStrict105StatusTrigger installs the pre-676 trigger function (676 down) in this test schema.
func restoreStrict105StatusTrigger(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	down, err := os.ReadFile("../../migrations/676_upgrade_status_observed_skew.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(down), "CREATE OR REPLACE FUNCTION validate_control_upgrade_status_105()")
	if start < 0 {
		t.Fatal("676 down does not define validate_control_upgrade_status_105")
	}
	if _, err := pool.Exec(t.Context(), string(down[start:])); err != nil {
		t.Fatal(err)
	}
}

func assertStatusOutcome(t *testing.T, pool *pgxpool.Pool, delivery *fakeStatusDelivery, naks, terms int, reason string) {
	t.Helper()
	if delivery.naks != naks || delivery.terms != terms {
		t.Fatalf("naks/terms = %d/%d, want %d/%d", delivery.naks, delivery.terms, naks, terms)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var rejections int
	var stored string
	if err := pool.QueryRow(ctx, `SELECT count(*),coalesce(max(reason),'') FROM control_upgrade_status_rejections_096
		WHERE stream=$1 AND subject=$2`, upgradeStatusStream, delivery.subject).Scan(&rejections, &stored); err != nil {
		t.Fatal(err)
	}
	if want := map[bool]int{true: 1, false: 0}[reason != ""]; rejections != want || stored != reason {
		t.Fatalf("rejections = %d %q, want %d %q", rejections, stored, want, reason)
	}
	if reason == "" {
		return
	}
	var receipts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM control_upgrade_status_receipts`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("rejected status receipts = %d, %v", receipts, err)
	}
}
