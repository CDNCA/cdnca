//go:build integration

package controlupgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A paused plan can be cancelled while none of its nodes may be installing (no status past
// accepted, no unexpired accepted command). The plan then publishes nothing more and its node is free.
func TestCancelPausedRolloutPostgres(t *testing.T) {
	type scenario struct {
		name     string
		publish  bool
		statuses []string
		refused  bool
	}
	for _, test := range []scenario{
		{name: "command not yet published", publish: false},
		{name: "published without a status", publish: true},
		{name: "accepted and unexpired", publish: true, statuses: []string{"accepted"}, refused: true},
		{name: "claimed", publish: true, statuses: []string{"accepted", "claimed"}, refused: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCreateFlowFixture(t, "1.0.24", "1.0.27", 0, 127, 90)
			created := fixture.create(t, t.Context(), fixture.request("paused-cancel"))
			fixture.start(t, created, "paused-cancel")
			command := loadLicenseProcessCommand(t, fixture.pool, created.ID, fixture.nodeID)
			if test.publish {
				claims, err := fixture.service.store.ClaimOutbox(t.Context(), "paused-cancel", time.Now(), time.Minute, 1)
				if err != nil || len(claims) != 1 {
					t.Fatalf("outbox claim = (%+v, %v)", claims, err)
				}
				if err := fixture.service.store.SettleOutbox(t.Context(), RolloutOutboxSettlement{OutboxID: command.ID,
					ClaimToken: claims[0].ClaimToken, PayloadSHA256: claims[0].Message.PayloadSHA256,
					Disposition: RolloutOutboxPublished, PublishedStream: upgradeCommandStream, PublishedSequence: 7}); err != nil {
					t.Fatal(err)
				}
			}
			if len(test.statuses) > 0 {
				identity, err := fixture.service.ResolveStatusIdentity(t.Context(), command.ID)
				if err != nil {
					t.Fatal(err)
				}
				for index, state := range test.statuses {
					receipt := agentRolloutStatus(t, command, uint64(index+1), state, uuid.NewString(), "",
						time.Now().Add(time.Duration(index)*time.Millisecond))
					if _, err := fixture.service.RecordStatus(t.Context(), identity, receipt); err != nil {
						t.Fatalf("status %s: %v", state, err)
					}
				}
			}
			revision := func() uint64 {
				var value uint64
				if err := fixture.pool.QueryRow(t.Context(), `SELECT revision FROM control_upgrade_rollout_plans
					WHERE id=$1`, created.ID).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			action := func(operation PlanAction, label string) (RolloutWriteResult, error) {
				return fixture.service.ApplyRolloutAction(t.Context(), fixture.actor, RolloutActionRequest{
					RolloutActionBody: RolloutActionBody{ExpectedRevision: revision(), Reason: "operator_requested"},
					PlanID:            created.ID, Operation: string(operation),
					IdempotencyKey: "control-upgrade-" + label, RequestID: "control-upgrade-request-" + label})
			}
			if paused, err := action(PlanPauseAction, "pause"); err != nil || paused.Detail.State != PlanPaused {
				t.Fatalf("pause = (%+v, %v)", paused.Detail.RolloutSummary, err)
			}
			// Only a cancelled plan's published, unconfirmed command is retracted from JetStream.
			retractions := func(skip []string) []RolloutCommandRetraction {
				items, err := fixture.service.store.ListCommandRetractions(t.Context(), skip, 100)
				if err != nil {
					t.Fatal(err)
				}
				var mine []RolloutCommandRetraction
				for _, item := range items {
					if item.OutboxID == command.ID {
						mine = append(mine, item)
					}
				}
				return mine
			}
			if items := retractions(nil); len(items) != 0 {
				t.Fatalf("paused plan retractions = %+v", items)
			}
			before := revision()
			cancelled, err := action(PlanCancel, "cancel")
			if test.refused {
				if !errors.Is(err, ErrPlanCancelNodesStarted) || revision() != before {
					t.Fatalf("cancel with started node = (%+v, %v), revision %d -> %d",
						cancelled.Detail.RolloutSummary, err, before, revision())
				}
				assertPausedCancelRefusedBySQL(t, fixture, created.ID)
				return
			}
			if err != nil || cancelled.Detail.State != PlanCancelled || cancelled.Detail.Revision != before+1 {
				t.Fatalf("cancel paused = (%+v, %v)", cancelled.Detail.RolloutSummary, err)
			}
			items := retractions(nil)
			if !test.publish && len(items) != 0 || test.publish && (len(items) != 1 ||
				items[0].Stream != upgradeCommandStream || items[0].Sequence != 7 || items[0].ExpiresAt == nil) {
				t.Fatalf("cancelled plan retractions = %+v", items)
			}
			if items := retractions([]string{command.ID}); len(items) != 0 {
				t.Fatalf("retractions skipping the deleted command = %+v", items)
			}
			if claims, err := fixture.service.store.ClaimOutbox(t.Context(), "paused-cancel-after", time.Now().Add(time.Hour),
				time.Minute, 10); err != nil || len(claims) != 0 {
				t.Fatalf("cancelled plan outbox claim = (%+v, %v)", claims, err)
			}
			if _, err := action(PlanResume, "resume-cancelled"); !errors.Is(err, ErrInvalidPlanTransition) {
				t.Fatalf("resume of a cancelled plan error = %v", err)
			}
			next := fixture.create(t, t.Context(), fixture.request("after-paused-cancel"))
			if next.ID == created.ID {
				t.Fatal("create after cancel returned the cancelled plan")
			}
			// Down to 674 would leave a cancelled plan the 674 trigger cannot have produced. 676 is undone
			// first, as the migrator does (down SQL, then its schema_migrations row).
			readDown := func(name string) string {
				t.Helper()
				down, err := os.ReadFile(filepath.Join("..", "..", "migrations", name+".down.sql"))
				if err != nil {
					t.Fatal(err)
				}
				return string(down)
			}
			tx, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			if _, err := tx.Exec(t.Context(), readDown("676_upgrade_status_observed_skew")); err != nil {
				t.Fatalf("676 down: %v", err)
			}
			if _, err := tx.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=676`); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(t.Context(), readDown("675_upgrade_paused_cancel"))
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "P6752" {
				t.Fatalf("675 down with a plan cancelled while paused: %v", err)
			}
		})
	}
}

// assertPausedCancelRefusedBySQL writes the cancelled snapshot directly: migration 675 refuses it too.
func assertPausedCancelRefusedBySQL(t *testing.T, fixture createFlowFixture, planID string) {
	t.Helper()
	var snapshot, digest []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT canonical_snapshot_bytes,canonical_snapshot_sha256
		FROM control_upgrade_rollout_plans WHERE id=$1`, planID).Scan(&snapshot, &digest); err != nil {
		t.Fatal(err)
	}
	plan, _, err := decodeRolloutPlan(snapshot, digest)
	if err != nil || plan.State != PlanPaused {
		t.Fatalf("paused plan = (%s, %v)", plan.State, err)
	}
	plan.State, plan.ResumeState, plan.Revision = PlanCancelled, "", plan.Revision+1
	encoded, err := encodeRolloutValue(plan)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	_, err = tx.Exec(t.Context(), `UPDATE control_upgrade_rollout_plans SET state='cancelled',resume_state='',
		revision=$2,canonical_snapshot_bytes=$3,canonical_snapshot_sha256=$4 WHERE id=$1`,
		planID, plan.Revision, encoded, sum[:])
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P6753" {
		t.Fatalf("direct paused -> cancelled with a started node: %v", err)
	}
}

// loadLicenseProcessCommand reads the node command the plan start wrote for the node.
func loadLicenseProcessCommand(t *testing.T, pool *pgxpool.Pool, planID, nodeID string) RolloutNodeCommand {
	t.Helper()
	var command RolloutNodeCommand
	var execution int64
	if err := pool.QueryRow(t.Context(), `SELECT command_id,plan_id,plan_revision,batch_id,installation_id,node_id,
		action,signed_execution_bytes,command_grant_bytes,command_grant_expires_at,
		coalesce(command_schema,''),coalesce(execution_sequence,0) FROM control_upgrade_node_commands
		WHERE plan_id=$1 AND node_id=$2`,
		planID, nodeID).Scan(&command.ID, &command.PlanID, &command.PlanRevision, &command.BatchID,
		&command.InstallationID, &command.NodeID, &command.Action, &command.SignedExecutionBytes,
		&command.CommandGrantBytes, &command.CommandGrantExpiresAt,
		&command.CommandSchema, &execution); err != nil {
		t.Fatal(err)
	}
	command.ExecutionSequence = uint64(execution)
	command.SignedExecutionSHA256 = hex.EncodeToString(sha256Bytes(command.SignedExecutionBytes))
	return command
}
