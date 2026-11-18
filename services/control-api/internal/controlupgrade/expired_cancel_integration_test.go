//go:build integration

package controlupgrade

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A command claimed on a node whose grant expired: the agent now closes it claimed -> installing -> failed(PLAN_EXPIRED); a node that never reports again leaves
// the command claimed. Either way the paused plan must be cancellable: a command whose last status is
// terminal (healthy, failed, rolled_back) or whose grant expired more than MaxUpgradeGrantLifetime ago
// cannot be installing any more.
func TestCancelPausedRolloutAfterExpiredCommandPostgres(t *testing.T) {
	for _, test := range []struct {
		name          string
		statuses      []string
		expiredFor    time.Duration
		pausedByAgent bool
		refused       bool
	}{
		{name: "agent closed the expired claimed command as failed",
			statuses: []string{"accepted", "claimed", "installing", "failed"}, pausedByAgent: true},
		{name: "claimed and silent past the grace", statuses: []string{"accepted", "claimed"}, expiredFor: 20 * time.Minute},
		{name: "claimed and silent within the grace", statuses: []string{"accepted", "claimed"}, expiredFor: 5 * time.Minute,
			refused: true},
		{name: "installing and silent past the grace", statuses: []string{"accepted", "claimed", "installing"},
			expiredFor: 20 * time.Minute},
		{name: "installing with an unexpired grant", statuses: []string{"accepted", "claimed", "installing"}, refused: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A same-version re-release plan: no control-issued rollback, a failed node pauses the plan.
			fixture := newCreateFlowFixture(t, "1.0.27", "1.0.27", 124, 127, 0)
			created := fixture.create(t, t.Context(), fixture.request("expired-cancel"))
			fixture.start(t, created, "expired-cancel")
			command := loadLicenseProcessCommand(t, fixture.pool, created.ID, fixture.nodeID)
			claims, err := fixture.service.store.ClaimOutbox(t.Context(), "expired-cancel", time.Now(), time.Minute, 1)
			if err != nil || len(claims) != 1 {
				t.Fatalf("outbox claim = (%+v, %v)", claims, err)
			}
			if err := fixture.service.store.SettleOutbox(t.Context(), RolloutOutboxSettlement{OutboxID: command.ID,
				ClaimToken: claims[0].ClaimToken, PayloadSHA256: claims[0].Message.PayloadSHA256,
				Disposition: RolloutOutboxPublished, PublishedStream: upgradeCommandStream, PublishedSequence: 7}); err != nil {
				t.Fatal(err)
			}
			identity, err := fixture.service.ResolveStatusIdentity(t.Context(), command.ID)
			if err != nil {
				t.Fatal(err)
			}
			for index, state := range test.statuses {
				receipt := agentRolloutStatus(t, command, uint64(index+1), state, uuid.NewString(), "",
					time.Now().Add(time.Duration(index)*time.Millisecond))
				if state == "failed" {
					receipt = withAgentStatusFailure(t, receipt, "1.0.27", "PLAN_EXPIRED")
				}
				if _, err := fixture.service.RecordStatus(t.Context(), identity, receipt); err != nil {
					t.Fatalf("status %s: %v", state, err)
				}
			}
			if test.expiredFor > 0 {
				backdateCommandGrantExpiry(t, fixture, command.ID, time.Now().Add(-test.expiredFor))
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
			if test.pausedByAgent {
				var state, node string
				if err := fixture.pool.QueryRow(t.Context(), `SELECT state,
					convert_from(canonical_snapshot_bytes,'UTF8')::jsonb->'NodeStates'->>$2
					FROM control_upgrade_rollout_plans WHERE id=$1`, created.ID, fixture.nodeID).Scan(&state, &node); err != nil {
					t.Fatal(err)
				}
				if state != string(PlanPaused) || node != string(NodeFailed) {
					t.Fatalf("plan after the failed status = (%s, node %s), want (paused, failed)", state, node)
				}
			} else if paused, err := action(PlanPauseAction, "pause"); err != nil || paused.Detail.State != PlanPaused {
				t.Fatalf("pause = (%+v, %v)", paused.Detail.RolloutSummary, err)
			}
			before := revision()
			cancelled, err := action(PlanCancel, "cancel")
			if test.refused {
				if !errors.Is(err, ErrPlanCancelNodesStarted) || revision() != before {
					t.Fatalf("cancel with a possibly installing node = (%+v, %v)", cancelled.Detail.RolloutSummary, err)
				}
				assertPausedCancelRefusedBySQL(t, fixture, created.ID)
				return
			}
			if err != nil || cancelled.Detail.State != PlanCancelled || cancelled.Detail.Revision != before+1 {
				t.Fatalf("cancel paused = (%+v, %v)", cancelled.Detail.RolloutSummary, err)
			}
		})
	}
}

// withAgentStatusFailure gives a failed status the plan's current version and the agent's code.
func withAgentStatusFailure(t *testing.T, receipt RolloutStatusReceipt, currentVersion, code string) RolloutStatusReceipt {
	t.Helper()
	var payload agentRolloutStatusV1
	if err := json.Unmarshal(receipt.StatusBytes, &payload); err != nil {
		t.Fatal(err)
	}
	payload.CurrentVersion, payload.ErrorCode = currentVersion, code
	receipt.StatusBytes = mustJSONRollout(t, payload)
	receipt.StatusSHA256 = digestRolloutWireBytes(receipt.StatusBytes)
	return receipt
}

// backdateCommandGrantExpiry moves a stored command grant expiry into the past; the command row is
// otherwise immutable (migration 096), so the row triggers are bypassed for this test write only.
func backdateCommandGrantExpiry(t *testing.T, fixture createFlowFixture, commandID string, expiresAt time.Time) {
	t.Helper()
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if tag, err := tx.Exec(t.Context(), `UPDATE control_upgrade_node_commands SET command_grant_expires_at=$2
		WHERE command_id=$1`, commandID, expiresAt.UTC()); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("backdate command grant = (%v, %v)", tag, err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}
