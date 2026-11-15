package securityactivation

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Recovery rollback retries (migration 670). A failed recovery rollback used
// to be followed by another one on the next reconcile pass at once, without
// end. Now a candidate has at most one recovery
// rollback in flight; after a failed attempt n the next waits
// recoveryRetryDelay(n) (1, 2, 4, 8 minutes), and after maxRecoveryAttempts
// failed attempts the candidate is marked recovery failed, the platform
// administrators are notified and nothing more is sent. Rollouts written before
// 670 have no attempt row and do not count.
const (
	maxRecoveryAttempts      = 5
	recoveryRetryBase        = time.Minute
	recoveryRecipientRight   = "platform.admin"
	recoveryFailedTemplateID = "security_activation.recovery_failed.zh-cn"
)

func recoveryRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		return 0
	}
	return recoveryRetryBase << min(attempt-1, maxRecoveryAttempts-2)
}

// recoveryInFlightSQL: a recovery deployment of candidate $1 (latest attempt
// per rollout and node) that has not ended, or a superseded failure waiting
// for redelivery.
const recoveryInFlightSQL = `SELECT EXISTS(
	SELECT 1 FROM security_policy_activation_recovery_rollouts recovery
	JOIN node_deployments deployment ON deployment.rollout_id=recovery.rollout_id
	WHERE recovery.candidate_id=$1
	  AND deployment.attempt=(SELECT max(retry.attempt) FROM node_deployments retry
	      WHERE retry.rollout_id=deployment.rollout_id AND retry.node_id=deployment.node_id)
	  AND (deployment.state NOT IN ('healthy','failed','reverted','rollback_failed')
	       OR ` + edgedeployment.SupersededDeploymentSQL + `))`

// nextRecoveryAttempt decides whether createRecoveryRollouts may send a new
// recovery rollback now; it returns the attempt number to record. It marks
// the candidate recovery failed (and notifies) once the attempts are spent.
func (store *Store) nextRecoveryAttempt(ctx context.Context, tx pgx.Tx, candidate Candidate, now time.Time) (int, bool, error) {
	var failed, inFlight bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM security_activation_recovery_failures_670
		WHERE candidate_id=$1)`, candidate.ID).Scan(&failed); err != nil || failed {
		return 0, false, err
	}
	if err := tx.QueryRow(ctx, recoveryInFlightSQL, candidate.ID).Scan(&inFlight); err != nil || inFlight {
		return 0, false, err
	}
	var last int
	var ended *time.Time
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(attempt.attempt),0),max(deployment.updated_at)
		FROM security_activation_recovery_attempts_670 attempt
		LEFT JOIN node_deployments deployment ON deployment.rollout_id=attempt.rollout_id
		WHERE attempt.candidate_id=$1 AND attempt.attempt=(SELECT max(latest.attempt)
		    FROM security_activation_recovery_attempts_670 latest WHERE latest.candidate_id=$1)`,
		candidate.ID).Scan(&last, &ended); err != nil {
		return 0, false, err
	}
	if last >= maxRecoveryAttempts {
		return 0, false, store.markRecoveryFailed(ctx, tx, candidate, last, now)
	}
	if last > 0 && ended != nil && now.Before(ended.Add(recoveryRetryDelay(last))) {
		return 0, false, nil
	}
	return last + 1, true, nil
}

func recordRecoveryAttempt(ctx context.Context, tx pgx.Tx, candidateID, rolloutID uuid.UUID, attempt int, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO security_activation_recovery_attempts_670(candidate_id,rollout_id,attempt,created_at)
		VALUES($1,$2,$3,$4)`, candidateID, rolloutID, attempt, now)
	return err
}

func (store *Store) markRecoveryFailed(ctx context.Context, tx pgx.Tx, candidate Candidate, attempts int, now time.Time) error {
	command, err := tx.Exec(ctx, `INSERT INTO security_activation_recovery_failures_670(candidate_id,attempts,failed_at)
		VALUES($1,$2,$3) ON CONFLICT (candidate_id) DO NOTHING`, candidate.ID, attempts, now)
	if err != nil || command.RowsAffected() == 0 {
		return err
	}
	slog.Error("security activation recovery rollback gave up; administrators notified",
		"candidate_id", candidate.ID, "site_id", candidate.SiteID, "attempts", attempts)
	if err := store.notifyRecoveryFailed(ctx, tx, candidate, attempts, now); err != nil {
		// EnqueueTx rolled its savepoint back; the failure stays recorded.
		slog.Warn("security activation recovery failure not notified", "candidate_id", candidate.ID, "error", err)
	}
	return nil
}

func (store *Store) notifyRecoveryFailed(ctx context.Context, tx pgx.Tx, candidate Candidate, attempts int, now time.Time) error {
	if store.alerts == nil {
		return nil
	}
	var platform uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL
		ORDER BY id LIMIT 1`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	var domain string
	if err := tx.QueryRow(ctx, `SELECT domain FROM sites WHERE id=$1`, candidate.SiteID).Scan(&domain); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, platform, recoveryRecipientRight)
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	values := notification.TemplateContext{
		"site_domain":  notification.PublicValue(domain),
		"candidate_id": notification.PublicValue(candidate.ID.String()),
		"attempts":     notification.PublicValue(strconv.Itoa(attempts)),
		"occurred_at":  notification.PublicValue(now.UTC().Format(time.DateTime)),
	}
	source := "security-activation-recovery-failed/" + candidate.ID.String()
	for _, recipient := range recipients {
		if _, err := store.alerts.EnqueueTx(ctx, tx, notification.EnqueueRequest{ScopeID: platform, RecipientID: recipient,
			SourceEventID: source, EventType: notification.EventTypeSecurityActivationRecoveryFailed,
			Policy: notification.DeliverySystemRequired,
			Templates: map[notification.Channel]notification.TemplateRef{
				notification.ChannelSMS:   {ID: recoveryFailedTemplateID, Version: 1, Channel: notification.ChannelSMS},
				notification.ChannelEmail: {ID: recoveryFailedTemplateID, Version: 1, Channel: notification.ChannelEmail},
			},
			Contexts:       map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: values, notification.ChannelEmail: values},
			AuditRequestID: source,
		}); err != nil {
			return err
		}
	}
	return nil
}
