package firewalldispatch

import (
	"context"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitycoordmetrics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type dispatchDB interface {
	begin(context.Context) (dispatchTx, error)
}

type dispatchTx interface {
	claim(context.Context, int, time.Time) ([]claimedCommand, error)
	promoteRetryable(context.Context, uuid.UUID) error
	markPublished(context.Context, uuid.UUID, int, time.Time) error
	markFailure(context.Context, uuid.UUID, int, time.Time, string, bool, time.Time) error
	loadForStatus(context.Context, *agentv1.FirewallStatus) (claimedCommand, error)
	markAcked(context.Context, uuid.UUID, string, *agentv1.FirewallStatus, string, time.Time) (AckDisposition, error)
	commit(context.Context) error
	rollback(context.Context) error
}

type postgresDB struct{ pool *pgxpool.Pool }

func (d *postgresDB) begin(ctx context.Context) (dispatchTx, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin firewall dispatch transaction: %w", err)
	}
	return &postgresTx{tx: tx}, nil
}

type postgresTx struct {
	tx            pgx.Tx
	globalOutcome securitycoordmetrics.GlobalOutcome
}

func (t *postgresTx) securityCoordinationOutcome() securitycoordmetrics.GlobalOutcome {
	return t.globalOutcome
}

const claimSQL = `
WITH ranked AS MATERIALIZED (
    SELECT id,
           ROW_NUMBER() OVER (PARTITION BY tenant_scope_id ORDER BY available_at,id) AS tenant_rank
    FROM firewall_command_outbox outbox
    WHERE outbox.state IN ('pending','retryable') AND outbox.available_at<=$2
      -- A08: a global (host) command goes only to a node its scope owns.
      AND (outbox.policy_kind<>'global' OR EXISTS (
          SELECT 1 FROM nodes owner WHERE owner.id=outbox.node_id AND owner.scope_id=outbox.tenant_scope_id))
      AND NOT EXISTS (
		  SELECT 1 FROM firewall_command_outbox lower
		  WHERE lower.tenant_scope_id=outbox.tenant_scope_id
		    AND lower.node_id=outbox.node_id
		    AND lower.site_id=outbox.site_id AND lower.policy_kind=outbox.policy_kind AND lower.policy_id=outbox.policy_id
		    AND ((outbox.policy_kind='global' AND lower.global_revision<outbox.global_revision) OR
		         (outbox.policy_kind<>'global' AND lower.policy_version<outbox.policy_version))
            AND lower.state NOT IN ('acked','failed')
      )
)
SELECT outbox.id,outbox.installation_id,outbox.tenant_scope_id,outbox.site_id,outbox.node_id,
       outbox.policy_id,outbox.policy_kind,outbox.publication_id,COALESCE(outbox.global_revision,0),
       outbox.policy_version,outbox.expected_active_policy_version,outbox.idempotency_key,
       outbox.state,outbox.attempts,outbox.command_bytes,outbox.command_sha256
FROM firewall_command_outbox outbox
JOIN ranked ON ranked.id=outbox.id
ORDER BY ranked.tenant_rank,outbox.available_at,outbox.id
FOR UPDATE OF outbox SKIP LOCKED
LIMIT $1`

func (t *postgresTx) claim(ctx context.Context, limit int, now time.Time) ([]claimedCommand, error) {
	rows, err := t.tx.Query(ctx, claimSQL, limit, now)
	if err != nil {
		return nil, fmt.Errorf("claim firewall command facts: %w", err)
	}
	defer rows.Close()
	commands := make([]claimedCommand, 0, limit)
	for rows.Next() {
		var command claimedCommand
		var digest []byte
		if err := rows.Scan(&command.id, &command.installationID, &command.tenantScopeID, &command.siteID, &command.nodeID,
			&command.policyID, &command.policyKind, &command.publicationID, &command.globalRevision,
			&command.policyVersion, &command.expectedActiveVersion, &command.idempotencyKey, &command.state,
			&command.attempts, &command.commandBytes, &digest); err != nil {
			return nil, fmt.Errorf("scan firewall command fact: %w", err)
		}
		if len(digest) == len(command.commandSHA256) {
			copy(command.commandSHA256[:], digest)
		}
		commands = append(commands, command)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate firewall command facts: %w", err)
	}
	return commands, nil
}

func (t *postgresTx) promoteRetryable(ctx context.Context, id uuid.UUID) error {
	result, err := t.tx.Exec(ctx, `UPDATE firewall_command_outbox SET state='pending',updated_at=now()
        WHERE id=$1 AND state='retryable'`, id)
	return requireOne(result, err, "promote retryable firewall command")
}

func (t *postgresTx) markPublished(ctx context.Context, id uuid.UUID, attempts int, now time.Time) error {
	result, err := t.tx.Exec(ctx, `UPDATE firewall_command_outbox
        SET state='published',attempts=$2,published_at=$3,available_at=$3,last_error=NULL,updated_at=$3
        WHERE id=$1 AND state='pending'`, id, attempts, now)
	return requireOne(result, err, "settle published firewall command")
}

func (t *postgresTx) markFailure(ctx context.Context, id uuid.UUID, attempts int, available time.Time, code string, terminal bool, now time.Time) error {
	state := StateRetryable
	if terminal {
		state = StateFailed
		available = now
	}
	// The terminal branch binds state='failed'; dynamic binding keeps one CAS query for both dispositions.
	result, err := t.tx.Exec(ctx, `UPDATE firewall_command_outbox
        SET state=$3,attempts=$2,available_at=$4,published_at=NULL,last_error=$5,updated_at=$6
        WHERE id=$1 AND state='pending'`, id, attempts, state, available, code, now)
	if err := requireOne(result, err, "settle failed firewall command"); err != nil {
		return err
	}
	if terminal {
		return t.settleGlobalPublication(ctx, id, now)
	}
	return nil
}

func (t *postgresTx) loadForStatus(ctx context.Context, status *agentv1.FirewallStatus) (claimedCommand, error) {
	tenantID, err := uuid.Parse(status.GetTenantId())
	if err != nil || tenantID == uuid.Nil || !canonicalUUID(status.GetIdempotencyKey()) {
		return claimedCommand{}, ErrStatusConflict
	}
	var command claimedCommand
	var digest []byte
	err = t.tx.QueryRow(ctx, `SELECT id,installation_id,tenant_scope_id,site_id,node_id,policy_id,policy_kind,publication_id,
		COALESCE(global_revision,0),policy_version,
        expected_active_policy_version,idempotency_key,state,attempts,command_bytes,command_sha256
        FROM firewall_command_outbox WHERE tenant_scope_id=$1 AND idempotency_key=$2 FOR UPDATE`,
		tenantID, status.IdempotencyKey).Scan(&command.id, &command.installationID, &command.tenantScopeID,
		&command.siteID, &command.nodeID, &command.policyID, &command.policyKind, &command.publicationID,
		&command.globalRevision, &command.policyVersion, &command.expectedActiveVersion,
		&command.idempotencyKey, &command.state, &command.attempts, &command.commandBytes, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return claimedCommand{}, ErrStatusConflict
	}
	if err != nil {
		return claimedCommand{}, fmt.Errorf("load firewall command for status: %w", err)
	}
	if len(digest) == len(command.commandSHA256) {
		copy(command.commandSHA256[:], digest)
	}
	return command, nil
}

func (t *postgresTx) markAcked(ctx context.Context, id uuid.UUID, state string, status *agentv1.FirewallStatus, fingerprint string, now time.Time) (AckDisposition, error) {
	if status == nil {
		return AckRejected, ErrStatusConflict
	}
	disposition := AckSettled
	switch state {
	case StatePending:
		if err := t.promotePendingToPublished(ctx, id, true, now); err != nil {
			return AckRejected, err
		}
		disposition = AckRescued
	case StateRetryable:
		if err := t.promoteRetryable(ctx, id); err != nil {
			return AckRejected, err
		}
		if err := t.promotePendingToPublished(ctx, id, true, now); err != nil {
			return AckRejected, err
		}
		disposition = AckRescued
	case StatePublished:
	case StateAcked:
		var stored string
		if err := t.tx.QueryRow(ctx, `SELECT COALESCE(last_error,'') FROM firewall_command_outbox
            WHERE id=$1 AND state='acked' FOR UPDATE`, id).Scan(&stored); err != nil {
			return AckRejected, err
		}
		if stored != fingerprint {
			return AckRejected, ErrStatusConflict
		}
		return AckReplayed, nil
	default:
		return AckRejected, ErrStatusConflict
	}
	terminal := terminalState(status.State)
	if terminal == "" {
		return AckRejected, ErrStatusConflict
	}
	result, err := t.tx.Exec(ctx, `UPDATE firewall_command_outbox
		SET state='acked',acked_at=$2,last_error=$3,updated_at=$2,terminal_state=$4,active_policy_version=$5
		WHERE id=$1 AND state='published'`, id, now, fingerprint, terminal, status.ActivePolicyVersion)
	if err := requireOne(result, err, "settle firewall status ACK"); err != nil {
		return AckRejected, err
	}
	if err := t.settleGlobalPublication(ctx, id, now); err != nil {
		return AckRejected, err
	}
	return disposition, nil
}

func terminalState(state agentv1.FirewallStatusState) string {
	switch state {
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_APPLIED:
		return "applied"
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED:
		return "failed"
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_ROLLED_BACK:
		return "rolled_back"
	default:
		return ""
	}
}

func (t *postgresTx) settleGlobalPublication(ctx context.Context, commandID uuid.UUID, now time.Time) error {
	var publicationID uuid.UUID
	var kind string
	if err := t.tx.QueryRow(ctx, `SELECT publication_id,policy_kind FROM firewall_command_outbox WHERE id=$1`, commandID).
		Scan(&publicationID, &kind); err != nil {
		return err
	}
	if kind != "global" {
		return nil
	}
	var operation string
	var total, terminal, applied, rolledBack int64
	if err := t.tx.QueryRow(ctx, `SELECT operation FROM global_firewall_publication_outbox WHERE id=$1 FOR UPDATE`, publicationID).
		Scan(&operation); err != nil {
		return err
	}
	err := t.tx.QueryRow(ctx, `SELECT count(*),
		count(*) FILTER (WHERE command.state IN ('acked','failed')),
		count(*) FILTER (WHERE command.terminal_state='applied'),
		count(*) FILTER (WHERE command.terminal_state='rolled_back')
		FROM firewall_command_outbox command WHERE command.publication_id=$1 AND command.policy_kind='global'`, publicationID).
		Scan(&total, &terminal, &applied, &rolledBack)
	if err != nil || total == 0 || terminal != total {
		return err
	}
	state := "failed"
	switch {
	case operation == "apply" && applied == total:
		state = "active"
	case operation == "recover" && rolledBack == total:
		state = "rolled_back"
	case applied > 0 || rolledBack > 0:
		state = "partial"
	}
	result, err := t.tx.Exec(ctx, `UPDATE global_firewall_publication_outbox SET state=$2,updated_at=$3,
		last_error=CASE WHEN $2 IN ('active','rolled_back') THEN NULL ELSE 'target_terminal_failure' END
		WHERE id=$1 AND state='projected'`, publicationID, state, now)
	if err := requireOne(result, err, "settle global firewall publication"); err != nil {
		return err
	}
	if state == "active" || state == "rolled_back" {
		_, err = t.tx.Exec(ctx, `UPDATE global_firewall_policies policy SET active_revision=publication.revision,
			active_sha256=publication.document_sha256,
			deployment_state=CASE WHEN policy.revision=publication.revision THEN $2 ELSE policy.deployment_state END,
			updated_at=$3
			FROM global_firewall_publication_outbox publication
			WHERE publication.id=$1 AND policy.tenant_scope_id=publication.tenant_scope_id AND policy.id=publication.policy_id`, publicationID, state, now)
	} else {
		_, err = t.tx.Exec(ctx, `UPDATE global_firewall_policies policy SET
			deployment_state=CASE WHEN policy.revision=publication.revision THEN $2 ELSE policy.deployment_state END,
			updated_at=$3
			FROM global_firewall_publication_outbox publication
			WHERE publication.id=$1 AND policy.tenant_scope_id=publication.tenant_scope_id AND policy.id=publication.policy_id`, publicationID, state, now)
	}
	if err == nil {
		switch state {
		case "active":
			t.globalOutcome = securitycoordmetrics.GlobalActive
		case "partial":
			t.globalOutcome = securitycoordmetrics.GlobalPartial
		case "failed":
			t.globalOutcome = securitycoordmetrics.GlobalFailed
		case "rolled_back":
			t.globalOutcome = securitycoordmetrics.GlobalRolledBack
		}
	}
	return err
}

func (t *postgresTx) promotePendingToPublished(ctx context.Context, id uuid.UUID, increment bool, now time.Time) error {
	result, err := t.tx.Exec(ctx, `UPDATE firewall_command_outbox
        SET state='published',attempts=attempts+CASE WHEN $2 THEN 1 ELSE 0 END,published_at=$3,updated_at=$3
        WHERE id=$1 AND state='pending'`, id, increment, now)
	return requireOne(result, err, "rescue firewall command publication")
}

func (t *postgresTx) commit(ctx context.Context) error   { return t.tx.Commit(ctx) }
func (t *postgresTx) rollback(ctx context.Context) error { return t.tx.Rollback(ctx) }

func requireOne(result pgconnCommandTag, err error, action string) error {
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if result.RowsAffected() != 1 {
		return ErrClaimLost
	}
	return nil
}

type pgconnCommandTag interface{ RowsAffected() int64 }
