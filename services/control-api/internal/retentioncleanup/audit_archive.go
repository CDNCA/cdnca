package retentioncleanup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	// AuditArchiveAction marks each committed audit archive batch.
	AuditArchiveAction = "system_cleanup.retention.archive"
	auditTable         = "audit_events"
)

// archiveCandidatesSQL selects, after the scope's checkpoint ($2), the
// contiguous run of rows older than the advance cutoff ($3, the shortest
// category retention) that ends before the chain head. Rows of longer-lived
// categories in that run are copied too but stay in audit_events until their
// own category expires (unified-log; FX01 stopped at the first such row).
const archiveCandidatesSQL = `SELECT ` + audit.ChainColumns + `
	FROM audit_events
	WHERE scope_id = $1 AND stream_position > $2
	  AND stream_position < (SELECT max(stream_position) FROM audit_events WHERE scope_id = $1)
	  AND stream_position < COALESCE((SELECT min(stream_position) FROM audit_events
	      WHERE scope_id = $1 AND stream_position > $2 AND occurred_at >= $3::timestamptz),
	      9223372036854775807)
	ORDER BY stream_position
	LIMIT $4`

// expiredCopiedSQL deletes archived rows (at or below the checkpoint $2)
// whose own category cutoff passed and that are no longer pinned.
const expiredCopiedSQL = `DELETE FROM audit_events WHERE id IN (
	SELECT event.id FROM audit_events event
	JOIN unnest($3::text[], $4::timestamptz[]) AS cutoff(category, before) ON cutoff.category = event.category
	WHERE event.scope_id = $1 AND event.stream_position <= $2 AND cutoff.before IS NOT NULL
	  AND event.occurred_at < cutoff.before AND NOT audit_event_pinned_331(event.id)
	ORDER BY event.stream_position LIMIT $5)`

// purgeArchiveSQL drops archive copies of rows that left audit_events, except
// the checkpoint row itself (the chain resumes from its hash).
const purgeArchiveSQL = `DELETE FROM audit_event_archive archived
	WHERE archived.scope_id = $1 AND archived.stream_position < $2
	  AND NOT EXISTS (SELECT 1 FROM audit_events event WHERE event.id = archived.id)`

// archiveAudit archives every scope's expired audit prefix (FX01).
func (worker *Worker) archiveAudit(ctx context.Context) Result {
	result := Result{Table: auditTable}
	// Check the role once instead of failing per scope.
	var member bool
	if err := worker.pool.QueryRow(ctx, `SELECT CASE WHEN to_regrole($1) IS NULL THEN false
		ELSE pg_has_role(current_user, $1, 'MEMBER') END`, Role).Scan(&member); err != nil {
		result.Err = err
		return result
	}
	if !member {
		result.Err = ErrRoleUnavailable
		return result
	}
	rows, err := worker.pool.Query(ctx, `SELECT id FROM access_scopes ORDER BY id`)
	if err != nil {
		result.Err = err
		return result
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		result.Err = err
		return result
	}
	for _, scopeID := range scopes {
		for batch := 0; batch < worker.config.MaxBatches; batch++ {
			archived, deleted, err := worker.archiveAuditBatch(ctx, scopeID)
			result.Archived += archived
			result.Deleted += deleted
			if err != nil {
				result.Err = errors.Join(result.Err, fmt.Errorf("scope %s: %w", scopeID, err))
				break
			}
			if archived < int64(worker.config.BatchSize) && deleted < int64(worker.config.BatchSize) {
				break
			}
			select {
			case <-ctx.Done():
				result.Err = errors.Join(result.Err, ctx.Err())
				return result
			case <-time.After(worker.config.BatchPause):
			}
		}
	}
	return result
}

func (worker *Worker) archiveAuditBatch(ctx context.Context, scopeID uuid.UUID) (archived, deleted int64, err error) {
	err = pgx.BeginFunc(ctx, worker.pool, func(tx pgx.Tx) error {
		var locked, member bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1),
			CASE WHEN to_regrole($2) IS NULL THEN false ELSE pg_has_role(current_user, $2, 'MEMBER') END`,
			advisoryLockKey, Role).Scan(&locked, &member); err != nil {
			return err
		}
		if !member {
			return ErrRoleUnavailable
		}
		if !locked {
			return nil
		}
		days, err := LoadAuditRetention(ctx, tx)
		if err != nil {
			return err
		}
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&now); err != nil {
			return err
		}
		categories, cutoffs, advance := auditCutoffs(days, now)
		if advance == nil {
			return nil // every category keeps forever
		}
		var checkpoint int64
		var previousHash []byte
		err = tx.QueryRow(ctx, `SELECT through_position, through_hash FROM audit_chain_checkpoints
			WHERE scope_id = $1 FOR UPDATE`, scopeID).Scan(&checkpoint, &previousHash)
		hasCheckpoint := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		rows, err := tx.Query(ctx, archiveCandidatesSQL, scopeID, checkpoint, advance, worker.config.BatchSize)
		if err != nil {
			return err
		}
		candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (audit.ChainRecord, error) {
			return audit.ScanChainRecord(row)
		})
		if err != nil {
			return err
		}
		// Never archive a segment that does not verify from the checkpoint.
		for index, event := range candidates {
			if err := audit.VerifyChainRecord(event, checkpoint+int64(index)+1, previousHash); err != nil {
				return err
			}
			previousHash = event.EventHash
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+Role); err != nil {
			return err
		}
		if len(candidates) > 0 {
			last := candidates[len(candidates)-1]
			command, err := tx.Exec(ctx, `INSERT INTO audit_event_archive(`+audit.ChainCopyColumns+`)
				SELECT `+audit.ChainCopyColumns+`
				FROM audit_events WHERE scope_id = $1 AND stream_position > $2 AND stream_position <= $3`,
				scopeID, checkpoint, last.StreamPosition)
			if err != nil {
				return err
			}
			if command.RowsAffected() != int64(len(candidates)) {
				return fmt.Errorf("archived %d audit rows, want %d", command.RowsAffected(), len(candidates))
			}
			if hasCheckpoint {
				_, err = tx.Exec(ctx, `UPDATE audit_chain_checkpoints SET through_position = $2, through_hash = $3,
					updated_at = transaction_timestamp() WHERE scope_id = $1`, scopeID, last.StreamPosition, last.EventHash)
			} else {
				_, err = tx.Exec(ctx, `INSERT INTO audit_chain_checkpoints(scope_id, through_position, through_hash)
					VALUES($1, $2, $3)`, scopeID, last.StreamPosition, last.EventHash)
			}
			if err != nil {
				return err
			}
			checkpoint = last.StreamPosition
			archived = int64(len(candidates))
		}
		if checkpoint > 0 {
			// Rows at or below the checkpoint leave once their own category
			// expired; pinned rows (foreign key, head, newest of their group,
			// cache.*) stay. Then their archive copies go too.
			command, err := tx.Exec(ctx, expiredCopiedSQL, scopeID, checkpoint, categories, cutoffs, worker.config.BatchSize)
			if err != nil {
				return err
			}
			deleted = command.RowsAffected()
			if _, err := tx.Exec(ctx, purgeArchiveSQL, scopeID, checkpoint); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "RESET ROLE"); err != nil {
			return err
		}
		if archived == 0 && deleted == 0 {
			return nil
		}
		platformScope, err := platformAuditScope(ctx, tx)
		if err != nil {
			return err
		}
		return worker.auditor.Append(ctx, tx, audit.Event{
			ScopeID: platformScope, Action: AuditArchiveAction, ResourceType: "audit_chain", ResourceID: scopeID.String(),
			RequestID: "retention-" + uuid.NewString(), Result: "success",
			Payload: map[string]any{"scope_id": scopeID.String(), "through_position": checkpoint,
				"archived": archived, "deleted": deleted},
		})
	})
	if err != nil {
		return 0, 0, err
	}
	return archived, deleted, nil
}

func platformAuditScope(ctx context.Context, tx pgx.Tx) (uuid.UUID, error) {
	var scopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL
		ORDER BY created_at, id LIMIT 1`).Scan(&scopeID); err != nil {
		return uuid.Nil, fmt.Errorf("load platform audit scope: %w", err)
	}
	return scopeID, nil
}
