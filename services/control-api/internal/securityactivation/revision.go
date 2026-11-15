package securityactivation

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A candidate's release goes to its nodes with source revision N+1 long before
// promotion. The claim used to only record N+1 and leave the scope at N, so any
// edit in between advanced the scope to N+1 and published it too; the nodes,
// having accepted N+1 with the candidate's root, refused it and the edit never
// took effect (for example a quick block edit). The claim now
// takes N+1 (reserveCandidateRevision): later edits get N+2 and up, a
// publication at a reserved revision is refused (edgepublish
// publicationExistsForSourceRevision) and the automatic channel counts it as
// covered (edgeautopublish). Promote only checks the scope is still at N+1.
//
// Every advance of edge_configuration_scopes takes its row lock, and the
// claim holds it (lockActivationScope), so no writer sees N between the
// claim's read and its advance.

// reserveCandidateRevision advances the scope from revision-1 to the
// candidate's revision inside the claim (scope row locked by the caller).
func reserveCandidateRevision(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, revision int64, now time.Time) error {
	command, err := tx.Exec(ctx, `UPDATE edge_configuration_scopes SET source_revision=$2,updated_at=$3
		WHERE scope_id=$1 AND source_revision=$2::bigint-1`, scopeID, revision, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrSourceRevisionConflict
	}
	return nil
}

// recoveredRepublicationSourcePrefix names the system republication a
// recovered candidate queues (edge automatic requests, audit).
const recoveredRepublicationSourcePrefix = "security-activation-recovered/"

// republishRecoveredScopeTx sends the scope out once more after candidate's
// nodes went back to the release they ran before it, unless a publication
// newer than the candidate's revision already did: the scope's rows may hold
// edits whose own publication the reserved revision superseded, or (before
// migration 669) a publication that took the candidate's revision and the
// nodes refused. It goes through the system republication channel as a
// failed sync retry (node_sync), once per candidate (the 669 table). A
// refused republication (a suspended policy actor) never fails the
// recovery: it is rolled back to a savepoint, logged, and left to
// republishCollidedScopes on the next start.
func republishRecoveredScopeTx(ctx context.Context, tx pgx.Tx, candidate Candidate, now time.Time) error {
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	queued, err := queueRecoveredRepublicationTx(ctx, savepoint, candidate, now)
	if err != nil {
		_ = savepoint.Rollback(ctx)
		slog.Error("security activation recovery republication not queued", "candidate_id", candidate.ID,
			"tenant_scope_id", candidate.TenantScopeID, "error", err)
		return nil
	}
	if err := savepoint.Commit(ctx); err != nil {
		return err
	}
	if queued {
		slog.Info("security activation recovery republication queued", "candidate_id", candidate.ID,
			"tenant_scope_id", candidate.TenantScopeID, "candidate_source_revision", candidate.CandidateSourceRevision)
	}
	return nil
}

func queueRecoveredRepublicationTx(ctx context.Context, tx pgx.Tx, candidate Candidate, now time.Time) (bool, error) {
	var current int64
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
		candidate.TenantScopeID).Scan(&current); errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	var marked bool
	if err := tx.QueryRow(ctx, `WITH marked AS (
		INSERT INTO security_activation_recovery_republications_669(candidate_id,tenant_scope_id,source_revision,created_at)
		SELECT $1,$2,$3,$4 WHERE NOT EXISTS (
		  SELECT 1 FROM edge_config_publications publication
		  WHERE publication.configuration_scope_id=$2 AND publication.contract_version=1
		    AND publication.source_revision>$3)
		ON CONFLICT (candidate_id) DO NOTHING RETURNING 1)
		SELECT EXISTS(SELECT 1 FROM marked)`, candidate.ID, candidate.TenantScopeID,
		candidate.CandidateSourceRevision, now).Scan(&marked); err != nil {
		return false, err
	}
	if !marked {
		return false, nil
	}
	// One publication per revision: the republication takes its own.
	if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, candidate.TenantScopeID); err != nil {
		return false, err
	}
	_, err := edgeautopublish.RequestRepublicationTx(ctx, tx, edgeautopublish.RepublishRequest{
		ScopeID: candidate.TenantScopeID, Trigger: edgepublish.SystemTriggerNodeSync, SourceResourceID: candidate.SiteID,
		SourceRequestID: recoveredRepublicationSourcePrefix + candidate.ID.String(), FromRevision: current, Immediate: true,
	})
	return err == nil, err
}

// republishCollidedScopes heals scopes whose revision a publication took
// before migration 669 while a candidate held it, once the candidate is
// settled (promoted or recovered) and nothing newer was published since. A
// candidate recovered after 669 queues its own (republishRecoveredScopeTx).
// Run once when the worker starts; failures are logged, never fatal.
func (store *Store) republishCollidedScopes(ctx context.Context) {
	rows, err := store.pool.Query(ctx, `SELECT candidate.id FROM security_policy_activation_candidates candidate
		WHERE (candidate.candidate_status='promoted' OR candidate.recovered_at IS NOT NULL)
		  AND EXISTS (SELECT 1 FROM edge_config_publications publication
		    WHERE publication.configuration_scope_id=candidate.tenant_scope_id AND publication.contract_version=1
		      AND publication.source_revision=candidate.candidate_source_revision)
		  AND NOT EXISTS (SELECT 1 FROM edge_config_publications publication
		    WHERE publication.configuration_scope_id=candidate.tenant_scope_id AND publication.contract_version=1
		      AND publication.source_revision>candidate.candidate_source_revision)
		  AND NOT EXISTS (SELECT 1 FROM security_activation_recovery_republications_669 marked
		    WHERE marked.candidate_id=candidate.id)
		ORDER BY candidate.id LIMIT 100`)
	if err != nil {
		slog.Error("security activation revision collision scan failed", "error", err)
		return
	}
	candidateIDs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		slog.Error("security activation revision collision scan failed", "error", err)
		return
	}
	for _, candidateID := range candidateIDs {
		err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
			var candidate Candidate
			if err := tx.QueryRow(ctx, `SELECT tenant_scope_id,site_id,candidate_source_revision
				FROM security_policy_activation_candidates WHERE id=$1`, candidateID).
				Scan(&candidate.TenantScopeID, &candidate.SiteID, &candidate.CandidateSourceRevision); err != nil {
				return err
			}
			candidate.ID = candidateID
			queued, err := queueRecoveredRepublicationTx(ctx, tx, candidate, store.clock().UTC().Truncate(time.Microsecond))
			if err == nil && queued {
				slog.Info("security activation revision collision republication queued", "candidate_id", candidateID,
					"tenant_scope_id", candidate.TenantScopeID, "candidate_source_revision", candidate.CandidateSourceRevision)
			}
			return err
		})
		if err != nil {
			slog.Error("security activation revision collision republication failed", "candidate_id", candidateID, "error", err)
		}
	}
}
