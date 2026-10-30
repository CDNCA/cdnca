package securityactivation

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// rollbackFacts: the binding's latest promoted candidate (what is active),
// what was active before it, and the promoted candidate that last activated
// that (sec-rebind; read by loadRollbackFacts).
type rollbackFacts struct {
	promoted        bool
	inFlight        bool
	previousVersion int64
	previousPolicy  uuid.UUID
	target          uuid.UUID
	targetDeleted   bool
}

// rollbackAvailability decides whether the panel can roll back: to the
// library version active before the latest promotion (another library
// after a rebind, the withdrawn one after a detach). Nothing active before
// (a first binding) has nothing to restore: withdraw it instead.
func rollbackAvailability(facts rollbackFacts) RollbackAvailability {
	switch {
	case !facts.promoted:
		return RollbackAvailability{Reason: RollbackReasonNoCandidate}
	case facts.inFlight:
		return RollbackAvailability{Reason: RollbackReasonInFlight}
	case facts.previousVersion < 1 || facts.target == uuid.Nil:
		return RollbackAvailability{Reason: RollbackReasonNoPrevious}
	}
	target, policyID := facts.target, facts.previousPolicy
	result := RollbackAvailability{CandidateID: &target, PolicyID: &policyID, SourcePolicyVersion: facts.previousVersion}
	if facts.targetDeleted {
		result.Reason = RollbackReasonPolicyDeleted
		return result
	}
	result.Available = true
	return result
}

// Promotion order is candidate_source_revision: Promote CASes the scope's
// source_revision from candidate_source_revision-1 to it, so promoted
// candidates of a scope have distinct, increasing values. promoted_at can
// tie (same clock reading), and the id tie-break then picks at random.
func loadRollbackFacts(ctx context.Context, tx pgx.Tx, scopeID, bindingID uuid.UUID) (rollbackFacts, error) {
	var facts rollbackFacts
	var previousPolicy, target *uuid.UUID
	var previousVersion *int64
	var targetDeleted *bool
	err := tx.QueryRow(ctx, `WITH latest AS (
			SELECT candidate.created_at,candidate.id,publication.expected_active_policy_id,publication.expected_active_version
			FROM security_policy_activation_candidates candidate
			JOIN security_policy_publications publication
			  ON publication.tenant_scope_id=candidate.tenant_scope_id AND publication.id=candidate.last_bundle_id
			WHERE candidate.tenant_scope_id=$1 AND candidate.binding_id=$2 AND candidate.candidate_status='promoted'
			ORDER BY candidate.candidate_source_revision DESC LIMIT 1
		)
		SELECT EXISTS (SELECT 1 FROM security_policy_activation_candidates open
		         WHERE open.tenant_scope_id=$1 AND open.binding_id=$2
		           AND open.candidate_status IN ('claimed','canary','expanding','healthy')),
		       latest.expected_active_policy_id,latest.expected_active_version,target.id,target.deleted
		FROM latest
		LEFT JOIN LATERAL (
			SELECT candidate.id,policy.deleted_at IS NOT NULL AS deleted
			FROM security_policy_activation_candidates candidate
			JOIN security_policy_publications publication
			  ON publication.tenant_scope_id=candidate.tenant_scope_id AND publication.id=candidate.last_bundle_id
			JOIN security_policies policy ON policy.id=publication.policy_id
			WHERE candidate.tenant_scope_id=$1 AND candidate.binding_id=$2 AND candidate.candidate_status='promoted'
			  AND candidate.id<>latest.id AND NOT publication.detach
			  AND publication.policy_id=latest.expected_active_policy_id
			  AND publication.policy_version=latest.expected_active_version
			ORDER BY candidate.candidate_source_revision DESC LIMIT 1
		) target ON true`, scopeID, bindingID).Scan(&facts.inFlight, &previousPolicy, &previousVersion, &target, &targetDeleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return rollbackFacts{}, nil
	}
	if err != nil {
		return rollbackFacts{}, err
	}
	facts.promoted = true
	if previousPolicy != nil {
		facts.previousPolicy = *previousPolicy
	}
	if previousVersion != nil {
		facts.previousVersion = *previousVersion
	}
	if target != nil {
		facts.target = *target
	}
	facts.targetDeleted = targetDeleted != nil && *targetDeleted
	return facts, nil
}
