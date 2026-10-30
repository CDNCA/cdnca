package identityverification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const createDraftRecoveryTimeout = 2 * time.Second

type storedCase struct {
	Case
	subjectFingerprint         []byte
	legalFingerprint           []byte
	agentFingerprint           []byte
	retentionUntil             time.Time
	evidenceSettlementRequired bool
}

func (s *Service) createDraft(ctx context.Context, actor Actor, request CreateDraftRequest, digest [32]byte) (CreateDraftOutcome, error) {
	var outcome CreateDraftOutcome
	transactionPrepared := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		outcome.TransactionStarted = true
		if err := s.authorizeWrite(ctx, tx, actor, actor.TenantScopeID(), permissionSelfManage); err != nil {
			return err
		}
		outcome.AuthorizationPassed = true
		replayed, err := s.claimWrite(ctx, tx, actor, operationCreateDraft, request.IdempotencyKey, digest, &outcome.Case)
		if err != nil {
			return err
		}
		if replayed {
			if err := validateSettlementReplay(ctx, tx, actor, request, digest, outcome.Case.ID); err != nil {
				return err
			}
			transactionPrepared = true
			return nil
		}
		writeRequestID, err := loadWriteRequestID(ctx, tx, actor, operationCreateDraft,
			request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		caseID, err := s.nextID()
		if err != nil {
			return err
		}
		now := storeTime(s.now())
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_cases (
			id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,
			organization_name,legal_person_fingerprint,agent_fingerprint,agent_relationship,
			revision,created_at,state_changed_at,retention_until
		) VALUES($1,$2,$3,$4,'draft',$5,$6,$7,$8,$9,1,$10,$10,$11)`,
			caseID, actor.TenantScopeID(), actor.UserID, request.Kind, request.SubjectFingerprint,
			nullableText(request.OrganizationName), nullableBytes(request.LegalPersonFingerprint),
			nullableBytes(request.AgentFingerprint), nullableText(request.AgentRelationship), now,
			now.Add(s.retentionPeriod))
		if err != nil {
			return err
		}
		for index, material := range request.Materials {
			materialID, err := s.nextID()
			if err != nil {
				return err
			}
			envelopeHash := sha256.Sum256(material.EncryptedEnvelope)
			_, err = tx.Exec(ctx, `INSERT INTO identity_verification_materials (
				id,tenant_scope_id,case_id,ordinal,material_kind,envelope_provider,envelope_key_id,
				encrypted_envelope,envelope_sha256,object_reference,object_sha256,mime_type,size_bytes,created_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, materialID, actor.TenantScopeID(),
				caseID, index+1, material.Kind, material.EnvelopeProvider, material.EnvelopeKeyID,
				material.EncryptedEnvelope, envelopeHash[:], material.ObjectReference, material.ObjectSHA256,
				material.MIMEType, material.SizeBytes, now)
			if err != nil {
				return err
			}
		}
		if err := s.insertStateEvent(ctx, tx, actor, caseID, 1, "", StatusDraft, "case.created", now); err != nil {
			return err
		}
		stored, err := loadCase(ctx, tx, actor.TenantScopeID(), caseID, false)
		if err != nil {
			return err
		}
		outcome.Case = redactCase(stored, now)
		settlementID, err := s.nextID()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_evidence_settlements (
			id,tenant_scope_id,actor_user_id,case_id,write_request_id,operation,idempotency_key,
			request_digest,evidence_claim_digest,resolver_name,resolver_reference,state,revision,
			attempt_count,available_at,created_at,updated_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'commit_pending',1,0,$12,$12,$12)`,
			settlementID, actor.TenantScopeID(), actor.UserID, caseID, writeRequestID, operationCreateDraft,
			request.IdempotencyKey, digest[:], request.EvidenceClaimDigest[:], request.ResolverName,
			request.ResolverReference, now)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, outcome.Case, request.RequestID, operationCreateDraft, nil); err != nil {
			return err
		}
		if err := s.completeWrite(ctx, tx, actor, operationCreateDraft, request.IdempotencyKey,
			outcome.Case, now); err != nil {
			return err
		}
		transactionPrepared = true
		return nil
	})
	if err != nil {
		outcome.Case = Case{}
		outcome.SettlementBound = false
		if !transactionPrepared || commitDefinitelyRolledBack(err) {
			return outcome, fmt.Errorf("create identity verification draft: %w", mapStoreError(err))
		}
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), createDraftRecoveryTimeout)
		defer cancel()
		caseID, bindingErr := findDurableCreateBinding(recoveryCtx, s.pool, actor, request, digest)
		if bindingErr == nil {
			outcome.SettlementBound = true
		} else if !errors.Is(bindingErr, pgx.ErrNoRows) {
			return outcome, fmt.Errorf("create identity verification draft: %w", ErrCommitOutcomeUnknown)
		}
		if outcome.SettlementBound {
			recovered, recoveryErr := s.recoverCreateDraft(recoveryCtx, actor, caseID)
			if recoveryErr == nil {
				return recovered, nil
			}
		}
		return outcome, fmt.Errorf("create identity verification draft: %w", ErrCommitOutcomeUnknown)
	}
	outcome.SettlementBound = true
	return outcome, nil
}

func findDurableCreateBinding(ctx context.Context, pool *pgxpool.Pool, actor Actor,
	request CreateDraftRequest, digest [32]byte,
) (uuid.UUID, error) {
	var caseID uuid.UUID
	err := pool.QueryRow(ctx, `SELECT settlement.case_id
		FROM identity_verification_evidence_settlements settlement
		JOIN identity_verification_write_requests write_request
		  ON write_request.id=settlement.write_request_id
		 AND write_request.tenant_scope_id=settlement.tenant_scope_id
		 AND write_request.actor_user_id=settlement.actor_user_id
		 AND write_request.operation=settlement.operation
		 AND write_request.idempotency_key=settlement.idempotency_key
		 AND write_request.request_digest=settlement.request_digest
		JOIN identity_verification_cases verification_case
		  ON verification_case.tenant_scope_id=settlement.tenant_scope_id
		 AND verification_case.id=settlement.case_id
		 AND verification_case.applicant_user_id=settlement.actor_user_id
		WHERE settlement.tenant_scope_id=$1 AND settlement.actor_user_id=$2
		  AND settlement.operation=$3 AND settlement.idempotency_key=$4
		  AND settlement.request_digest=$5 AND settlement.evidence_claim_digest=$6
		  AND settlement.resolver_name=$7 AND settlement.resolver_reference=$8
		  AND verification_case.evidence_settlement_required
		  AND write_request.completed_at IS NOT NULL
		  AND write_request.response_body->>'id'=settlement.case_id::text
		  AND write_request.response_body->>'tenant_scope_id'=settlement.tenant_scope_id::text
		  AND write_request.response_body->>'applicant_user_id'=settlement.actor_user_id::text`,
		actor.TenantScopeID(), actor.UserID, operationCreateDraft, request.IdempotencyKey, digest[:],
		request.EvidenceClaimDigest[:], request.ResolverName, request.ResolverReference).Scan(&caseID)
	return caseID, err
}

func (s *Service) recoverCreateDraft(ctx context.Context, actor Actor, caseID uuid.UUID) (CreateDraftOutcome, error) {
	outcome := CreateDraftOutcome{TransactionStarted: true, SettlementBound: true}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeWrite(ctx, tx, actor, actor.TenantScopeID(), permissionSelfManage); err != nil {
			return err
		}
		outcome.AuthorizationPassed = true
		stored, err := loadCase(ctx, tx, actor.TenantScopeID(), caseID, true)
		if err != nil {
			return err
		}
		if stored.ApplicantUserID != actor.UserID {
			return ErrPermissionDenied
		}
		outcome.Case = redactCase(stored, storeTime(s.now()))
		outcome.Case.Replayed = true
		return nil
	})
	return outcome, err
}

func commitDefinitelyRolledBack(err error) bool {
	var pgErr *pgconn.PgError
	return errors.Is(err, pgx.ErrTxCommitRollback) || errors.As(err, &pgErr)
}

func (s *Service) submit(ctx context.Context, actor Actor, request MutationRequest, digest [32]byte) (Case, error) {
	var result Case
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeWrite(ctx, tx, actor, actor.TenantScopeID(), permissionSelfManage); err != nil {
			return err
		}
		replayed, err := s.claimWrite(ctx, tx, actor, operationSubmit, request.IdempotencyKey, digest, &result)
		if err != nil || replayed {
			return err
		}
		current, err := loadCaseByID(ctx, tx, request.CaseID, true)
		if err != nil {
			return err
		}
		if current.TenantScopeID != actor.TenantScopeID() || current.ApplicantUserID != actor.UserID {
			return ErrPermissionDenied
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if current.Status != StatusDraft {
			return ErrInvalidTransition
		}
		if current.evidenceSettlementRequired {
			var settled bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(
				SELECT 1 FROM identity_verification_evidence_settlements
				WHERE tenant_scope_id=$1 AND case_id=$2 AND actor_user_id=$3 AND state='settled'
			)`, actor.TenantScopeID(), current.ID, actor.UserID).Scan(&settled); err != nil {
				return err
			}
			if !settled {
				return ErrEvidenceSettlementPending
			}
		}
		if err := validateStableIdentity(ctx, tx, current, true); err != nil {
			return err
		}
		now := storeTime(s.now())
		expiresAt := now.Add(s.reviewTTL)
		submissionID, err := s.nextID()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_submissions (
			id,tenant_scope_id,case_id,applicant_user_id,case_revision,submission_digest,submitted_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, submissionID, actor.TenantScopeID(), current.ID,
			actor.UserID, current.Revision+1, digest[:], now, expiresAt)
		if err != nil {
			return err
		}
		if err := s.insertStateEvent(ctx, tx, actor, current.ID, current.Revision+1,
			StatusDraft, StatusSubmitted, "case.submitted", now); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE identity_verification_cases
			SET status='submitted',revision=revision+1,state_changed_at=$4,submitted_at=$4,expires_at=$5
			WHERE tenant_scope_id=$1 AND id=$2 AND revision=$3 AND status='draft'`,
			actor.TenantScopeID(), current.ID, current.Revision, now, expiresAt)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		stored, err := loadCase(ctx, tx, actor.TenantScopeID(), current.ID, false)
		if err != nil {
			return err
		}
		result = redactCase(stored, now)
		if err := s.appendAudit(ctx, tx, actor, result, request.RequestID, operationSubmit, nil); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operationSubmit, request.IdempotencyKey, result, now)
	})
	if err != nil {
		return Case{}, fmt.Errorf("submit identity verification: %w", mapStoreError(err))
	}
	return result, nil
}

func (s *Service) startReview(ctx context.Context, actor Actor, request MutationRequest, digest [32]byte) (Case, error) {
	var result Case
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeWrite(ctx, tx, actor, actor.TenantScopeID(), permissionRead, permissionReview); err != nil {
			return err
		}
		replayed, err := s.claimWrite(ctx, tx, actor, operationStartReview, request.IdempotencyKey, digest, &result)
		if err != nil || replayed {
			return err
		}
		current, err := loadCaseByID(ctx, tx, request.CaseID, true)
		if err != nil {
			return err
		}
		if current.TenantScopeID != actor.TenantScopeID() {
			return ErrPermissionDenied
		}
		if current.ApplicantUserID == actor.UserID {
			return ErrSelfReview
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if current.Status != StatusSubmitted {
			return ErrInvalidTransition
		}
		now := storeTime(s.now())
		if current.ExpiresAt == nil || !now.Before(*current.ExpiresAt) {
			return ErrExpired
		}
		assignmentID, err := s.nextID()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_review_assignments (
			id,tenant_scope_id,case_id,reviewer_user_id,case_revision,assigned_at
		) VALUES($1,$2,$3,$4,$5,$6)`, assignmentID, actor.TenantScopeID(), current.ID, actor.UserID,
			current.Revision+1, now)
		if err != nil {
			return err
		}
		if err := s.insertStateEvent(ctx, tx, actor, current.ID, current.Revision+1,
			StatusSubmitted, StatusReviewing, "review.started", now); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE identity_verification_cases
			SET status='reviewing',reviewer_user_id=$4,revision=revision+1,state_changed_at=$5
			WHERE tenant_scope_id=$1 AND id=$2 AND revision=$3 AND status='submitted'`,
			actor.TenantScopeID(), current.ID, current.Revision, actor.UserID, now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		stored, err := loadCase(ctx, tx, actor.TenantScopeID(), current.ID, false)
		if err != nil {
			return err
		}
		result = redactCase(stored, now)
		if err := s.appendAudit(ctx, tx, actor, result, request.RequestID, operationStartReview, nil); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operationStartReview, request.IdempotencyKey, result, now)
	})
	if err != nil {
		return Case{}, fmt.Errorf("start identity verification review: %w", mapStoreError(err))
	}
	return result, nil
}

func (s *Service) review(ctx context.Context, actor Actor, request ReviewRequest, digest [32]byte) (Case, error) {
	var result Case
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeWrite(ctx, tx, actor, actor.TenantScopeID(), permissionRead, permissionReview); err != nil {
			return err
		}
		replayed, err := s.claimWrite(ctx, tx, actor, operationReview, request.IdempotencyKey, digest, &result)
		if err != nil || replayed {
			return err
		}
		current, err := loadCaseByID(ctx, tx, request.CaseID, true)
		if err != nil {
			return err
		}
		if current.TenantScopeID != actor.TenantScopeID() {
			return ErrPermissionDenied
		}
		if current.ApplicantUserID == actor.UserID {
			return ErrSelfReview
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if current.Status != StatusReviewing {
			return ErrInvalidTransition
		}
		if current.ReviewerUserID == nil || *current.ReviewerUserID != actor.UserID {
			return ErrReviewAssignment
		}
		now := storeTime(s.now())
		if current.ExpiresAt == nil || !now.Before(*current.ExpiresAt) {
			return ErrExpired
		}
		if request.Decision == DecisionApprove {
			if err := s.bindApprovedSubject(ctx, tx, current, now); err != nil {
				return err
			}
		}
		reviewID, err := s.nextID()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_reviews (
			id,tenant_scope_id,case_id,reviewer_user_id,decision,reason_code,
			expected_revision,resulting_revision,reviewed_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, reviewID, actor.TenantScopeID(), current.ID,
			actor.UserID, request.Decision, request.ReasonCode, current.Revision, current.Revision+1, now)
		if err != nil {
			return err
		}
		if err := s.insertStateEvent(ctx, tx, actor, current.ID, current.Revision+1,
			StatusReviewing, request.Decision, "review.decided", now); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE identity_verification_cases
			SET status=$4,revision=revision+1,state_changed_at=$5,terminal_at=$5,retention_until=$6
			WHERE tenant_scope_id=$1 AND id=$2 AND revision=$3 AND status='reviewing'`,
			actor.TenantScopeID(), current.ID, current.Revision, request.Decision, now, now.Add(s.retentionPeriod))
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		stored, err := loadCase(ctx, tx, actor.TenantScopeID(), current.ID, false)
		if err != nil {
			return err
		}
		result = redactCase(stored, now)
		if err := s.appendAudit(ctx, tx, actor, result, request.RequestID, operationReview,
			map[string]any{"decision": request.Decision, "reason_code": request.ReasonCode}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operationReview, request.IdempotencyKey, result, now)
	})
	if err != nil {
		return Case{}, fmt.Errorf("review identity verification: %w", mapStoreError(err))
	}
	return result, nil
}

func (s *Service) withdraw(ctx context.Context, actor Actor, request MutationRequest, digest [32]byte) (Case, error) {
	return s.finishWithoutReview(ctx, actor, request, digest, operationWithdraw, StatusWithdrawn, false)
}

func (s *Service) expire(ctx context.Context, actor Actor, request MutationRequest, digest [32]byte) (Case, error) {
	return s.finishWithoutReview(ctx, actor, request, digest, operationExpire, StatusExpired, true)
}

func (s *Service) finishWithoutReview(ctx context.Context, actor Actor, request MutationRequest, digest [32]byte,
	operation, target string, requireExpiry bool,
) (Case, error) {
	var result Case
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeWrite(ctx, tx, actor, actor.TenantScopeID(), permissionSelfManage); err != nil {
			return err
		}
		replayed, err := s.claimWrite(ctx, tx, actor, operation, request.IdempotencyKey, digest, &result)
		if err != nil || replayed {
			return err
		}
		current, err := loadCaseByID(ctx, tx, request.CaseID, true)
		if err != nil {
			return err
		}
		if current.TenantScopeID != actor.TenantScopeID() || current.ApplicantUserID != actor.UserID {
			return ErrPermissionDenied
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		now := storeTime(s.now())
		if requireExpiry {
			if current.Status != StatusSubmitted && current.Status != StatusReviewing {
				return ErrInvalidTransition
			}
			if current.ExpiresAt == nil || now.Before(*current.ExpiresAt) {
				return ErrNotExpired
			}
		} else if current.Status != StatusDraft && current.Status != StatusSubmitted {
			return ErrInvalidTransition
		}
		if err := s.insertStateEvent(ctx, tx, actor, current.ID, current.Revision+1,
			current.Status, target, "case."+target, now); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE identity_verification_cases
			SET status=$4,revision=revision+1,state_changed_at=$5,terminal_at=$5,retention_until=$6
			WHERE tenant_scope_id=$1 AND id=$2 AND revision=$3 AND status=$7`,
			actor.TenantScopeID(), current.ID, current.Revision, target, now, now.Add(s.retentionPeriod), current.Status)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		stored, err := loadCase(ctx, tx, actor.TenantScopeID(), current.ID, false)
		if err != nil {
			return err
		}
		result = redactCase(stored, now)
		if err := s.appendAudit(ctx, tx, actor, result, request.RequestID, operation, nil); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operation, request.IdempotencyKey, result, now)
	})
	if err != nil {
		return Case{}, fmt.Errorf("%s identity verification: %w", strings.TrimPrefix(operation, "identity_verification."), mapStoreError(err))
	}
	return result, nil
}

func (s *Service) get(ctx context.Context, actor Actor, caseID uuid.UUID) (Case, error) {
	var result Case
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeWrite(ctx, tx, actor, actor.TenantScopeID(), permissionSelfManage); err != nil {
			return err
		}
		stored, err := loadCase(ctx, tx, actor.TenantScopeID(), caseID, false)
		if err != nil {
			return err
		}
		if stored.ApplicantUserID != actor.UserID {
			return ErrPermissionDenied
		}
		result = redactCase(stored, storeTime(s.now()))
		return nil
	})
	if err != nil {
		return Case{}, fmt.Errorf("get identity verification: %w", mapStoreError(err))
	}
	return result, nil
}

func (s *Service) getForReview(ctx context.Context, actor Actor, caseID uuid.UUID) (Case, error) {
	var result Case
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeWrite(ctx, tx, actor, actor.TenantScopeID(), permissionRead, permissionReview); err != nil {
			return err
		}
		stored, err := loadCase(ctx, tx, actor.TenantScopeID(), caseID, true)
		if err != nil {
			return err
		}
		result = redactCase(stored, storeTime(s.now()))
		return nil
	})
	if err != nil {
		return Case{}, fmt.Errorf("get identity verification for review: %w", mapStoreError(err))
	}
	return result, nil
}

func (s *Service) bindApprovedSubject(ctx context.Context, tx pgx.Tx, current storedCase, now time.Time) error {
	switch current.Kind {
	case KindPersonalInitial:
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_verified_persons
			WHERE tenant_scope_id=$1 AND applicant_user_id=$2)`, current.TenantScopeID,
			current.ApplicantUserID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrAlreadyVerified
		}
		_, err := tx.Exec(ctx, `INSERT INTO identity_verified_persons (
			tenant_scope_id,applicant_user_id,identity_fingerprint,initial_case_id,approved_at
		) VALUES($1,$2,$3,$4,$5)`, current.TenantScopeID, current.ApplicantUserID,
			current.subjectFingerprint, current.ID, now)
		return err
	case KindPersonalReverification:
		return validateStableIdentity(ctx, tx, current, false)
	case KindEnterprise:
		if err := validateStableIdentity(ctx, tx, current, false); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_verified_organizations
			WHERE tenant_scope_id=$1 AND subject_fingerprint=$2)`, current.TenantScopeID,
			current.subjectFingerprint).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrAlreadyVerified
		}
		_, err := tx.Exec(ctx, `INSERT INTO identity_verified_organizations (
			tenant_scope_id,subject_fingerprint,organization_name,legal_person_fingerprint,
			agent_fingerprint,agent_relationship,approved_case_id,approved_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, current.TenantScopeID, current.subjectFingerprint,
			current.OrganizationName, current.legalFingerprint, current.agentFingerprint,
			current.AgentRelationship, current.ID, now)
		return err
	default:
		return ErrInvalidTransition
	}
}

func validateStableIdentity(ctx context.Context, tx pgx.Tx, current storedCase, submitting bool) error {
	if current.Kind == KindPersonalInitial {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_verified_persons
			WHERE tenant_scope_id=$1 AND applicant_user_id=$2)`, current.TenantScopeID,
			current.ApplicantUserID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrAlreadyVerified
		}
		return nil
	}
	var approved []byte
	err := tx.QueryRow(ctx, `SELECT identity_fingerprint FROM identity_verified_persons
		WHERE tenant_scope_id=$1 AND applicant_user_id=$2`, current.TenantScopeID,
		current.ApplicantUserID).Scan(&approved)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInitialApprovalRequired
	}
	if err != nil {
		return err
	}
	expected := current.subjectFingerprint
	if current.Kind == KindEnterprise {
		expected = current.agentFingerprint
	}
	if !equalBytes(approved, expected) {
		return ErrIdentityMismatch
	}
	if submitting && current.Kind == KindEnterprise {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_verified_organizations
			WHERE tenant_scope_id=$1 AND subject_fingerprint=$2)`, current.TenantScopeID,
			current.subjectFingerprint).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrAlreadyVerified
		}
	}
	return nil
}

func (s *Service) claimWrite(ctx context.Context, tx pgx.Tx, actor Actor, operation, key string,
	digest [32]byte, replay *Case,
) (bool, error) {
	id, err := s.nextID()
	if err != nil {
		return false, err
	}
	now := storeTime(s.now())
	_, err = tx.Exec(ctx, `INSERT INTO identity_verification_write_requests (
		id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)
	ON CONFLICT (tenant_scope_id,actor_user_id,operation,idempotency_key) DO NOTHING`,
		id, actor.TenantScopeID(), actor.UserID, operation, key, digest[:], now)
	if err != nil {
		return false, err
	}
	var storedDigest, response []byte
	err = tx.QueryRow(ctx, `SELECT request_digest,response_body FROM identity_verification_write_requests
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4
		FOR UPDATE`, actor.TenantScopeID(), actor.UserID, operation, key).Scan(&storedDigest, &response)
	if err != nil {
		return false, err
	}
	if !equalBytes(storedDigest, digest[:]) {
		return false, ErrIdempotencyConflict
	}
	if response == nil {
		return false, nil
	}
	if err := json.Unmarshal(response, replay); err != nil {
		return false, err
	}
	replay.Replayed = true
	return true, nil
}

func loadWriteRequestID(ctx context.Context, tx pgx.Tx, actor Actor, operation, key string,
	digest [32]byte,
) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM identity_verification_write_requests
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND operation=$3
		  AND idempotency_key=$4 AND request_digest=$5
		FOR UPDATE`, actor.TenantScopeID(), actor.UserID, operation, key, digest[:]).Scan(&id)
	return id, err
}

func validateSettlementReplay(ctx context.Context, tx pgx.Tx, actor Actor, request CreateDraftRequest,
	digest [32]byte, caseID uuid.UUID,
) error {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1
		FROM identity_verification_evidence_settlements settlement
		JOIN identity_verification_write_requests write_request
		  ON write_request.id=settlement.write_request_id
		WHERE settlement.tenant_scope_id=$1 AND settlement.actor_user_id=$2
		  AND settlement.case_id=$3 AND settlement.operation=$4
		  AND settlement.idempotency_key=$5 AND settlement.request_digest=$6
		  AND settlement.evidence_claim_digest=$7 AND settlement.resolver_name=$8
		  AND settlement.resolver_reference=$9
		  AND write_request.completed_at IS NOT NULL
		  AND write_request.response_body->>'id'=$3::text
	)`, actor.TenantScopeID(), actor.UserID, caseID, operationCreateDraft, request.IdempotencyKey,
		digest[:], request.EvidenceClaimDigest[:], request.ResolverName, request.ResolverReference).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrIdempotencyConflict
	}
	return nil
}

func (s *Service) completeWrite(ctx context.Context, tx pgx.Tx, actor Actor, operation, key string,
	result Case, now time.Time,
) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE identity_verification_write_requests
		SET response_body=$5,completed_at=$6
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4
			AND completed_at IS NULL`, actor.TenantScopeID(), actor.UserID, operation, key, encoded, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func (s *Service) insertStateEvent(ctx context.Context, tx pgx.Tx, actor Actor, caseID uuid.UUID,
	revision int64, from, to, reason string, now time.Time,
) error {
	id, err := s.nextID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO identity_verification_state_events (
		id,tenant_scope_id,case_id,case_revision,from_status,to_status,actor_user_id,reason_code,occurred_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, actor.TenantScopeID(), caseID, revision,
		nullableText(from), to, actor.UserID, reason, now)
	return err
}

func (s *Service) appendAudit(ctx context.Context, tx pgx.Tx, actor Actor, result Case,
	requestID, action string, extra map[string]any,
) error {
	payload := map[string]any{"kind": result.Kind, "status": result.Status, "revision": result.Revision}
	for key, value := range extra {
		payload[key] = value
	}
	if actor.PlatformReviewer() {
		// 代审记管理员本人（actor_user=管理员，审计挂在被审租户 scope 下）。
		payload["actor_scope_id"] = actor.ScopeID.String()
		payload["actor_scope_kind"] = "platform"
	}
	return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.TenantScopeID(), ActorUserID: &actor.UserID,
		Action: action, ResourceType: "identity_verification_case", ResourceID: result.ID.String(),
		RequestID: requestID, Result: "success", Payload: payload})
}

func loadCaseByID(ctx context.Context, tx pgx.Tx, caseID uuid.UUID, lock bool) (storedCase, error) {
	query := caseQuery + ` WHERE verification_case.id=$1`
	if lock {
		query += ` FOR UPDATE OF verification_case`
	}
	return scanCase(tx.QueryRow(ctx, query, caseID))
}

func loadCase(ctx context.Context, tx pgx.Tx, scopeID, caseID uuid.UUID, lock bool) (storedCase, error) {
	query := caseQuery + ` WHERE verification_case.tenant_scope_id=$1 AND verification_case.id=$2`
	if lock {
		query += ` FOR UPDATE OF verification_case`
	}
	item, err := scanCase(tx.QueryRow(ctx, query, scopeID, caseID))
	if err != nil {
		return storedCase{}, err
	}
	materialQuery := `SELECT id,material_kind,envelope_provider,envelope_key_id,
		encrypted_envelope,envelope_sha256,object_reference,object_sha256,mime_type,size_bytes,created_at
		FROM identity_verification_materials WHERE tenant_scope_id=$1 AND case_id=$2 ORDER BY ordinal`
	if lock {
		materialQuery += ` FOR SHARE`
	}
	rows, err := tx.Query(ctx, materialQuery, scopeID, caseID)
	if err != nil {
		return storedCase{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var material Material
		var encryptedEnvelope, envelopeHash, objectHash []byte
		var keyID, objectReference string
		if err := rows.Scan(&material.ID, &material.Kind, &material.EnvelopeProvider, &keyID,
			&encryptedEnvelope, &envelopeHash, &objectReference, &objectHash, &material.MIMEType,
			&material.SizeBytes, &material.CreatedAt); err != nil {
			return storedCase{}, err
		}
		material.EnvelopeKeyID = maskReference(keyID)
		material.EncryptedEnvelopePresent = len(encryptedEnvelope) > 0
		material.EnvelopeSHA256Hint = fingerprintHint(envelopeHash)
		material.ObjectReference = maskReference(objectReference)
		material.ObjectSHA256Hint = fingerprintHint(objectHash)
		item.Materials = append(item.Materials, material)
	}
	return item, rows.Err()
}

const caseQuery = `SELECT verification_case.id,verification_case.tenant_scope_id,
	verification_case.applicant_user_id,verification_case.kind,verification_case.status,
	verification_case.subject_fingerprint,verification_case.organization_name,
	verification_case.legal_person_fingerprint,verification_case.agent_fingerprint,
	verification_case.agent_relationship,verification_case.reviewer_user_id,verification_case.revision,
	verification_case.created_at,verification_case.state_changed_at,verification_case.submitted_at,
	verification_case.expires_at,verification_case.terminal_at,verification_case.retention_until,
	verification_case.evidence_settlement_required,review.reason_code
	FROM identity_verification_cases verification_case
	LEFT JOIN identity_verification_reviews review
	  ON review.tenant_scope_id=verification_case.tenant_scope_id
	 AND review.case_id=verification_case.id
	 AND review.reviewer_user_id=verification_case.reviewer_user_id
	 AND review.decision=verification_case.status
	 AND review.resulting_revision=verification_case.revision`

type rowScanner interface {
	Scan(...any) error
}

func scanCase(row rowScanner) (storedCase, error) {
	var item storedCase
	var organizationName, relationship *string
	var decisionReason *string
	err := row.Scan(&item.ID, &item.TenantScopeID, &item.ApplicantUserID, &item.Kind, &item.Status,
		&item.subjectFingerprint, &organizationName, &item.legalFingerprint, &item.agentFingerprint,
		&relationship, &item.ReviewerUserID, &item.Revision, &item.CreatedAt, &item.StateChangedAt,
		&item.SubmittedAt, &item.ExpiresAt, &item.TerminalAt, &item.retentionUntil,
		&item.evidenceSettlementRequired, &decisionReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedCase{}, ErrNotFound
	}
	if err != nil {
		return storedCase{}, err
	}
	if organizationName != nil {
		item.OrganizationName = *organizationName
	}
	if relationship != nil {
		item.AgentRelationship = *relationship
	}
	if decisionReason != nil {
		item.DecisionReasonCode = *decisionReason
	}
	if !validCaseDecisionReason(item.Status, item.DecisionReasonCode) {
		return storedCase{}, ErrUnavailable
	}
	return item, nil
}

func redactCase(stored storedCase, now time.Time) Case {
	result := stored.Case
	result.SubjectFingerprintHint = fingerprintHint(stored.subjectFingerprint)
	result.LegalFingerprintHint = fingerprintHint(stored.legalFingerprint)
	result.AgentFingerprintHint = fingerprintHint(stored.agentFingerprint)
	result.Retention = retentionStatus(result.Status, stored.retentionUntil, now)
	if result.Materials == nil {
		result.Materials = []Material{}
	}
	return result
}

func retentionStatus(status string, eligibleAt, now time.Time) Retention {
	result := Retention{EligibleAt: eligibleAt, ReasonCode: "case_not_terminal"}
	if status != StatusApproved && status != StatusRejected && status != StatusWithdrawn && status != StatusExpired {
		return result
	}
	result.ReasonCode = "retention_period_active"
	if !now.Before(eligibleAt) {
		result.Eligible = true
		result.ReasonCode = "eligible_for_evidence_erasure"
	}
	return result
}

func fingerprintHint(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	encoded := hex.EncodeToString(value)
	if len(encoded) <= 12 {
		return "sha256:********"
	}
	return "sha256:********" + encoded[len(encoded)-12:]
}

func maskReference(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "********"
	}
	return "********" + value[len(value)-8:]
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func storeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func (s *Service) nextID() (uuid.UUID, error) {
	id, err := s.newID()
	if err != nil {
		return uuid.Nil, fmt.Errorf("generate identity verification ID: %w", err)
	}
	if id == uuid.Nil {
		return uuid.Nil, errors.New("generate identity verification ID: nil UUID")
	}
	return id, nil
}

func mapStoreError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "40001", "40P01", "55P03":
			return ErrUnavailable
		}
		if pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "identity_verification_one_active_personal_review_idx",
				"identity_verification_one_active_enterprise_review_idx":
				return ErrActiveReview
			case "identity_verified_persons_pkey", "identity_verified_organizations_pkey":
				return ErrAlreadyVerified
			case "identity_verification_evidence_settlements_case_key",
				"identity_verification_evidence_settlements_write_key",
				"identity_verification_evidence_resolver_reference_key":
				return ErrIdempotencyConflict
			}
		}
		if pgErr.Code == "P0001" {
			switch {
			case strings.Contains(pgErr.Message, "evidence settlement is not settled"):
				return ErrEvidenceSettlementPending
			case strings.Contains(pgErr.Message, "fingerprint mismatch"):
				return ErrIdentityMismatch
			case strings.Contains(pgErr.Message, "already approved"):
				return ErrAlreadyVerified
			}
		}
		return ErrUnavailable
	}
	for _, stable := range []error{
		ErrInvalidInput,
		ErrInvalidService,
		ErrPermissionDenied,
		ErrNotFound,
		ErrRevisionConflict,
		ErrInvalidTransition,
		ErrIdempotencyConflict,
		ErrActiveReview,
		ErrInitialApprovalRequired,
		ErrIdentityMismatch,
		ErrAlreadyVerified,
		ErrSelfReview,
		ErrReviewAssignment,
		ErrExpired,
		ErrNotExpired,
		ErrEvidenceSettlementPending,
		ErrSettlementClaimLost,
		ErrCommitOutcomeUnknown,
		ErrUnavailable,
	} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	return ErrUnavailable
}
