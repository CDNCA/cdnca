package rbacmanagerhttp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type stepUpTxConsumer interface {
	ConsumeStepUpTxWithScopes(context.Context, pgx.Tx, mfa.Actor, []uuid.UUID, mfa.ConsumeStepUpRequest) (mfa.Evidence, error)
}

type MFAStepUpVerifier struct {
	consumer stepUpTxConsumer
}

var _ rbacmanager.StepUpVerifier = (*MFAStepUpVerifier)(nil)

func NewMFAStepUpVerifier(service *mfa.Service) (*MFAStepUpVerifier, error) {
	if service == nil {
		return nil, ErrStepUpUnavailable
	}
	return &MFAStepUpVerifier{consumer: service}, nil
}

func newMFAStepUpVerifier(consumer stepUpTxConsumer) (*MFAStepUpVerifier, error) {
	if consumer == nil {
		return nil, ErrStepUpUnavailable
	}
	return &MFAStepUpVerifier{consumer: consumer}, nil
}

func (verifier *MFAStepUpVerifier) VerifyAndConsume(
	ctx context.Context,
	tx pgx.Tx,
	proof rbacmanager.StepUpProof,
	check rbacmanager.StepUpCheck,
) (rbacmanager.StepUpEvidence, error) {
	if verifier == nil || verifier.consumer == nil || tx == nil || check.Actor.UserID == uuid.Nil ||
		check.Actor.ScopeID == uuid.Nil || check.Actor.SessionID == uuid.Nil || check.TenantID == uuid.Nil ||
		check.RoleID == uuid.Nil || check.Audience != "custom-rbac" || !validStepUpAction(check) ||
		!validBindingText(check.RequestID) || !validBindingText(check.TraceID) ||
		len(check.MutationDigest) != sha256.Size || len(check.Permissions) == 0 ||
		!slices.IsSorted(check.Permissions) {
		return rbacmanager.StepUpEvidence{}, ErrStepUpUnavailable
	}
	binding, err := stepUpBindingDigest(check)
	if err != nil {
		return rbacmanager.StepUpEvidence{}, ErrStepUpUnavailable
	}
	// The RBAC transaction already holds the v1 global-exclusive lock and the
	// actor scope lock. Stage2B re-enters the same global lock and, because a
	// tenant actor's scope is the tenant scope, the same scope identity; any
	// other tenant scope changes the identity and the database rejects it.
	var tenantScopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='tenant' AND tenant_id=$1`,
		check.TenantID).Scan(&tenantScopeID); err != nil {
		return rbacmanager.StepUpEvidence{}, ErrStepUpUnavailable
	}
	lockedScopes, err := iamstage2b.BeginAuthorityMutation(ctx, tx, iamstage2b.OperationMFAConsumeStepUp,
		[]uuid.UUID{check.Actor.ScopeID, tenantScopeID})
	if err != nil {
		return rbacmanager.StepUpEvidence{}, ErrStepUpUnavailable
	}
	evidence, err := verifier.consumer.ConsumeStepUpTxWithScopes(ctx, tx, mfa.Actor{
		UserID: check.Actor.UserID, ScopeID: check.Actor.ScopeID, SessionID: check.Actor.SessionID,
	}, lockedScopes, mfa.ConsumeStepUpRequest{
		Token: proof.Token, TenantID: check.TenantID, Audience: check.Audience, Action: check.Action,
		ResourceBindingDigest: binding[:],
		Context:               mfa.RequestContext{RequestID: check.RequestID, TraceID: check.TraceID},
	})
	if err != nil || evidence.ProofID == uuid.Nil || evidence.ActorUserID != check.Actor.UserID ||
		evidence.ActorScopeID != check.Actor.ScopeID || evidence.SessionID != check.Actor.SessionID ||
		evidence.TenantID != check.TenantID || evidence.Audience != check.Audience ||
		evidence.Action != check.Action || !slices.Equal(evidence.ResourceBindingDigest, binding[:]) {
		return rbacmanager.StepUpEvidence{}, ErrStepUpUnavailable
	}
	return rbacmanager.StepUpEvidence{
		ProofID: evidence.ProofID, Method: evidence.Method, VerifiedAt: evidence.VerifiedAt,
	}, nil
}

func validStepUpAction(check rbacmanager.StepUpCheck) bool {
	switch check.Action {
	case "identity.custom_role.create":
		return check.GrantID == uuid.Nil && check.SubjectUserID == uuid.Nil && check.ExpectedRevision == 0
	case "identity.custom_role.publish", "identity.custom_role.deactivate":
		return check.GrantID == uuid.Nil && check.SubjectUserID == uuid.Nil && check.ExpectedRevision >= 1
	case "identity.custom_role.assign":
		return check.GrantID == uuid.Nil && check.SubjectUserID != uuid.Nil && check.ExpectedRevision >= 1
	case "identity.custom_role.revoke":
		return check.GrantID != uuid.Nil && check.SubjectUserID != uuid.Nil && check.ExpectedRevision >= 1
	default:
		return false
	}
}

func validBindingText(value string) bool {
	return value == strings.TrimSpace(value) && len(value) >= 1 && len(value) <= 128
}

func stepUpBindingDigest(check rbacmanager.StepUpCheck) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(struct {
		Version       int       `json:"version"`
		TenantID      uuid.UUID `json:"tenant_id"`
		ActorUserID   uuid.UUID `json:"actor_user_id"`
		ActorScopeID  uuid.UUID `json:"actor_scope_id"`
		SessionID     uuid.UUID `json:"session_id"`
		RoleID        uuid.UUID `json:"role_id"`
		GrantID       uuid.UUID `json:"grant_id"`
		SubjectUserID uuid.UUID `json:"subject_user_id"`
		Expected      int64     `json:"expected_revision"`
		Action        string    `json:"action"`
		Mutation      []byte    `json:"mutation_sha256"`
		RequestID     string    `json:"request_id"`
		TraceID       string    `json:"trace_id"`
		Permissions   []string  `json:"permissions"`
	}{2, check.TenantID, check.Actor.UserID, check.Actor.ScopeID, check.Actor.SessionID,
		check.RoleID, check.GrantID, check.SubjectUserID, check.ExpectedRevision, check.Action,
		append([]byte(nil), check.MutationDigest...), check.RequestID, check.TraceID,
		append([]string(nil), check.Permissions...)})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
