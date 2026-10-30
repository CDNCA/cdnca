//go:build integration

package identity_test

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type managedPasswordResetStepUpCall struct {
	actor   identity.ManagedPasswordResetStepUpActor
	scopes  []uuid.UUID
	request identity.ManagedPasswordResetStepUpRequest
}

type managedPasswordResetStepUpConsumer struct {
	calls []managedPasswordResetStepUpCall
	err   error
}

func (consumer *managedPasswordResetStepUpConsumer) BeginManagedPasswordResetAuthorityMutation(
	ctx context.Context,
	tx pgx.Tx,
	scopes []uuid.UUID,
) ([]uuid.UUID, error) {
	return iamstage2b.BeginAuthorityMutation(ctx, tx, iamstage2b.OperationMFAConsumeStepUp, scopes)
}

func (consumer *managedPasswordResetStepUpConsumer) ConsumeManagedPasswordResetStepUp(
	_ context.Context,
	tx pgx.Tx,
	actor identity.ManagedPasswordResetStepUpActor,
	scopes []uuid.UUID,
	request identity.ManagedPasswordResetStepUpRequest,
) (identity.ManagedPasswordResetStepUpEvidence, error) {
	if tx == nil {
		return identity.ManagedPasswordResetStepUpEvidence{}, identity.ErrManagedPasswordResetUnavailable
	}
	consumer.calls = append(consumer.calls, managedPasswordResetStepUpCall{
		actor: actor, scopes: append([]uuid.UUID(nil), scopes...), request: request,
	})
	if consumer.err != nil {
		return identity.ManagedPasswordResetStepUpEvidence{}, consumer.err
	}
	return identity.ManagedPasswordResetStepUpEvidence{
		ProofID: uuid.New(), ActorUserID: actor.UserID, ActorScopeID: actor.ScopeID,
		SessionID: actor.SessionID, TenantID: request.TenantID, Method: "totp",
		Audience: request.Audience, Action: request.Action, VerifiedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Minute), UseOrdinal: 1,
		ResourceBindingDigest: append([]byte(nil), request.ResourceBindingDigest...),
	}, nil
}

func TestManagedPasswordResetIsTargetBoundIdempotentAndRevokesSessions(t *testing.T) {
	fixture := seedManagedUserAuthorityFixture(t, "identity.users.manage")
	actorSessionID := uuid.New()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, actorSessionID, uuid.New(), fixture.actor.UserID,
		fixture.actor.ScopeID, bytes.Repeat([]byte{0x66}, 32), time.Now().Add(-time.Hour),
		time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	fixture.actor.SessionID = actorSessionID
	consumer := &managedPasswordResetStepUpConsumer{}
	fixture.service.SetManagedPasswordResetStepUpConsumer(consumer)
	var tenantID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`,
		fixture.targetScopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	input := identity.ResetManagedUserPasswordInput{
		ID: fixture.targetUserID, TenantScopeID: fixture.targetScopeID, ExpectedRevision: 1,
		NewPassword: "replacement-password-long-enough", StepUpToken: "opaque-reset-proof",
		IdempotencyKey: "managed-password-reset", RequestID: "managed-password-reset-request",
	}

	result, err := fixture.service.ResetManagedUserPassword(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != fixture.targetUserID || result.ScopeID != fixture.targetScopeID ||
		result.TenantID == nil || *result.TenantID != tenantID || result.Revision != 2 {
		t.Fatalf("ResetManagedUserPassword() = %#v", result)
	}
	if len(consumer.calls) != 1 {
		t.Fatalf("step-up calls = %d, want 1", len(consumer.calls))
	}
	call := consumer.calls[0]
	wantScopes := []uuid.UUID{fixture.actor.ScopeID, fixture.targetScopeID}
	sort.Slice(wantScopes, func(left, right int) bool { return bytes.Compare(wantScopes[left][:], wantScopes[right][:]) < 0 })
	if call.actor.UserID != fixture.actor.UserID || call.actor.ScopeID != fixture.actor.ScopeID ||
		call.actor.SessionID != actorSessionID || !equalUUIDs(call.scopes, wantScopes) ||
		call.request.Token != input.StepUpToken || call.request.TenantID != tenantID ||
		call.request.Audience != identity.ManagedPasswordResetStepUpAudience ||
		call.request.Action != identity.ManagedPasswordResetStepUpAction ||
		len(call.request.ResourceBindingDigest) != 32 {
		t.Fatalf("step-up call = %#v", call)
	}

	var passwordHash, storedSecret, auditPayload string
	var revision, revokedSessions, receipts, audits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT password_hash,revision FROM users WHERE id=$1`,
		fixture.targetUserID).Scan(&passwordHash, &revision); err != nil {
		t.Fatal(err)
	}
	if !identity.VerifyPassword(passwordHash, input.NewPassword) || passwordHash == input.NewPassword || revision != 2 {
		t.Fatalf("stored password/revision is invalid: revision=%d hash=%q", revision, passwordHash)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM auth_sessions WHERE user_id=$1 AND revoked_at IS NOT NULL),
		(SELECT count(*) FROM identity_write_requests WHERE operation='identity.user.password.reset' AND idempotency_key=$2),
		(SELECT secret_hash FROM identity_write_requests WHERE operation='identity.user.password.reset' AND idempotency_key=$2),
		(SELECT count(*) FROM audit_events WHERE action='identity.user.password.reset' AND request_id=$3),
		(SELECT payload::text FROM audit_events WHERE action='identity.user.password.reset' AND request_id=$3)`,
		fixture.targetUserID, input.IdempotencyKey, input.RequestID).
		Scan(&revokedSessions, &receipts, &storedSecret, &audits, &auditPayload); err != nil {
		t.Fatal(err)
	}
	if revokedSessions != 1 || receipts != 1 || audits != 1 || storedSecret != passwordHash ||
		bytes.Contains([]byte(auditPayload), []byte(input.NewPassword)) ||
		bytes.Contains([]byte(auditPayload), []byte(input.StepUpToken)) {
		t.Fatalf("reset facts revoked=%d receipts=%d audits=%d secretMatch=%t audit=%s",
			revokedSessions, receipts, audits, storedSecret == passwordHash, auditPayload)
	}

	replayed, err := fixture.service.ResetManagedUserPassword(t.Context(), fixture.actor, input)
	if err != nil || replayed.ID != result.ID || replayed.Revision != result.Revision || len(consumer.calls) != 1 {
		t.Fatalf("exact replay = %#v, %v, step-up calls=%d", replayed, err, len(consumer.calls))
	}
	changed := input
	changed.NewPassword = "different-replacement-password"
	if _, err := fixture.service.ResetManagedUserPassword(t.Context(), fixture.actor, changed); !errors.Is(err, identity.ErrIdempotencyConflict) {
		t.Fatalf("changed password replay error = %v, want idempotency conflict", err)
	}

	if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=now(),revocation_reason='test'
		WHERE id=$1`, actorSessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.ResetManagedUserPassword(t.Context(), fixture.actor, input); !errors.Is(err, identity.ErrInvalidSession) {
		t.Fatalf("revoked actor replay error = %v, want invalid session", err)
	}
}

func TestManagedPasswordResetRejectsStepUpAndTargetMismatchesWithoutSideEffects(t *testing.T) {
	tests := map[string]func(*managedUserAuthorityFixture, *identity.ResetManagedUserPasswordInput, *managedPasswordResetStepUpConsumer){
		"wrong target scope": func(fixture *managedUserAuthorityFixture, input *identity.ResetManagedUserPasswordInput, _ *managedPasswordResetStepUpConsumer) {
			input.TenantScopeID = uuid.New()
		},
		"invalid proof": func(_ *managedUserAuthorityFixture, _ *identity.ResetManagedUserPasswordInput, consumer *managedPasswordResetStepUpConsumer) {
			consumer.err = identity.ErrManagedPasswordResetStepUpRequired
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := seedManagedUserAuthorityFixture(t, "identity.users.manage")
			actorSessionID := uuid.New()
			if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
				id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
			) VALUES($1,$2,$3,$4,$5,$6,$7)`, actorSessionID, uuid.New(), fixture.actor.UserID,
				fixture.actor.ScopeID, bytes.Repeat([]byte{0x67}, 32), time.Now().Add(-time.Hour),
				time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			fixture.actor.SessionID = actorSessionID
			consumer := &managedPasswordResetStepUpConsumer{}
			fixture.service.SetManagedPasswordResetStepUpConsumer(consumer)
			input := identity.ResetManagedUserPasswordInput{
				ID: fixture.targetUserID, TenantScopeID: fixture.targetScopeID, ExpectedRevision: 1,
				NewPassword: "replacement-password-long-enough", StepUpToken: "opaque-reset-proof",
				IdempotencyKey: "rejected-managed-password-reset", RequestID: "rejected-managed-password-reset-request",
			}
			mutate(&fixture, &input, consumer)
			_, err := fixture.service.ResetManagedUserPassword(t.Context(), fixture.actor, input)
			if name == "invalid proof" && !errors.Is(err, identity.ErrManagedPasswordResetStepUpRequired) {
				t.Fatalf("reset error = %v, want step-up required", err)
			}
			if name == "wrong target scope" && !errors.Is(err, identity.ErrUserNotFound) {
				t.Fatalf("reset error = %v, want user not found", err)
			}
			var revision, revoked, receipts, audits int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT
				(SELECT revision FROM users WHERE id=$1),
				(SELECT count(*) FROM auth_sessions WHERE user_id=$1 AND revoked_at IS NOT NULL),
				(SELECT count(*) FROM identity_write_requests WHERE idempotency_key=$2),
				(SELECT count(*) FROM audit_events WHERE action='identity.user.password.reset' AND request_id=$3)`,
				fixture.targetUserID, input.IdempotencyKey, input.RequestID).
				Scan(&revision, &revoked, &receipts, &audits); err != nil {
				t.Fatal(err)
			}
			if revision != 1 || revoked != 0 || receipts != 0 || audits != 0 {
				t.Fatalf("rejected reset side effects revision=%d revoked=%d receipts=%d audits=%d",
					revision, revoked, receipts, audits)
			}
		})
	}
}

func equalUUIDs(left, right []uuid.UUID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
