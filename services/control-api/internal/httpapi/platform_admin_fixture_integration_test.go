package httpapi

// Platform-admin fixtures shared by the approval center PG cases; they came
// from the removed billing HTTP tests (community edition has no billing). The
// billing.adjustments.* codes stay in the shared permission catalog.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func insertBillingPlatformUser(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	username, displayName, passwordHash string,
	assignRole bool,
) uuid.UUID {
	t.Helper()
	userID, roleCandidate := uuid.New(), uuid.New()
	runBillingAuthorityMutation(t, pool, []uuid.UUID{scopeID}, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO roles (id,scope_id,name,description,system_role)
			VALUES($1,$2,'platform_admin','Billing platform administrator',true)
			ON CONFLICT (scope_id,name) DO NOTHING`, roleCandidate, scopeID); err != nil {
			return err
		}
		var roleID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM roles WHERE scope_id=$1 AND name='platform_admin' AND system_role`, scopeID).Scan(&roleID); err != nil {
			return err
		}
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO role_permissions (role_id,permission_name)
					SELECT $1,name FROM permissions
					WHERE name=ANY($2::text[]) ON CONFLICT DO NOTHING`,
				[]any{roleID, []string{"billing.adjustments.manage", "billing.adjustments.propose", "billing.adjustments.approve"}}},
			{`INSERT INTO users (id,username,display_name,password_hash) VALUES($1,$2,$3,$4)`, []any{userID, username, displayName, passwordHash}},
			{`INSERT INTO memberships (scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		if assignRole {
			_, err := tx.Exec(ctx, `INSERT INTO role_assignments (scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, userID, roleID)
			return err
		}
		return nil
	})
	return userID
}

type httpBillingApprovalStepUpConsumer struct {
	now time.Time
}

func (consumer *httpBillingApprovalStepUpConsumer) ConsumeStepUpTxWithScopes(
	ctx context.Context,
	tx pgx.Tx,
	actor mfa.Actor,
	_ []uuid.UUID,
	request mfa.ConsumeStepUpRequest,
) (mfa.Evidence, error) {
	now := consumer.now.UTC().Truncate(time.Microsecond)
	credentialID, activationID, verificationID, proofID, useID :=
		uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := sha256.Sum256([]byte(credentialID.String()))
	tokenDigest := sha256.Sum256([]byte(request.Token))
	createdAt := now.Add(-2 * time.Minute)
	// A platform-scoped proof has no tenant (446: NULL, never the zero UUID).
	var tenantID any = request.TenantID
	if request.TenantID == uuid.Nil {
		tenantID = nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mfa_credentials(
		id,user_id,scope_id,method,account_label,secret_key_id,envelope_algorithm,
		secret_ciphertext,secret_ciphertext_sha256,totp_algorithm,totp_digits,totp_period_seconds,
		idempotency_key,request_digest,request_id,trace_id,encrypted_at,created_at,challenge_expires_at)
		VALUES($1,$2,$3,'totp','Billing approval HTTP test','billing-approval-http-test','external-envelope-v1',
		$4,$5,'sha1',6,30,$6,$5,$6,$6,$7,$7,$8)`, credentialID, actor.UserID, actor.ScopeID,
		bytes.Repeat([]byte{0x42}, 17), seed[:], "credential-"+credentialID.String(), createdAt,
		createdAt.Add(10*time.Minute)); err != nil {
		return mfa.Evidence{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mfa_credential_events(
		id,credential_id,user_id,scope_id,event_type,totp_counter,idempotency_key,request_digest,
		request_id,trace_id,occurred_at) VALUES
		($1,$2,$3,$4,'activated',1,$5,$6,$5,$5,$7),
		($8,$2,$3,$4,'totp_verified',2,$9,$6,$10,$10,$11)`, activationID, credentialID,
		actor.UserID, actor.ScopeID, "activate-"+activationID.String(), seed[:], createdAt.Add(time.Minute),
		verificationID, "verify-"+verificationID.String(), request.Context.RequestID, now); err != nil {
		return mfa.Evidence{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mfa_step_up_proofs(
		id,token_digest,actor_user_id,actor_scope_id,auth_session_id,tenant_id,credential_id,
		authentication_event_id,authentication_method,permissions_digest,audience,action,max_uses,
		idempotency_key,request_digest,request_id,trace_id,issued_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'totp',$9,$10,$11,1,$12,$9,$13,$14,$15,$16)`,
		proofID, tokenDigest[:], actor.UserID, actor.ScopeID, actor.SessionID, tenantID,
		credentialID, verificationID, seed[:], request.Audience, request.Action,
		"proof-"+proofID.String(), request.Context.RequestID, request.Context.TraceID, now,
		now.Add(5*time.Minute)); err != nil {
		return mfa.Evidence{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mfa_step_up_uses(
		id,proof_id,actor_user_id,actor_scope_id,auth_session_id,tenant_id,use_ordinal,
		request_id,trace_id,resource_binding_sha256,used_at)
		VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10)`, useID, proofID, actor.UserID,
		actor.ScopeID, actor.SessionID, tenantID, request.Context.RequestID,
		request.Context.TraceID, request.ResourceBindingDigest, now); err != nil {
		return mfa.Evidence{}, err
	}
	return mfa.Evidence{
		ProofID: proofID, ActorUserID: actor.UserID, ActorScopeID: actor.ScopeID,
		SessionID: actor.SessionID, TenantID: request.TenantID, Method: mfa.MethodTOTP,
		Audience: request.Audience, Action: request.Action, VerifiedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), UseOrdinal: 1,
		ResourceBindingDigest: append([]byte(nil), request.ResourceBindingDigest...),
	}, nil
}

func runBillingAuthorityMutation(
	t *testing.T,
	pool *pgxpool.Pool,
	scopes []uuid.UUID,
	mutation func(context.Context, pgx.Tx) error,
) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if err := iamlock.AcquireExclusive(t.Context(), tx); err != nil {
			return err
		}
		if _, err := iamlock.AcquireScopes(t.Context(), tx, scopes); err != nil {
			return err
		}
		return mutation(t.Context(), tx)
	}); err != nil {
		t.Fatalf("commit billing authority mutation: %v", err)
	}
}
