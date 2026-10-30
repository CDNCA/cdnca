//go:build integration

package mfa

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestPlatformScopedStepUp: a platform administrator issues and
// consumes a proof without a tenant; a tenant user cannot obtain or use one;
// platform and tenant proofs never satisfy each other.
func TestPlatformScopedStepUp(t *testing.T) {
	fixture := newMFAFixture(t)
	_, codes := fixture.activate(t, "platform-scope")
	binding := bytes.Repeat([]byte{0x51}, 32)
	request := func(key string) StepUpRequest {
		return StepUpRequest{PlatformScope: true, Audience: "migrate-import", Action: "migrate_import.job.confirm",
			Authentication: Authentication{Method: MethodRecoveryCode, Code: codes[len(key)%len(codes)]},
			TTL:            MaxStepUpTTL, MaxUses: 1, IdempotencyKey: key, Context: requestContext(key)}
	}
	proof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, request("pp-a"))
	if err != nil {
		t.Fatalf("platform proof: %v", err)
	}
	var storedTenant *uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT tenant_id FROM mfa_step_up_proofs WHERE id=$1`,
		proof.ProofID).Scan(&storedTenant); err != nil || storedTenant != nil {
		t.Fatalf("stored tenant = %v (%v), want NULL", storedTenant, err)
	}
	consume := ConsumeStepUpRequest{Token: proof.Token, PlatformScope: true, Audience: "migrate-import",
		Action: "migrate_import.job.confirm", ResourceBindingDigest: binding, Context: requestContext("pp-use")}
	// A tenant-bound consume of a platform proof is a binding mismatch.
	tenantConsume := consume
	tenantConsume.PlatformScope, tenantConsume.TenantID = false, fixture.tenantA.id
	tenantConsume.Context = requestContext("pp-use-tenant")
	if _, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, tenantConsume); !errors.Is(err, ErrProofBinding) {
		t.Fatalf("tenant consume of platform proof: %v", err)
	}
	evidence := consumeWithScopes(t, fixture, fixture.actor, []uuid.UUID{fixture.actor.ScopeID}, consume)
	if !evidence.PlatformScope || evidence.TenantID != uuid.Nil || evidence.UseOrdinal != 1 {
		t.Fatalf("evidence = %+v", evidence)
	}
	if _, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, ConsumeStepUpRequest{Token: proof.Token,
		PlatformScope: true, Audience: consume.Audience, Action: consume.Action, ResourceBindingDigest: binding,
		Context: requestContext("pp-use-2")}); !errors.Is(err, ErrProofConsumed) {
		t.Fatalf("second use: %v", err)
	}
	var usedTenant *uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT tenant_id FROM mfa_step_up_uses WHERE proof_id=$1`,
		proof.ProofID).Scan(&usedTenant); err != nil || usedTenant != nil {
		t.Fatalf("use tenant = %v (%v)", usedTenant, err)
	}

	// A tenant-bound proof does not satisfy a platform consume.
	tenantReq := fixture.proofRequest("pp-tenant", Authentication{Method: MethodRecoveryCode, Code: codes[3]}, 1)
	tenantProof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, tenantReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, ConsumeStepUpRequest{Token: tenantProof.Token,
		PlatformScope: true, Audience: tenantReq.Audience, Action: tenantReq.Action,
		Context: requestContext("pp-tenant-use")}); !errors.Is(err, ErrProofBinding) {
		t.Fatalf("platform consume of tenant proof: %v", err)
	}

	// Tenant user: cannot issue a platform proof.
	tenantActor := fixture.tenantActor(t)
	enrollment, err := fixture.service.BeginEnrollment(t.Context(), tenantActor, EnrollmentRequest{
		AccountLabel: "tenant@example.invalid", IdempotencyKey: "tenant-enroll", Context: requestContext("tenant-enroll")})
	if err != nil {
		t.Fatal(err)
	}
	activation, err := fixture.service.Activate(t.Context(), tenantActor, ActivationRequest{
		CredentialID: enrollment.CredentialID, Code: currentCode(decodeTOTPSecret(enrollment.Secret), fixture.clock.Now()),
		IdempotencyKey: "tenant-activate", Context: requestContext("tenant-activate")})
	if err != nil {
		t.Fatal(err)
	}
	tenantPlatform := request("tenant-platform")
	tenantPlatform.Authentication.Code = activation.RecoveryCodes[0]
	if _, err := fixture.service.CreateStepUp(t.Context(), tenantActor, tenantPlatform); !errors.Is(err, ErrProofBinding) {
		t.Fatalf("tenant user platform proof: %v", err)
	}
	if count := countPlatformProofs(t, fixture, tenantActor.UserID); count != 0 {
		t.Fatalf("tenant user platform proofs = %d", count)
	}
	// The table rule holds even for direct inserts: a tenant session row with
	// NULL tenant is refused by the proof trigger.
	_, err = fixture.pool.Exec(t.Context(), `INSERT INTO mfa_step_up_proofs(
		id,token_digest,actor_user_id,actor_scope_id,auth_session_id,tenant_id,credential_id,authentication_event_id,
		authentication_method,permissions_digest,audience,action,max_uses,idempotency_key,request_digest,request_id,
		trace_id,issued_at,expires_at)
		SELECT $1,$2,$3,$4,$5,NULL,proof.credential_id,proof.authentication_event_id,proof.authentication_method,
		       proof.permissions_digest,'a','b',1,'direct',proof.request_digest,'r','t',proof.issued_at,proof.expires_at
		FROM mfa_step_up_proofs proof WHERE proof.id=$6`, uuid.New(), bytes.Repeat([]byte{9}, 32),
		tenantActor.UserID, tenantActor.ScopeID, tenantActor.SessionID, proof.ProofID)
	if err == nil {
		t.Fatal("direct tenant-session platform proof accepted")
	}
}

func consumeWithScopes(t *testing.T, fixture mfaFixture, actor Actor, scopes []uuid.UUID,
	request ConsumeStepUpRequest) Evidence {
	t.Helper()
	var evidence Evidence
	err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		locked, err := iamstage2b.BeginAuthorityMutation(t.Context(), tx, iamstage2b.OperationMFAConsumeStepUp, scopes)
		if err != nil {
			return err
		}
		evidence, err = fixture.service.ConsumeStepUpTxWithScopes(t.Context(), tx, actor, locked, request)
		return err
	})
	if err != nil {
		t.Fatalf("ConsumeStepUpTxWithScopes: %v", err)
	}
	return evidence
}

func countPlatformProofs(t *testing.T, fixture mfaFixture, userID uuid.UUID) int {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM mfa_step_up_proofs
		WHERE actor_user_id=$1 AND tenant_id IS NULL`, userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// tenantActor is an active tenant-A member with a live session.
func (fixture mfaFixture) tenantActor(t *testing.T) Actor {
	t.Helper()
	actor := Actor{UserID: uuid.New(), ScopeID: fixture.tenantA.scopeID, SessionID: uuid.New()}
	ctx := t.Context()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'mfa-tenant-user','Tenant user','h')`,
			[]any{actor.UserID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{actor.ScopeID, actor.UserID}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, []any{actor.SessionID, uuid.New(), actor.UserID, actor.ScopeID,
			bytes.Repeat([]byte{4}, 32), fixture.clock.Now().Add(-time.Minute), fixture.clock.Now().Add(time.Hour)}},
	} {
		if _, err := fixture.pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return actor
}
