package mfa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/google/uuid"
)

// MFA optional（ 决定）：操作者没启用 MFA 时敏感操作直接放行，
// 审计记「操作者未启用 MFA」；启用了 MFA 就照旧要证明，缺码、错码都拒绝。
func TestStepUpWaivedOnlyWhenOperatorHasNoActiveMFA(t *testing.T) {
	fixture := newMFAFixture(t)
	binding := bytes.Repeat([]byte{0x24}, 32)
	request := func(name, token string) ConsumeStepUpRequest {
		return ConsumeStepUpRequest{Token: token, TenantID: fixture.tenantA.id, Audience: "impersonation",
			Action: "grant.create", ResourceBindingDigest: binding, Context: requestContext(name)}
	}
	consumeTx := func(r ConsumeStepUpRequest) (Evidence, error) {
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		locked, err := iamstage2b.BeginAuthorityMutation(t.Context(), tx, iamstage2b.OperationMFAConsumeStepUp,
			[]uuid.UUID{fixture.actor.ScopeID, fixture.tenantA.scopeID})
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := fixture.service.ConsumeStepUpTxWithScopes(t.Context(), tx, fixture.actor, locked, r)
		if err == nil {
			if commitErr := tx.Commit(t.Context()); commitErr != nil {
				t.Fatal(commitErr)
			}
		}
		return evidence, err
	}

	// 未启用 MFA：空令牌放行（两种入口），不写证明使用，审计注明未启用。
	evidence, err := consumeTx(request("waive-tx", ""))
	if err != nil || !evidence.Waived || evidence.ProofID == uuid.Nil || evidence.Method != MethodNone ||
		evidence.ActorUserID != fixture.actor.UserID || evidence.TenantID != fixture.tenantA.id ||
		evidence.UseOrdinal != 1 || !bytes.Equal(evidence.ResourceBindingDigest, binding) {
		t.Fatalf("waived consume = (%+v,%v)", evidence, err)
	}
	if evidence, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, request("waive-pool", "")); err != nil ||
		!evidence.Waived {
		t.Fatalf("waived ConsumeStepUp = (%+v,%v)", evidence, err)
	}
	assertCount(t, fixture.pool, "mfa_step_up_uses", 0)
	assertAuditCount(t, fixture.pool, "request-waive-tx", "mfa.step_up.waive", 1)
	var note string
	var enabled bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT payload->>'step_up_note',(payload->>'mfa_enabled')::boolean
		FROM audit_events WHERE request_id='request-waive-tx' AND action='mfa.step_up.waive'`).Scan(&note, &enabled); err != nil {
		t.Fatal(err)
	}
	if note != "操作者未启用 MFA" || enabled {
		t.Fatalf("waive audit note=%q mfa_enabled=%v", note, enabled)
	}
	// 未启用时伪造的令牌仍是无效证明，不当作放行。
	if _, err := consumeTx(request("waive-bogus", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("bogus token without MFA error = %v, want ErrInvalidProof", err)
	}

	// 启用 MFA 之后：缺码拒绝、错码签不出证明。
	enrollment, _ := fixture.activate(t, "waive-active")
	if _, err := consumeTx(request("active-missing", "")); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("missing proof with active MFA error = %v, want ErrInvalidProof", err)
	}
	if _, err := fixture.service.ConsumeStepUp(t.Context(), fixture.actor, request("active-missing-pool", "")); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("missing proof (pool) with active MFA error = %v, want ErrInvalidProof", err)
	}
	assertAuditCount(t, fixture.pool, "request-active-missing-pool", "mfa.step_up.consume", 1)
	secret := decodeTOTPSecret(enrollment.Secret)
	fixture.clock.Add(2 * TOTPPeriod)
	current := currentCode(secret, fixture.clock.Now())
	wrong := "000000"
	if current == wrong {
		wrong = "111111"
	}
	if _, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest("active-wrong",
		Authentication{Method: MethodTOTP, Code: wrong}, 1)); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("wrong code with active MFA error = %v, want ErrInvalidCode", err)
	}
	proof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest("active-ok",
		Authentication{Method: MethodTOTP, Code: current}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if evidence, err := consumeTx(request("active-ok-use", proof.Token)); err != nil || evidence.Waived || evidence.ProofID == uuid.Nil {
		t.Fatalf("valid proof with active MFA = (%+v,%v)", evidence, err)
	}
}
