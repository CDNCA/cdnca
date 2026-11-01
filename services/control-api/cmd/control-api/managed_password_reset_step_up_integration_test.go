//go:build integration

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/cdnca/cdnca/services/control-api/internal/mfacipher"
	"github.com/google/uuid"
)

// MFA step-up display：平台管理员在「用户列表」重置租户用户密码的真实链路——
// 真 mfa.Service 签发 identity.user.password.reset 证明，经生产适配器交给
// identity 托管重置消费。错码要得到 mfa_invalid_code（前端据此说「验证码错误」），
// 正确的当前码要真的改掉密码，不能被别的环节拒掉。
func TestManagedPasswordResetConsumesRealPlatformStepUpProof(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	now := time.Now().UTC()
	platformScopeID, adminID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tenantID, tenantScopeID, targetID, ownerRoleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'7878')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL),($2,'tenant',$3)`,
			[]any{platformScopeID, tenantScopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES
			($1,$2,'admin','unused'),($3,$4,'7878@7878.vip','unused')`,
			[]any{adminID, "stepup-admin-" + uuid.NewString()[:8], targetID, "stepup-target-" + uuid.NewString()[:8]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($3,$4)`,
			[]any{platformScopeID, adminID, tenantScopeID, targetID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'step-up admin',true)`,
			[]any{roleID, platformScopeID, "stepup-admin-" + uuid.NewString()[:8]}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'identity.users.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
			[]any{platformScopeID, adminID, roleID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','owner',true)`,
			[]any{ownerRoleID, tenantScopeID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
			[]any{tenantScopeID, targetID, ownerRoleID}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$1,$2,$3,$4,$5,$6)`,
			[]any{sessionID, adminID, platformScopeID, bytes.Repeat([]byte{0x5a}, 32), now.Add(-time.Minute), now.Add(time.Hour)}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := mfacipher.New(mfacipher.Key{ID: "mfa-v1", Material: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cipher.Close() })
	clock := now
	service, err := mfa.NewServiceWithDependencies(pool, cipher, audit.New(pool), mfa.Config{
		Clock: func() time.Time { return clock }, Random: rand.Reader, Issuer: "CDNCA", EnrollmentTTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	mfaActor := mfa.Actor{UserID: adminID, ScopeID: platformScopeID, SessionID: sessionID}
	meta := func(name string) mfa.RequestContext {
		return mfa.RequestContext{RequestID: "mfa-" + name, TraceID: "trace-" + name}
	}
	enrollment, err := service.BeginEnrollment(ctx, mfaActor, mfa.EnrollmentRequest{
		AccountLabel: "admin", IdempotencyKey: "enroll", Context: meta("enroll")})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Activate(ctx, mfaActor, mfa.ActivationRequest{CredentialID: enrollment.CredentialID,
		Code: totpAt(secret, clock), IdempotencyKey: "activate", Context: meta("activate")}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * mfa.TOTPPeriod) // 激活用掉的计数器之后，用户再看身份验证器得到的新码

	proofRequest := func(name, code string) mfa.StepUpRequest {
		return mfa.StepUpRequest{TenantID: tenantID, Audience: identity.ManagedPasswordResetStepUpAudience,
			Action:         identity.ManagedPasswordResetStepUpAction,
			Authentication: mfa.Authentication{Method: mfa.MethodTOTP, Code: code},
			TTL:            5 * time.Minute, MaxUses: 1, IdempotencyKey: name, Context: meta(name)}
	}
	current := totpAt(secret, clock)
	wrong := fmt.Sprintf("%06d", (mustAtoi(t, current)+500000)%1000000)
	if _, err := service.CreateStepUp(ctx, mfaActor, proofRequest("step-up-wrong", wrong)); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("wrong code CreateStepUp error = %v, want ErrInvalidCode", err)
	}
	proof, err := service.CreateStepUp(ctx, mfaActor, proofRequest("step-up-ok", current))
	if err != nil {
		t.Fatalf("current code CreateStepUp: %v", err)
	}

	tokens, err := identity.NewTokenManager("managed-password-reset-step-up-integration-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := newManagedPasswordResetStepUpAdapter(service)
	if err != nil {
		t.Fatal(err)
	}
	identityService.SetManagedPasswordResetStepUpConsumer(adapter)
	newPassword := "Replacement-password-7878"
	result, err := identityService.ResetManagedUserPassword(ctx,
		identity.Actor{UserID: adminID, ScopeID: platformScopeID, ScopeKind: "platform", SessionID: sessionID},
		identity.ResetManagedUserPasswordInput{ID: targetID, TenantScopeID: tenantScopeID, ExpectedRevision: 1,
			NewPassword: newPassword, StepUpToken: proof.Token,
			IdempotencyKey: "reset-user-password-key", RequestID: "reset-user-password-request"})
	if err != nil {
		t.Fatalf("ResetManagedUserPassword with a real proof: %v", err)
	}
	var hash string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, targetID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if result.Revision != 2 || !identity.VerifyPassword(hash, newPassword) {
		t.Fatalf("password not reset: revision=%d", result.Revision)
	}
}

// MFA optional：管理员没启用 MFA 时不带 step-up 令牌也能重置密码，
// 审计记「操作者未启用 MFA」；启用 MFA 后不带令牌就被拒（mfa_step_up_required）。
func TestManagedPasswordResetWaivesStepUpWithoutMFA(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	now := time.Now().UTC()
	platformScopeID, adminID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tenantID, tenantScopeID, targetID, ownerRoleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'7878')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL),($2,'tenant',$3)`,
			[]any{platformScopeID, tenantScopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES
			($1,$2,'admin','unused'),($3,$4,'7878@7878.vip','unused')`,
			[]any{adminID, "stepup-admin-" + uuid.NewString()[:8], targetID, "stepup-target-" + uuid.NewString()[:8]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($3,$4)`,
			[]any{platformScopeID, adminID, tenantScopeID, targetID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'step-up admin',true)`,
			[]any{roleID, platformScopeID, "stepup-admin-" + uuid.NewString()[:8]}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'identity.users.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
			[]any{platformScopeID, adminID, roleID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','owner',true)`,
			[]any{ownerRoleID, tenantScopeID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
			[]any{tenantScopeID, targetID, ownerRoleID}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$1,$2,$3,$4,$5,$6)`,
			[]any{sessionID, adminID, platformScopeID, bytes.Repeat([]byte{0x5a}, 32), now.Add(-time.Minute), now.Add(time.Hour)}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := mfacipher.New(mfacipher.Key{ID: "mfa-v1", Material: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cipher.Close() })
	service, err := mfa.NewServiceWithDependencies(pool, cipher, audit.New(pool), mfa.Config{
		Clock: func() time.Time { return now }, Random: rand.Reader, Issuer: "CDNCA", EnrollmentTTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("managed-password-reset-waive-integration-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := newManagedPasswordResetStepUpAdapter(service)
	if err != nil {
		t.Fatal(err)
	}
	identityService.SetManagedPasswordResetStepUpConsumer(adapter)
	actor := identity.Actor{UserID: adminID, ScopeID: platformScopeID, ScopeKind: "platform", SessionID: sessionID}
	newPassword := "Replacement-password-7878"
	result, err := identityService.ResetManagedUserPassword(ctx, actor, identity.ResetManagedUserPasswordInput{
		ID: targetID, TenantScopeID: tenantScopeID, ExpectedRevision: 1, NewPassword: newPassword,
		IdempotencyKey: "reset-user-password-waive", RequestID: "reset-user-password-waive"})
	if err != nil {
		t.Fatalf("ResetManagedUserPassword without MFA: %v", err)
	}
	var hash, note string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, targetID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if result.Revision != 2 || !identity.VerifyPassword(hash, newPassword) {
		t.Fatalf("password not reset: revision=%d", result.Revision)
	}
	if err := pool.QueryRow(ctx, `SELECT payload->>'step_up_note' FROM audit_events
		WHERE request_id='reset-user-password-waive' AND action='mfa.step_up.waive'`).Scan(&note); err != nil || note != "操作者未启用 MFA" {
		t.Fatalf("waive audit note=%q err=%v", note, err)
	}

	mfaActor := mfa.Actor{UserID: adminID, ScopeID: platformScopeID, SessionID: sessionID}
	enrollment, err := service.BeginEnrollment(ctx, mfaActor, mfa.EnrollmentRequest{AccountLabel: "admin",
		IdempotencyKey: "enroll", Context: mfa.RequestContext{RequestID: "enroll", TraceID: "enroll"}})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Activate(ctx, mfaActor, mfa.ActivationRequest{CredentialID: enrollment.CredentialID,
		Code: totpAt(secret, now), IdempotencyKey: "activate",
		Context: mfa.RequestContext{RequestID: "activate", TraceID: "activate"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := identityService.ResetManagedUserPassword(ctx, actor, identity.ResetManagedUserPasswordInput{
		ID: targetID, TenantScopeID: tenantScopeID, ExpectedRevision: 2, NewPassword: "Another-password-7878",
		IdempotencyKey: "reset-user-password-active", RequestID: "reset-user-password-active"}); !errors.Is(err,
		identity.ErrManagedPasswordResetStepUpRequired) {
		t.Fatalf("reset without proof after enabling MFA error = %v, want step-up required", err)
	}
}

func totpAt(secret []byte, at time.Time) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(at.Unix()/int64(mfa.TOTPPeriod/time.Second)))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	var result int
	if _, err := fmt.Sscanf(value, "%d", &result); err != nil {
		t.Fatal(err)
	}
	return result
}
