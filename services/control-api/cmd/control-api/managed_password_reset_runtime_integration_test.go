//go:build integration

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
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

// user password login：管理端「重置 xxx 的密码」走真实 MFA 服务 + 生产适配器：
// 平台管理员对 UI 新建的租户用户签发租户 proof，再用它重置密码；新密码能登录，旧密码不能。
func TestManagedPasswordResetWithRealStepUpPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	tokens, err := identity.NewTokenManager("managed-reset-runtime-secret-at-least-32-bytes", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := mfacipher.New(mfacipher.Key{ID: "mfa-kek-v1", Material: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cipher.Close() })
	mfaService, err := mfa.NewServiceWithDependencies(pool, cipher, audit.New(pool), mfa.Config{
		Clock: clock, Random: rand.Reader, Issuer: "CDNCA Test",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := newManagedPasswordResetStepUpAdapter(mfaService)
	if err != nil {
		t.Fatal(err)
	}
	identityService.SetManagedPasswordResetStepUpConsumer(adapter)

	// 平台管理员：系统角色 platform_owner 带 platform.admin（与全新安装一致）。
	platformScopeID, adminID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{platformScopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'reset-admin','Reset admin','unused')`, []any{adminID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{platformScopeID, adminID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'platform_owner','owner',true)`, []any{roleID, platformScopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) SELECT $1,name FROM permissions
			WHERE name IN ('platform.admin','identity.users.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{platformScopeID, adminID, roleID}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$1,$2,$3,$4,$5,$6)`, []any{sessionID, adminID, platformScopeID, bytes.Repeat([]byte{4}, 32),
			now.Add(-time.Minute), now.Add(time.Hour)}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("%s: %v", statement.sql, err)
		}
	}
	admin := identity.Actor{UserID: adminID, ScopeID: platformScopeID, ScopeKind: "platform", SessionID: sessionID}
	mfaActor := mfa.Actor{UserID: adminID, ScopeID: platformScopeID, SessionID: sessionID}

	// 与「用户列表 → 新增用户」相同的创建路径。
	target, err := identityService.CreateUser(ctx, admin, identity.CreateUserInput{
		Username: "reset-target", Password: "Original-password-1",
		Fields: identity.UserFields{DisplayName: "reset-target@example.com", Email: "reset-target@example.com"},
		Role:   identity.UserRoleOwner, IdempotencyKey: "create-reset-target", RequestID: "create-reset-target",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	enrollment, err := mfaService.BeginEnrollment(ctx, mfaActor, mfa.EnrollmentRequest{
		AccountLabel: "reset-admin", IdempotencyKey: "enroll", Context: mfa.RequestContext{RequestID: "enroll", TraceID: "enroll"},
	})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code := func(at time.Time) string {
		mac := hmac.New(sha1.New, secret)
		_ = binary.Write(mac, binary.BigEndian, uint64(at.Unix()/int64(mfa.TOTPPeriod/time.Second)))
		sum := mac.Sum(nil)
		offset := sum[len(sum)-1] & 0x0f
		return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
	}
	if _, err := mfaService.Activate(ctx, mfaActor, mfa.ActivationRequest{
		CredentialID: enrollment.CredentialID, Code: code(now), IdempotencyKey: "activate",
		Context: mfa.RequestContext{RequestID: "activate", TraceID: "activate"},
	}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(mfa.TOTPPeriod) // 激活用掉了当前窗口的码

	proof, err := mfaService.CreateStepUp(ctx, mfaActor, mfa.StepUpRequest{
		TenantID: *target.TenantID, Audience: identity.ManagedPasswordResetStepUpAudience,
		Action:         identity.ManagedPasswordResetStepUpAction,
		Authentication: mfa.Authentication{Method: mfa.MethodTOTP, Code: code(now)},
		TTL:            mfa.MaxStepUpTTL, MaxUses: 1, IdempotencyKey: "mfa-step-up-reset",
		Context: mfa.RequestContext{RequestID: "mfa-step-up-reset", TraceID: "mfa-step-up-reset"},
	})
	if err != nil {
		t.Fatalf("CreateStepUp for tenant user: %v", err)
	}
	result, err := identityService.ResetManagedUserPassword(ctx, admin, identity.ResetManagedUserPasswordInput{
		ID: target.ID, TenantScopeID: target.ScopeID, ExpectedRevision: target.Revision,
		NewPassword: "Replacement-password-1", StepUpToken: proof.Token,
		IdempotencyKey: "reset-user-password-1", RequestID: "reset-user-password-request-1",
	})
	if err != nil {
		t.Fatalf("ResetManagedUserPassword: %v", err)
	}
	if result.Revision != target.Revision+1 {
		t.Fatalf("revision = %d, want %d", result.Revision, target.Revision+1)
	}
	login := func(password string) error {
		_, err := identityService.Login(ctx, identity.LoginInput{Username: "reset-target", Password: password},
			identity.RequestInfo{RequestID: "reset-login", SourceIP: "203.0.113.30"})
		return err
	}
	if err := login("Replacement-password-1"); err != nil {
		t.Fatalf("login with the reset password: %v", err)
	}
	if err := login("Original-password-1"); err == nil {
		t.Fatal("the old password still signs in")
	}
}
