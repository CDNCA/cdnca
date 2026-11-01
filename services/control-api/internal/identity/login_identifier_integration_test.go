//go:build integration

package identity_test

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// user password login：登录框写的是「用户名、手机或邮箱」，管理端新建用户
// 必填邮箱、列表也以邮箱为主显示，但登录只按用户名查，邮箱/手机登录一律报密码错误。
func TestLoginAcceptsUsernameEmailOrPhonePostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	tokens, err := identity.NewTokenManager("login-identifier-integration-secret-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'Login identifier')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	insert := func(username, email, phone, password string) uuid.UUID {
		t.Helper()
		hash, err := identity.HashPassword(password)
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,email,phone,password_hash)
			VALUES($1,$2,$2,NULLIF($3,''),NULLIF($4,''),$5)`, id, username, email, phone, hash); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	const password = "Login-identifier-1"
	alice := insert("login-alice", "login-alice@example.com", "+8613800000001", password)
	// 另一个账号的用户名恰好等于 alice 的手机号：用户名精确命中优先。
	numeric := insert("8613800000002", "", "", "Numeric-username-1")
	insert("login-bob", "", "8613800000002", "Bob-password-1")

	login := func(identifier, secret string) (identity.AuthResult, error) {
		return service.Login(ctx, identity.LoginInput{Username: identifier, Password: secret},
			identity.RequestInfo{RequestID: "login-identifier", SourceIP: "203.0.113.20"})
	}
	for _, identifier := range []string{"login-alice", "login-alice@example.com", " Login-Alice@Example.COM ", "+8613800000001"} {
		result, err := login(identifier, password)
		if err != nil {
			t.Fatalf("login %q: %v", identifier, err)
		}
		if result.Principal.UserID != alice {
			t.Fatalf("login %q signed in %s, want %s", identifier, result.Principal.UserID, alice)
		}
	}
	if _, err := login("login-alice@example.com", "Wrong-password-1"); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("email with wrong password: %v", err)
	}
	if _, err := login("nobody@example.com", password); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("unknown email: %v", err)
	}
	result, err := login("8613800000002", "Numeric-username-1")
	if err != nil || result.Principal.UserID != numeric {
		t.Fatalf("username/phone collision resolved to %v (%v), want the username owner %s", result.Principal.UserID, err, numeric)
	}
}
