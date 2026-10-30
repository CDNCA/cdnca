//go:build integration

package identity_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type platformRecoveryFixture struct {
	pool    *pgxpool.Pool
	store   *identity.Store
	service *identity.Service
	input   identity.PlatformAdministratorRecoveryInput
	before  identity.AuthResult
}

func newPlatformRecoveryFixture(t *testing.T) platformRecoveryFixture {
	t.Helper()
	pool := newIdentityAuthorityPool(t)
	store := identity.NewStore(pool)
	username := "recovery-" + uuid.NewString()[:8]
	hash, err := identity.HashPassword("fixture-before-password")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := store.BootstrapPlatformUserWithEmail(t.Context(), username, "Recovery fixture", username+"@example.test", hash, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("recovery-fixture-token-signing-not-production", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(store, tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	before, err := service.Login(t.Context(), identity.LoginInput{Username: username, Password: "fixture-before-password", ScopeID: &owner.ScopeID}, identity.RequestInfo{RequestID: uuid.NewString(), SourceIP: "198.51.100.10"})
	if err != nil {
		t.Fatal(err)
	}
	return platformRecoveryFixture{pool: pool, store: store, service: service, before: before,
		input: identity.PlatformAdministratorRecoveryInput{UserID: owner.UserID, ScopeID: owner.ScopeID,
			ExpectedUsername: username, ExpectedRevision: 1, NewUsername: username + "-after",
			NewPassword: "fixture-after-password", RequestID: uuid.NewString()}}
}

func TestPlatformAdministratorRecovery(t *testing.T) {
	t.Run("commit receipt preserves identity MFA roles keys and revokes every scope", func(t *testing.T) {
		f := newPlatformRecoveryFixture(t)
		tenantID, tenantScopeID := uuid.New(), uuid.New()
		if _, err := f.pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'secondary fixture')`, tenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenantScopeID, tenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, tenantScopeID, f.input.UserID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(t.Context(), `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,now(),now()+interval '1 hour')`, uuid.New(), uuid.New(), f.input.UserID, tenantScopeID, bytes.Repeat([]byte{3}, 32)); err != nil {
			t.Fatal(err)
		}
		credentialID := uuid.New()
		if _, err := f.pool.Exec(t.Context(), `INSERT INTO mfa_credentials(id,user_id,scope_id,method,account_label,secret_key_id,
			envelope_algorithm,secret_ciphertext,secret_ciphertext_sha256,totp_algorithm,totp_digits,totp_period_seconds,
			idempotency_key,request_digest,request_id,trace_id,encrypted_at,created_at,challenge_expires_at)
			VALUES($1,$2,$3,'totp','recovery fixture','fixture-key','external-envelope-v1',$4,$5,'sha1',6,30,
			'fixture-enrollment',$5,'fixture-enrollment','fixture-trace',now(),now(),now()+interval '5 minutes')`,
			credentialID, f.input.UserID, f.input.ScopeID, bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(t.Context(), `INSERT INTO mfa_credential_events(id,credential_id,user_id,scope_id,event_type,totp_counter,
			idempotency_key,request_digest,request_id,trace_id,occurred_at)
			VALUES($1,$2,$3,$4,'activated',1,'fixture-activation',$5,'fixture-activation','fixture-trace',now())`,
			uuid.New(), credentialID, f.input.UserID, f.input.ScopeID, bytes.Repeat([]byte{6}, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(t.Context(), `INSERT INTO mfa_recovery_codes(id,credential_id,user_id,scope_id,ordinal,code_digest,created_at)
			VALUES($1,$2,$3,$4,1,$5,now())`, uuid.New(), credentialID, f.input.UserID, f.input.ScopeID, bytes.Repeat([]byte{7}, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(t.Context(), `INSERT INTO api_keys(id,key_id,key_prefix,scope_id,tenant_id,user_id,name,scopes,
			secret_digest,pepper_version,status,activated_at,created_by_user_id)
			VALUES($1,'cfk_AAAAAAAAAAAAAAAAAAAAAA','cfk_AAAAAAAAAAAAAAAAAAAAAA.',$2,$3,$4,'fixture key',ARRAY['sites.read'],
			$5,'legacy-v1','active',now(),$4)`, uuid.New(), tenantScopeID, tenantID, f.input.UserID, bytes.Repeat([]byte{8}, 32)); err != nil {
			t.Fatal(err)
		}
		const preserved = `SELECT jsonb_build_object(
			'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY scope_id) FROM memberships m WHERE user_id=$1),
			'roles',(SELECT jsonb_agg(to_jsonb(a) ORDER BY scope_id,role_id) FROM role_assignments a WHERE user_id=$1),
			'permissions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY role_id,permission_name) FROM role_permissions p),
			'mfa',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM mfa_credentials c WHERE user_id=$1),
			'mfa_events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM mfa_credential_events e WHERE user_id=$1),
			'mfa_codes',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM mfa_recovery_codes c WHERE user_id=$1),
			'api_keys',(SELECT jsonb_agg(to_jsonb(k) ORDER BY id) FROM api_keys k WHERE user_id=$1))`
		var before, after []byte
		if err := f.pool.QueryRow(t.Context(), preserved, f.input.UserID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, found, err := f.store.PlatformAdministratorRecoveryStatus(t.Context(), f.input.UserID, f.input.ScopeID, f.input.RequestID); err != nil || found {
			t.Fatalf("unexpected pre-commit receipt: %t %v", found, err)
		}
		receipt, err := f.store.RecoverPlatformAdministrator(t.Context(), f.input)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.UserID != f.input.UserID || receipt.ScopeID != f.input.ScopeID || receipt.Revision != 2 || receipt.RevokedSessions != 2 {
			t.Fatal("recovery receipt does not match the exact target and revoked sessions")
		}
		if err := f.pool.QueryRow(t.Context(), preserved, f.input.UserID).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("recovery changed membership, roles, MFA or API keys")
		}
		var username, hash, email string
		var revision int64
		if err := f.pool.QueryRow(t.Context(), `SELECT username,password_hash,revision,email FROM users WHERE id=$1`, f.input.UserID).Scan(&username, &hash, &revision, &email); err != nil {
			t.Fatal(err)
		}
		if username != f.input.NewUsername || revision != 2 || !strings.HasPrefix(hash, "$argon2id$") || !identity.VerifyPassword(hash, f.input.NewPassword) || email != f.input.ExpectedUsername+"@example.test" {
			t.Fatal("identity fields or Argon2id replacement mismatch")
		}
		stored, found, err := f.store.PlatformAdministratorRecoveryStatus(t.Context(), f.input.UserID, f.input.ScopeID, f.input.RequestID)
		if err != nil || !found || stored != receipt {
			t.Fatalf("receipt readback failed: %t %v", found, err)
		}
		if _, found, err := f.store.PlatformAdministratorRecoveryStatus(t.Context(), uuid.New(), f.input.ScopeID, f.input.RequestID); err != nil || found {
			t.Fatal("receipt leaked to another target")
		}
		var payload string
		var actor *uuid.UUID
		if err := f.pool.QueryRow(t.Context(), `SELECT payload::text,actor_user_id FROM audit_events WHERE action='identity.platform_admin.recover' AND request_id=$1`, f.input.RequestID).Scan(&payload, &actor); err != nil {
			t.Fatal(err)
		}
		if actor != nil || strings.Contains(payload, f.input.NewPassword) || strings.Contains(payload, hash) || !strings.Contains(payload, "local_root") {
			t.Fatal("local recovery audit leaked a secret or fabricated a logged-in actor")
		}
		if _, err := f.store.RecoverPlatformAdministrator(t.Context(), f.input); !errors.Is(err, identity.ErrPlatformRecoveryRequestUsed) {
			t.Fatalf("repeat request did not fail closed: %v", err)
		}
		f.input.RequestID = uuid.NewString()
		if _, err := f.store.RecoverPlatformAdministrator(t.Context(), f.input); !errors.Is(err, identity.ErrPlatformRecoveryPrecondition) {
			t.Fatalf("stale CAS retry was accepted: %v", err)
		}
		if _, err := f.service.AuthenticateSession(t.Context(), f.before.AccessToken); !errors.Is(err, identity.ErrInvalidSession) {
			t.Fatalf("old access remains accepted: %v", err)
		}
		if _, err := f.service.Refresh(t.Context(), f.before.RefreshToken, identity.RequestInfo{RequestID: uuid.NewString(), SourceIP: "198.51.100.10"}); !errors.Is(err, identity.ErrInvalidSession) {
			t.Fatalf("old refresh remains accepted: %v", err)
		}
		for _, login := range []identity.LoginInput{{Username: f.input.ExpectedUsername, Password: f.input.NewPassword}, {Username: f.input.NewUsername, Password: "fixture-before-password"}} {
			if _, err := f.service.Login(t.Context(), login, identity.RequestInfo{RequestID: uuid.NewString(), SourceIP: "198.51.100.10"}); !errors.Is(err, identity.ErrInvalidCredentials) {
				t.Fatalf("old credential remained valid: %v", err)
			}
		}
		login, err := f.service.Login(t.Context(), identity.LoginInput{Username: f.input.NewUsername, Password: f.input.NewPassword, ScopeID: &f.input.ScopeID}, identity.RequestInfo{RequestID: uuid.NewString(), SourceIP: "198.51.100.10"})
		if err != nil || login.Principal.UserID != f.input.UserID || login.Principal.ScopeID != f.input.ScopeID {
			t.Fatalf("recovered identity cannot log in: %v", err)
		}
	})
	for _, name := range []string{"wrong username", "wrong revision", "wrong scope", "disabled user", "disabled membership", "not platform owner", "tenant target", "username collision", "audit failure"} {
		t.Run(name, func(t *testing.T) {
			f := newPlatformRecoveryFixture(t)
			want := identity.ErrPlatformRecoveryPrecondition
			switch name {
			case "wrong username":
				f.input.ExpectedUsername = "wrong-username"
			case "wrong revision":
				f.input.ExpectedRevision++
			case "wrong scope":
				f.input.ScopeID = uuid.New()
			case "disabled user":
				if _, err := f.pool.Exec(t.Context(), `UPDATE users SET status='disabled' WHERE id=$1`, f.input.UserID); err != nil {
					t.Fatal(err)
				}
			case "disabled membership":
				if _, err := f.pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE user_id=$1`, f.input.UserID); err != nil {
					t.Fatal(err)
				}
			case "not platform owner":
				f.input.UserID = uuid.New()
				if _, err := f.pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'platform-no-owner','No owner','fixture')`, f.input.UserID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, f.input.ScopeID, f.input.UserID); err != nil {
					t.Fatal(err)
				}
				f.input.ExpectedUsername = "platform-no-owner"
			case "tenant target":
				u, err := f.service.CreateUser(t.Context(), identity.Actor{UserID: f.input.UserID, ScopeID: f.input.ScopeID, ScopeKind: "platform"}, identity.CreateUserInput{Username: "ordinary-tenant", Password: "fixture-before-password", Fields: identity.UserFields{DisplayName: "Tenant"}, Role: identity.UserRoleViewer, IdempotencyKey: uuid.NewString(), RequestID: uuid.NewString()})
				if err != nil {
					t.Fatal(err)
				}
				f.input.UserID = u.ID
				f.input.ScopeID = u.ScopeID
				f.input.ExpectedUsername = u.Username
			case "username collision":
				if _, err := f.pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Collision','fixture')`, uuid.New(), f.input.NewUsername); err != nil {
					t.Fatal(err)
				}
				want = identity.ErrPlatformRecoveryConflict
			case "audit failure":
				if _, err := f.pool.Exec(t.Context(), `CREATE FUNCTION reject_recovery_audit_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='identity.platform_admin.recover' THEN RAISE EXCEPTION 'fixture-secret-must-not-escape'; END IF; RETURN NEW; END $$;
				CREATE TRIGGER reject_recovery_audit_fixture BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_recovery_audit_fixture()`); err != nil {
					t.Fatal(err)
				}
				want = identity.ErrPlatformRecoveryUnavailable
			}
			const snapshot = `SELECT jsonb_build_object('user',(SELECT to_jsonb(u) FROM users u WHERE id=$1),'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM auth_sessions s WHERE user_id=$1))`
			var before, after []byte
			if err := f.pool.QueryRow(t.Context(), snapshot, f.input.UserID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.RecoverPlatformAdministrator(t.Context(), f.input); !errors.Is(err, want) || errors.Unwrap(err) != nil {
				t.Fatalf("recovery failure was not sanitized: %v", err)
			}
			if err := f.pool.QueryRow(t.Context(), snapshot, f.input.UserID).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("failed recovery changed identity or sessions")
			}
			if _, found, err := f.store.PlatformAdministratorRecoveryStatus(t.Context(), f.input.UserID, f.input.ScopeID, f.input.RequestID); err != nil || found {
				t.Fatalf("failed recovery has a committed receipt: %t %v", found, err)
			}
		})
	}
}

func TestPlatformAdministratorRecoveryConcurrentSessions(t *testing.T) {
	for _, order := range []string{"recovery-first", "login-first", "refresh-first"} {
		t.Run(order, func(t *testing.T) {
			f := newPlatformRecoveryFixture(t)
			pools := map[string]*pgxpool.Pool{}
			apps := map[string]string{}
			for _, name := range []string{"recover", "login", "refresh"} {
				cfg := f.pool.Config()
				app := "recovery-test-" + name + "-" + uuid.NewString()[:8]
				cfg.ConnConfig.RuntimeParams["application_name"] = app
				pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(pool.Close)
				pools[name] = pool
				apps[name] = app
			}
			wait := func(name string) {
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					var waiting bool
					if err := f.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND wait_event='advisory')`, apps[name]).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatal("operation did not join the shared global IAM lock queue")
			}
			holder, err := f.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(context.Background())
			if err := protocol.AcquireShared(t.Context(), holder); err != nil {
				t.Fatal(err)
			}
			tokens, err := identity.NewTokenManager("recovery-fixture-token-signing-not-production", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			loginService, err := identity.NewService(identity.NewStore(pools["login"]), tokens, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			refreshService, err := identity.NewService(identity.NewStore(pools["refresh"]), tokens, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			type sessionResult struct {
				result identity.AuthResult
				err    error
			}
			loginDone := make(chan sessionResult, 1)
			refreshDone := make(chan sessionResult, 1)
			recoveryDone := make(chan error, 1)
			start := func(name string) {
				switch name {
				case "recover":
					go func() {
						_, err := identity.NewStore(pools["recover"]).RecoverPlatformAdministrator(t.Context(), f.input)
						recoveryDone <- err
					}()
				case "login":
					go func() {
						result, err := loginService.Login(t.Context(), identity.LoginInput{Username: f.input.ExpectedUsername, Password: "fixture-before-password", ScopeID: &f.input.ScopeID}, identity.RequestInfo{RequestID: uuid.NewString(), SourceIP: "198.51.100.11"})
						loginDone <- sessionResult{result, err}
					}()
				case "refresh":
					go func() {
						result, err := refreshService.Refresh(t.Context(), f.before.RefreshToken, identity.RequestInfo{RequestID: uuid.NewString(), SourceIP: "198.51.100.12"})
						refreshDone <- sessionResult{result, err}
					}()
				}
				wait(name)
			}
			if order == "recovery-first" {
				start("recover")
				start("login")
				start("refresh")
			} else if order == "login-first" {
				start("login")
				start("recover")
				start("refresh")
			} else {
				start("refresh")
				start("recover")
				start("login")
			}
			if err := holder.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := <-recoveryDone; err != nil {
				t.Fatal(err)
			}
			login, refresh := <-loginDone, <-refreshDone
			if order == "login-first" {
				if login.err != nil {
					t.Fatal(login.err)
				}
			} else if !errors.Is(login.err, identity.ErrInvalidCredentials) {
				t.Fatalf("late old-password login was not denied: %v", login.err)
			}
			if order == "refresh-first" {
				if refresh.err != nil {
					t.Fatal(refresh.err)
				}
			} else if !errors.Is(refresh.err, identity.ErrInvalidSession) {
				t.Fatalf("late refresh was not denied: %v", refresh.err)
			}
			for _, result := range []identity.AuthResult{f.before, login.result, refresh.result} {
				if result.AccessToken != "" {
					if _, err := f.service.AuthenticateSession(t.Context(), result.AccessToken); !errors.Is(err, identity.ErrInvalidSession) {
						t.Fatalf("racing access token survived recovery: %v", err)
					}
				}
			}
			var active int
			if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_sessions WHERE user_id=$1 AND revoked_at IS NULL`, f.input.UserID).Scan(&active); err != nil {
				t.Fatal(err)
			}
			if active != 0 {
				t.Fatal("concurrent authentication left an active old-credential session")
			}
		})
	}
}
