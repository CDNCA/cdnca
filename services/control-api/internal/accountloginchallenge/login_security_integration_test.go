package accountloginchallenge

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This fixture uses the real password verifier, policy writer, OTP consumer,
// IAM locks, session store and audit writer. Only notification delivery is captured.
func TestPostgresLoginSecurityAtomicSession(t *testing.T) {
	pool := accountLoginChallengePool(t)
	password := "login-security-test-password"
	hash, err := identity.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	bootstrap, err := store.BootstrapPlatformUser(t.Context(), "login-security-admin", "Admin", hash, "security-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("s", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	adminLogin, err := issuer.Login(t.Context(), identity.LoginInput{Username: "login-security-admin", Password: password}, identity.RequestInfo{RequestID: "admin-login", SourceIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	adminSession, err := issuer.AuthenticateSession(t.Context(), adminLogin.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	actor := identity.Actor{UserID: bootstrap.UserID, ScopeID: bootstrap.ScopeID, ScopeKind: "platform", SessionID: adminSession.SessionID}
	user, err := issuer.CreateUser(t.Context(), actor, identity.CreateUserInput{Username: "login-security-user", Password: password, Fields: identity.UserFields{DisplayName: "Security user", Email: "security@example.com", Phone: "+8613812345678"}, Role: identity.UserRoleOwner, IdempotencyKey: "create-security-user", RequestID: "create-security-user"})
	if err != nil {
		t.Fatal(err)
	}
	settingsValue := systemusersettings.DefaultSettings()
	settingsValue.EmailCodeLoginEnabled, settingsValue.SMSCodeLoginEnabled = true, true
	settingsJSON, _ := json.Marshal(settingsValue)
	if _, err := pool.Exec(t.Context(), `INSERT INTO platform_system_user_settings(platform_scope_id,revision,settings,updated_by_user_id,updated_at) VALUES($1,1,$2,$3,now())`, bootstrap.ScopeID, settingsJSON, bootstrap.UserID); err != nil {
		t.Fatal(err)
	}
	contacts := new(capturingLoginContacts)
	clock := time.Now().UTC()
	service, err := NewService(pool, Config{DigestKey: []byte(strings.Repeat("d", 32)), Policy: staticLoginPolicy{emailEnabled: true, smsEnabled: true}, Issuer: issuer, Contacts: contacts, Clock: func() time.Time { return clock }, Entropy: strings.NewReader(strings.Repeat("\x00", 4096)), SourceLimit: 1000, SubjectLimit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	issuer.SetLoginChallengeConsumer(service)
	request := identity.RequestInfo{RequestID: "security-login", SourceIP: "192.0.2.1"}
	login := identity.LoginInput{Username: user.Username, Password: password, ScopeID: &user.ScopeID}
	policy := identity.UpdateManagedUserLoginSecurityInput{UserID: user.ID, TenantScopeID: user.ScopeID, ExpectedRevision: 0, LoginVerification: "email", LoginAllowlist: []string{"192.0.2.1"}, IdempotencyKey: "security-policy-1", RequestID: "security-policy-1"}
	var revision int64
	sessionCount := func() int {
		var count int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_sessions WHERE user_id=$1`, user.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	issue := func(key string) CreateResult {
		t.Helper()
		created, err := service.CreatePassword(t.Context(), PasswordCreateInput{Login: login, Request: request, Source: request.SourceIP, IdempotencyKey: key, RequestID: key})
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	proofLogin := func(created CreateResult, otp, key string) (identity.AuthResult, error) {
		input := login
		input.Challenge = &identity.LoginChallengeProof{ChallengeID: created.ChallengeID, OTP: otp, IdempotencyKey: key}
		return issuer.Login(t.Context(), input, request)
	}
	assertChallenge := func(id uuid.UUID, state string, attempts, receipts int) {
		t.Helper()
		var actualState string
		var actualAttempts, actualReceipts int
		if err := pool.QueryRow(t.Context(), `SELECT state,failed_attempts,(SELECT count(*) FROM account_login_challenge_verify_receipts_197 WHERE challenge_id=$1) FROM account_login_challenges_197 WHERE id=$1`, id).Scan(&actualState, &actualAttempts, &actualReceipts); err != nil {
			t.Fatal(err)
		}
		if actualState != state || actualAttempts != attempts || actualReceipts != receipts {
			t.Fatalf("challenge state=%s attempts=%d receipts=%d", actualState, actualAttempts, actualReceipts)
		}
	}
	t.Run("default and independent canonical revision receipt", func(t *testing.T) {
		initial, err := issuer.GetManagedUserLoginSecurity(t.Context(), actor, user.ID, user.ScopeID)
		if err != nil || initial.Revision != 0 || initial.LoginVerification != "none" || len(initial.LoginAllowlist) != 0 {
			t.Fatalf("default=%+v err=%v", initial, err)
		}
		if _, err := issuer.Login(t.Context(), login, request); err != nil {
			t.Fatal(err)
		}
		stored, err := issuer.UpdateManagedUserLoginSecurity(t.Context(), actor, policy)
		if err != nil || stored.Revision != 1 {
			t.Fatalf("policy=%+v err=%v", stored, err)
		}
		revision = stored.Revision
		replay, err := issuer.UpdateManagedUserLoginSecurity(t.Context(), actor, policy)
		if err != nil || replay.Revision != stored.Revision {
			t.Fatalf("replay=%+v err=%v", replay, err)
		}
		changed := policy
		changed.LoginVerification = "sms"
		if _, err := issuer.UpdateManagedUserLoginSecurity(t.Context(), actor, changed); !errors.Is(err, identity.ErrIdempotencyConflict) {
			t.Fatalf("conflict=%v", err)
		}
		var userRevision int64
		if err := pool.QueryRow(t.Context(), `SELECT revision FROM users WHERE id=$1`, user.ID).Scan(&userRevision); err != nil || userRevision != user.Revision {
			t.Fatalf("user revision changed=%d err=%v", userRevision, err)
		}
	})
	t.Run("real password and OTP cannot use passwordless bypass", func(t *testing.T) {
		before := sessionCount()
		var required *identity.LoginVerificationRequired
		if _, err := issuer.Login(t.Context(), login, request); !errors.As(err, &required) || required.Channel != "email" {
			t.Fatalf("required=%v err=%v", required, err)
		}
		created, err := service.Create(t.Context(), CreateInput{ScopeID: user.ScopeID, Identifier: "security@example.com", Channel: notification.ChannelEmail, Source: request.SourceIP, IdempotencyKey: "legacy-for-policy", RequestID: "legacy-for-policy"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Verify(t.Context(), VerifyInput{ScopeID: user.ScopeID, ChallengeID: created.ChallengeID, Identifier: "security@example.com", Channel: notification.ChannelEmail, Source: request.SourceIP, OTP: contacts.otp, IdempotencyKey: "bypass-attempt", RequestID: "bypass-attempt"}); !errors.Is(err, ErrOTPInvalid) {
			t.Fatalf("passwordless bypass=%v", err)
		}
		assertChallenge(created.ChallengeID, "queued", 0, 0)
		if _, err := proofLogin(created, "111111", "wrong-code"); !errors.Is(err, identity.ErrLoginChallengeInvalid) {
			t.Fatal(err)
		}
		assertChallenge(created.ChallengeID, "queued", 1, 1)
		if _, err := proofLogin(created, "111111", "wrong-code"); !errors.Is(err, identity.ErrLoginChallengeInvalid) {
			t.Fatal(err)
		}
		assertChallenge(created.ChallengeID, "queued", 1, 1)
		if _, err := proofLogin(created, "000000", "wrong-code"); !errors.Is(err, identity.ErrLoginChallengeIdempotencyConflict) {
			t.Fatal(err)
		}
		if sessionCount() != before {
			t.Fatal("denied login created a session")
		}
		if _, err := proofLogin(created, "000000", "valid-code"); err != nil {
			t.Fatal(err)
		}
		assertChallenge(created.ChallengeID, "consumed", 1, 2)
		if _, err := proofLogin(created, "000000", "replay-code"); !errors.Is(err, identity.ErrLoginChallengeUsed) {
			t.Fatal(err)
		}
		if sessionCount() != before+1 {
			t.Fatal("challenge replay created another session")
		}
	})
	for _, failureTable := range []string{"auth_sessions", "audit_events"} {
		t.Run("database failure rolls back OTP and session "+failureTable, func(t *testing.T) {
			created := issue("issue-rollback-" + failureTable)
			before := sessionCount()
			condition := fmt.Sprintf("NEW.user_id='%s'::uuid", user.ID)
			if failureTable == "audit_events" {
				condition = fmt.Sprintf("NEW.actor_user_id='%s'::uuid AND NEW.action='auth.login' AND NEW.result='success'", user.ID)
			}
			if _, err := pool.Exec(t.Context(), fmt.Sprintf(`CREATE FUNCTION login_security_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF %s THEN RAISE EXCEPTION 'injected login storage failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER login_security_fail BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION login_security_fail()`, condition, failureTable), pgx.QueryExecModeSimpleProtocol); err != nil {
				t.Fatal(err)
			}
			if _, err := proofLogin(created, "000000", "rollback-"+failureTable); err == nil {
				t.Fatal("injected database failure was ignored")
			}
			assertChallenge(created.ChallengeID, "queued", 0, 0)
			if sessionCount() != before {
				t.Fatal("failed transaction left session")
			}
			if _, err := pool.Exec(t.Context(), fmt.Sprintf(`DROP TRIGGER login_security_fail ON %s; DROP FUNCTION login_security_fail()`, failureTable), pgx.QueryExecModeSimpleProtocol); err != nil {
				t.Fatal(err)
			}
			if _, err := proofLogin(created, "000000", "rollback-"+failureTable); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("one real challenge creates at most one concurrent session", func(t *testing.T) {
		created := issue("issue-concurrent")
		before := sessionCount()
		results := make(chan error, 2)
		var wait sync.WaitGroup
		for i := 0; i < 2; i++ {
			wait.Add(1)
			go func(i int) {
				defer wait.Done()
				_, err := proofLogin(created, "000000", fmt.Sprintf("concurrent-%d", i))
				results <- err
			}(i)
		}
		wait.Wait()
		close(results)
		successes := 0
		for err := range results {
			if err == nil {
				successes++
			} else if !errors.Is(err, identity.ErrLoginChallengeUsed) {
				t.Fatal(err)
			}
		}
		if successes != 1 || sessionCount() != before+1 {
			t.Fatalf("successes=%d sessions=%d", successes, sessionCount()-before)
		}
	})
	t.Run("current policy revision source channel and expiry are enforced", func(t *testing.T) {
		created := issue("issue-old-policy")
		policy.ExpectedRevision = revision
		policy.IdempotencyKey = "policy-next"
		policy.RequestID = policy.IdempotencyKey
		updated, err := issuer.UpdateManagedUserLoginSecurity(t.Context(), actor, policy)
		if err != nil {
			t.Fatal(err)
		}
		revision = updated.Revision
		if _, err := proofLogin(created, "000000", "stale-policy"); !errors.Is(err, identity.ErrLoginChallengeInvalid) {
			t.Fatalf("stale policy=%v", err)
		}
		wrongSource := request
		wrongSource.SourceIP = ""
		if _, err := issuer.Login(t.Context(), login, wrongSource); !errors.Is(err, identity.ErrLoginSourceDenied) {
			t.Fatalf("source=%v", err)
		}
		created = issue("issue-expiring")
		clock = clock.Add(6 * time.Minute)
		if _, err := proofLogin(created, "000000", "expired"); !errors.Is(err, identity.ErrLoginChallengeInvalid) {
			t.Fatalf("expiry=%v", err)
		}
		clock = time.Now().UTC()
	})

	t.Run("five invalid attempts lock the real challenge", func(t *testing.T) {
		created := issue("issue-attempt-lock")
		before := sessionCount()
		for i := 0; i < 5; i++ {
			if _, err := proofLogin(created, "111111", fmt.Sprintf("locked-%d", i)); !errors.Is(err, identity.ErrLoginChallengeInvalid) {
				t.Fatalf("attempt%d: %v", i, err)
			}
		}
		assertChallenge(created.ChallengeID, "locked", 5, 5)
		if _, err := proofLogin(created, "000000", "locked-correct"); !errors.Is(err, identity.ErrLoginChallengeInvalid) {
			t.Fatalf("locked correct=%v", err)
		}
		assertChallenge(created.ChallengeID, "locked", 5, 6)
		if sessionCount() != before {
			t.Fatal("locked challenge created session")
		}
	})
	t.Run("current contact is checked again after issue", func(t *testing.T) {
		created := issue("issue-contact-change")
		updated, err := issuer.UpdateUser(t.Context(), actor, identity.UpdateUserInput{ID: user.ID, ExpectedRevision: user.Revision, Fields: identity.UserFields{DisplayName: user.DisplayName, Email: "changed@example.com", Phone: *user.Phone}, Status: user.Status, Role: user.Role, IdempotencyKey: "security-contact-change", RequestID: "security-contact-change"})
		if err != nil {
			t.Fatal(err)
		}
		user = updated
		if _, err := proofLogin(created, "000000", "old-contact"); !errors.Is(err, identity.ErrLoginChallengeInvalid) {
			t.Fatalf("old contact=%v", err)
		}
		assertChallenge(created.ChallengeID, "queued", 1, 1)
		created = issue("issue-current-contact")
		if contacts.destination != "changed@example.com" {
			t.Fatal("challenge sent to stale contact")
		}
		if _, err := proofLogin(created, "000000", "current-contact"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("SMS channel runtime and system switch are enforced", func(t *testing.T) {
		policy.ExpectedRevision = revision
		policy.LoginVerification = "sms"
		policy.IdempotencyKey = "policy-sms"
		policy.RequestID = policy.IdempotencyKey
		updated, err := issuer.UpdateManagedUserLoginSecurity(t.Context(), actor, policy)
		if err != nil {
			t.Fatal(err)
		}
		revision = updated.Revision
		created := issue("issue-sms")
		if contacts.destination != *user.Phone {
			t.Fatal("SMS challenge used wrong contact")
		}
		if _, err := proofLogin(created, "000000", "sms-success"); err != nil {
			t.Fatal(err)
		}
		created = issue("issue-sms-disabled")
		service.availableChannels = []notification.Channel{notification.ChannelEmail}
		if _, err := proofLogin(created, "000000", "sms-runtime-disabled"); !errors.Is(err, identity.ErrLoginSecurityUnavailable) {
			t.Fatalf("missing runtime=%v", err)
		}
		assertChallenge(created.ChallengeID, "queued", 0, 0)
		service.availableChannels = nil
		settings, err := systemusersettings.NewService(pool, audit.New(pool), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		settingsValue.SMSCodeLoginEnabled = false
		settingsActor := systemusersettings.Actor{UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind}
		if _, err := settings.Save(t.Context(), settingsActor, systemusersettings.SaveRequest{ExpectedRevision: 1, Value: settingsValue, IdempotencyKey: "disable-sms", RequestID: "disable-sms"}); err != nil {
			t.Fatal(err)
		}
		if _, err := proofLogin(created, "000000", "sms-system-disabled"); !errors.Is(err, identity.ErrLoginMethodDisabled) {
			t.Fatalf("disabled system=%v", err)
		}
		if _, err := service.CreatePassword(t.Context(), PasswordCreateInput{Login: login, Request: request, Source: request.SourceIP, IdempotencyKey: "disabled-issue", RequestID: "disabled-issue"}); !errors.Is(err, identity.ErrLoginMethodDisabled) {
			t.Fatalf("disabled issuance=%v", err)
		}
		assertChallenge(created.ChallengeID, "queued", 0, 0)
		settingsValue.SMSCodeLoginEnabled = true
		if _, err := settings.Save(t.Context(), settingsActor, systemusersettings.SaveRequest{ExpectedRevision: 2, Value: settingsValue, IdempotencyKey: "enable-sms", RequestID: "enable-sms"}); err != nil {
			t.Fatal(err)
		}
		if _, err := proofLogin(created, "000000", "sms-reenabled"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("password changes cannot be bypassed by an issued OTP", func(t *testing.T) {
		created := issue("issue-password-change")
		tenantActor := identity.Actor{UserID: user.ID, ScopeID: user.ScopeID, ScopeKind: "tenant"}
		newPassword := "login-security-new-password"
		if err := issuer.ChangePassword(t.Context(), tenantActor, identity.ChangePasswordInput{CurrentPassword: password, NewPassword: newPassword, RequestID: "security-password-change"}); err != nil {
			t.Fatal(err)
		}
		before := sessionCount()
		if _, err := proofLogin(created, "000000", "old-password"); !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Fatalf("old password=%v", err)
		}
		assertChallenge(created.ChallengeID, "queued", 0, 0)
		if sessionCount() != before {
			t.Fatal("old password created session")
		}
		login.Password = newPassword
		if _, err := proofLogin(created, "000000", "new-password"); err != nil {
			t.Fatal(err)
		}
	})
}
