package accountloginchallenge

import (
	"context"
 "encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresLoginChallengeCreatesOneTimeVerifiedSession(t *testing.T) {
	pool := accountLoginChallengePool(t)
	scopeID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL);
		INSERT INTO users(id,username,display_name,email,phone,password_hash,status)
			VALUES($2,'login-code-owner','Login code owner','owner@example.com','+8613812345678','not-used','active');
		INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`,
		pgx.QueryExecModeSimpleProtocol, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("l", 32), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	contacts := new(capturingLoginContacts)
	service, err := NewService(pool, Config{
		DigestKey: []byte(strings.Repeat("d", 32)), Policy: staticLoginPolicy{emailEnabled: true, smsEnabled: true}, Issuer: issuer,
		Contacts: contacts, Clock: func() time.Time { return now }, Entropy: strings.NewReader(strings.Repeat("\x00", 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
 issuer.SetLoginChallengeConsumer(service)
 settings := systemusersettings.DefaultSettings()
 settings.EmailCodeLoginEnabled, settings.SMSCodeLoginEnabled = true, true
 rawSettings, _ := json.Marshal(settings)
 if _, err := pool.Exec(t.Context(), `INSERT INTO platform_system_user_settings(platform_scope_id,revision,settings,updated_by_user_id,updated_at) VALUES($1,1,$2,$3,now())`, scopeID, rawSettings, userID); err != nil { t.Fatal(err) }
	created, err := service.Create(t.Context(), CreateInput{
		ScopeID: scopeID, Identifier: "OWNER@EXAMPLE.COM", Channel: notification.ChannelEmail, Source: "192.0.2.44",
		IdempotencyKey: "login-create-1", RequestID: "login-request-1",
	})
	if err != nil || created.ChallengeID == uuid.Nil || contacts.calls != 1 || contacts.otp != "000000" ||
		contacts.destination != "owner@example.com" {
		t.Fatalf("created=(%+v,%v) contacts=%+v", created, err, contacts)
	}
	replayed, err := service.Create(t.Context(), CreateInput{
		ScopeID: scopeID, Identifier: "owner@example.com", Channel: notification.ChannelEmail, Source: "192.0.2.44",
		IdempotencyKey: "login-create-1", RequestID: "login-request-1",
	})
	if err != nil || !replayed.Replayed || replayed.ChallengeID != created.ChallengeID || contacts.calls != 1 {
		t.Fatalf("replayed=(%+v,%v) contact calls=%d", replayed, err, contacts.calls)
	}
	if _, err := service.Create(t.Context(), CreateInput{
		ScopeID: scopeID, Identifier: "other@example.com", Channel: notification.ChannelEmail, Source: "192.0.2.44",
		IdempotencyKey: "login-create-1", RequestID: "login-request-1",
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("create conflict error=%v", err)
	}
	unknown, err := service.Create(t.Context(), CreateInput{
		ScopeID: scopeID, Identifier: "unknown@example.com", Channel: notification.ChannelEmail, Source: "192.0.2.45",
		IdempotencyKey: "login-create-unknown", RequestID: "login-request-unknown",
	})
	if err != nil || unknown.ChallengeID == uuid.Nil || contacts.calls != 1 {
		t.Fatalf("unknown result=(%+v,%v) contact calls=%d", unknown, err, contacts.calls)
	}
	if _, err := service.Verify(t.Context(), VerifyInput{
		ScopeID: scopeID, ChallengeID: created.ChallengeID, Identifier: "owner@example.com", Channel: notification.ChannelEmail,
		Source: "192.0.2.44", OTP: "111111", IdempotencyKey: "login-verify-invalid", RequestID: "login-request-2",
	}); !errors.Is(err, ErrOTPInvalid) {
		t.Fatalf("invalid OTP error=%v", err)
	}
	verified, err := service.Verify(t.Context(), VerifyInput{
		ScopeID: scopeID, ChallengeID: created.ChallengeID, Identifier: "owner@example.com", Channel: notification.ChannelEmail,
		Source: "192.0.2.44", OTP: contacts.otp, IdempotencyKey: "login-verify-success", RequestID: "login-request-3",
		UserAgent: "login-integration-test",
	})
	if err != nil || verified.Auth.AccessToken == "" || verified.Auth.RefreshToken == "" ||
		verified.Auth.Principal.UserID != userID || verified.Auth.Principal.ScopeID != scopeID {
		t.Fatalf("verified=(%+v,%v)", verified, err)
	}
	if _, err := service.Verify(t.Context(), VerifyInput{
		ScopeID: scopeID, ChallengeID: created.ChallengeID, Identifier: "owner@example.com", Channel: notification.ChannelEmail,
		Source: "192.0.2.44", OTP: contacts.otp, IdempotencyKey: "login-verify-replay", RequestID: "login-request-4",
	}); !errors.Is(err, ErrChallengeUsed) {
		t.Fatalf("verification replay error=%v", err)
	}
	smsCreated, err := service.Create(t.Context(), CreateInput{
		ScopeID: scopeID, Identifier: "+8613812345678", Channel: notification.ChannelSMS, Source: "192.0.2.46",
		IdempotencyKey: "login-create-sms", RequestID: "login-request-sms-1",
	})
	if err != nil || smsCreated.ChallengeID == uuid.Nil || contacts.calls != 2 || contacts.destination != "+8613812345678" {
		t.Fatalf("SMS native challenge=(%+v,%v) contacts=%+v", smsCreated, err, contacts)
	}
	smsVerified, err := service.Verify(t.Context(), VerifyInput{
		ScopeID: scopeID, ChallengeID: smsCreated.ChallengeID, Identifier: "+8613812345678", Channel: notification.ChannelSMS,
		Source: "192.0.2.46", OTP: contacts.otp, IdempotencyKey: "login-verify-sms", RequestID: "login-request-sms-2",
		UserAgent: "login-integration-test",
	})
	if err != nil || smsVerified.Auth.Principal.UserID != userID {
		t.Fatalf("SMS native verification=(%+v,%v)", smsVerified, err)
	}
	var sessionCount, auditCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_sessions WHERE user_id=$1 AND scope_id=$2`, userID, scopeID).Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action='auth.login' AND result='success'
		AND payload->>'authentication_method' IN ('email_code','sms_code')`, scopeID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 2 || auditCount != 2 {
		t.Fatalf("sessions=%d login audits=%d", sessionCount, auditCount)
	}
}

type staticLoginPolicy struct {
	emailEnabled bool
	smsEnabled   bool
}

func (policy staticLoginPolicy) GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error) {
	return systemusersettings.PublicSettings{
		EmailCodeLoginEnabled: policy.emailEnabled, EmailAntiAbuseMode: "none",
		SMSCodeLoginEnabled: policy.smsEnabled, SMSAntiAbuseMode: "native",
	}, nil
}

type capturingLoginContacts struct {
	calls       int
	destination string
	otp         string
}

func (contacts *capturingLoginContacts) Enqueue(_ context.Context, _ pgx.Tx, request ContactRequest) error {
	contacts.calls++
	contacts.destination = request.Destination
	contacts.otp = request.OTP
	return nil
}

func accountLoginChallengePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := admin.Acquire(t.Context())
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	for _, lock := range []string{"hashtextextended('cdnca-jobhttp-command-external-roles',0)", "726491175848210"} {
		if _, err := connection.Exec(t.Context(), "SELECT pg_advisory_lock("+lock+")"); err != nil {
			connection.Release()
			admin.Close()
			t.Fatal(err)
		}
	}
	databaseName := "account_login_challenge_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^account_login_challenge_[a-f0-9]{32}$`).MatchString(databaseName) {
		t.Fatalf("unsafe database name %q", databaseName)
	}
	identifier := pgx.Identifier{databaseName}.Sanitize()
	databaseCreated := false
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		cleanupCtx, cancel := databasetest.CleanupContext()
		defer cancel()
		if databaseCreated {
			if _, err := connection.Exec(cleanupCtx, "DROP DATABASE "+identifier+" WITH (FORCE)"); err != nil {
				t.Errorf("drop database: %v", err)
			}
		}
		for _, lock := range []string{"726491175848210", "hashtextextended('cdnca-jobhttp-command-external-roles',0)"} {
			var unlocked bool
			if err := connection.QueryRow(cleanupCtx, "SELECT pg_advisory_unlock("+lock+")").Scan(&unlocked); err != nil || !unlocked {
				t.Errorf("unlock migration role lock %s: unlocked=%t err=%v", lock, unlocked, err)
			}
		}
		connection.Release()
		admin.Close()
	})
	var safeRoles bool
	if err := connection.QueryRow(t.Context(), `SELECT
		to_regrole('cdnca_control_app') IS NOT NULL AND to_regrole('cdnca_plugin_webhook_runtime') IS NOT NULL
		AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('cdnca_control_app','cdnca_plugin_webhook_runtime')
			AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))`).Scan(&safeRoles); err != nil || !safeRoles {
		t.Fatalf("migration roles are unavailable or unsafe: safe=%t err=%v", safeRoles, err)
	}
	if _, err := connection.Exec(t.Context(), "CREATE DATABASE "+identifier); err != nil {
		t.Fatal(err)
	}
	databaseCreated = true
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.Database = databaseName
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err = pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER SCHEMA public OWNER TO CURRENT_USER;
		REVOKE ALL ON SCHEMA public FROM PUBLIC;
		GRANT ALL ON SCHEMA public TO CURRENT_USER`); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	pool.Close()
	pool = nil
	runtimeConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	runtimeConfig.ConnConfig.Database = databaseName
	pool, err = pgxpool.NewWithConfig(t.Context(), runtimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}
