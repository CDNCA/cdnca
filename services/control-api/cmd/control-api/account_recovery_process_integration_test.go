//go:build integration

package main

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoverycontext"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var accountRecoveryURLPattern = regexp.MustCompile(`https://console[.]example[.]test/reset#[^\r\n]+`)

func TestAccountRecoveryProductionContextNotificationAndConfirmationPostgreSQL17(t *testing.T) {
	pool := openNotificationRuntimeDatabase(t)
	server := newSMTPTestServer(t, smtpTestServerConfig{})
	tenantID, scopeID, userID, username := seedAccountRecoveryProcessIdentity(t, pool)
	seedAccountRecoveryProcessHost(t, pool, "recovery.example.test", tenantID, scopeID, userID)
	seedAccountRecoveryProcessSession(t, pool, userID, scopeID)

	template := notification.TemplateRef{ID: "account_recovery_email", Version: 1, Channel: notification.ChannelEmail}
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref: template, Subject: "重置密码", Body: "请使用安全链接重置密码", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	notificationRuntime, err := openNotificationProcessRuntime(t.Context(), notificationRuntimeConfig{
		Enabled: true, Worker: notification.WorkerConfig{
			BatchSize: 1, LeaseDuration: 2 * time.Second, LeaseSafetyMargin: 250 * time.Millisecond,
			MaxAttempts: 3, BaseDelay: 20 * time.Millisecond, MaxDelay: 100 * time.Millisecond,
		},
		RecoveryTemplates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: template},
		EmailProvider:     notificationEmailProviderSMTPTLS, SMTP: server.clientConfig(),
		IdleWait: 5 * time.Millisecond, ErrorBackoffBase: 10 * time.Millisecond,
		ErrorBackoffMax: 50 * time.Millisecond, MaxConsecutiveFailures: 3,
		SendTimeout: time.Second, StartupTimeout: time.Second, ShutdownTimeout: time.Second,
	}, pool, notificationRuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := notificationRuntime.Close(); err != nil {
			t.Errorf("close notification runtime: %v", err)
		}
	})

	resolver, err := accountrecoverycontext.NewResolver(pool, accountrecoverycontext.Config{})
	if err != nil {
		t.Fatal(err)
	}
	recoveryConfig := validAccountRecoveryRuntimeConfig(t)
	recoveryRuntime, err := openAccountRecoveryRuntime(
		t.Context(), recoveryConfig, pool, nil, accountRecoveryRuntimeDependencies{
			TrustedContext: resolver.Resolve, Notifications: notificationRuntime,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := recoveryRuntime.Close(); err != nil {
			t.Errorf("close account recovery runtime: %v", err)
		}
	})
	handler := withAccountRecoveryRoutes(http.NotFoundHandler(), recoveryRuntime)

	unknownHost := accountRecoveryProcessRequest(t, accountRecoveryRequestPath, "unknown.example.test", map[string]string{
		"username": username,
	}, "unknown-host")
	unknownHostResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownHostResponse, unknownHost)
	if unknownHostResponse.Code != http.StatusServiceUnavailable ||
		!strings.Contains(unknownHostResponse.Body.String(), "account_recovery_unavailable") {
		t.Fatalf("unknown host response=%d body=%q", unknownHostResponse.Code, unknownHostResponse.Body.String())
	}

	unknownAccount := accountRecoveryProcessRequest(t, accountRecoveryRequestPath, "recovery.example.test", map[string]string{
		"username": "missing-account",
	}, "unknown-account")
	unknownAccountResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownAccountResponse, unknownAccount)
	knownAccount := accountRecoveryProcessRequest(t, accountRecoveryRequestPath, "recovery.example.test", map[string]string{
		"username": username,
	}, "known-account")
	knownAccountResponse := httptest.NewRecorder()
	handler.ServeHTTP(knownAccountResponse, knownAccount)
	var unknownEnvelope, knownEnvelope struct {
		Data struct {
			Code       string `json:"code"`
			AcceptedAt string `json:"accepted_at"`
		} `json:"data"`
	}
	unknownDecode := json.Unmarshal(unknownAccountResponse.Body.Bytes(), &unknownEnvelope)
	knownDecode := json.Unmarshal(knownAccountResponse.Body.Bytes(), &knownEnvelope)
	_, unknownTimeErr := time.Parse(time.RFC3339Nano, unknownEnvelope.Data.AcceptedAt)
	_, knownTimeErr := time.Parse(time.RFC3339Nano, knownEnvelope.Data.AcceptedAt)
	if unknownAccountResponse.Code != http.StatusAccepted || knownAccountResponse.Code != http.StatusAccepted ||
		unknownDecode != nil || knownDecode != nil || unknownTimeErr != nil || knownTimeErr != nil ||
		unknownEnvelope.Data.Code != "account_recovery_request_accepted" ||
		knownEnvelope.Data.Code != unknownEnvelope.Data.Code {
		t.Fatalf("enumerating responses unknown=(%d,%q) known=(%d,%q)",
			unknownAccountResponse.Code, unknownAccountResponse.Body.String(),
			knownAccountResponse.Code, knownAccountResponse.Body.String())
	}

	waitForCondition(t, 2*time.Second, func() bool { return len(server.messages()) == 1 })
	message, err := mail.ReadMessage(strings.NewReader(server.messages()[0]))
	if err != nil {
		t.Fatal(err)
	}
	decodedBody, err := io.ReadAll(quotedprintable.NewReader(message.Body))
	if err != nil {
		t.Fatal(err)
	}
	match := accountRecoveryURLPattern.FindString(string(decodedBody))
	parsed, err := url.Parse(match)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment == "" {
		t.Fatalf("recovery URL=%q error=%v", match, err)
	}
	fragment, err := url.ParseQuery(parsed.Fragment)
	if err != nil || fragment.Get("token") == "" || fragment.Get("recovery_context") == "" {
		t.Fatalf("recovery fragment=%q error=%v", parsed.Fragment, err)
	}

	newPassword := "Production-recovery-password-2"
	confirmation := accountRecoveryProcessRequest(t, accountRecoveryConfirmationPath, "recovery.example.test", map[string]string{
		"token": fragment.Get("token"), "recovery_context": fragment.Get("recovery_context"),
		"new_password": newPassword, "confirm_password": newPassword,
	}, "confirmation")
	confirmationResponse := httptest.NewRecorder()
	handler.ServeHTTP(confirmationResponse, confirmation)
	if confirmationResponse.Code != http.StatusNoContent {
		t.Fatalf("confirmation response=%d body=%q", confirmationResponse.Code, confirmationResponse.Body.String())
	}
	var passwordHash string
	var activeSessions int
	if err := pool.QueryRow(t.Context(), `SELECT password_hash FROM users WHERE id=$1`, userID).Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_sessions WHERE user_id=$1 AND revoked_at IS NULL`, userID).
		Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if !identity.VerifyPassword(passwordHash, newPassword) || activeSessions != 0 {
		t.Fatalf("password/session result verified=%t active_sessions=%d",
			identity.VerifyPassword(passwordHash, newPassword), activeSessions)
	}
}

func accountRecoveryProcessRequest(
	t *testing.T,
	path, host string,
	body map[string]string,
	idempotencyKey string,
) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://"+host+path, strings.NewReader(string(encoded)))
	request.RemoteAddr = "198.51.100.80:443"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("Authorization", "Bearer ignored")
	request.Header.Set("Cookie", "cdnca_refresh=ignored")
	request.Header.Set("X-Tenant-ID", uuid.NewString())
	request.Header.Set("X-Scope-ID", uuid.NewString())
	return request
}

func seedAccountRecoveryProcessIdentity(
	t *testing.T,
	pool *pgxpool.Pool,
) (uuid.UUID, uuid.UUID, uuid.UUID, string) {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	username := "recovery-process-" + strings.ReplaceAll(userID.String(), "-", "")[:12]
	hash, err := identity.HashPassword("Original-recovery-password-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Recovery process tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,email,password_hash)
		 VALUES($1,$2,'Recovery process user','recovery-process@example.test',$3)`, []any{userID, username, hash}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return tenantID, scopeID, userID, username
}

func seedAccountRecoveryProcessHost(
	t *testing.T,
	pool *pgxpool.Pool,
	hostname string,
	tenantID, scopeID, userID uuid.UUID,
) {
	t.Helper()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO account_recovery_public_host_revisions(
			hostname,revision,tenant_id,tenant_scope_id,state,actor_user_id,actor_scope_id,
			request_id,trace_id,recorded_at
		) VALUES($1,1,$2,$3,'active',$4,$3,'process-host-binding',
			'0123456789abcdef0123456789abcdef',now())`, hostname, tenantID, scopeID, userID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO account_recovery_public_hosts(
			hostname,tenant_id,tenant_scope_id,state,current_revision,created_at,updated_at
		) VALUES($1,$2,$3,'active',1,now(),now())`, hostname, tenantID, scopeID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func seedAccountRecoveryProcessSession(t *testing.T, pool *pgxpool.Pool, userID, scopeID uuid.UUID) {
	t.Helper()
	digest := sha256.Sum256([]byte(uuid.NewString()))
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,now(),now()+interval '1 hour')`,
		uuid.New(), uuid.New(), userID, scopeID, digest[:]); err != nil {
		t.Fatal(err)
	}
}
