//go:build integration

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeyusage"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestAPIKeyUsageRuntimeCompositionDrainsToPostgres(t *testing.T) {
	taskID := strings.TrimSpace(os.Getenv("CDNCA_API_KEY_USAGE_COMPOSITION_TASK_ID"))
	if taskID == "" {
		t.Skip("task-only API key usage composition environment is required")
	}
	pool := newDashboardCompositionTestPool(t)
	var version, listenAddresses, socketDirectory string
	if err := pool.QueryRow(t.Context(), `SELECT current_setting('server_version_num'),
		current_setting('listen_addresses'),current_setting('unix_socket_directories')`).Scan(
		&version, &listenAddresses, &socketDirectory,
	); err != nil {
		t.Fatal(err)
	}
	if version != "170009" || listenAddresses != "" || pool.Config().ConnConfig.Host != socketDirectory ||
		!strings.Contains(socketDirectory, taskID) {
		t.Fatalf("non-task PostgreSQL rejected: version=%s listen=%q host=%q socket=%q",
			version, listenAddresses, pool.Config().ConnConfig.Host, socketDirectory)
	}

	now := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	tenantID, scopeID, userID, roleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `
			WITH new_tenant AS (
				INSERT INTO tenants(id,display_name,created_at,updated_at) VALUES($1,'Usage tenant',$5,$5)
			), new_scope AS (
				INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($2,'tenant',$1,$5)
			), new_user AS (
				INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
				VALUES($3,'usage-runtime-user','Usage Runtime User','test-hash',$5,$5)
			), new_membership AS (
				INSERT INTO memberships(scope_id,user_id,created_at) VALUES($2,$3,$5)
			), new_role AS (
				INSERT INTO roles(id,scope_id,name,description,system_role,created_at)
				VALUES($4,$2,'usage_runtime_owner','Usage runtime owner',true,$5)
			), new_permissions AS (
				INSERT INTO role_permissions(role_id,permission_name)
				VALUES($4,'api_keys.self.manage'),($4,'sites.read')
			)
			INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($2,$3,$4,$5)`,
			tenantID, scopeID, userID, roleID, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	principal := identity.Principal{
		UserID: userID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: &tenantID,
		Permissions: []string{"api_keys.self.manage", "sites.read"},
	}
	pepper := bytes.Repeat([]byte{0x75}, 32)
	keyService := apikey.NewService(pool, pepper, func() time.Time { return now })
	expiresAt := now.Add(time.Hour)
	issued, err := keyService.CreateSelf(t.Context(), principal, apikey.CreateInput{
		Name: "composition usage", Scopes: []string{"sites.read"}, ExpiresAt: &expiresAt,
		IdempotencyKey: "composition-usage-create", RequestID: "composition-usage-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := newAPIKeyUsageRuntime(pool)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := now
	api := httpapi.New(pool, nil, httpapi.Config{
		APIKeyPepper: pepper, Now: func() time.Time { return observedAt }, APIKeyUsageRecorder: runtime,
	})
	credential := issued.Key.KeyID + "." + issued.Secret
	for attempt := 0; attempt < 2; attempt++ {
		request := httptest.NewRequest(http.MethodGet, "/v1/sites", nil)
		request.Header.Set("Authorization", "CdncaKey "+credential)
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("authenticated attempt %d status=%d body=%s", attempt+1, response.Code, response.Body.String())
		}
		observedAt = observedAt.Add(500 * time.Millisecond)
	}
	latestObservedAt := observedAt.Add(-500 * time.Millisecond)

	revoked, err := keyService.CreateSelf(t.Context(), principal, apikey.CreateInput{
		Name: "composition revoked", Scopes: []string{"sites.read"}, ExpiresAt: &expiresAt,
		IdempotencyKey: "composition-revoked-create", RequestID: "composition-revoked-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	revokedRequest := httptest.NewRequest(http.MethodGet, "/v1/sites", nil)
	revokedRequest.Header.Set("Authorization", "CdncaKey "+revoked.Key.KeyID+"."+revoked.Secret)
	revokedResponse := httptest.NewRecorder()
	api.Handler().ServeHTTP(revokedResponse, revokedRequest)
	if revokedResponse.Code != http.StatusOK {
		t.Fatalf("pre-revoke request status=%d body=%s", revokedResponse.Code, revokedResponse.Body.String())
	}
	if _, err := keyService.RevokeSelf(t.Context(), principal, apikey.MutationInput{
		ID: revoked.Key.ID, ExpectedRevision: revoked.Key.Revision,
		IdempotencyKey: "composition-revoked-revoke", RequestID: "composition-revoked-revoke",
	}); err != nil {
		t.Fatal(err)
	}
	worker, ok := runtime.worker.(*apikeyusage.Runtime)
	if !ok || worker.Counters().Accepted != 3 {
		t.Fatalf("TryRecord attempts = %#v, want three accepted attempts", worker.Counters())
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("idempotent runtime close: %v", err)
	}
	var lastUsedAt *time.Time
	if err := pool.QueryRow(t.Context(), `SELECT last_used_at FROM api_keys WHERE id=$1`,
		issued.Key.ID).Scan(&lastUsedAt); err != nil {
		t.Fatal(err)
	}
	if lastUsedAt == nil || !lastUsedAt.Equal(latestObservedAt) {
		t.Fatalf("retry-merged last_used_at = %v, want %v", lastUsedAt, latestObservedAt)
	}
	var revokedLastUsedAt *time.Time
	if err := pool.QueryRow(t.Context(), `SELECT last_used_at FROM api_keys WHERE id=$1`,
		revoked.Key.ID).Scan(&revokedLastUsedAt); err != nil {
		t.Fatal(err)
	}
	if revokedLastUsedAt != nil {
		t.Fatalf("pre-flush revoked key persisted last_used_at %v", *revokedLastUsedAt)
	}
	if err := pool.Ping(t.Context()); err != nil {
		t.Fatalf("runtime closed caller-owned pool: %v", err)
	}
}
