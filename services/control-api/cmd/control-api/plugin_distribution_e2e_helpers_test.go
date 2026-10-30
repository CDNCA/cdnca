package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func waitLicenseFixture(t *testing.T, path string) licenseFixture {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		encoded, err := os.ReadFile(path)
		if err == nil {
			var fixture licenseFixture
			if err := json.Unmarshal(encoded, &fixture); err != nil {
				t.Fatal(err)
			}
			return fixture
		}
		if time.Now().After(deadline) {
			t.Fatalf("license fixture %s not ready: %v", path, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// postOperator asks the license half to act as the platform operator; path may carry ?plugin=<id>.
func postOperator(fixture licenseFixture, path string, body any) int {
	encoded, _ := json.Marshal(body)
	if body == nil {
		encoded = nil
	}
	response, err := http.Post(fixture.OperatorURL+path, "application/json", bytes.NewReader(encoded))
	if err != nil {
		return 0
	}
	defer response.Body.Close()
	return response.StatusCode
}

type licenseAuthorization struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	Revision uint64 `json:"revision"`
	Receipts []struct {
		Action           string `json:"action"`
		StableReasonCode string `json:"stable_reason_code"`
	} `json:"transition_receipts"`
}

func (authorization licenseAuthorization) receiptActions() []string {
	actions := make([]string, 0, len(authorization.Receipts))
	for _, receipt := range authorization.Receipts {
		actions = append(actions, receipt.Action)
	}
	return actions
}

func licenseState(t *testing.T, fixture licenseFixture, pluginID string) licenseAuthorization {
	t.Helper()
	response, err := http.Get(fixture.OperatorURL + "/state?plugin=" + pluginID)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var state licenseAuthorization
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&state) != nil {
		t.Fatalf("license state status=%d", response.StatusCode)
	}
	return state
}

// controlE2EDatabase migrates a fresh control-api schema and seeds one tenant administrator whose role grants the
// production plugin installation permissions. It returns a token minter for that administrator's session.
func controlE2EDatabase(t *testing.T, databaseURL string) (*pgxpool.Pool, uuid.UUID,
	func(*identity.TokenManager) string) {
	t.Helper()
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "plugin_distribution_e2e_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		// t.Context() is already cancelled when cleanup runs.
		cleanupCtx, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	// A tenant's access scope shares the tenant UUID; the plugin installation routes require that identity.
	tenantID, userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	scopeID := tenantID
	now := time.Now().UTC().Truncate(time.Second)
	refresh := sha256.Sum256(sessionID[:])
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'插件联调租户')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'plugin-e2e-admin','插件管理员','unused')`,
			[]any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','owner',true)`,
			[]any{roleID, scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'plugin_installations.read'),
			($1,'plugin_installations.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{scopeID, userID, roleID}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, []any{sessionID, uuid.New(), userID, scopeID, refresh[:],
			now.Add(-time.Minute), now.Add(time.Hour)}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return pool, scopeID, func(tokens *identity.TokenManager) string {
		raw, _, err := tokens.Mint(userID, scopeID, sessionID)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
}

type upgradeView struct {
	VerificationID string   `json:"verification_id"`
	Version        string   `json:"version"`
	ApprovedScopes []string `json:"approved_scopes"`
}

type installationView struct {
	AuthorizationID     uuid.UUID    `json:"authorization_id"`
	VerificationID      string       `json:"verification_id"`
	Version             string       `json:"version"`
	Status              string       `json:"status"`
	Revision            uint64       `json:"revision"`
	ApprovedScopes      []string     `json:"approved_scopes"`
	LKGVersion          *string      `json:"lkg_version"`
	AuthorizationStatus string       `json:"authorization_status"`
	AvailableUpgrade    *upgradeView `json:"available_upgrade"`
}

type installationPage struct {
	Items []installationView `json:"items"`
}

func (page installationPage) find(id uuid.UUID) *installationView {
	for index := range page.Items {
		if page.Items[index].AuthorizationID == id {
			return &page.Items[index]
		}
	}
	return nil
}

// controlClient calls the production plugin installation handler the way the management console does.
type controlClient struct {
	t        *testing.T
	handler  http.Handler
	token    string
	tenantID uuid.UUID
	// platform calls /v1/platform/plugin-installations (instance-wide themes and rule packs).
	platform bool
}

func (client controlClient) do(method, path string, headers map[string]string, body any) *httptest.ResponseRecorder {
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	prefix := "/v1/tenant-scopes/" + client.tenantID.String() + "/plugin-installations"
	if client.platform {
		prefix = "/v1/platform/plugin-installations"
	}
	request := httptest.NewRequest(method, prefix+path, bytes.NewReader(encoded))
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("X-Request-ID", "plugin-e2e-"+uuid.NewString()[:8])
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	client.handler.ServeHTTP(response, request)
	return response
}

func (client controlClient) list() installationPage {
	client.t.Helper()
	response := client.do(http.MethodGet, "", nil, nil)
	var page installationPage
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil {
		client.t.Fatalf("list status=%d body=%s", response.Code, response.Body.String())
	}
	return page
}

func (client controlClient) get(id uuid.UUID) installationView {
	client.t.Helper()
	response := client.do(http.MethodGet, "/"+id.String(), nil, nil)
	var view installationView
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &view) != nil {
		client.t.Fatalf("get status=%d body=%s", response.Code, response.Body.String())
	}
	return view
}

func (client controlClient) mutate(id uuid.UUID, action string, revision uint64, body any,
	want int) installationView {
	client.t.Helper()
	// A 503 (license unavailable / result unknown) is retried with the same body, revision and idempotency key, as
	// the management console does; the server either finishes the original attempt or replays its result.
	headers := map[string]string{"If-Match": `"` + jsonNumber(revision) + `"`,
		"Idempotency-Key": action + "-" + uuid.NewString()[:8]}
	response := client.do(http.MethodPost, "/"+id.String()+"/"+action, headers, body)
	for attempt := 0; attempt < 4 && response.Code == http.StatusServiceUnavailable; attempt++ {
		client.t.Logf("%s answered 503 (%s); retrying the same request", action, strings.TrimSpace(response.Body.String()))
		time.Sleep(2 * time.Second)
		response = client.do(http.MethodPost, "/"+id.String()+"/"+action, headers, body)
	}
	var wrapper struct {
		Installation installationView `json:"installation"`
	}
	if response.Code != want || json.Unmarshal(response.Body.Bytes(), &wrapper) != nil {
		client.t.Fatalf("%s status=%d body=%s", action, response.Code, response.Body.String())
	}
	return wrapper.Installation
}

func jsonNumber(value uint64) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

// platformE2EToken adds a platform administrator (system role platform_owner of the platform scope, which
// migration 600 grants plugin_installations.platform.*) and returns a session token minter.
func platformE2EToken(t *testing.T, pool *pgxpool.Pool) func(*identity.TokenManager) string {
	t.Helper()
	ctx := t.Context()
	userID, sessionID := uuid.New(), uuid.New()
	var scopeID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).
		Scan(&scopeID); err != nil {
		scopeID = uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL)`, scopeID); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	refresh := sha256.Sum256(sessionID[:])
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'plugin-e2e-platform','平台管理员','unused')`,
			[]any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		// Fresh installs create platform_owner at bootstrap with every permission (identity.BootstrapPlatformUser).
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'platform_owner','owner',true)
			ON CONFLICT (scope_id,name) DO NOTHING`, []any{uuid.New(), scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) SELECT role.id,permission.name FROM roles role
			CROSS JOIN (VALUES ('plugin_installations.platform.read'),('plugin_installations.platform.manage')) permission(name)
			WHERE role.scope_id=$1 AND role.name='platform_owner' ON CONFLICT DO NOTHING`, []any{scopeID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) SELECT $1,$2,id FROM roles
			WHERE scope_id=$1 AND system_role AND name='platform_owner'`, []any{scopeID, userID}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, []any{sessionID, uuid.New(), userID, scopeID, refresh[:],
			now.Add(-time.Minute), now.Add(time.Hour)}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return func(tokens *identity.TokenManager) string {
		raw, _, err := tokens.Mint(userID, scopeID, sessionID)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
}
