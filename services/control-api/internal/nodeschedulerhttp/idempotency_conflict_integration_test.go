//go:build integration

package nodeschedulerhttp

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// platform-default 与 smart-schedule 的 Idempotency-Key：同键换体 409，同键同体回放不再执行
// （中间被别的请求改掉的值不会被重放改回）。改前 handler 读了键后丢弃，同键换体照常写入、返回 200。
func TestPlatformDefaultAndSmartScheduleIdempotencyHTTP(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	scopeID, userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	refresh := sha256.Sum256([]byte(sessionID.String()))
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform');
		INSERT INTO users(id,username,display_name,password_hash) VALUES($2,'idemconflict-admin','平台管理员','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($1,$2);
		INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($3,$1,'platform_owner','idemconflict',true);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($3,'platform.admin') ON CONFLICT DO NOTHING;
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3);
		INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($4,$5,$2,$1,$6,$7,$8)`, pgx.QueryExecModeSimpleProtocol,
		scopeID, userID, roleID, sessionID, uuid.New(), refresh[:], now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("s", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return now }
	sessions, err := sessioncredential.NewVerifier(tokens, clock)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x31}, 32), clock)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := nodescheduler.NewIAMService(pool, clock, authorizer, nil)
	if err != nil {
		t.Fatal(err)
	}
	actor := nodescheduler.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform",
		Credential: nodescheduler.Credential{Kind: nodescheduler.CredentialSession, Raw: raw}}
	created, err := service.PutGroup(ctx, actor, nodescheduler.PutGroupRequest{
		GroupID: uuid.New(), Name: "幂等线路", Region: "香港", FailoverMode: nodescheduler.FailoverPrimaryOffline,
		IdempotencyKey: "idemconflict-create", RequestID: "idemconflict-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	groupID := created.Group.GroupID
	handler, err := NewHandler(service, &staticAuthenticator{actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	handler = handler.WithSmartSchedule(nopSmartReader{})
	send := func(method, path, key, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		request.Header.Set("X-Request-ID", "idemconflict-"+uuid.NewString())
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	isDefault := func() bool {
		t.Helper()
		var value bool
		if err := pool.QueryRow(ctx, `SELECT is_platform_default FROM node_line_groups WHERE id=$1`, groupID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}

	defaultPath := "/v1/node-line-groups/" + groupID.String() + "/platform-default"
	if recorder := send(http.MethodPost, defaultPath, "pd-1", `{"is_platform_default":true}`); recorder.Code != http.StatusOK {
		t.Fatalf("set default = %d %s", recorder.Code, recorder.Body)
	}
	recorder := send(http.MethodPost, defaultPath, "pd-1", `{"is_platform_default":false}`)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "idempotency") {
		t.Fatalf("same key, other body = %d %s; want 409 idempotency conflict", recorder.Code, recorder.Body)
	}
	if !isDefault() {
		t.Fatal("conflicting replay changed the platform default")
	}
	if recorder := send(http.MethodPost, defaultPath, "pd-2", `{"is_platform_default":false}`); recorder.Code != http.StatusOK || isDefault() {
		t.Fatalf("unset default = %d %s default=%v", recorder.Code, recorder.Body, isDefault())
	}
	if recorder := send(http.MethodPost, defaultPath, "pd-1", `{"is_platform_default":true}`); recorder.Code != http.StatusOK ||
		!strings.Contains(recorder.Body.String(), `"is_platform_default":false`) || isDefault() {
		t.Fatalf("replay pd-1 = %d %s default=%v; want 200 without re-applying", recorder.Code, recorder.Body, isDefault())
	}

	smartPath := "/v1/node-line-groups/" + groupID.String() + "/smart-schedule"
	settings := func(topN string) string {
		return `{"enabled":true,"top_n":` + topN + `,"granularity":"carrier","latency_window_minutes":15,"max_load_percent":85}`
	}
	if recorder := send(http.MethodPut, smartPath, "ss-1", settings("3")); recorder.Code != http.StatusOK {
		t.Fatalf("put smart schedule = %d %s", recorder.Code, recorder.Body)
	}
	recorder = send(http.MethodPut, smartPath, "ss-1", settings("5"))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "idempotency") {
		t.Fatalf("same key, other settings = %d %s; want 409 idempotency conflict", recorder.Code, recorder.Body)
	}
	if recorder := send(http.MethodPut, smartPath, "ss-2", settings("4")); recorder.Code != http.StatusOK ||
		!strings.Contains(recorder.Body.String(), `"top_n":4`) {
		t.Fatalf("put top_n 4 = %d %s", recorder.Code, recorder.Body)
	}
	if recorder := send(http.MethodPut, smartPath, "ss-1", settings("3")); recorder.Code != http.StatusOK ||
		!strings.Contains(recorder.Body.String(), `"top_n":4`) {
		t.Fatalf("replay ss-1 = %d %s; want 200 showing the current top_n 4", recorder.Code, recorder.Body)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_scheduling_write_requests WHERE target_group_id=$1 AND
		operation IN ('node_scheduling.group.platform_default','node_scheduling.group.smart_schedule')`, groupID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 4 {
		t.Fatalf("write request rows = %d, want 4 (pd-1, pd-2, ss-1, ss-2)", rows)
	}
}
