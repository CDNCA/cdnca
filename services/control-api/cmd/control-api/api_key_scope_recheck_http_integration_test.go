//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AA-KEY-01 正式 HTTP 回归（来自审测 TestReviewAPIKeyGrantScopesRecheckedAfterRoleChangeHTTP）：
// 管理员 PATCH owner→viewer 先进入授权锁等待，用户创建只含 sites.manage 的密钥随后排队；
// 释放栅栏后角色变更先提交，创建必须 403 permission_denied（details.reason=scopes_revoked），不留密钥。
// 响应正文与凭据不打印。

type scopeRecheckHTTP struct {
	pool       *pgxpool.Pool
	server     *httptest.Server
	adminToken string
	userToken  string
	user       identity.ManagedUser
}

type scopeRecheckResponse struct {
	status int
	body   []byte
}

func scopeRecheckRandom(t *testing.T) []byte {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal("random source unavailable")
	}
	return value
}

func (f scopeRecheckHTTP) call(t *testing.T, method, path string, body any, bearer, credential, idem, revision string) scopeRecheckResponse {
	t.Helper()
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, f.server.URL+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal("prepare request failed")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "scope-recheck-"+uuid.NewString())
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	if credential != "" {
		request.Header.Set("Authorization", "CdncaKey "+credential)
	}
	if idem != "" {
		request.Header.Set("Idempotency-Key", idem)
	}
	if revision != "" {
		request.Header.Set("If-Match", revision)
	}
	response, err := f.server.Client().Do(request)
	if err != nil {
		t.Error("HTTP request failed")
		return scopeRecheckResponse{}
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return scopeRecheckResponse{status: response.StatusCode, body: raw}
}

type scopeRecheckError struct {
	Error struct {
		Code    string `json:"code"`
		Details struct {
			Reason string   `json:"reason"`
			Scopes []string `json:"scopes"`
		} `json:"details"`
	} `json:"error"`
}

func scopeRecheckDecode(t *testing.T, response scopeRecheckResponse, want int, output any) {
	t.Helper()
	if response.status != want {
		var envelope scopeRecheckError
		_ = json.Unmarshal(response.body, &envelope)
		t.Fatalf("HTTP status=%d code=%s want=%d", response.status, envelope.Error.Code, want)
	}
	if output != nil && json.Unmarshal(response.body, output) != nil {
		t.Fatal("decode response failed; body suppressed")
	}
}

func newScopeRecheckHTTP(t *testing.T) scopeRecheckHTTP {
	t.Helper()
	pool := newDashboardCompositionTestPool(t)
	password := base64.RawURLEncoding.EncodeToString(scopeRecheckRandom(t))
	hash, err := identity.HashPassword(password)
	if err != nil {
		t.Fatal("password hash failed")
	}
	store := identity.NewStore(pool)
	if _, err := store.BootstrapPlatformUserWithEmail(t.Context(), "recheck-admin", "撤权回归管理员",
		"recheck-admin@example.invalid", hash, "recheck-bootstrap"); err != nil {
		t.Fatal("bootstrap failed")
	}
	tokens, err := identity.NewTokenManager(base64.RawURLEncoding.EncodeToString(scopeRecheckRandom(t)), time.Hour)
	if err != nil {
		t.Fatal("token configuration failed")
	}
	service, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal("identity configuration failed")
	}
	api := httpapi.New(pool, service, httpapi.Config{CookieSecure: false, APIKeyPepper: scopeRecheckRandom(t)})
	if api.InitializationError() != nil {
		t.Fatal("HTTP API initialization failed")
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	f := scopeRecheckHTTP{pool: pool, server: server}
	var login struct {
		AccessToken string `json:"access_token"`
	}
	scopeRecheckDecode(t, f.call(t, "POST", "/v1/auth/login", map[string]any{"username": "recheck-admin", "password": password}, "", "", "", ""), 200, &login)
	f.adminToken = login.AccessToken
	scopeRecheckDecode(t, f.call(t, "POST", "/v1/admin/users", map[string]any{
		"username": "recheck-owner", "password": password, "display_name": "撤权回归租户",
		"email": "recheck-owner@example.invalid", "phone": nil, "role": identity.UserRoleOwner,
	}, f.adminToken, "", "recheck-create-user", ""), 201, &f.user)
	scopeRecheckDecode(t, f.call(t, "POST", "/v1/auth/login", map[string]any{"username": "recheck-owner", "password": password}, "", "", "", ""), 200, &login)
	f.userToken = login.AccessToken
	return f
}

func (f scopeRecheckHTTP) waitLockWaiters(t *testing.T, count int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var actual int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
			WHERE l.locktype='advisory' AND NOT l.granted AND a.datname=current_database()`).Scan(&actual); err != nil {
			t.Fatal("lock wait observation failed")
		}
		if actual >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected HTTP request did not enter lock queue; no product verdict")
}

func TestAPIKeyCreateQueuedBehindRoleNarrowingHTTP(t *testing.T) {
	f := newScopeRecheckHTTP(t)
	holder, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal("lock fixture unavailable")
	}
	defer holder.Rollback(context.Background())
	if err := iamlock.AcquireShared(t.Context(), holder); err != nil {
		t.Fatal("shared lock fixture unavailable")
	}
	adminDone := make(chan scopeRecheckResponse, 1)
	go func() {
		adminDone <- f.call(t, "PATCH", "/v1/admin/users/"+f.user.ID.String(), map[string]any{
			"expected_revision": f.user.Revision, "display_name": f.user.DisplayName,
			"email": "recheck-owner@example.invalid", "phone": nil, "status": "active", "role": identity.UserRoleViewer,
		}, f.adminToken, "", "recheck-role-viewer", "")
	}()
	f.waitLockWaiters(t, 1)
	keyDone := make(chan scopeRecheckResponse, 1)
	go func() {
		keyDone <- f.call(t, "POST", "/v1/account/api-keys", map[string]any{
			"name": "recheck-stale-grant", "scopes": []string{"sites.manage"}, "ip_allowlist": []string{},
		}, f.userToken, "", "recheck-stale-grant", `"0"`)
	}()
	f.waitLockWaiters(t, 2)
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal("lock release failed")
	}
	scopeRecheckDecode(t, <-adminDone, 200, nil)
	var refused scopeRecheckError
	scopeRecheckDecode(t, <-keyDone, 403, &refused)
	if refused.Error.Code != "permission_denied" || refused.Error.Details.Reason != "scopes_revoked" ||
		len(refused.Error.Details.Scopes) != 1 || refused.Error.Details.Scopes[0] != "sites.manage" {
		t.Fatalf("stale grant refusal code=%s reason=%s scopes=%v", refused.Error.Code, refused.Error.Details.Reason, refused.Error.Details.Scopes)
	}
	var keys, audits int
	if err := f.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM api_keys WHERE name='recheck-stale-grant'),
		(SELECT count(*) FROM audit_events WHERE action='api_key.self.create')`).Scan(&keys, &audits); err != nil || keys != 0 || audits != 0 {
		t.Fatalf("refused create left keys=%d audits=%d query_ok=%v", keys, audits, err == nil)
	}

	// 正控：撤权后仍持有的 sites.read 照常签发、可读、写被拒；同 key 精确重放返回同一结果。
	body := map[string]any{"name": "recheck-read", "scopes": []string{"sites.read"}, "ip_allowlist": []string{}}
	var issued, replay apikey.IssuedKey
	scopeRecheckDecode(t, f.call(t, "POST", "/v1/account/api-keys", body, f.userToken, "", "recheck-read", `"0"`), 201, &issued)
	scopeRecheckDecode(t, f.call(t, "POST", "/v1/account/api-keys", body, f.userToken, "", "recheck-read", `"0"`), 201, &replay)
	if replay.Key.ID != issued.Key.ID || replay.Secret != issued.Secret {
		t.Fatal("exact create replay changed the original response")
	}
	credential := issued.Key.KeyID + "." + issued.Secret
	scopeRecheckDecode(t, f.call(t, "GET", "/v1/sites", nil, "", credential, "", ""), 200, nil)
	if denied := f.call(t, "POST", "/v1/sites", map[string]any{}, "", credential, "", ""); denied.status != 403 {
		t.Fatalf("read-only key write status=%d", denied.status)
	}
}
