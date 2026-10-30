package announcementhttp

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestHTTPGlobalArchiveLifecycleValidationAndSession(t *testing.T) {
	pool := isolatedHTTPAnnouncementPool(t)
	scopeID, userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	digest := sha256.Sum256(sessionID[:])
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'global-archive-http','global-archive-http','hash')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'global-archive','',true)`, []any{roleID, scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'announcements.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{scopeID, userID, roleID}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, []any{sessionID, uuid.New(), userID, scopeID, digest[:], httpFixedNow, httpFixedNow.Add(time.Hour)}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := identity.Principal{UserID: userID, ScopeID: scopeID, ScopeKind: "platform", Permissions: []string{"announcements.manage"}}
	store := newHTTPAnnouncementStore(t, pool, allowHTTPAnnouncementAuthorizer{})
	handler, err := New(store, AuthenticateFunc(func(*http.Request) (SessionEnvelope, error) {
		return SessionEnvelope{Principal: principal, SessionID: sessionID}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	write := func(path, body, key, revision string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		request.Header.Set("X-Request-ID", uuid.NewString())
		if revision != "" {
			request.Header.Set("If-Match", revision)
		}
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, request)
		return response
	}
	created := write("/v1/admin/announcements/global", `{"title":"HTTP归档","body":"正文","all_tenants":true,"tenant_scope_ids":[],"role_targets":[],"user_targets":[],"withdrawal_visibility":"retain"}`, "create", "")
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	var item announcement.GlobalAnnouncement
	if err := json.Unmarshal(created.Body.Bytes(), &item); err != nil || item.LifecycleRevision != 1 {
		t.Fatalf("create lifecycle: %+v %v", item, err)
	}
	path := "/v1/admin/announcements/global/" + item.ID.String()
	body := `{"expected_lifecycle_revision":1}`
	for _, revision := range []string{"", `"2"`} {
		if response := write(path+"/archive", body, "invalid", revision); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid lifecycle header: %d %s", response.Code, response.Body)
		}
	}
	principal.ScopeKind = "tenant"
	if response := write(path+"/archive", body, "tenant", `"1"`); response.Code != http.StatusForbidden {
		t.Fatalf("tenant global archive: %d %s", response.Code, response.Body)
	}
	principal.ScopeKind = "platform"
	for _, replayed := range []bool{false, true} {
		response := write(path+"/archive", body, "archive", `"1"`)
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &item) != nil || !item.Archived || item.LifecycleRevision != 2 || item.Replayed != replayed {
			t.Fatalf("archive replay=%t: %d %s", replayed, response.Code, response.Body)
		}
	}
	if response := write(path+"/archive", body, "stale", `"1"`); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "version_conflict") {
		t.Fatalf("stale revision: %d %s", response.Code, response.Body)
	}
	listed := performListRequest(handler.Handler(), "/v1/admin/announcements/global?status=archived")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), item.ID.String()) {
		t.Fatalf("archived list: %d %s", listed.Code, listed.Body)
	}
	response := write(path+"/restore", `{"expected_lifecycle_revision":2}`, "restore", `"2"`)
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &item) != nil || item.Archived || item.LifecycleRevision != 3 {
		t.Fatalf("restore: %d %s", response.Code, response.Body)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='test-revoke' WHERE id=$1`, sessionID, httpFixedNow); err != nil {
		t.Fatal(err)
	}
	if response := write(path+"/restore", `{"expected_lifecycle_revision":2}`, "restore", `"2"`); response.Code != http.StatusForbidden {
		t.Fatalf("revoked replay: %d %s", response.Code, response.Body)
	}
}
