//go:build integration

package statuspagehttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/statuspage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 保存关闭后公开接口立即 404，重新开启后立即 200 且品牌/组件回读，不等 30 秒快照。
func TestPostgresPublicFollowsSaveImmediately(t *testing.T) {
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		pool = databasetest.MigratedPool(t, nil)
	}
	userID, scopeID := seedStatusPageAdmin(t, pool)
	service, err := statuspage.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(),
			Principal: identity.Principal{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}}, nil
	}, func(*http.Request) string { return "203.0.113.7" })
	if err != nil {
		t.Fatal(err)
	}
	serve := func(method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		var reader bytes.Buffer
		if body != nil {
			if err := json.NewEncoder(&reader).Encode(body); err != nil {
				t.Fatal(err)
			}
		}
		request := httptest.NewRequest(method, path, &reader)
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	revision := func() int64 {
		t.Helper()
		response := serve(http.MethodGet, AdminRoute, nil, map[string]string{"Authorization": "Bearer t"})
		var view statuspage.AdminView
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &view) != nil {
			t.Fatalf("admin view %d %s", response.Code, response.Body)
		}
		return view.Revision
	}
	save := func(enabled bool) {
		t.Helper()
		request := statuspage.SaveRequest{
			Settings:   statuspage.Settings{Enabled: enabled, Title: "品牌甲状态", Description: "说明甲", ShowLogo: true},
			Groups:     []statuspage.GroupInput{},
			Components: []statuspage.ComponentInput{{Name: "官网入口甲", NameEN: "Website A", Source: statuspage.SourceManual}},
		}
		response := serve(http.MethodPut, AdminRoute, request, map[string]string{
			"Authorization": "Bearer t", "If-Match": `"` + strconv.FormatInt(revision(), 10) + `"`})
		if response.Code != http.StatusOK {
			t.Fatalf("save enabled=%v: %d %s", enabled, response.Code, response.Body)
		}
	}
	public := func(headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		return serve(http.MethodGet, PublicRoute, nil, headers)
	}

	save(true)
	opened := public(nil)
	if opened.Code != http.StatusOK || opened.Header().Get("Cache-Control") != "public, no-cache" || opened.Header().Get("ETag") == "" {
		t.Fatalf("open: %d %q %q", opened.Code, opened.Header().Get("Cache-Control"), opened.Header().Get("ETag"))
	}
	if again := public(map[string]string{"If-None-Match": opened.Header().Get("ETag")}); again.Code != http.StatusNotModified {
		t.Fatalf("revalidation: %d", again.Code)
	}

	save(false) // the open snapshot is seconds old, well inside its 30 s TTL
	closed := public(nil)
	if closed.Code != http.StatusNotFound || closed.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(closed.Body.String(), "status_page_disabled") {
		t.Fatalf("closed: %d %q", closed.Code, closed.Header().Get("Cache-Control"))
	}
	if stale := public(map[string]string{"If-None-Match": opened.Header().Get("ETag")}); stale.Code != http.StatusNotFound {
		t.Fatalf("closed page revalidated as %d", stale.Code)
	}

	save(true)
	reopened := public(nil)
	var view statuspage.PublicView
	if reopened.Code != http.StatusOK || json.Unmarshal(reopened.Body.Bytes(), &view) != nil {
		t.Fatalf("reopened: %d %s", reopened.Code, reopened.Body)
	}
	if view.Title != "品牌甲状态" || view.Description != "说明甲" || !view.ShowLogo ||
		!strings.Contains(reopened.Body.String(), "官网入口甲") || reopened.Header().Get("Cache-Control") != "public, no-cache" {
		t.Fatalf("reopened view: %+v %q", view, reopened.Header().Get("Cache-Control"))
	}
}

func seedStatusPageAdmin(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	userID, roleID := uuid.New(), uuid.New()
	var scopeID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&scopeID); err == pgx.ErrNoRows {
		scopeID = uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL)`, scopeID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `
		INSERT INTO users(id,username,display_name,password_hash,status) VALUES($2,'status-page-owner','Status page owner','not-used','active');
		INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active');
		INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($3,$1,'status_page_owner','Integration role',true);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($3,'system_configuration.read'),($3,'system_configuration.manage');
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		pgx.QueryExecModeSimpleProtocol, scopeID, userID, roleID)
	if err != nil {
		t.Fatal(err)
	}
	return userID, scopeID
}
