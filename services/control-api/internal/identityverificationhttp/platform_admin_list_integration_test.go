//go:build integration

package identityverificationhttp

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

// fix-decide1027b 第3项：管理端实名审核入口。平台管理员经真实 handler 跨租户列出实名申请
// （带租户名、申请人用户名），按状态过滤、游标翻页；无 platform.admin 的平台成员与租户会话 403。
func TestHTTPIntegrationPlatformAdministratorListsCasesAcrossTenants(t *testing.T) {
	fixture := newHTTPIntegrationFixture(t)
	var platformScope uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'
		ORDER BY created_at LIMIT 1`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`,
			platformScope); err != nil {
			t.Fatal(err)
		}
	}
	adminToken, _ := insertHTTPPlatformSession(t, fixture, platformScope, "platform.admin")
	viewerToken, _ := insertHTTPPlatformSession(t, fixture, platformScope, "sites.manage")
	submitted := fixture.createSubmitted(t, "admin-list-submitted", 'k')
	draftToken := integrationToken('m')
	fixture.registry.add(fixture.otherUser.Actor, draftToken,
		integrationPersonalEvidence(identityverification.KindPersonalInitial, bytesOf(32, 'm'), 'n'))
	draft := decodeCase(t, fixture.create(t, "other-user", identityverification.KindPersonalInitial,
		draftToken, "admin-list-draft-create", http.StatusCreated))
	var tenantName, applicantName string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT t.display_name,u.username FROM access_scopes s
		JOIN tenants t ON t.id=s.tenant_id, users u WHERE s.id=$1 AND u.id=$2`,
		fixture.applicant.ScopeID, fixture.applicant.UserID).Scan(&tenantName, &applicantName); err != nil {
		t.Fatal(err)
	}
	base := apiPrefix + "/admin/cases"

	if response := fixture.request(t, viewerToken, http.MethodGet, base, "", "", 0); response.Code != http.StatusForbidden {
		t.Fatalf("non-admin platform list = %d %s", response.Code, response.Body.String())
	}
	if response := fixture.request(t, "reviewer", http.MethodGet, base, "", "", 0); response.Code != http.StatusForbidden {
		t.Fatalf("tenant reviewer admin list = %d %s", response.Code, response.Body.String())
	}

	type page struct {
		Items []struct {
			ID                uuid.UUID `json:"id"`
			Status            string    `json:"status"`
			TenantScopeID     uuid.UUID `json:"tenant_scope_id"`
			TenantName        string    `json:"tenant_name"`
			ApplicantUsername string    `json:"applicant_username"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	list := func(query string) page {
		t.Helper()
		response := fixture.request(t, adminToken, http.MethodGet, base+query, "", "", 0)
		if response.Code != http.StatusOK {
			t.Fatalf("admin list %s = %d %s", query, response.Code, response.Body.String())
		}
		var result page
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	only := list("?status=submitted")
	if len(only.Items) != 1 || only.Items[0].ID != submitted.ID || only.NextCursor != "" {
		t.Fatalf("submitted filter = %+v", only)
	}
	item := only.Items[0]
	if item.TenantScopeID != fixture.applicant.ScopeID || item.TenantName != tenantName ||
		item.ApplicantUsername != applicantName || item.Status != "submitted" {
		t.Fatalf("admin row = %+v want tenant %s/%s applicant %s", item, fixture.applicant.ScopeID, tenantName, applicantName)
	}
	one := list("?limit=1")
	if len(one.Items) != 1 || one.NextCursor == "" {
		t.Fatalf("first page = %+v", one)
	}
	next := list("?limit=1&cursor=" + one.NextCursor)
	if len(next.Items) != 1 || next.Items[0].ID == one.Items[0].ID {
		t.Fatalf("second page = %+v", next)
	}
	if seen := map[uuid.UUID]bool{one.Items[0].ID: true, next.Items[0].ID: true}; !seen[submitted.ID] || !seen[draft.ID] {
		t.Fatalf("pages %s,%s want %s,%s", one.Items[0].ID, next.Items[0].ID, submitted.ID, draft.ID)
	}
	if response := fixture.request(t, adminToken, http.MethodGet, base+"?status=submitted&cursor="+one.NextCursor,
		"", "", 0); response.Code != http.StatusBadRequest {
		t.Fatalf("cursor reused with another filter = %d", response.Code)
	}
	if approved := list("?status=approved"); len(approved.Items) != 0 {
		t.Fatalf("approved filter = %+v", approved)
	}
}
