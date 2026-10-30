//go:build integration

package identityverificationhttp

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

// "平台管理员也能代审……管理员是最高权限，租户审核可做的管理都可一个人做"。
// 平台管理员会话经真实 handler 以 ?tenant_scope_id= 列表/查看/领取/裁决；审计记管理员本人。
func TestHTTPIntegrationPlatformAdministratorReviewsTenantCase(t *testing.T) {
	fixture := newHTTPIntegrationFixture(t)
	tenantScope := fixture.applicant.ScopeID
	var platformScope uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'
		ORDER BY created_at LIMIT 1`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`,
			platformScope); err != nil {
			t.Fatal(err)
		}
	}
	adminToken, adminID := insertHTTPPlatformSession(t, fixture, platformScope, "platform.admin")
	viewerToken, _ := insertHTTPPlatformSession(t, fixture, platformScope, "sites.manage")

	submitted := fixture.createSubmitted(t, "platform-review", 0x71)
	target := "?tenant_scope_id=" + tenantScope.String()
	base := apiPrefix + "/reviewer/cases"

	if response := fixture.request(t, viewerToken, http.MethodGet, base+target, "", "", 0); response.Code != http.StatusForbidden {
		t.Fatalf("non-admin platform list = %d %s", response.Code, response.Body.String())
	}
	assertAPIError(t, fixture.request(t, adminToken, http.MethodGet, base, "", "", 0),
		http.StatusBadRequest, "identity_verification_invalid_request")
	assertAPIError(t, fixture.request(t, "reviewer", http.MethodGet, base+target, "", "", 0),
		http.StatusBadRequest, "identity_verification_invalid_request")
	assertAPIError(t, fixture.request(t, adminToken, http.MethodGet,
		apiPrefix+"/cases/"+submitted.ID.String(), "", "", 0),
		http.StatusUnauthorized, "identity_verification_unauthenticated")

	list := fixture.request(t, adminToken, http.MethodGet, base+target+"&status=submitted&limit=20", "", "", 0)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), submitted.ID.String()) {
		t.Fatalf("platform admin list = %d %s", list.Code, list.Body.String())
	}
	detail := fixture.request(t, adminToken, http.MethodGet, base+"/"+submitted.ID.String()+target, "", "", 0)
	if detail.Code != http.StatusOK {
		t.Fatalf("platform admin detail = %d %s", detail.Code, detail.Body.String())
	}
	otherTarget := "?tenant_scope_id=" + fixture.otherReviewer.ScopeID.String()
	if response := fixture.request(t, adminToken, http.MethodPost, base+"/"+submitted.ID.String()+"/claim"+otherTarget,
		"", "platform-cross-claim", submitted.Revision); response.Code == http.StatusOK {
		t.Fatalf("cross-tenant claim = %d %s", response.Code, response.Body.String())
	}
	claimed := fixture.request(t, adminToken, http.MethodPost, base+"/"+submitted.ID.String()+"/claim"+target,
		"", "platform-claim", submitted.Revision)
	if claimed.Code != http.StatusOK {
		t.Fatalf("platform admin claim = %d %s", claimed.Code, claimed.Body.String())
	}
	claimedCase := decodeCase(t, claimed)
	approved := fixture.request(t, adminToken, http.MethodPost, base+"/"+submitted.ID.String()+"/decision"+target,
		`{"decision":"approved","reason_code":"evidence_verified"}`, "platform-approve", claimedCase.Revision)
	if approved.Code != http.StatusOK || decodeCase(t, approved).Status != identityverification.StatusApproved {
		t.Fatalf("platform admin approve = %d %s", approved.Code, approved.Body.String())
	}
	for _, action := range []string{"identity_verification.start_review", "identity_verification.review"} {
		var actorScope, actorKind string
		if err := fixture.pool.QueryRow(t.Context(), `SELECT payload->>'actor_scope_id',payload->>'actor_scope_kind'
			FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2 AND action=$3 AND result='success'
			ORDER BY stream_position DESC LIMIT 1`, tenantScope, adminID, action).Scan(&actorScope, &actorKind); err != nil {
			t.Fatalf("%s audit: %v", action, err)
		}
		if actorScope != platformScope.String() || actorKind != "platform" {
			t.Fatalf("%s audit actor scope=%s kind=%s", action, actorScope, actorKind)
		}
	}
}

// insertHTTPPlatformSession adds a platform member with permission and
// registers its session token with the fixture authenticator.
func insertHTTPPlatformSession(t *testing.T, fixture *httpIntegrationFixture, platformScope uuid.UUID,
	permission string,
) (string, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New()
	must := func(query string, args ...any) {
		t.Helper()
		if _, err := fixture.pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	must(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'test-password-hash')`,
		userID, "idreview-http-"+strings.ReplaceAll(uuid.NewString(), "-", "")[:8])
	must(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platformScope, userID)
	must(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'idreview http platform',true)`,
		roleID, platformScope, "idreview-http-"+strings.ReplaceAll(roleID.String(), "-", "")[:12])
	must(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission)
	must(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, platformScope, userID, roleID)
	sessionHash := sha256.Sum256(sessionID[:])
	must(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$1,$2,$3,$4,$5,$6)`, sessionID, userID, platformScope, sessionHash[:],
		time.Now().UTC().Add(-time.Hour), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
	rawSession, _, err := fixture.tokens.Mint(userID, platformScope, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	fixture.platformSessions[rawSession] = identity.AuthenticatedSession{SessionID: sessionID,
		Principal: identity.Principal{UserID: userID, ScopeID: platformScope, ScopeKind: "platform"}}
	return rawSession, userID
}
