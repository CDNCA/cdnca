package httpapi

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// TestNodeConfigurationScopesHTTP serves a node's tenants to a platform
// reader only: tenants, users without nodes.read and nodes of other scopes
// get nothing.
func TestNodeConfigurationScopesHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	admin, err := identityStore.BootstrapPlatformUser(t.Context(), "scopesadmin", "Scopes Admin", passwordHash, "configuration-scopes-test")
	if err != nil {
		t.Fatal(err)
	}
	reader := insertTestUser(t, pool, admin.ScopeID, "scopesreader", "Scopes Reader", passwordHash, "active")
	grantNodePermissions(t, pool, admin.ScopeID, reader, "nodes.read")
	insertTestUser(t, pool, admin.ScopeID, "scopesviewer", "Scopes Viewer", passwordHash, "active")
	tenantName, tenantScope := insertTenantAdmin(t, pool, passwordHash)
	tokens, err := identity.NewTokenManager("node-configuration-scopes-test-key-at-least-thirty-two", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := identity.NewService(identityStore, tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := monitoringHTTPServer(New(pool, auth, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}))
	t.Cleanup(server.Close)
	client := server.Client()
	readerAuth, _ := loginOK(t, client, server.URL, "scopesreader")
	viewerAuth, _ := loginOK(t, client, server.URL, "scopesviewer")
	tenantAuth := loginForScope(t, client, server.URL, tenantName, tenantScope)
	nodeID, foreign := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		VALUES($1,$2,'shared-node','active',$3,1)`, nodeID, admin.ScopeID, admin.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,created_by_user_id,display_id) VALUES($1,$2,'foreign',$3,1)`,
		foreign, tenantScope, admin.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at) VALUES($1,$2,now())`,
		nodeID, tenantScope); err != nil {
		t.Fatal(err)
	}

	path := server.URL + "/v1/nodes/" + nodeID.String() + "/configuration-scopes"
	var view struct {
		NodeID string `json:"node_id"`
		Scopes []struct {
			ScopeID    string  `json:"scope_id"`
			ScopeKind  string  `json:"scope_kind"`
			TenantName string  `json:"tenant_name"`
			Current    *string `json:"current_config_version_id"`
		} `json:"scopes"`
		Rejections []any `json:"rejections"`
	}
	response := doRequest(t, client, http.MethodGet, path, nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &view)
	response.Body.Close()
	if view.NodeID != nodeID.String() || len(view.Scopes) != 1 || view.Scopes[0].ScopeID != tenantScope.String() ||
		view.Scopes[0].ScopeKind != "tenant" || view.Scopes[0].Current != nil || view.Rejections == nil {
		t.Fatalf("configuration scopes = %+v", view)
	}
	for _, test := range []struct {
		url, token, code string
		status           int
	}{
		{path, viewerAuth.AccessToken, "permission_denied", http.StatusForbidden},
		{path, tenantAuth.AccessToken, "permission_denied", http.StatusForbidden},
		{server.URL + "/v1/nodes/" + foreign.String() + "/configuration-scopes", readerAuth.AccessToken, "node_not_found", http.StatusNotFound},
		{server.URL + "/v1/nodes/not-a-uuid/configuration-scopes", readerAuth.AccessToken, "validation_error", http.StatusBadRequest},
	} {
		response := doRequest(t, client, http.MethodGet, test.url, nil, nil, test.token)
		assertError(t, response, test.status, test.code, "")
		response.Body.Close()
	}
}
