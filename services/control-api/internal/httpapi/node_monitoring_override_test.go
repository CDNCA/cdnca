package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringoverride"
	"github.com/google/uuid"
)

func TestNodeMonitoringOverrideHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	admin, err := identityStore.BootstrapPlatformUser(t.Context(), "overrideadmin", "Override Admin", passwordHash, "monitoring-override-test")
	if err != nil {
		t.Fatal(err)
	}
	manager := insertTestUser(t, pool, admin.ScopeID, "overridemanager", "Override Manager", passwordHash, "active")
	grantNodePermissions(t, pool, admin.ScopeID, manager, "nodes.read", "nodes.manage")
	reader := insertTestUser(t, pool, admin.ScopeID, "overridereader", "Override Reader", passwordHash, "active")
	grantNodePermissions(t, pool, admin.ScopeID, reader, "nodes.read")
	insertTestUser(t, pool, admin.ScopeID, "overrideviewer", "Override Viewer", passwordHash, "active")
	tenantName, tenantScope := insertTenantAdmin(t, pool, passwordHash)
	tokens, err := identity.NewTokenManager("node-monitoring-override-test-key-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := identity.NewService(identityStore, tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := monitoringHTTPServer(New(pool, auth, Config{APIKeyPepper: bytes.Repeat([]byte{0x51}, 32)}))
	t.Cleanup(server.Close)
	client := server.Client()
	managerAuth, _ := loginOK(t, client, server.URL, "overridemanager")
	readerAuth, _ := loginOK(t, client, server.URL, "overridereader")
	viewerAuth, _ := loginOK(t, client, server.URL, "overrideviewer")
	tenantAuth := loginForScope(t, client, server.URL, tenantName, tenantScope)
	nodeID, foreign := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		VALUES($1,$2,'override-node','active',$3,1)`, nodeID, admin.ScopeID, admin.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,created_by_user_id,display_id) VALUES($1,$2,'foreign',$3,1)`,
		foreign, tenantScope, admin.UserID); err != nil {
		t.Fatal(err)
	}
	path := server.URL + "/v1/nodes/" + nodeID.String() + "/monitoring/override"
	put := func(token, key string, body any) *http.Response {
		t.Helper()
		encoded, _ := json.Marshal(body)
		request, _ := http.NewRequest(http.MethodPut, path, bytes.NewReader(encoded))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	var view nodemonitoringoverride.View
	response := doRequest(t, client, http.MethodGet, path, nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &view)
	response.Body.Close()
	if view.SchemaVersion != 1 || view.NodeID != nodeID || view.Revision != 0 || view.PlatformState != "unconfigured" ||
		view.EffectivePolicy != nil || view.DeliveryState != "awaiting_configuration" {
		t.Fatalf("initial view = %+v", view)
	}
	body := map[string]any{"expected_revision": 0, "override": map[string]any{
		"monitor_enabled": true, "protocol": "tcp", "probe_timeout_ms": 5000, "monitor_port": 80, "monitor_action": nil}}
	response = put(managerAuth.AccessToken, "override-http-1", body)
	decodeResponse(t, response, http.StatusOK, &view)
	response.Body.Close()
	if view.Revision != 1 || view.Override.MonitorPort == nil || *view.Override.MonitorPort != 80 || view.UpdatedAt == nil {
		t.Fatalf("saved view = %+v", view)
	}
	response = put(managerAuth.AccessToken, "override-http-1", body)
	decodeResponse(t, response, http.StatusOK, &view)
	response.Body.Close()
	if view.Revision != 1 {
		t.Fatalf("replayed view = %+v", view)
	}
	response = doRequest(t, client, http.MethodGet, path, nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &view)
	response.Body.Close()
	if view.Revision != 1 || view.Override.Protocol == nil || *view.Override.Protocol != "tcp" || *view.Override.ProbeTimeoutMS != 5000 {
		t.Fatalf("reloaded view = %+v", view)
	}

	for _, test := range []struct {
		token, key string
		body       any
		status     int
		code       string
	}{
		{readerAuth.AccessToken, "override-http-2", body, http.StatusForbidden, "permission_denied"},
		{tenantAuth.AccessToken, "override-http-2", body, http.StatusForbidden, "permission_denied"},
		{managerAuth.AccessToken, "", body, http.StatusBadRequest, "validation_error"},
		{managerAuth.AccessToken, "override-http-1", map[string]any{"expected_revision": 1, "override": map[string]any{}}, http.StatusConflict, "idempotency_conflict"},
		{managerAuth.AccessToken, "override-http-3", body, http.StatusConflict, "version_conflict"},
		{managerAuth.AccessToken, "override-http-4", map[string]any{"expected_revision": 1}, http.StatusBadRequest, "invalid_request"},
		{managerAuth.AccessToken, "override-http-5", map[string]any{"expected_revision": 1, "override": map[string]any{}, "extra": 1}, http.StatusBadRequest, "invalid_request"},
		{managerAuth.AccessToken, "override-http-6", map[string]any{"expected_revision": 1, "override": map[string]any{"monitor_port": 65536}}, http.StatusBadRequest, "validation_error"},
		{managerAuth.AccessToken, "override-http-7", map[string]any{"expected_revision": 1, "override": map[string]any{"protocol": "udp"}}, http.StatusBadRequest, "validation_error"},
		{managerAuth.AccessToken, "override-http-8", map[string]any{"expected_revision": 1, "override": map[string]any{"probe_timeout_ms": 50}}, http.StatusBadRequest, "validation_error"},
		{managerAuth.AccessToken, "override-http-9", map[string]any{"expected_revision": 1, "override": map[string]any{"monitor_action": "stop"}}, http.StatusBadRequest, "validation_error"},
	} {
		response := put(test.token, test.key, test.body)
		assertError(t, response, test.status, test.code, "")
		response.Body.Close()
	}
	for _, test := range []struct {
		token  string
		status int
		code   string
	}{
		{"", http.StatusUnauthorized, "invalid_session"}, {viewerAuth.AccessToken, http.StatusForbidden, "permission_denied"},
		{tenantAuth.AccessToken, http.StatusForbidden, "permission_denied"},
	} {
		response := doRequest(t, client, http.MethodGet, path, nil, nil, test.token)
		assertError(t, response, test.status, test.code, "")
		response.Body.Close()
	}
	for _, absent := range []uuid.UUID{foreign, uuid.New()} {
		response := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes/"+absent.String()+"/monitoring/override", nil, nil, readerAuth.AccessToken)
		assertError(t, response, http.StatusNotFound, "node_not_found", "")
		response.Body.Close()
	}
	response = doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes/not-a-uuid/monitoring/override", nil, nil, readerAuth.AccessToken)
	assertError(t, response, http.StatusBadRequest, "validation_error", "")
	response.Body.Close()
	response = doRequest(t, client, http.MethodGet, path+"?x=1", nil, nil, readerAuth.AccessToken)
	assertError(t, response, http.StatusBadRequest, "validation_error", "")
	response.Body.Close()

	// The failure action "pause" is now enforced and therefore saved.
	response = put(managerAuth.AccessToken, "override-http-pause", map[string]any{"expected_revision": 1, "override": map[string]any{
		"monitor_enabled": true, "protocol": "tcp", "probe_timeout_ms": 5000, "monitor_port": 80, "monitor_action": "pause"}})
	decodeResponse(t, response, http.StatusOK, &view)
	response.Body.Close()
	if view.Revision != 2 || view.Override.MonitorAction == nil || *view.Override.MonitorAction != "pause" {
		t.Fatalf("pause override = %+v", view)
	}

	// Serving events: the node's hold transitions, scoped like the override.
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_serving_events(id,node_id,source,event,reason_code,hold_revision,detail,occurred_at)
		VALUES($1,$2,'availability_monitor','held','probe_unhealthy',1,'{"healthy":false}',now()-interval '1 minute'),
		      ($3,$2,'availability_monitor','released','probe_recovered',2,'{}',now())`, uuid.New(), nodeID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	eventsPath := server.URL + "/v1/nodes/" + nodeID.String() + "/serving/events"
	var events struct {
		Total int64 `json:"total"`
		Items []struct {
			Event      string         `json:"event"`
			ReasonCode string         `json:"reason_code"`
			Detail     map[string]any `json:"detail"`
		} `json:"items"`
	}
	response = doRequest(t, client, http.MethodGet, eventsPath+"?limit=1", nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &events)
	response.Body.Close()
	if events.Total != 2 || len(events.Items) != 1 || events.Items[0].Event != "released" || events.Items[0].ReasonCode != "probe_recovered" {
		t.Fatalf("serving events = %+v", events)
	}
	for _, test := range []struct {
		url, token, code string
		status           int
	}{
		{eventsPath, viewerAuth.AccessToken, "permission_denied", http.StatusForbidden},
		{server.URL + "/v1/nodes/" + foreign.String() + "/serving/events", readerAuth.AccessToken, "node_monitoring_not_found", http.StatusNotFound},
		{eventsPath + "?limit=0", readerAuth.AccessToken, "validation_error", http.StatusBadRequest},
		{eventsPath + "?from=2026-01-01T00:00:00Z&to=2026-03-01T00:00:00Z", readerAuth.AccessToken, "validation_error", http.StatusBadRequest},
		{eventsPath + "?kind=x", readerAuth.AccessToken, "validation_error", http.StatusBadRequest},
	} {
		response := doRequest(t, client, http.MethodGet, test.url, nil, nil, test.token)
		assertError(t, response, test.status, test.code, "")
		response.Body.Close()
	}

	// A10/N06 switch log: every node of the scope, filtered, foreign node matches nothing.
	scopeEvents := server.URL + "/v1/nodes/serving/events"
	var scopePage struct {
		Total int64 `json:"total"`
		Items []struct {
			NodeID   uuid.UUID `json:"node_id"`
			NodeName string    `json:"node_name"`
			Event    string    `json:"event"`
		} `json:"items"`
	}
	response = doRequest(t, client, http.MethodGet, scopeEvents+"?event=held", nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &scopePage)
	response.Body.Close()
	if scopePage.Total != 1 || len(scopePage.Items) != 1 || scopePage.Items[0].NodeID != nodeID || scopePage.Items[0].NodeName == "" {
		t.Fatalf("scope switch log = %+v", scopePage)
	}
	response = doRequest(t, client, http.MethodGet, scopeEvents+"?node_id="+foreign.String(), nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &scopePage)
	response.Body.Close()
	if scopePage.Total != 0 || len(scopePage.Items) != 0 {
		t.Fatalf("foreign node switch log = %+v", scopePage)
	}
	for _, test := range []struct {
		url, token, code string
		status           int
	}{
		{scopeEvents, viewerAuth.AccessToken, "permission_denied", http.StatusForbidden},
		{scopeEvents, tenantAuth.AccessToken, "permission_denied", http.StatusForbidden},
		{scopeEvents + "?source=admin", readerAuth.AccessToken, "validation_error", http.StatusBadRequest},
		{scopeEvents + "?ip=bad", readerAuth.AccessToken, "validation_error", http.StatusBadRequest},
		{scopeEvents + "?node_id=" + strings.ToUpper(nodeID.String()), readerAuth.AccessToken, "validation_error", http.StatusBadRequest},
		{scopeEvents + "?event=", readerAuth.AccessToken, "validation_error", http.StatusBadRequest},
		{scopeEvents + "?kind=x", readerAuth.AccessToken, "validation_error", http.StatusBadRequest},
	} {
		response := doRequest(t, client, http.MethodGet, test.url, nil, nil, test.token)
		assertError(t, response, test.status, test.code, "")
		response.Body.Close()
	}
}
