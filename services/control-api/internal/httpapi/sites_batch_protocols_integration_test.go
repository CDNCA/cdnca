package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// 待出包前全量跑（PG）：网站协议批量设置直接写站点的
// http2_enabled / http3_enabled / tls_prefer_server_ciphers——逐站版本校验与
// 失败原因、只改选中的站点、审计 site.batch.set_protocols + site.tls_profile.update、
// 站点改动推高 scope 的 source_revision（发布读这三列）。
func TestSiteBatchSetProtocolsHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	baseTime := time.Now().UTC().Truncate(time.Second)
	key := newSiteTestKey(t, "control-site-protocols-key")
	trust := newSiteTestTrust(t, key)
	installSiteTestEntitlement(t, pool, trust, baseTime, siteTestLeaseOptions{serial: 1, limit: 100, key: key})
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(context.Background(), "siteprotoadmin", "Site Protocol Administrator",
		passwordHash, "site-protocol-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenant := insertSiteTenant(t, pool, "tenant-site-proto", "tenant-proto", "Tenant Protocols", passwordHash)
	tokens, err := identity.NewTokenManager("site-protocol-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		EntitlementTrust: trust, Now: func() time.Time { return baseTime }}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	auth := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)

	first := createSite(t, client, server.URL, auth.AccessToken, "proto-create-first", createSiteRequest{
		Basic: disabledSiteBasic("proto-first.example", "192.0.2.111")})
	stale := createSite(t, client, server.URL, auth.AccessToken, "proto-create-stale", createSiteRequest{
		Basic: disabledSiteBasic("proto-stale.example", "192.0.2.112")})
	untouched := createSite(t, client, server.URL, auth.AccessToken, "proto-create-untouched", createSiteRequest{
		Basic: disabledSiteBasic("proto-untouched.example", "192.0.2.113")})
	var revisionBefore int64
	if err := pool.QueryRow(context.Background(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
		tenant.scopeID).Scan(&revisionBefore); err != nil {
		t.Fatal(err)
	}

	missing := uuid.New()
	body := map[string]any{
		"action": "set_protocols",
		"items": []map[string]any{
			{"id": first.ID, "expected_version": first.Version},
			{"id": stale.ID, "expected_version": stale.Version + 5},
			{"id": missing, "expected_version": 1},
		},
		"protocols": map[string]any{"http2_enabled": false, "tls_prefer_server_ciphers": true},
	}
	response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/batch-action", body,
		auth.AccessToken, "proto-batch", "", "proto-batch-request")
	var result batchSiteActionResponse
	decodeResponse(t, response, http.StatusOK, &result)
	response.Body.Close()
	if len(result.Items) != 3 || result.Items[0].Status != "updated" || result.Items[0].Site == nil {
		t.Fatalf("result = %#v", result.Items)
	}
	assertBatchFailure(t, result.Items[1], "version_conflict")
	assertBatchFailure(t, result.Items[2], "site_not_found")
	updated := result.Items[0].Site.Basic
	if *updated.HTTP2Enabled || !*updated.HTTP3Enabled || updated.TLSPreferServerCiphers == nil ||
		!*updated.TLSPreferServerCiphers || result.Items[0].Site.Version != first.Version+1 {
		t.Fatalf("updated site = %#v version %d", updated, result.Items[0].Site.Version)
	}
	for _, id := range []uuid.UUID{stale.ID, untouched.ID} {
		detail := getSite(t, client, server.URL, id, auth.AccessToken)
		if !*detail.Basic.HTTP2Enabled || detail.Basic.TLSPreferServerCiphers != nil || detail.Version != 1 {
			t.Fatalf("site %s changed: %#v", id, detail.Basic)
		}
	}
	var revisionAfter int64
	if err := pool.QueryRow(context.Background(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
		tenant.scopeID).Scan(&revisionAfter); err != nil {
		t.Fatal(err)
	}
	if revisionAfter <= revisionBefore {
		t.Fatalf("source_revision %d -> %d, want advanced", revisionBefore, revisionAfter)
	}
	var batchAudits, tlsAudits int
	if err := pool.QueryRow(context.Background(), `SELECT
		count(*) FILTER (WHERE action='site.batch.set_protocols'),
		count(*) FILTER (WHERE action='site.tls_profile.update' AND resource_id=$2)
		FROM audit_events WHERE request_id=$1`, "proto-batch-request", first.ID.String()).Scan(&batchAudits, &tlsAudits); err != nil {
		t.Fatal(err)
	}
	if batchAudits != 3 || tlsAudits != 1 {
		t.Fatalf("audits batch=%d tls=%d, want 3/1", batchAudits, tlsAudits)
	}

	// null prefer is "by preset" again; an identical retry replays
	reset := map[string]any{"action": "set_protocols",
		"items":     []map[string]any{{"id": first.ID, "expected_version": first.Version + 1}},
		"protocols": map[string]any{"tls_prefer_server_ciphers": nil}}
	post := func(key string) batchSiteActionResponse {
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/batch-action", reset, auth.AccessToken, key, "")
		var out batchSiteActionResponse
		decodeResponse(t, response, http.StatusOK, &out)
		response.Body.Close()
		return out
	}
	once := post("proto-reset")
	if once.Items[0].Status != "updated" || once.Items[0].Site.Basic.TLSPreferServerCiphers != nil ||
		*once.Items[0].Site.Basic.HTTP2Enabled {
		t.Fatalf("reset = %#v", once.Items[0])
	}
	if replay := post("proto-reset"); mustJSON(t, replay) != mustJSON(t, once) {
		t.Fatal("replay differs")
	}

	// protocols without a change, or on another action, is rejected
	for index, invalid := range []map[string]any{
		{"action": "set_protocols", "items": []map[string]any{{"id": first.ID, "expected_version": 1}}, "protocols": map[string]any{}},
		{"action": "set_protocols", "items": []map[string]any{{"id": first.ID, "expected_version": 1}}},
		{"action": "enable", "items": []map[string]any{{"id": first.ID, "expected_version": 1}}, "protocols": map[string]any{"http3_enabled": false}},
	} {
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/sites/batch-action", invalid,
			auth.AccessToken, "proto-invalid-"+string(rune('a'+index)), "")
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	}
	if err := audit.New(pool).VerifyScope(context.Background(), tenant.scopeID); err != nil {
		t.Fatal(err)
	}
}
