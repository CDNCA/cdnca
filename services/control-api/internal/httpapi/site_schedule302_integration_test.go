//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/siteschedule302"
	"github.com/google/uuid"
)

// TestSiteSchedule302HTTP: GET defaults, PUT enables with
// normalization (sites.revision, If-Match, idempotency, signing key kept
// across edits), a site without a plain HTTP port is refused, turning it off
// deletes the settings and the key; every write is audited
// (site.schedule302.update) with changes and denial reasons.
func TestSiteSchedule302HTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	ctx := context.Background()
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	tenant := insertSecurityTenant(t, pool, "Schedule302", "schedule302-a", passwordHash)
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		SELECT assignment.role_id,permission FROM role_assignments assignment,
		unnest(ARRAY['sites.read','sites.manage']) permission
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 ON CONFLICT DO NOTHING`, tenant.scopeID, tenant.userID); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("schedule302-secret-at-least-32-bytes-long", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x53}, 32)}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	auth := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)
	site := insertQuickBlockSite(t, pool, tenant.scopeID, tenant.userID)
	path := func(id uuid.UUID) string { return server.URL + "/v1/sites/" + id.String() + "/schedule302" }
	get := func(id uuid.UUID) siteschedule302.State {
		t.Helper()
		response := siteRequest(t, client, http.MethodGet, path(id), nil, auth.AccessToken, "", "")
		var state siteschedule302.State
		decodeResponse(t, response, http.StatusOK, &state)
		response.Body.Close()
		return state
	}
	state := get(site)
	if state.Version != 1 || state.Settings.Enabled || !state.PlainHTTP || state.Settings.SignatureTTLSeconds != 60 {
		t.Fatalf("default = %+v", state)
	}
	on := map[string]any{"enabled": true, "target": "address", "keep_path": true, "keep_query": false,
		"signature_ttl_seconds": 120, "https_to_http": false, "extensions": []string{".MP4", "zip", "mp4"},
		"path_prefixes": []string{"/dl/"}, "min_size_bytes": 1048576}
	bad := map[string]any{"enabled": true, "target": "ip", "keep_path": true, "keep_query": true, "signature_ttl_seconds": 60,
		"https_to_http": false, "extensions": []string{}, "path_prefixes": []string{}, "min_size_bytes": 0}
	response := siteRequest(t, client, http.MethodPut, path(site), bad, auth.AccessToken, "s302-bad", `"1"`)
	assertError(t, response, http.StatusBadRequest, "validation_error", "")

	sourceBefore := scopeSourceRevision(t, pool, tenant.scopeID)
	response = siteRequest(t, client, http.MethodPut, path(site), on, auth.AccessToken, "s302-on", `"1"`)
	var updated siteschedule302.State
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	if response.Header.Get("ETag") != `"2"` || !updated.Settings.Enabled || !slices.Equal(updated.Settings.Extensions, []string{"mp4", "zip"}) ||
		updated.Settings.SignatureTTLSeconds != 120 || updated.UpdatedAt == nil {
		t.Fatalf("enabled = %+v", updated)
	}
	if after := scopeSourceRevision(t, pool, tenant.scopeID); after != sourceBefore+1 {
		t.Fatalf("source revision %d -> %d", sourceBefore, after)
	}
	var key []byte
	if err := pool.QueryRow(ctx, `SELECT sign_key FROM site_schedule302_settings WHERE site_id=$1`, site).Scan(&key); err != nil || len(key) != 32 {
		t.Fatalf("signing key %x %v", key, err)
	}
	// Replay returns the stored result; reuse with other input conflicts; stale version conflicts.
	response = siteRequest(t, client, http.MethodPut, path(site), on, auth.AccessToken, "s302-on", `"1"`)
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	response = siteRequest(t, client, http.MethodPut, path(site), map[string]any{"enabled": false}, auth.AccessToken, "s302-on", `"2"`)
	assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
	response = siteRequest(t, client, http.MethodPut, path(site), map[string]any{"enabled": false}, auth.AccessToken, "s302-stale", `"1"`)
	assertError(t, response, http.StatusConflict, "version_conflict", "")
	// An edit keeps the key (redirects already issued stay valid).
	on["signature_ttl_seconds"] = 300
	response = siteRequest(t, client, http.MethodPut, path(site), on, auth.AccessToken, "s302-edit", `"2"`)
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	var kept []byte
	if err := pool.QueryRow(ctx, `SELECT sign_key FROM site_schedule302_settings WHERE site_id=$1`, site).Scan(&kept); err != nil || !bytes.Equal(kept, key) {
		t.Fatalf("key rotated on edit: %v", err)
	}
	// Off: settings and key go.
	response = siteRequest(t, client, http.MethodPut, path(site), map[string]any{"enabled": false}, auth.AccessToken, "s302-off", `"3"`)
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM site_schedule302_settings WHERE site_id=$1`, site).Scan(&rows); err != nil || rows != 0 || updated.Settings.Enabled {
		t.Fatalf("off rows=%d state=%+v err=%v", rows, updated, err)
	}

	events := audittest.Query(t, pool, `scope_id=$1 AND action=$2 AND resource_id=$3`, tenant.scopeID, siteschedule302.AuditAction, site.String())
	var results []string
	for _, item := range events {
		results = append(results, item.Result)
		if item.Payload["ip"] == nil || item.Payload["site_id"] != site.String() {
			t.Fatalf("audit payload = %+v", item.Payload)
		}
	}
	// bad (validation, not audited), on, replay (no event), conflict, stale, edit, off.
	if want := []string{"success", "denied", "denied", "success", "success"}; !slices.Equal(results, want) {
		t.Fatalf("audit results = %v want %v", results, want)
	}
	if enabled, ok := audittest.Find(events[0].Changes, "enabled"); !ok || enabled.Before != false || enabled.After != true {
		t.Fatalf("audit changes = %+v", events[0].Changes)
	}
	if ttl, ok := audittest.Find(events[3].Changes, "signature_ttl_seconds"); !ok || len(events[3].Changes) != 1 {
		t.Fatalf("edit changes = %+v (%+v)", events[3].Changes, ttl)
	}
	if events[1].ReasonCode != "idempotency_conflict" || events[2].ReasonCode != "revision_conflict" {
		t.Fatalf("denied reasons = %q %q", events[1].ReasonCode, events[2].ReasonCode)
	}
	if err := audit.New(pool).VerifyScope(ctx, tenant.scopeID); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
}
