//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/sitequickblock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSiteQuickBlockHTTP: GET/PUT
// /v1/sites/{site_id}/quick-block. Two sites bound to one WAF library; one
// site's override changes it only (sites.revision, If-Match, idempotency,
// lock, IP library gate, no-library refusal, delete on inherit, audit), and
// the library write guard refuses a change the override cannot ride on.
func TestSiteQuickBlockHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	ctx := context.Background()
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	tenantA := insertSecurityTenant(t, pool, "Site Quick Block A", "site-quick-block-a", passwordHash)
	tenantB := insertSecurityTenant(t, pool, "Site Quick Block B", "site-quick-block-b", passwordHash)
	readerID := insertSiteScopeUser(t, pool, tenantA.scopeID, "site-quick-block-reader", "Site Quick Block Reader", passwordHash,
		[]string{"security_policies.read"})
	tokens, err := identity.NewTokenManager("site-quick-block-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	authA := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	authB := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)
	reader := loginForScope(t, client, server.URL, "site-quick-block-reader", tenantA.scopeID)
	path := func(siteID uuid.UUID) string { return server.URL + "/v1/sites/" + siteID.String() + "/quick-block" }
	var updated sitequickblock.State

	// IP library gate (the control plane has none yet): turning a block on
	// is refused; an override that only turns things off is not.
	plain := createSecurityPolicy(t, client, server.URL, authA.AccessToken, "site-quick-block-plain", createSecurityPolicyRequest{
		PolicyFields: validSecurityPolicyFields("Site quick block plain WAF", securitypolicy.KindWAF)})
	siteC := insertQuickBlockSite(t, pool, tenantA.scopeID, tenantA.userID)
	bindQuickBlockSite(t, pool, tenantA.scopeID, siteC, plain.ID, 0)
	response := siteRequest(t, client, http.MethodPut, path(siteC), map[string]any{"block_idc_global": true}, authA.AccessToken, "qb-no-intel", `"1"`)
	assertError(t, response, http.StatusUnprocessableEntity, "quick_block_ip_intel_unavailable", "")
	response = siteRequest(t, client, http.MethodPut, path(siteC), map[string]any{"block_idc_cn": false, "carriers": []string{}},
		authA.AccessToken, "qb-c-off", `"1"`)
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	if updated.Version != 2 || updated.Effective.BlockIDCCN || updated.Override.Carriers == nil {
		t.Fatalf("off without library = %+v", updated)
	}
	insertQuickBlockIPIntel(t, pool)

	waf := createSecurityPolicy(t, client, server.URL, authA.AccessToken, "site-quick-block-waf", createSecurityPolicyRequest{
		PolicyFields: validSecurityPolicyFields("Site quick block WAF", securitypolicy.KindWAF)})
	library := securitypolicy.QuickBlock{BlockIDCCN: true, Carriers: []string{"carrier:cn-mobile"},
		AllowedCrawlers: []securitypolicy.TrustedCrawler{{Networks: []string{"66.249.64.0/19"}, UserAgentPrefixes: []string{"Googlebot"}}}}
	response = siteRequest(t, client, http.MethodPut, server.URL+"/v1/security-policies/"+waf.ID.String()+"/quick-block",
		library, authA.AccessToken, "site-quick-block-library", `"1"`)
	decodeResponse(t, response, http.StatusOK, &waf)
	response.Body.Close()
	siteA := insertQuickBlockSite(t, pool, tenantA.scopeID, tenantA.userID)
	siteB := insertQuickBlockSite(t, pool, tenantA.scopeID, tenantA.userID)
	bare := insertQuickBlockSite(t, pool, tenantA.scopeID, tenantA.userID)
	// Site A publishes version 1 (latest 2), site B nothing yet.
	bindQuickBlockSite(t, pool, tenantA.scopeID, siteA, waf.ID, 1)
	bindQuickBlockSite(t, pool, tenantA.scopeID, siteB, waf.ID, 0)

	get := func(siteID uuid.UUID, token string) (sitequickblock.State, string) {
		t.Helper()
		response := siteRequest(t, client, http.MethodGet, path(siteID), nil, token, "", "")
		var state sitequickblock.State
		decodeResponse(t, response, http.StatusOK, &state)
		response.Body.Close()
		return state, response.Header.Get("ETag")
	}

	// Inheriting: the library's quick block is the site's.
	state, etag := get(siteA, reader.AccessToken)
	if etag != `"1"` || state.Version != 1 || !state.Override.Inherits() || state.Library == nil ||
		state.Library.PolicyID != waf.ID || state.Library.Version != 2 || state.Library.ActiveVersion != 1 || !state.Library.Supported ||
		state.Effective == nil || !state.Effective.BlockIDCCN || len(state.Effective.Carriers) != 1 || state.UpdatedAt != nil {
		t.Fatalf("inherited state = %+v etag %s", state, etag)
	}
	response = siteRequest(t, client, http.MethodGet, path(siteA), nil, authB.AccessToken, "", "")
	assertError(t, response, http.StatusNotFound, "site_not_found", "")
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"block_idc_cn": false}, reader.AccessToken, "qb-reader", `"1"`)
	assertError(t, response, http.StatusForbidden, "permission_denied", "")
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"block_idc_cn": false, "extra": 1},
		authA.AccessToken, "qb-unknown", `"1"`)
	assertError(t, response, http.StatusBadRequest, "invalid_request", "")

	sourceBefore := scopeSourceRevision(t, pool, tenantA.scopeID)
	carriers := []string{"carrier:cn-unicom", "carrier:cn-telecom"}
	override := map[string]any{"block_idc_cn": false, "block_idc_global": true, "carriers": carriers,
		"allowed_crawlers": []securitypolicy.TrustedCrawler{}}
	response = siteRequest(t, client, http.MethodPut, path(siteA), override, authA.AccessToken, "qb-put", `"1"`)
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	if response.Header.Get("ETag") != `"2"` || updated.Version != 2 || updated.Override.BlockIDCCN == nil || *updated.Override.BlockIDCCN ||
		updated.Override.Carriers == nil || (*updated.Override.Carriers)[0] != "carrier:cn-telecom" ||
		updated.Effective.BlockIDCCN || !updated.Effective.BlockIDCGlobal || len(updated.Effective.AllowedCrawlers) != 0 ||
		updated.UpdatedAt == nil {
		t.Fatalf("updated state = %+v", updated)
	}
	if after := scopeSourceRevision(t, pool, tenantA.scopeID); after != sourceBefore+1 {
		t.Fatalf("source revision %d -> %d, want +1", sourceBefore, after)
	}
	// Only site A changed.
	if state, _ := get(siteB, authA.AccessToken); state.Version != 1 || !state.Override.Inherits() || !state.Effective.BlockIDCCN {
		t.Fatalf("site B = %+v", state)
	}
	// Replay, conflicting replay, stale version.
	response = siteRequest(t, client, http.MethodPut, path(siteA), override, authA.AccessToken, "qb-put", `"1"`)
	var replayed sitequickblock.State
	decodeResponse(t, response, http.StatusOK, &replayed)
	response.Body.Close()
	if replayed.Version != 2 {
		t.Fatalf("replayed = %+v", replayed)
	}
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"block_idc_cn": true}, authA.AccessToken, "qb-put", `"1"`)
	assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"block_idc_cn": true}, authA.AccessToken, "qb-stale", `"1"`)
	assertError(t, response, http.StatusConflict, "version_conflict", "")

	// The library write guard: a library without a quick block of its own
	// switched to default block cannot carry site C's own global IDC block,
	// so the change is refused and names the site (only it).
	response = siteRequest(t, client, http.MethodPut, path(siteC), map[string]any{"block_idc_global": true}, authA.AccessToken, "qb-c", `"2"`)
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	blockDefault := validSecurityPolicyFields("Site quick block plain WAF", securitypolicy.KindWAF)
	blockDefault.DefaultAction = securitypolicy.ActionBlock
	response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/security-policies/"+plain.ID.String(), blockDefault,
		authA.AccessToken, "qb-library-block", quoteVersion(plain.Revision))
	body := assertErrorBody(t, response, http.StatusUnprocessableEntity, "quick_block_site_override_conflict")
	if !strings.Contains(body, siteC.String()) || strings.Contains(body, siteA.String()) {
		t.Fatalf("guard message = %s", body)
	}
	var latest int64
	if err := pool.QueryRow(ctx, `SELECT revision FROM security_policies WHERE id=$1`, plain.ID).Scan(&latest); err != nil || latest != plain.Revision {
		t.Fatalf("library revision after refusal = %d, %v", latest, err)
	}
	// A change the override still applies to goes through.
	renamed := validSecurityPolicyFields("Site quick block plain WAF renamed", securitypolicy.KindWAF)
	response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/security-policies/"+plain.ID.String(), renamed,
		authA.AccessToken, "qb-library-rename", quoteVersion(plain.Revision))
	decodeResponse(t, response, http.StatusOK, &plain)
	response.Body.Close()

	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"block_idc_cn": false, "carriers": []string{}},
		authA.AccessToken, "qb-off", `"2"`)
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	if updated.Version != 3 || updated.Effective.BlockIDCGlobal || updated.Effective.BlockIDCCN || len(updated.Effective.Carriers) != 0 ||
		len(updated.Effective.AllowedCrawlers) != 1 {
		t.Fatalf("off state = %+v", updated)
	}

	// A platform administrator's lock makes the site read only for tenants.
	if _, err := pool.Exec(ctx, `UPDATE sites SET lock_reason='quick block test',locked_at=now(),locked_by_user_id=$2 WHERE id=$1`, siteA, tenantA.userID); err != nil {
		t.Fatal(err)
	}
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{}, authA.AccessToken, "qb-locked", `"3"`)
	assertError(t, response, http.StatusConflict, "site_locked", "")
	if _, err := pool.Exec(ctx, `UPDATE sites SET lock_reason=NULL,locked_at=NULL,locked_by_user_id=NULL WHERE id=$1`, siteA); err != nil {
		t.Fatal(err)
	}

	// An automatic scope publishes the site change as its policy's actor.
	if _, err := pool.Exec(ctx, `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,required_consecutive_successes,
		max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,reason,created_at)
		VALUES($1,1,'automatic',ARRAY[$2::uuid],30000,15000,2,3,600,$1,$3,'site_quick_block_test',clock_timestamp())`,
		tenantA.scopeID, uuid.New(), readerID); err != nil {
		t.Fatal(err)
	}
	// Everything back to inherit: the row goes.
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"block_idc_cn": nil}, authA.AccessToken, "qb-inherit", `"3"`)
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	if updated.Version != 4 || !updated.Override.Inherits() || updated.UpdatedAt != nil || !updated.Effective.BlockIDCCN {
		t.Fatalf("inherit state = %+v", updated)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM site_quick_block_overrides WHERE site_id=$1`, siteA).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("override rows = %d, %v", rows, err)
	}
	var actorUserID uuid.UUID
	var operation string
	if err := pool.QueryRow(ctx, `SELECT actor_user_id,operation FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1 AND source_resource_id=$2`, tenantA.scopeID, siteA).Scan(&actorUserID, &operation); err != nil {
		t.Fatal(err)
	}
	if actorUserID != readerID || operation != "site.update" {
		t.Fatalf("automatic publication actor %s operation %s, want policy actor %s", actorUserID, operation, readerID)
	}

	// A site without a WAF library can only inherit.
	response = siteRequest(t, client, http.MethodPut, path(bare), map[string]any{"block_idc_cn": false}, authA.AccessToken, "qb-bare", `"1"`)
	assertError(t, response, http.StatusUnprocessableEntity, "quick_block_no_library", "")
	if state, _ := get(bare, authA.AccessToken); state.Library != nil || state.Effective != nil {
		t.Fatalf("bare state = %+v", state)
	}

	// Rule 10 audit: actor, IP, site scope, change summary; refusals denied with a reason code.
	type event struct {
		Result  string
		Payload map[string]any
		Actor   uuid.UUID
		Changes []audit.Change
	}
	auditRows, err := pool.Query(ctx, `SELECT result,payload,actor_user_id,changes FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND resource_type='site' AND resource_id=$3 ORDER BY stream_position`,
		tenantA.scopeID, sitequickblock.AuditAction, siteA.String())
	if err != nil {
		t.Fatal(err)
	}
	events, err := pgx.CollectRows(auditRows, func(row pgx.CollectableRow) (event, error) {
		var value event
		var raw, changes []byte
		if err := row.Scan(&value.Result, &raw, &value.Actor, &changes); err != nil {
			return value, err
		}
		value.Changes = audittest.DecodeChanges(t, changes)
		return value, json.Unmarshal(raw, &value.Payload)
	})
	if err != nil {
		t.Fatal(err)
	}
	var results []string
	for _, item := range events {
		reason, _ := item.Payload["reason_code"].(string)
		results = append(results, item.Result+":"+reason)
		if item.Actor != tenantA.userID || item.Payload["ip"] != "127.0.0.1" || item.Payload["site_id"] != siteA.String() {
			t.Fatalf("audit event = %+v", item)
		}
	}
	if got := strings.Join(results, ","); got != "success:,denied:idempotency_conflict,denied:revision_conflict,"+
		"success:,denied:site_locked,success:" {
		t.Fatalf("audit results = %s", got)
	}
	global, _ := audittest.Find(events[0].Changes, "block_idc_global")
	if len(events[0].Changes) != 4 || global.Before != "inherit" || global.After != true {
		t.Fatalf("first change summary = %v", events[0].Changes)
	}
	var intelDenied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action=$2 AND resource_id=$3
		AND result='denied' AND payload->>'reason_code'='ip_intel_unavailable'`, tenantA.scopeID, sitequickblock.AuditAction,
		siteC.String()).Scan(&intelDenied); err != nil || intelDenied != 1 {
		t.Fatalf("ip intel denied audits = %d, %v", intelDenied, err)
	}
	if err := audit.New(pool).VerifyScope(ctx, tenantA.scopeID); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
}

func insertQuickBlockIPIntel(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	// Since 353 the library is the downloaded artifact ipintel/base.
	artifactsynctest.SeedDownloaded(t, pool, artifactsynctest.IPIntelBase(3, "ipx-test", strings.Repeat("0", 64), 2),
		bytes.Repeat([]byte{1}, 65))
}

func insertQuickBlockSite(t *testing.T, pool *pgxpool.Pool, scopeID, owner uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	domain := "qb" + strings.ReplaceAll(id.String(), "-", "")[:12] + ".example.com"
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,display_id)
				VALUES($1,$2,$3,$4,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3,
				(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2))`, []any{id, scopeID, owner, domain}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{id}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, []any{id}},
		} {
			if _, err := tx.Exec(context.Background(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("insert site: %v", err)
	}
	return id
}

// bindQuickBlockSite binds the site's WAF slot to policy (active version 0:
// none published). A published binding is seeded directly (foreign keys off):
// its publication is not under test.
func bindQuickBlockSite(t *testing.T, pool *pgxpool.Pool, scopeID, siteID, policyID uuid.UUID, active int64) {
	t.Helper()
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if active == 0 {
			_, err := tx.Exec(context.Background(), `INSERT INTO security_policy_site_bindings
				(id,tenant_scope_id,site_id,policy_id,policy_kind,created_at,updated_at)
				VALUES($1,$2,$3,$4,'waf',now(),now())`, uuid.New(), scopeID, siteID, policyID)
			return err
		}
		if _, err := tx.Exec(context.Background(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `INSERT INTO security_policy_site_bindings
			(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,last_claimed_policy_version,last_bundle_id,
			 revision,created_at,updated_at)
			VALUES($1,$2,$3,$4,'waf',$5,$5,$6,1,now(),now())`, uuid.New(), scopeID, siteID, policyID, active, uuid.New())
		return err
	}); err != nil {
		t.Fatalf("bind site: %v", err)
	}
}

func scopeSourceRevision(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) int64 {
	t.Helper()
	var revision int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE((SELECT source_revision FROM edge_configuration_scopes
		WHERE scope_id=$1),0)`, scopeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}

func assertErrorBody(t *testing.T, response *http.Response, status int, code string) string {
	t.Helper()
	defer response.Body.Close()
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(response.Body); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if response.StatusCode != status || json.Unmarshal(buffer.Bytes(), &envelope) != nil || envelope.Error.Code != code {
		t.Fatalf("response %d %s, want %d %s", response.StatusCode, buffer.String(), status, code)
	}
	return buffer.String()
}
