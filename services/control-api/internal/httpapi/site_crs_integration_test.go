//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecrs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSiteCRSHTTP (PA-12): a WAF library running the default CRS profile
// (system/crs-pl1) is bound to two sites; one site picks another profile and
// excludes rules (sites.revision, If-Match, idempotency, profile and export
// checks), the other keeps the library's; policies and overrides need a
// downloaded pack; every write is audited.
func TestSiteCRSHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	ctx := context.Background()
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	tenantA := insertSecurityTenant(t, pool, "Site CRS A", "site-crs-a", passwordHash)
	tokens, err := identity.NewTokenManager("site-crs-secret-at-least-32-bytes-long", 5*time.Minute)
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
	authA := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)

	managedFields := func(name, profile string, exclusions []int) createSecurityPolicyRequest {
		fields := validSecurityPolicyFields(name, securitypolicy.KindWAF)
		fields.Rules = append(fields.Rules, securitypolicy.Rule{Name: "CRS", Priority: 200, Enabled: true,
			Action: securitypolicy.ActionManagedWAF, Flow: securitypolicy.FlowContinue, Conditions: []securitypolicy.Condition{},
			ActionConfig: securitypolicy.ActionConfig{ManagedWAF: &securitypolicy.ManagedWAFConfig{
				RequestBodyLimit: 13107200, RequestBodyNoFilesLimit: 131072, RequestBodyLimitAction: "reject",
				ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 100000, Profile: profile, Exclusions: exclusions}}})
		return createSecurityPolicyRequest{PolicyFields: fields}
	}
	// No pack downloaded: a managed WAF policy is refused.
	response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies",
		managedFields("CRS without packs", securitypolicy.DefaultCRSProfile, nil), authA.AccessToken, "crs-no-pack", "")
	assertError(t, response, http.StatusBadRequest, "validation_error", "")

	seedCRSProfilePacks(t, pool)
	response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies",
		managedFields("CRS bad exclusion", securitypolicy.DefaultCRSProfile, []int{913100}), authA.AccessToken, "crs-bad-excl", "")
	assertError(t, response, http.StatusBadRequest, "validation_error", "")
	waf := createSecurityPolicy(t, client, server.URL, authA.AccessToken, "crs-library",
		managedFields("CRS library", securitypolicy.DefaultCRSProfile, []int{942100}))

	siteA := insertQuickBlockSite(t, pool, tenantA.scopeID, tenantA.userID)
	siteB := insertQuickBlockSite(t, pool, tenantA.scopeID, tenantA.userID)
	bare := insertQuickBlockSite(t, pool, tenantA.scopeID, tenantA.userID)
	bindQuickBlockSite(t, pool, tenantA.scopeID, siteA, waf.ID, 0)
	bindQuickBlockSite(t, pool, tenantA.scopeID, siteB, waf.ID, 0)
	path := func(siteID uuid.UUID) string { return server.URL + "/v1/sites/" + siteID.String() + "/crs" }
	get := func(siteID uuid.UUID) sitecrs.State {
		t.Helper()
		response := siteRequest(t, client, http.MethodGet, path(siteID), nil, authA.AccessToken, "", "")
		var state sitecrs.State
		decodeResponse(t, response, http.StatusOK, &state)
		response.Body.Close()
		return state
	}

	state := get(siteA)
	if state.Version != 1 || !state.Override.Inherits() || state.Library == nil || state.Library.Profile != securitypolicy.DefaultCRSProfile ||
		!slices.Equal(state.Effective.Exclusions, []int{942100}) || len(state.Profiles) != 4 {
		t.Fatalf("inherited = %+v", state)
	}
	// Without the synced CRS rule text the profiles carry no tier; with it,
	// every profile is a protection tier counted from the rules
	// (仅记录 < 标准防护 < 严格防护 < 极严格防护).
	if state.Profiles[0].Tier != nil {
		t.Fatalf("tier without CRS rule text = %+v", state.Profiles[0].Tier)
	}
	crsRules := map[string]rulecatalog.Item{}
	for _, item := range rulecatalog.CRSWAFSeed() {
		crsRules[item.SystemKey] = item
	}
	crsBody, err := json.Marshal(crsRules["waf_set:crs_rules"].Body)
	if err != nil {
		t.Fatal(err)
	}
	// The signed catalog consumer writes security_system_rules; the fixture
	// writes the row the consumer would (as the edgepublish CRS fixture does).
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO security_system_rules(system_key,kind,name,sort,hidden,revision,body,status,delivery_id,first_seen_at,updated_at)
			VALUES('waf_set:crs_rules','waf_rule_set','OWASP CRS',101,true,2,$1,'active',$2,now(),now())`, crsBody, uuid.New())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	state = get(siteA)
	tiers := map[string]string{}
	for _, profile := range state.Profiles {
		if profile.Tier == nil {
			t.Fatalf("%s has no tier", profile.PackID)
		}
		tiers[profile.PackID] = fmt.Sprintf("%d:%s:%d:%d:%s", profile.Tier.Order, profile.Tier.Name, len(profile.Tier.Sets),
			profile.Tier.Paranoia, profile.Tier.Previous)
		if profile.Tier.Order > 0 && len(profile.Tier.Added) == 0 {
			t.Fatalf("%s adds nothing", profile.PackID)
		}
	}
	if tiers["system/crs-pl1-log"] != "0:仅记录:5:1:" || tiers["system/crs-pl1"] != "1:标准防护:5:1:system/crs-pl1-log" ||
		tiers["system/crs-pl2"] != "2:严格防护:11:2:system/crs-pl1" || tiers["system/crs-pl3"] != "3:极严格防护:11:3:system/crs-pl2" {
		t.Fatalf("tiers = %v", tiers)
	}

	pl2 := "system/crs-pl2"
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"profile": "system/crs-pl9"}, authA.AccessToken, "crs-pl9", `"1"`)
	assertError(t, response, http.StatusUnprocessableEntity, "crs_profile_unavailable", "")
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"exclusions": []int{913100}}, authA.AccessToken, "crs-913", `"1"`)
	assertError(t, response, http.StatusUnprocessableEntity, "crs_exclusion_not_exported", "")
	response = siteRequest(t, client, http.MethodPut, path(bare), map[string]any{"profile": pl2}, authA.AccessToken, "crs-bare", `"1"`)
	assertError(t, response, http.StatusUnprocessableEntity, "crs_no_managed_waf", "")
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"profile": "crs-pl2"}, authA.AccessToken, "crs-bad", `"1"`)
	assertError(t, response, http.StatusBadRequest, "validation_error", "")

	sourceBefore := scopeSourceRevision(t, pool, tenantA.scopeID)
	override := map[string]any{"profile": pl2, "exclusions": []int{942180, 941100}}
	response = siteRequest(t, client, http.MethodPut, path(siteA), override, authA.AccessToken, "crs-put", `"1"`)
	var updated sitecrs.State
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	if response.Header.Get("ETag") != `"2"` || updated.Effective.Profile != pl2 ||
		!slices.Equal(updated.Effective.Exclusions, []int{941100, 942180}) || updated.UpdatedAt == nil {
		t.Fatalf("updated = %+v", updated)
	}
	if after := scopeSourceRevision(t, pool, tenantA.scopeID); after != sourceBefore+1 {
		t.Fatalf("source revision %d -> %d", sourceBefore, after)
	}
	if other := get(siteB); other.Effective.Profile != securitypolicy.DefaultCRSProfile || !other.Override.Inherits() {
		t.Fatalf("site B = %+v", other)
	}
	response = siteRequest(t, client, http.MethodPut, path(siteA), override, authA.AccessToken, "crs-put", `"1"`)
	var replayed sitecrs.State
	decodeResponse(t, response, http.StatusOK, &replayed)
	response.Body.Close()
	if replayed.Version != 2 {
		t.Fatalf("replay = %+v", replayed)
	}
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"profile": nil}, authA.AccessToken, "crs-put", `"2"`)
	assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"profile": nil}, authA.AccessToken, "crs-stale", `"1"`)
	assertError(t, response, http.StatusConflict, "version_conflict", "")
	// Application types (waf-apptype): an unknown pack is refused before the
	// store, one not downloaded is denied, WordPress is stored and audited.
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"apps": []string{"wordpress"}},
		authA.AccessToken, "crs-app-bad", `"2"`)
	assertError(t, response, http.StatusBadRequest, "validation_error", "")
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"apps": []string{"system/app-joomla"}},
		authA.AccessToken, "crs-app-missing", `"2"`)
	assertError(t, response, http.StatusUnprocessableEntity, "crs_app_unavailable", "")
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{"apps": []string{"system/app-wordpress"}},
		authA.AccessToken, "crs-app", `"2"`)
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	if !slices.Equal(updated.Override.Apps, []string{"system/app-wordpress"}) || updated.Override.Profile != nil ||
		len(updated.Apps) != 8 || updated.Version != 3 {
		t.Fatalf("apps state = %+v", updated)
	}
	appEvents := audittest.Query(t, pool, `scope_id=$1 AND action=$2 AND resource_id=$3`, tenantA.scopeID, sitecrs.AppsAuditAction, siteA.String())
	if len(appEvents) != 1 || appEvents[0].Result != "success" || appEvents[0].Payload["ip"] == nil {
		t.Fatalf("apps audit = %+v", appEvents)
	}
	if change, ok := audittest.Find(appEvents[0].Changes, "apps"); !ok || fmt.Sprint(change.Before) != "[]" ||
		fmt.Sprint(change.After) != "[system/app-wordpress]" {
		t.Fatalf("apps audit changes = %+v", appEvents[0].Changes)
	}
	if other := get(siteB); len(other.Override.Apps) != 0 {
		t.Fatalf("site B apps = %+v", other.Override)
	}
	// Back to inherit: the row goes.
	response = siteRequest(t, client, http.MethodPut, path(siteA), map[string]any{}, authA.AccessToken, "crs-inherit", `"3"`)
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM site_crs_overrides WHERE site_id=$1`, siteA).Scan(&rows); err != nil || rows != 0 ||
		updated.Effective.Profile != securitypolicy.DefaultCRSProfile {
		t.Fatalf("inherit rows=%d state=%+v err=%v", rows, updated, err)
	}

	// Rule 10 audit (unified log: changes and reason codes are columns).
	events := audittest.Query(t, pool, `scope_id=$1 AND action=$2 AND resource_id=$3`, tenantA.scopeID, sitecrs.AuditAction, siteA.String())
	var results []string
	for _, item := range events {
		results = append(results, item.Result)
		if item.Payload["ip"] == nil || item.Payload["site_id"] != siteA.String() {
			t.Fatalf("audit payload = %+v", item.Payload)
		}
	}
	// pl9, 913100, bad id (validation, not audited), put, replay (no event), conflict, stale,
	// bad app (validation), app not downloaded, app, inherit.
	if want := []string{"denied", "denied", "success", "denied", "denied", "denied", "success", "success"}; !slices.Equal(results, want) {
		t.Fatalf("audit results = %v want %v", results, want)
	}
	if profile, ok := audittest.Find(events[2].Changes, "profile"); !ok || profile.Before != "inherit" || profile.After != pl2 {
		t.Fatalf("audit changes = %+v", events[2].Changes)
	}
	if events[0].ReasonCode != "crs_profile_unavailable" || events[1].ReasonCode != "crs_exclusion_not_exported" {
		t.Fatalf("denied reasons = %q %q", events[0].ReasonCode, events[1].ReasonCode)
	}
	if err := audit.New(pool).VerifyScope(ctx, tenantA.scopeID); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
}

// seedCRSProfilePacks stores the system/crs-* packs (libs/rulepack goldens)
// as downloaded catalog artifacts.
func seedCRSProfilePacks(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	paths, err := filepath.Glob("../../../../libs/rulepack/testdata/crs-profiles/crs-*.json")
	if err != nil || len(paths) != 4 {
		t.Fatalf("goldens: %v %v", paths, err)
	}
	// The application exclusion packs (waf-apptype) are downloaded alike.
	apps, err := filepath.Glob("../../../../libs/rulepack/testdata/crs-apps/app-*.json")
	if err != nil || len(apps) != 8 {
		t.Fatalf("application goldens: %v %v", apps, err)
	}
	paths = append(paths, apps...)
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var head struct {
			PackID  string `json:"pack_id"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(content, &head); err != nil {
			t.Fatal(err)
		}
		entry, err := artifactcatalog.CRSProfilePackEntry(head.PackID, head.Version, 1, content, "")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		if entry.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("entry digest")
		}
		artifactsynctest.SeedDownloaded(t, pool, entry, content)
	}
}
