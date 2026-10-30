package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/wafsubscription"
	"github.com/google/uuid"
)

// NF37 / PA-25: platform operators manage subscription libraries; a tenant
// subscribes to a fetched one and gets a downloaded (not enabled) user layer
// rule pack, still listed after the operator deleted the subscription, and
// unsubscribing keeps the pack.
func TestWAFRuleSubscriptionHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(context.Background(), "subadmin", "Sub Admin", passwordHash, "sub-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenant := insertSecurityTenant(t, pool, "Sub Tenant", "sub-tenant", passwordHash)
	tokens, err := identity.NewTokenManager("waf-subscription-integration-secret-32b", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	platformAuth, _ := loginOK(t, client, server.URL, "subadmin")
	tenantAuth := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)
	call := func(method, path string, body any, token string) *http.Response {
		return siteRequest(t, client, method, server.URL+path, body, token, "", "")
	}

	response := call(http.MethodPost, "/v1/waf-rule-subscriptions", wafsubscription.Input{Name: "x", SourceURL: "https://rules.example.com/a.json"}, tenantAuth.AccessToken)
	assertError(t, response, http.StatusForbidden, "forbidden", "")
	response = call(http.MethodPost, "/v1/waf-rule-subscriptions", wafsubscription.Input{Name: "x", SourceURL: "https://169.254.169.254/latest"}, platformAuth.AccessToken)
	assertError(t, response, http.StatusBadRequest, "validation_error", "")

	var created wafsubscription.Subscription
	response = call(http.MethodPost, "/v1/waf-rule-subscriptions", wafsubscription.Input{Name: "已知漏洞防护", SourceURL: "https://rules.example.com/a.json", Enabled: true}, platformAuth.AccessToken)
	decodeResponse(t, response, http.StatusCreated, &created)
	if created.IntervalMinutes != wafsubscription.DefaultIntervalMinutes || created.Revision != 0 {
		t.Fatalf("created = %+v", created)
	}
	var updated wafsubscription.Subscription
	response = call(http.MethodPatch, "/v1/waf-rule-subscriptions/"+created.ID.String(),
		wafsubscription.Input{Name: "已知漏洞防护", SourceURL: "https://rules.example.com/b.json", IntervalMinutes: 60, Enabled: true}, platformAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &updated)
	if updated.IntervalMinutes != 60 || updated.SourceURL != "https://rules.example.com/b.json" {
		t.Fatalf("updated = %+v", updated)
	}

	available := func() []wafsubscription.TenantSubscription {
		var page tenantWAFRuleSubscriptionListResponse
		decodeResponse(t, call(http.MethodGet, "/v1/waf-rule-subscriptions/available", nil, tenantAuth.AccessToken), http.StatusOK, &page)
		return page.Items
	}
	if got := available(); len(got) != 0 {
		t.Fatalf("never fetched library listed: %+v", got)
	}
	// The subscription no longer appears as a WAF rule library.
	var page wafRuleLibraryListResponse
	decodeResponse(t, call(http.MethodGet, "/v1/waf-rule-libraries?limit=100", nil, tenantAuth.AccessToken), http.StatusOK, &page)
	for _, item := range page.Items {
		if item.ID == created.ID.String() {
			t.Fatalf("subscription listed as a WAF rule library: %+v", item)
		}
	}
	// Seed the snapshot a successful fetch stores.
	feed, err := wafsubscription.Compile([]byte(`{"version":"20261017","rules":[{"id":"r1","name":"S2-045","enable":1,"action":"protect",
	  "matcher_groups":[{"matcher":[{"field":"header","key":"Content-Type","op":"contain","value":"%{"}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rules := mustJSON(t, feed.Rules)
	if _, err := pool.Exec(context.Background(), `UPDATE waf_rule_subscriptions SET revision=1,rules=$2,rule_count=1,
		rules_sha256=$3,feed_version='20261017',last_success_at=now() WHERE id=$1`, created.ID, rules, feed.SHA256[:]); err != nil {
		t.Fatal(err)
	}
	got := available()
	if len(got) != 1 || got[0].Subscribed || got[0].FeedVersion != "20261017" || got[0].SyncedAt == nil || got[0].Revision != 1 {
		t.Fatalf("tenant subscriptions = %+v", got)
	}
	// Only tenants subscribe; the old library route does not know the subscription.
	response = call(http.MethodPost, "/v1/waf-rule-subscriptions/"+created.ID.String()+"/subscribe", nil, platformAuth.AccessToken)
	assertError(t, response, http.StatusForbidden, "forbidden", "")
	response = call(http.MethodPost, "/v1/waf-rule-libraries/"+created.ID.String()+"/subscribe", nil, tenantAuth.AccessToken)
	assertError(t, response, http.StatusNotFound, "not_found", "")

	var subscribed wafsubscription.TenantSubscription
	decodeResponse(t, call(http.MethodPost, "/v1/waf-rule-subscriptions/"+created.ID.String()+"/subscribe", nil, tenantAuth.AccessToken),
		http.StatusOK, &subscribed)
	packID := wafsubscription.PackID(tenant.scopeID, created.ID)
	if !subscribed.Subscribed || subscribed.Pack == nil || subscribed.Pack.PackID != packID ||
		subscribed.Pack.CurrentVersion != "1.0.0" || subscribed.Pack.UpdatePolicy != "auto" {
		t.Fatalf("subscribed = %+v / %+v", subscribed, subscribed.Pack)
	}
	// The pack is a downloaded user layer pack of the tenant, not enabled.
	var view struct {
		Packs []struct {
			PackID string `json:"pack_id"`
			Layer  string `json:"layer"`
			Effect *struct {
				Enabled bool `json:"enabled"`
			} `json:"effect"`
			Versions []struct {
				Source string `json:"source"`
			} `json:"versions"`
		} `json:"packs"`
	}
	decodeResponse(t, call(http.MethodGet, "/v1/rule-packs?level=tenant&object_id="+tenant.scopeID.String(), nil, tenantAuth.AccessToken),
		http.StatusOK, &view)
	if len(view.Packs) != 1 || view.Packs[0].PackID != packID || view.Packs[0].Layer != "user" || view.Packs[0].Effect == nil ||
		view.Packs[0].Effect.Enabled || len(view.Packs[0].Versions) != 1 || view.Packs[0].Versions[0].Source != "subscription" {
		t.Fatalf("tenant rule packs = %+v", view.Packs)
	}
	// The subscription's pack name is reserved for it.
	reserved, err := rulepack.CompilePack(wafsubscription.Pack(tenant.scopeID, uuid.New(), "mine", "", wafsubscription.Revision{Major: 1}, feed.Rules))
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/rule-packs", bytes.NewReader(reserved.Canonical))
	request.Header.Set("Authorization", "Bearer "+tenantAuth.AccessToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if body := readBody(response.Body); response.StatusCode != http.StatusBadRequest || !strings.Contains(body, "reserved") {
		t.Fatalf("import into a subscription name = %d %s", response.StatusCode, body)
	}

	var adminList wafRuleSubscriptionListResponse
	decodeResponse(t, call(http.MethodGet, "/v1/waf-rule-subscriptions", nil, platformAuth.AccessToken), http.StatusOK, &adminList)
	if len(adminList.Items) != 1 || adminList.Items[0].Subscribers != 1 || adminList.Items[0].PendingSites != 0 {
		t.Fatalf("admin list = %+v", adminList.Items)
	}
	var packs wafSubscriptionPackListResponse
	decodeResponse(t, call(http.MethodGet, "/v1/waf-rule-subscriptions/packs?subscription_id="+created.ID.String(), nil,
		platformAuth.AccessToken), http.StatusOK, &packs)
	if len(packs.Items) != 1 || packs.Items[0].TenantName != "Sub Tenant" || packs.Items[0].LatestVersion != "1.0.0" ||
		packs.Items[0].PendingSites == nil {
		t.Fatalf("subscriber packs = %+v", packs.Items)
	}
	var events int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND
		(action='rule.subscription.subscribe' AND changes @> '[{"field":"subscribed","before":false,"after":true}]' OR
		 action='rule.pack.version.create' AND resource_id=$2 AND payload->>'source'='subscription') AND payload ? 'ip'`,
		tenant.scopeID, packID+"@1.0.0").Scan(&events); err != nil || events != 2 {
		t.Fatalf("subscribe audit events = %d (%v)", events, err)
	}

	response = call(http.MethodDelete, "/v1/waf-rule-subscriptions/"+created.ID.String(), nil, platformAuth.AccessToken)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d", response.StatusCode)
	}
	response.Body.Close()
	if got = available(); len(got) != 1 || !got[0].Deleted || !got[0].Subscribed {
		t.Fatalf("deleted subscription not listed for its subscriber: %+v", got)
	}
	response = call(http.MethodDelete, "/v1/waf-rule-subscriptions/"+created.ID.String()+"/subscription", nil, tenantAuth.AccessToken)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unsubscribe status = %d %s", response.StatusCode, readBody(response.Body))
	}
	response.Body.Close()
	if got = available(); len(got) != 0 {
		t.Fatalf("after unsubscribe = %+v", got)
	}
	// Unsubscribing keeps the pack (it may be enabled and mounted).
	decodeResponse(t, call(http.MethodGet, "/v1/rule-packs?level=tenant&object_id="+tenant.scopeID.String(), nil, tenantAuth.AccessToken),
		http.StatusOK, &view)
	if len(view.Packs) != 1 || view.Packs[0].PackID != packID {
		t.Fatalf("pack after unsubscribe = %+v", view.Packs)
	}
}
