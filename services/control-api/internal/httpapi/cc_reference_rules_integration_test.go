package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

type ccReferenceErrorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Details struct {
			Field    string                           `json:"field"`
			Reason   string                           `json:"reason"`
			Policies []securitypolicy.CCReferenceUser `json:"policies"`
		} `json:"details"`
	} `json:"error"`
}

// a CC rule built from the scope's own
// matcher and filters is expanded on save, kept in step with their edits,
// and keeps them from being deleted or disabled.
func TestCCReferenceRulesHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(context.Background(), "ccrefadmin", "CC Ref Admin", passwordHash, "ccref-bootstrap"); err != nil {
		t.Fatalf("BootstrapPlatformUser: %v", err)
	}
	tenantA := insertSecurityTenant(t, pool, "CC Ref Tenant A", "ccref-a", passwordHash)
	tenantB := insertSecurityTenant(t, pool, "CC Ref Tenant B", "ccref-b", passwordHash)
	insertPackageSubscriptionWithSpec(t, pool, tenantA.scopeID, tenantA.userID, func(groupID uuid.UUID) string {
		return strings.Replace(validL4HTTPPackageSpec(groupID), `"custom_cc":false`, `"custom_cc":true`, 1)
	})
	tokens, err := identity.NewTokenManager("cc-reference-rules-integration-secret-32b", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	platformAuth, _ := loginOK(t, client, server.URL, "ccrefadmin")
	tenantAAuth := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	tenantBAuth := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)

	createReference := func(token, kind, key string, body map[string]any) ccReference {
		t.Helper()
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies/"+kind, body, token, key, "")
		var item ccReference
		decodeResponse(t, response, http.StatusCreated, &item)
		response.Body.Close()
		return item
	}
	refusal := func(response *http.Response, status int) ccReferenceErrorEnvelope {
		t.Helper()
		var envelope ccReferenceErrorEnvelope
		decodeResponse(t, response, status, &envelope)
		response.Body.Close()
		return envelope
	}
	matcher := createReference(tenantAAuth.AccessToken, "matchers", "ref-matcher", map[string]any{
		"name": "登录", "description": "", "enabled": true, "field": "path", "operator": "prefix", "values": []string{"/login"}})
	rate := createReference(tenantAAuth.AccessToken, "filters", "ref-rate", map[string]any{
		"name": "频率", "description": "", "enabled": true, "type": "req_rate",
		"parameters": map[string]any{"within_second": 10, "max_req": 30}})
	five := createReference(tenantAAuth.AccessToken, "filters", "ref-five", map[string]any{
		"name": "五秒盾", "description": "", "enabled": true, "type": "five_second",
		"parameters": map[string]any{"within_second": 60, "max_req": 3}})
	urlAuth := createReference(tenantAAuth.AccessToken, "filters", "ref-urlauth", map[string]any{
		"name": "URL鉴权", "description": "", "enabled": true, "type": "url_auth", "parameters": map[string]any{}})
	otherMatcher := createReference(tenantBAuth.AccessToken, "matchers", "ref-other", map[string]any{
		"name": "别人的", "description": "", "enabled": true, "field": "path", "operator": "prefix", "values": []string{"/"}})

	policyBody := func(name string, ref securitypolicy.CCReference) createSecurityPolicyRequest {
		return createSecurityPolicyRequest{PolicyFields: securitypolicy.PolicyFields{
			Kind: securitypolicy.KindCC, Name: name, Enabled: true, DefaultAction: securitypolicy.ActionAllow,
			Rules: []securitypolicy.Rule{{Name: "登录 · 频率", Priority: 1, Enabled: true, Flow: securitypolicy.FlowContinue,
				Action: securitypolicy.ActionRateLimit, Conditions: []securitypolicy.Condition{}, CCReference: &ref}},
		}}
	}

	policy := createSecurityPolicy(t, client, server.URL, tenantAAuth.AccessToken, "ref-policy",
		policyBody("引用规则组", securitypolicy.CCReference{MatcherID: matcher.ID, Filter1ID: rate.ID, Action: securitypolicy.ActionBlock}))
	t.Run("save expands the reference", func(t *testing.T) {
		rule := policy.Rules[0]
		limit := rule.ActionConfig.RateLimit
		if len(rule.Conditions) != 1 || rule.Conditions[0].Field != "path" || rule.Conditions[0].Values[0] != "/login" ||
			rule.Action != securitypolicy.ActionRateLimit || limit == nil || limit.WindowSeconds != 10 || limit.MaxRequests != 30 ||
			limit.ResponseAction != "temporary_ban" || rule.CCReference == nil || rule.CCReference.MatcherVersion != 1 ||
			rule.CCReference.Filter1Version != 1 {
			t.Fatalf("expanded rule = %#v", rule)
		}
		pair := createSecurityPolicy(t, client, server.URL, tenantAAuth.AccessToken, "ref-pair",
			policyBody("频率后五秒盾", securitypolicy.CCReference{MatcherID: matcher.ID, Filter1ID: rate.ID, Filter2ID: &five.ID,
				Action: securitypolicy.ActionBlock}))
		challenge := pair.Rules[0].ActionConfig.Challenge
		if challenge == nil || challenge.Type != "five_second" || challenge.TriggerMaxRequests != 30 || challenge.MaxFailures != 3 {
			t.Fatalf("pair rule = %#v", pair.Rules[0])
		}
	})

	t.Run("references must be usable in the policy scope", func(t *testing.T) {
		cross := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies",
			policyBody("跨租户", securitypolicy.CCReference{MatcherID: otherMatcher.ID, Filter1ID: rate.ID, Action: securitypolicy.ActionBlock}),
			tenantAAuth.AccessToken, "ref-cross", "")
		if got := refusal(cross, http.StatusBadRequest); got.Error.Details.Field != "rules[0].cc_reference.matcher_id" ||
			got.Error.Details.Reason != securitypolicy.CCReferenceUnavailable {
			t.Fatalf("cross-scope refusal = %#v", got)
		}
		unsupported := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies",
			policyBody("URL鉴权", securitypolicy.CCReference{MatcherID: matcher.ID, Filter1ID: urlAuth.ID, Action: securitypolicy.ActionBlock}),
			tenantAAuth.AccessToken, "ref-unsupported", "")
		if got := refusal(unsupported, http.StatusBadRequest); got.Error.Details.Field != "rules[0].cc_reference.filter1_id" ||
			got.Error.Details.Reason != securitypolicy.CCReferenceUnsupported {
			t.Fatalf("unsupported refusal = %#v", got)
		}
	})

	t.Run("in use cannot be deleted or disabled", func(t *testing.T) {
		deleted := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/security-policies/matchers/"+matcher.ID.String(), nil,
			tenantAAuth.AccessToken, "ref-delete", `"1"`)
		got := refusal(deleted, http.StatusConflict)
		if got.Error.Code != "cc_reference_in_use" || len(got.Error.Details.Policies) != 2 {
			t.Fatalf("delete refusal = %#v", got)
		}
		disabled := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies/filters/"+five.ID.String()+"/disable", nil,
			tenantAAuth.AccessToken, "ref-disable", `"1"`)
		got = refusal(disabled, http.StatusConflict)
		if got.Error.Code != "cc_reference_in_use" || len(got.Error.Details.Policies) != 1 || got.Error.Details.Policies[0].Name != "频率后五秒盾" {
			t.Fatalf("disable refusal = %#v", got)
		}
		free := createReference(tenantAAuth.AccessToken, "matchers", "ref-free", map[string]any{
			"name": "未用", "description": "", "enabled": true, "field": "path", "operator": "prefix", "values": []string{"/free"}})
		off := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies/matchers/"+free.ID.String()+"/disable", nil,
			tenantAAuth.AccessToken, "ref-free-disable", `"1"`)
		var item ccReference
		decodeResponse(t, off, http.StatusOK, &item)
		off.Body.Close()
		usesDisabled := siteRequest(t, client, http.MethodPost, server.URL+"/v1/security-policies",
			policyBody("禁用的", securitypolicy.CCReference{MatcherID: free.ID, Filter1ID: rate.ID, Action: securitypolicy.ActionBlock}),
			tenantAAuth.AccessToken, "ref-uses-disabled", "")
		if got := refusal(usesDisabled, http.StatusBadRequest); got.Error.Details.Reason != securitypolicy.CCReferenceUnavailable {
			t.Fatalf("disabled matcher refusal = %#v", got)
		}
	})

	readPolicy := func() securitypolicy.Policy {
		t.Helper()
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/"+policy.ID.String(), nil, tenantAAuth.AccessToken, "", "")
		var item securitypolicy.Policy
		decodeResponse(t, response, http.StatusOK, &item)
		response.Body.Close()
		return item
	}
	editMatcher := func(key, version string, body map[string]any, status int) *http.Response {
		t.Helper()
		response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/security-policies/matchers/"+matcher.ID.String(), body,
			tenantAAuth.AccessToken, key, version)
		if response.StatusCode != status {
			t.Fatalf("edit matcher status = %d, body=%s", response.StatusCode, readBody(response.Body))
		}
		return response
	}

	t.Run("matcher edit re-expands its policies", func(t *testing.T) {
		editMatcher("ref-edit", `"1"`, map[string]any{"name": "登录", "description": "", "enabled": true, "field": "path",
			"operator": "prefix", "values": []string{"/admin"}}, http.StatusOK).Body.Close()
		current := readPolicy()
		if current.Revision != 2 || current.Rules[0].Conditions[0].Values[0] != "/admin" || current.Rules[0].CCReference.MatcherVersion != 2 {
			t.Fatalf("re-expanded policy = %#v", current)
		}
		var versions int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM security_policy_versions WHERE policy_id=$1`, policy.ID).Scan(&versions); err != nil {
			t.Fatal(err)
		}
		if versions != 2 {
			t.Fatalf("policy versions = %d", versions)
		}
	})

	t.Run("equal re-expansion keeps the revision", func(t *testing.T) {
		editMatcher("ref-rename", `"2"`, map[string]any{"name": "登录入口", "description": "改名", "enabled": true, "field": "path",
			"operator": "prefix", "values": []string{"/admin"}}, http.StatusOK).Body.Close()
		current := readPolicy()
		if current.Revision != 2 {
			t.Fatalf("rename bumped policy revision to %d", current.Revision)
		}
		resaved := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/security-policies/"+policy.ID.String(), createdFields(current),
			tenantAAuth.AccessToken, "ref-resave", `"2"`)
		var item securitypolicy.Policy
		decodeResponse(t, resaved, http.StatusOK, &item)
		resaved.Body.Close()
		if item.Revision != 2 {
			t.Fatalf("equal policy save revision = %d", item.Revision)
		}
	})

	t.Run("edit the node cannot run is refused whole", func(t *testing.T) {
		response := editMatcher("ref-regex", `"3"`, map[string]any{"name": "登录入口", "description": "", "enabled": true, "field": "path",
			"operator": "regex", "values": []string{".*"}}, http.StatusBadRequest)
		if got := refusal(response, http.StatusBadRequest); got.Error.Details.Field != "operator" ||
			got.Error.Details.Reason != securitypolicy.CCReferenceUnsupported {
			t.Fatalf("regex refusal = %#v", got)
		}
		read := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/matchers/"+matcher.ID.String(), nil, tenantAAuth.AccessToken, "", "")
		var item ccReference
		decodeResponse(t, read, http.StatusOK, &item)
		read.Body.Close()
		if item.Version != 3 || item.Operator != "prefix" || readPolicy().Revision != 2 {
			t.Fatalf("refused edit was written: %#v", item)
		}
	})

	t.Run("list by target scope", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/filters?page=1&limit=100&status=enabled&scope_id="+tenantA.scopeID.String(),
			nil, platformAuth.AccessToken, "", "")
		var list ccReferenceList
		decodeResponse(t, response, http.StatusOK, &list)
		response.Body.Close()
		for _, item := range list.Items {
			if item.ScopeID != tenantA.scopeID {
				t.Fatalf("scope_id filter leaked %#v", item)
			}
		}
		if list.Total < 3 {
			t.Fatalf("tenant A filters = %#v", list)
		}
		foreign := siteRequest(t, client, http.MethodGet, server.URL+"/v1/security-policies/matchers?scope_id="+tenantA.scopeID.String(),
			nil, tenantBAuth.AccessToken, "", "")
		assertError(t, foreign, http.StatusForbidden, "permission_denied", "")
		foreign.Body.Close()
	})
}
