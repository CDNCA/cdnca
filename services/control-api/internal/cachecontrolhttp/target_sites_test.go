package cachecontrolhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestTargetSitesTenantResolvesOwnScopeAndPlatformAllScopes(t *testing.T) {
	userID, tenantScope, platformScope, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	type call struct {
		actor     cachecontrol.Actor
		allScopes bool
		request   cachecontrol.ResolveTargetSitesRequest
	}
	var calls []call
	control := &fakeControl{targetSites: func(_ context.Context, actor cachecontrol.Actor, allScopes bool,
		request cachecontrol.ResolveTargetSitesRequest) (cachecontrol.TargetSiteGrouping, error) {
		calls = append(calls, call{actor, allScopes, request})
		return cachecontrol.TargetSiteGrouping{
			Groups: []cachecontrol.TargetSiteGroup{{
				Site:     cachecontrol.TargetSiteCandidate{SiteID: siteID, ScopeID: tenantScope, DisplayID: "12", Domain: "a.test"},
				Ordinals: []int{1},
			}},
			Unmatched: []cachecontrol.UnmatchedTarget{{Ordinal: 2, Reason: cachecontrol.TargetReasonNoSite}},
		}, nil
	}}
	tenant := principal(userID, tenantScope, "tenant", "sites.read")
	platform := principal(userID, platformScope, "platform", "platform.admin")
	authenticate := func(request *http.Request) (identity.Principal, error) {
		if request.Header.Get("Authorization") == "platform" {
			return platform, nil
		}
		return tenant, nil
	}
	handler := testHandler(t, control, &fakeReader{}, authenticate)
	body := map[string]any{"action": "purge", "target_type": "exact_url",
		"targets": []string{"https://a.test/1", "https://none.test/2"}}

	response := serve(t, handler, http.MethodPost, "/v1/cache-operations/target-sites", body, "tenant", "")
	if response.Code != http.StatusOK {
		t.Fatalf("tenant status = %d: %s", response.Code, response.Body.String())
	}
	var view TargetSitesView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Groups) != 1 || view.Groups[0].SiteID != siteID || view.Groups[0].ScopeID != tenantScope ||
		len(view.Unmatched) != 1 || view.Unmatched[0].TargetOrdinal != 2 || view.Unmatched[0].Reason != "target_site_not_found" {
		t.Fatalf("view = %+v", view)
	}
	if calls[0].allScopes || calls[0].actor.ScopeID != tenantScope || len(calls[0].request.Targets) != 2 {
		t.Fatalf("tenant call = %+v", calls[0])
	}

	// A tenant cannot widen its scope.
	if response := serve(t, handler, http.MethodPost, "/v1/cache-operations/target-sites?scope_id="+uuid.NewString(),
		body, "tenant", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("tenant scope_id status = %d", response.Code)
	}
	// A tenant principal on the platform route is refused.
	if response := serve(t, handler, http.MethodPost, "/v1/admin/cache-operations/target-sites",
		body, "tenant", ""); response.Code != http.StatusForbidden {
		t.Fatalf("tenant on admin route status = %d", response.Code)
	}

	// An administrator without scope_id matches every tenant's sites.
	response = serve(t, handler, http.MethodPost, "/v1/admin/cache-operations/target-sites", body, "platform", "")
	if response.Code != http.StatusOK {
		t.Fatalf("platform status = %d: %s", response.Code, response.Body.String())
	}
	last := calls[len(calls)-1]
	if !last.allScopes || last.actor.ScopeID != platformScope || last.actor.ActorScopeID != platformScope {
		t.Fatalf("platform all-scope call = %+v", last)
	}
	// With scope_id it matches that tenant's.
	response = serve(t, handler, http.MethodPost, "/v1/admin/cache-operations/target-sites?scope_id="+tenantScope.String(),
		body, "platform", "")
	if response.Code != http.StatusOK {
		t.Fatalf("platform scoped status = %d", response.Code)
	}
	last = calls[len(calls)-1]
	if last.allScopes || last.actor.ScopeID != tenantScope || last.actor.ActorScopeID != platformScope {
		t.Fatalf("platform scoped call = %+v", last)
	}
	// Unknown query keys stay refused on the platform route.
	if response := serve(t, handler, http.MethodPost, "/v1/admin/cache-operations/target-sites?site_id=x",
		body, "platform", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("unknown query status = %d", response.Code)
	}
	// Empty and oversized target lists are refused before the store.
	before := len(calls)
	for _, targets := range [][]string{{}, make([]string, EdgeCacheTaskV2MaxTargets+1)} {
		if response := serve(t, handler, http.MethodPost, "/v1/cache-operations/target-sites",
			map[string]any{"action": "purge", "target_type": "exact_url", "targets": targets}, "tenant", ""); response.Code != http.StatusBadRequest {
			t.Fatalf("targets %d status = %d", len(targets), response.Code)
		}
	}
	if len(calls) != before {
		t.Fatal("invalid bodies reached the store")
	}
}

func TestTargetSitesRequiresSitesRead(t *testing.T) {
	userID, scopeID := uuid.New(), uuid.New()
	control := &fakeControl{targetSites: func(context.Context, cachecontrol.Actor, bool,
		cachecontrol.ResolveTargetSitesRequest) (cachecontrol.TargetSiteGrouping, error) {
		t.Fatal("store reached without sites.read")
		return cachecontrol.TargetSiteGrouping{}, nil
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", "billing.read"), nil
	})
	response := serve(t, handler, http.MethodPost, "/v1/cache-operations/target-sites",
		map[string]any{"action": "purge", "target_type": "exact_url", "targets": []string{"https://a.test/"}}, "tenant", "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestCarryingNodesListsScopeNodes(t *testing.T) {
	userID, scopeID, nodeID := uuid.New(), uuid.New(), uuid.New()
	control := &fakeControl{carryingNodes: func(_ context.Context, actor cachecontrol.Actor) ([]cachecontrol.CarryingNode, error) {
		if actor.ScopeID != scopeID {
			t.Fatalf("actor = %+v", actor)
		}
		return []cachecontrol.CarryingNode{{ID: nodeID, DisplayID: "7", Name: "hk-1", IPv4: "192.0.2.1"}}, nil
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", "sites.read"), nil
	})
	response := serve(t, handler, http.MethodGet, "/v1/cache-operations/carrying-nodes", nil, "tenant", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	var view CarryingNodesView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Items) != 1 || view.Items[0].ID != nodeID || view.Items[0].Name != "hk-1" || view.Items[0].IPv4 != "192.0.2.1" {
		t.Fatalf("view = %+v", view)
	}
	if response := serve(t, handler, http.MethodPost, "/v1/cache-operations/carrying-nodes", nil, "tenant", ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", response.Code)
	}
}
