package marketsubscribehttp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/marketsubscribe"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

type fakeSiteRollout struct {
	actor   site.Actor
	version int64
	digest  string
	err     error
}

func (f *fakeSiteRollout) SiteBindings(context.Context, uuid.UUID) ([]marketsubscribe.SiteBinding, error) {
	return []marketsubscribe.SiteBinding{{Name: "HK", Role: "primary"}}, f.err
}
func (f *fakeSiteRollout) SiteLeaves(context.Context, uuid.UUID) ([]marketsubscribe.LeafStatus, error) {
	return []marketsubscribe.LeafStatus{{State: "applied", Node: marketsubscribe.LeafNodeDelivery{State: "delivering",
		Reason: "site_syncing"}}}, f.err
}
func (f *fakeSiteRollout) PreviewSite(_ context.Context, actor site.Actor, id uuid.UUID) (marketsubscribe.SiteRolloutResult, error) {
	f.actor = actor
	return marketsubscribe.SiteRolloutResult{Plan: marketsubscribe.SitePlan{SiteID: id, SiteVersion: 7, Revision: 3}}, f.err
}
func (f *fakeSiteRollout) ApplySite(_ context.Context, actor site.Actor, id uuid.UUID, version int64, digest string) (marketsubscribe.SiteRolloutResult, error) {
	f.actor, f.version, f.digest = actor, version, digest
	return marketsubscribe.SiteRolloutResult{Plan: marketsubscribe.SitePlan{SiteID: id, SiteVersion: 8}}, f.err
}

func TestSiteRolloutRoutes(t *testing.T) {
	svc := &fakeSiteRollout{}
	caller := admin
	h := New(&fake{}, func(*http.Request) (Caller, error) { return caller, nil }).WithSiteRollout(svc)
	site := uuid.New().String()
	digest := strings.Repeat("a", 64)

	if w := do(h, "GET", "/v1/admin/sites/"+site+"/market-supplies", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"role":"primary"`) {
		t.Fatalf("bindings: %d %s", w.Code, w.Body)
	}
	// fix-mktsiteconf7 §1: each leaf's receipt and node delivery, read back.
	if w := do(h, "GET", "/v1/admin/sites/"+site+"/market-rollout/leaves", ""); w.Code != 200 ||
		!strings.Contains(w.Body.String(), `"node":{"state":"delivering","reason":"site_syncing"`) {
		t.Fatalf("leaves: %d %s", w.Code, w.Body)
	}
	// Preview takes nothing from the page: no revision, no config.
	if w := do(h, "POST", "/v1/admin/sites/"+site+"/market-rollout/site-preview", `{"revision":1}`); w.Code != 400 {
		t.Fatalf("preview with revision: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/admin/sites/"+site+"/market-rollout/site-preview", `{}`); w.Code != 200 ||
		!strings.Contains(w.Body.String(), `"site_version":7`) || svc.actor.UserID != admin.UserID {
		t.Fatalf("preview: %d %s", w.Code, w.Body)
	}
	if w := do(h, "POST", "/v1/admin/sites/"+site+"/market-rollout/site-apply", `{"site_version":7}`); w.Code != 400 {
		t.Fatalf("apply without digest: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/admin/sites/"+site+"/market-rollout/site-apply", `{"site_version":7,"digest":"`+digest+`"}`); w.Code != 200 ||
		svc.version != 7 || svc.digest != digest {
		t.Fatalf("apply: %d %s", w.Code, w.Body)
	}
	// Saved again since the preview: 409 with the fresh plan to re-check.
	svc.err = marketsubscribe.ErrSiteChanged
	if w := do(h, "POST", "/v1/admin/sites/"+site+"/market-rollout/site-apply", `{"site_version":7,"digest":"`+digest+`"}`); w.Code != 409 ||
		!strings.Contains(w.Body.String(), `"site_changed"`) || !strings.Contains(w.Body.String(), `"site_version":8`) {
		t.Fatalf("changed: %d %s", w.Code, w.Body)
	}
	// fix-nopkgpub4: no valid package, the controller's subscriptions take no push.
	svc.err = marketsubscribe.ErrSitePackageUnavailable
	if w := do(h, "POST", "/v1/admin/sites/"+site+"/market-rollout/site-apply", `{"site_version":7,"digest":"`+digest+`"}`); w.Code != 409 ||
		!strings.Contains(w.Body.String(), `"site_package_unavailable"`) {
		t.Fatalf("no package: %d %s", w.Code, w.Body)
	}
	svc.err = marketsubscribe.ErrNotFound
	if w := do(h, "POST", "/v1/admin/sites/"+site+"/market-rollout/site-preview", `{}`); w.Code != 404 {
		t.Fatalf("not found: %d", w.Code)
	}
	svc.err = errors.New("boom")
	if w := do(h, "GET", "/v1/admin/sites/"+site+"/market-supplies", ""); w.Code != 500 {
		t.Fatalf("internal: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/admin/sites/x/market-rollout/site-preview", `{}`); w.Code != 400 {
		t.Fatalf("bad site: %d", w.Code)
	}
	// Buying alone does not edit sites.
	caller = Caller{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionPurchase}}
	if w := do(h, "POST", "/v1/admin/sites/"+site+"/market-rollout/site-preview", `{}`); w.Code != 403 {
		t.Fatalf("purchase only: %d", w.Code)
	}
	if w := do(h, "GET", "/v1/admin/sites/"+site+"/market-rollout/leaves", ""); w.Code != 403 {
		t.Fatalf("leaves, purchase only: %d", w.Code)
	}
}
