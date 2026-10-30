package marketsubscribehttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsubscribe"
	"github.com/google/uuid"
)

type fake struct {
	bound   [2]uuid.UUID
	applied bool
	err     error
	result  marketsubscribe.Result
}

func (f *fake) Supplies(context.Context) ([]marketsubscribe.Supply, error) {
	return []marketsubscribe.Supply{{Name: "s"}}, nil
}
func (f *fake) Bind(_ context.Context, site, supply uuid.UUID, _ string, _ int) error {
	f.bound = [2]uuid.UUID{site, supply}
	return f.err
}
func (f *fake) Unbind(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (f *fake) Preview(context.Context, uuid.UUID, int64, siteconf.Config) (marketsubscribe.Result, error) {
	return marketsubscribe.Result{}, f.err
}
func (f *fake) Apply(context.Context, uuid.UUID, int64, siteconf.Config) (marketsubscribe.Result, error) {
	f.applied = true
	if f.err != nil {
		return f.result, f.err
	}
	return marketsubscribe.Result{Applied: true}, nil
}

var admin = Caller{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{"sites.manage"}}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
	return w
}

func TestHandler(t *testing.T) {
	svc := &fake{}
	allowed := true
	h := New(svc, func(*http.Request) (Caller, error) {
		if !allowed {
			return Caller{}, errors.New("no")
		}
		return admin, nil
	})
	site, supply := uuid.New(), uuid.New()
	if w := do(h, "GET", "/v1/admin/market/supplies", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"items"`) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if w := do(h, "PUT", "/v1/admin/sites/"+site.String()+"/market-supplies/"+supply.String(), `{"role":"primary","priority":5}`); w.Code != 204 || svc.bound[1] != supply {
		t.Fatalf("bind: %d", w.Code)
	}
	if w := do(h, "PUT", "/v1/admin/sites/x/market-supplies/"+supply.String(), `{}`); w.Code != 400 {
		t.Fatalf("bad id: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/admin/sites/"+site.String()+"/market-rollout/apply", `{"revision":0,"config":{}}`); w.Code != 400 || svc.applied {
		t.Fatalf("revision 0: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/admin/sites/"+site.String()+"/market-rollout/apply", `{"revision":2,"config":{},"extra":1}`); w.Code != 400 {
		t.Fatalf("unknown field: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/admin/sites/"+site.String()+"/market-rollout/apply", `{"revision":2,"config":{}}`); w.Code != 200 || !svc.applied {
		t.Fatalf("apply: %d", w.Code)
	}
	svc.err = marketsubscribe.ErrStaleRevision
	if w := do(h, "POST", "/v1/admin/sites/"+site.String()+"/market-rollout/preview", `{"revision":2,"config":{}}`); w.Code != 409 ||
		!strings.Contains(w.Body.String(), "stale_revision") {
		t.Fatalf("stale: %d %s", w.Code, w.Body)
	}
	svc.err = marketsubscribe.ErrSitePackageUnavailable
	if w := do(h, "POST", "/v1/admin/sites/"+site.String()+"/market-rollout/apply", `{"revision":2,"config":{}}`); w.Code != 409 ||
		!strings.Contains(w.Body.String(), "site_package_unavailable") {
		t.Fatalf("no package: %d %s", w.Code, w.Body)
	}
	svc.err = marketsubscribe.ErrRevisionConflict
	if w := do(h, "POST", "/v1/admin/sites/"+site.String()+"/market-rollout/apply", `{"revision":2,"config":{}}`); w.Code != 409 ||
		!strings.Contains(w.Body.String(), "revision_conflict") {
		t.Fatalf("revision conflict: %d %s", w.Code, w.Body)
	}
	svc.err = marketsubscribe.ErrReceiptPending
	svc.result = marketsubscribe.Result{Revision: 2, Reason: "receipt_pending",
		Leaves: []marketsubscribe.LeafResult{{State: "receipt_pending"}}}
	if w := do(h, "POST", "/v1/admin/sites/"+site.String()+"/market-rollout/apply", `{"revision":2,"config":{}}`); w.Code != 202 ||
		!strings.Contains(w.Body.String(), `"reason":"receipt_pending"`) || !strings.Contains(w.Body.String(), `"applied":false`) {
		t.Fatalf("receipt pending: %d %s", w.Code, w.Body)
	}
	allowed = false
	if w := do(h, "GET", "/v1/admin/market/supplies", ""); w.Code != 403 {
		t.Fatalf("unauthorized: %d", w.Code)
	}
}

type fakeForwarder struct{ calls []string }

func (f *fakeForwarder) Forward(_ context.Context, method, path, key string, body []byte) (int, []byte, error) {
	if key != "" {
		f.calls = append(f.calls, method+" "+path+" key="+key+" "+string(body))
	} else {
		f.calls = append(f.calls, method+" "+path+" "+string(body))
	}
	if path == "/v1/members/me" {
		return http.StatusUnauthorized, []byte(`{"error":"unauthenticated"}`), nil
	}
	return http.StatusOK, []byte(`{"items":[]}`), nil
}

func TestMemberRoutesForwardAllowlistOnly(t *testing.T) {
	forwarder := &fakeForwarder{}
	h := New(&fake{}, func(*http.Request) (Caller, error) { return admin, nil }).WithMember(forwarder, "1.0.35")
	id := uuid.NewString()
	if w := do(h, "GET", "/v1/admin/market/offers", ""); w.Code != 200 {
		t.Fatalf("offers: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/admin/market/offers/"+id+"/publish", ""); w.Code != 200 {
		t.Fatalf("publish: %d", w.Code)
	}
	if w := do(h, "POST", "/v1/admin/market/subscriptions", `{"offer_id":"`+id+`","days":3}`); w.Code != 200 {
		t.Fatalf("purchase: %d", w.Code)
	}
	if w := do(h, "GET", "/v1/admin/market/ledger/balance?buyer_id=a&seller_id=b&currency=CNY", ""); w.Code != 200 {
		t.Fatalf("balance: %d", w.Code)
	}
	options := `{"components":[{"kind":"own_pool","node_pool_ref":"` + id + `"}]}`
	if w := do(h, "POST", "/v1/admin/market/offers/plugin-options", options); w.Code != 200 {
		t.Fatalf("plugin options: %d", w.Code)
	}
	if w := do(h, "GET", "/v1/admin/market/member", ""); w.Code != http.StatusBadGateway {
		t.Fatalf("market 401 must not log the admin out: %d", w.Code)
	}
	for _, bad := range []struct{ method, path, body string }{
		{"POST", "/v1/admin/market/offers/../../relay/publish", ""},
		{"POST", "/v1/admin/market/offers/not-an-id/publish", ""},
		{"GET", "/v1/admin/market/offers?page=1", ""},
		{"POST", "/v1/admin/market/subscriptions", "not json"},
		{"GET", "/v1/admin/market/relay/inbox", ""},
	} {
		// 3xx (the mux cleaning a ".." path) or 4xx: either way nothing is forwarded.
		before := len(forwarder.calls)
		if w := do(h, bad.method, bad.path, bad.body); w.Code < 300 || len(forwarder.calls) != before {
			t.Errorf("%s %s forwarded: %d", bad.method, bad.path, w.Code)
		}
	}
	want := []string{"GET /v1/offers ", "POST /v1/offers/" + id + "/publish ", `POST /v1/subscriptions {"offer_id":"` + id + `","days":3}`,
		"GET /v1/ledger/balance?buyer_id=a&currency=CNY&seller_id=b ", "POST /v1/offers/plugin-options " + options, "GET /v1/members/me "}
	if strings.Join(forwarder.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("forwarded:\n%v\nwant\n%v", forwarder.calls, want)
	}
}
