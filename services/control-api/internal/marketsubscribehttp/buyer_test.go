package marketsubscribehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/pluginkind"
	"github.com/google/uuid"
)

type scriptedForwarder struct {
	calls  []string
	status int
	body   string
}

func (f *scriptedForwarder) Forward(_ context.Context, method, path, key string, body []byte) (int, []byte, error) {
	f.calls = append(f.calls, method+" "+path+" key="+key+" "+string(body))
	return f.status, []byte(f.body), nil
}

type fakeStore struct {
	scope   uuid.UUID
	acked   string
	listErr error
}

func (s *fakeStore) Advisories(_ context.Context, scope uuid.UUID, plugin string) ([]Advisory, error) {
	s.scope = scope
	return []Advisory{{ID: uuid.New(), PluginID: "acme.waf"}}, s.listErr
}
func (s *fakeStore) Acknowledge(_ context.Context, scope, _, _ uuid.UUID, disposition, _ string) (Acknowledgement, error) {
	s.scope, s.acked = scope, disposition
	return Acknowledgement{Disposition: disposition}, nil
}

type countingReporter struct{ calls int }

func (r *countingReporter) Report(context.Context) error { r.calls++; return nil }

func caller(kind string, permissions ...string) Caller {
	return Caller{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: kind, Permissions: permissions}
}

func buyerHandler(c *Caller, f Forwarder, store BuyerStore, reporter ...AdvisoryReporter) http.Handler {
	var r AdvisoryReporter
	if len(reporter) == 1 {
		r = reporter[0]
	}
	return New(&fake{}, func(*http.Request) (Caller, error) { return *c, nil }).WithMember(f, "1.0.35").WithBuyer(store, r)
}

func request(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	h.ServeHTTP(w, r)
	return w
}

func TestMarketplacePermissionMatrix(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"items":[]}`}
	current := caller("platform")
	h := buyerHandler(&current, f, &fakeStore{})
	key := map[string]string{"Idempotency-Key": "k-1"}
	id := uuid.NewString()
	cases := []struct {
		name    string
		caller  Caller
		method  string
		path    string
		body    string
		allowed bool
	}{
		{"browse reads plugins", caller("platform", PermissionBrowse), "GET", "/v1/admin/market/plugins", "", true},
		{"browse cannot buy", caller("platform", PermissionBrowse), "POST", "/v1/admin/market/orders", `{}`, false},
		{"purchase buys", caller("platform", PermissionPurchase), "POST", "/v1/admin/market/orders", `{}`, true},
		{"purchase also browses", caller("platform", PermissionPurchase), "GET", "/v1/admin/market/licenses", "", true},
		{"purchase cannot sell", caller("platform", PermissionPurchase), "POST", "/v1/admin/market/offers", `{}`, false},
		{"sell lists offers", caller("platform", PermissionSell), "POST", "/v1/admin/market/offers", `{}`, true},
		{"sell cannot cancel licences", caller("platform", PermissionSell), "POST", "/v1/admin/market/licenses/" + id + "/cancel", "", false},
		{"marketplace codes list supplies", caller("platform", PermissionBrowse), "GET", "/v1/admin/market/supplies", "", true},
		{"marketplace codes cannot bind sites", caller("platform", PermissionPurchase, PermissionSell), "PUT", "/v1/admin/sites/" + id + "/market-supplies/" + id, `{"role":"primary"}`, false},
		{"marketplace codes cannot roll out", caller("platform", PermissionPurchase), "POST", "/v1/admin/sites/" + id + "/market-rollout/apply", `{"revision":1,"config":{}}`, false},
		{"legacy sites.manage keeps everything", caller("platform", "sites.manage"), "POST", "/v1/admin/market/disputes", `{}`, true},
		{"legacy platform.admin binds sites", caller("platform", "platform.admin"), "GET", "/v1/admin/market/supplies", "", true},
		{"tenant with codes cannot buy", caller("tenant", PermissionPurchase, "sites.manage"), "POST", "/v1/admin/market/orders", `{}`, false},
		{"tenant reads advisories", caller("tenant", "plugin_installations.read"), "GET", "/v1/admin/market/advisories", "", true},
		{"tenant reader cannot acknowledge", caller("tenant", "plugin_installations.read"), "POST", "/v1/admin/market/advisories/" + id + "/acknowledge", `{"disposition":"disabled"}`, false},
		{"tenant manager acknowledges", caller("tenant", "plugin_installations.manage"), "POST", "/v1/admin/market/advisories/" + id + "/acknowledge", `{"disposition":"disabled"}`, true},
		{"tenant installer reads one plugin (ui_page before confirming)", caller("tenant", "plugin_installations.read"), "GET", "/v1/admin/market/plugins/" + id, "", true},
		{"tenant installer looks its plugin up", caller("tenant", "plugin_installations.manage"), "GET", "/v1/admin/market/plugins?q=acme.reports", "", true},
		{"tenant installer cannot buy", caller("tenant", "plugin_installations.manage"), "POST", "/v1/admin/market/plugin-downloads", `{}`, false},
		{"tenant without plugin codes cannot read a plugin", caller("tenant", "sites.manage"), "GET", "/v1/admin/market/plugins/" + id, "", false},
		{"no permission", caller("platform"), "GET", "/v1/admin/market/plugins", "", false},
	}
	for _, tc := range cases {
		current = tc.caller
		before := len(f.calls)
		w := request(h, tc.method, tc.path, tc.body, key)
		if tc.allowed && w.Code == http.StatusForbidden || !tc.allowed && (w.Code != http.StatusForbidden || len(f.calls) != before) {
			t.Errorf("%s: %d %s", tc.name, w.Code, w.Body)
		}
	}
}

func TestBuyerForwardingContract(t *testing.T) {
	f := &scriptedForwarder{status: 201, body: `{"order":{"id":"x"},"checkout_url":"https://portal/c/1"}`}
	current := caller("platform", PermissionPurchase)
	h := buyerHandler(&current, f, &fakeStore{})
	id := uuid.NewString()
	if w := request(h, "POST", "/v1/admin/market/orders", `{"market":"plugin"}`, nil); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "idempotency_key_required") || len(f.calls) != 0 {
		t.Fatalf("order without key: %d %s", w.Code, w.Body)
	}
	if w := request(h, "POST", "/v1/admin/market/orders", `{"market":"plugin"}`, map[string]string{"Idempotency-Key": "bad key"}); w.Code != 400 {
		t.Fatalf("bad key: %d", w.Code)
	}
	if w := request(h, "POST", "/v1/admin/market/orders", `{"market":"plugin"}`, map[string]string{"Idempotency-Key": "order-1"}); w.Code != 201 ||
		!strings.Contains(w.Body.String(), "checkout_url") {
		t.Fatalf("order: %d %s", w.Code, w.Body)
	}
	f.status, f.body = 200, `{"items":[],"next_cursor":null}`
	request(h, "GET", "/v1/admin/market/plugins?q=waf&kind=rule_pack&price=free", "", nil)
	request(h, "GET", "/v1/admin/market/plugins?all_versions=1", "", nil)
	request(h, "GET", "/v1/admin/market/plugins?compat=1.0.30", "", nil)
	request(h, "GET", "/v1/admin/market/plugins?kind=theme&applies_to=user", "", nil)
	request(h, "GET", "/v1/admin/market/offers?region=hk&max_price=500&min_score=2.5&settlement_mode=escrow", "", nil)
	request(h, "GET", "/v1/admin/market/offers?cursor=1792915200000000000%7E"+id+"&limit=50", "", nil)
	request(h, "PUT", "/v1/admin/market/subscriptions/"+id+"/renewal-policy", `{"renewal_price_policy":"if_lesser_or_equal"}`,
		map[string]string{"Idempotency-Key": "rp-1"})
	request(h, "POST", "/v1/admin/market/disputes/"+id+"/withdraw", `{}`, map[string]string{"Idempotency-Key": "wd-1"})
	request(h, "PUT", "/v1/admin/market/subscriptions/"+id+"/selection", `{"max_unit_price_minor":300,"min_quality_score":2}`,
		map[string]string{"Idempotency-Key": "sel-1"})
	request(h, "POST", "/v1/admin/market/plugin-purchases", `{"price_plan_id":"`+id+`","plan_revision":2}`,
		map[string]string{"Idempotency-Key": "pp-1"})
	request(h, "GET", "/v1/admin/market/usage-statements?as=buyer&status=issued", "", nil)
	request(h, "GET", "/v1/admin/market/disputes?status=under_review&subject_kind=plugin_order&limit=20", "", nil)
	request(h, "POST", "/v1/admin/market/disputes", `{"subject_kind":"plugin_order","order_id":"`+id+`","reason_code":"not_working"}`,
		map[string]string{"Idempotency-Key": "dsp-1"})
	request(h, "POST", "/v1/admin/market/orders", `{"kind":"prepaid_topup","amount_minor":5000,"currency":"CNY"}`,
		map[string]string{"Idempotency-Key": "topup-1"})
	want := []string{
		`POST /v1/orders key=order-1 {"market":"plugin"}`,
		`GET /v1/plugins?compat=1.0.35&kind=rule_pack&price=free&q=waf key= `,
		`GET /v1/plugins key= `,
		`GET /v1/plugins?compat=1.0.30 key= `,
		`GET /v1/plugins?applies_to=user&compat=1.0.35&kind=theme key= `,
		`GET /v1/offers?max_price=500&min_score=2.5&region=hk&settlement_mode=escrow key= `,
		`GET /v1/offers?cursor=1792915200000000000~` + id + `&limit=50 key= `,
		`PUT /v1/subscriptions/` + id + `/renewal-policy key=rp-1 {"renewal_price_policy":"if_lesser_or_equal"}`,
		`POST /v1/disputes/` + id + `/withdraw key=wd-1 {}`,
		`PUT /v1/subscriptions/` + id + `/selection key=sel-1 {"max_unit_price_minor":300,"min_quality_score":2}`,
		`POST /v1/plugin-purchases key=pp-1 {"price_plan_id":"` + id + `","plan_revision":2}`,
		`GET /v1/usage-statements?as=buyer&status=issued key= `,
		`GET /v1/disputes?limit=20&status=under_review&subject_kind=plugin_order key= `,
		`POST /v1/disputes key=dsp-1 {"subject_kind":"plugin_order","order_id":"` + id + `","reason_code":"not_working"}`,
		`POST /v1/orders key=topup-1 {"kind":"prepaid_topup","amount_minor":5000,"currency":"CNY"}`,
	}
	if got := strings.Join(f.calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("forwarded:\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}
	for _, bad := range []string{
		"/v1/admin/market/plugins?kind=rootkit", "/v1/admin/market/plugins?kind=waf_rule_pack", "/v1/admin/market/plugins?kind=edge_script", "/v1/admin/market/plugins?sort=price", "/v1/admin/market/plugins?limit=0", "/v1/admin/market/plugins?applies_to=all", "/v1/admin/market/plugins?applies_to=user%2Csite",
		"/v1/admin/market/plugins?limit=201", "/v1/admin/market/offers?min_score=3.5", "/v1/admin/market/offers?max_price=-1", "/v1/admin/market/offers?limit=201",
		"/v1/admin/market/licenses?q=x", "/v1/admin/market/offers?all_versions=1", "/v1/admin/market/usage-statements?as=operator",
		"/v1/admin/market/disputes?status=open", "/v1/admin/market/disputes?subject_kind=offer",
	} {
		before := len(f.calls)
		if w := request(h, "GET", bad, "", nil); w.Code != 400 || len(f.calls) != before {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
	// An entry the market has not mounted yet answers plain-text 404.
	f.status, f.body = 404, "404 page not found\n"
	if w := request(h, "GET", "/v1/admin/market/disputes", "", nil); w.Code != http.StatusNotImplemented ||
		!strings.Contains(w.Body.String(), "market_feature_unavailable") {
		t.Fatalf("unmounted: %d %s", w.Code, w.Body)
	}
	f.status, f.body = 404, `{"error":"not_found"}`
	if w := request(h, "GET", "/v1/admin/market/orders/"+id, "", nil); w.Code != 404 {
		t.Fatalf("market 404: %d", w.Code)
	}
}

// TestPluginKindFilterMatchesMarket030 pins the kind filter to the market 030 kinds.
func TestPluginKindFilterMatchesMarket030(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"items":[],"next_cursor":null}`}
	current := caller("platform", PermissionPurchase)
	h := buyerHandler(&current, f, &fakeStore{})
	for _, kind := range pluginkind.All {
		before := len(f.calls)
		if w := request(h, "GET", "/v1/admin/market/plugins?all_versions=1&kind="+kind, "", nil); w.Code != 200 || len(f.calls) != before+1 {
			t.Errorf("kind=%s: %d", kind, w.Code)
		}
	}
}

func TestDevelopmentBuildDoesNotFilterByVersion(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"items":[]}`}
	h := New(&fake{}, func(*http.Request) (Caller, error) { return caller("platform", PermissionBrowse), nil }).WithMember(f, "development")
	request(h, "GET", "/v1/admin/market/plugins", "", nil)
	if len(f.calls) != 1 || f.calls[0] != "GET /v1/plugins key= " {
		t.Fatalf("calls %v", f.calls)
	}
}

func TestBuyerLocalRoutes(t *testing.T) {
	store := &fakeStore{}
	reporter := &countingReporter{}
	current := caller("tenant", "plugin_installations.manage")
	h := buyerHandler(&current, &scriptedForwarder{}, store, reporter)
	id := uuid.NewString()
	if w := request(h, "GET", "/v1/admin/market/advisories?plugin_id=acme.waf", "", nil); w.Code != 200 || store.scope != current.ScopeID {
		t.Fatalf("list: %d scope=%s", w.Code, store.scope)
	}
	if w := request(h, "GET", "/v1/admin/market/advisories?plugin_id=Bad", "", nil); w.Code != 400 {
		t.Fatalf("bad plugin: %d", w.Code)
	}
	for _, body := range []string{`{"disposition":"ignored"}`, `{"disposition":"disabled","extra":1}`,
		`{"disposition":"disabled","note":"` + strings.Repeat("长", 501) + `"}`} {
		if w := request(h, "POST", "/v1/admin/market/advisories/"+id+"/acknowledge", body, nil); w.Code != 400 {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
	if w := request(h, "POST", "/v1/admin/market/advisories/"+id+"/acknowledge", `{"disposition":"upgraded","note":"到 1.4.2"}`, nil); w.Code != 200 ||
		store.acked != "upgraded" {
		t.Fatalf("ack: %d %s", w.Code, w.Body)
	}

	if reporter.calls != 0 {
		t.Fatalf("tenant ack reported upstream %d times", reporter.calls)
	}
	current = caller("platform", PermissionPurchase)
	if w := request(h, "POST", "/v1/admin/market/advisories/"+id+"/acknowledge", `{"disposition":"disabled"}`, nil); w.Code != 200 ||
		reporter.calls != 1 {
		t.Fatalf("platform ack: %d reported=%d", w.Code, reporter.calls)
	}
}

type libraryStore struct {
	fakeStore
	items []LibraryItem
}

func (s *libraryStore) Library(context.Context) ([]LibraryItem, error) { return s.items, nil }

// PA-27: the embedded store reads the local plugin library and downloads through the market.
func TestPluginLibraryAndDownload(t *testing.T) {
	store := &libraryStore{items: []LibraryItem{{PluginID: "acme.waf", Installed: true, Withdrawn: true}}}
	f := &scriptedForwarder{status: 200, body: `{"plugin_id":"acme.waf","source":"free"}`}
	current := caller("platform", PermissionBrowse)
	h := buyerHandler(&current, f, store)
	if w := request(h, "GET", "/v1/admin/market/plugin-library", "", nil); w.Code != 200 ||
		!strings.Contains(w.Body.String(), `"withdrawn":true`) {
		t.Fatalf("library: %d %s", w.Code, w.Body)
	}
	if w := request(h, "GET", "/v1/admin/market/plugin-library?x=1", "", nil); w.Code != 400 {
		t.Fatalf("library query: %d", w.Code)
	}
	if w := request(h, "POST", "/v1/admin/market/plugin-downloads", `{"plugin_id":"acme.waf"}`, nil); w.Code != 403 || len(f.calls) != 0 {
		t.Fatalf("browse-only download: %d", w.Code)
	}
	current = caller("platform", PermissionPurchase)
	if w := request(h, "POST", "/v1/admin/market/plugin-downloads", `{"plugin_id":"acme.waf"}`, nil); w.Code != 200 ||
		strings.Join(f.calls, "") != `POST /v1/plugin-downloads key= {"plugin_id":"acme.waf"}` {
		t.Fatalf("download: %d %v", w.Code, f.calls)
	}
	current = caller("tenant", "plugin_installations.manage")
	if w := request(h, "GET", "/v1/admin/market/plugin-library", "", nil); w.Code != 403 {
		t.Fatalf("tenant library: %d", w.Code)
	}
}

// ML-11 listing page relays: the floor is readable by any market browser;
// node admissions and an offer's subscribers belong to sellers.
func TestListingPageRelays(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"items":[]}`}
	current := caller("platform", PermissionSell)
	h := buyerHandler(&current, f, &fakeStore{})
	id := uuid.NewString()
	for _, path := range []string{"/v1/admin/market/supply-limits-policy", "/v1/admin/market/node-admissions?limit=200",
		"/v1/admin/market/offers/" + id + "/subscribers"} {
		if w := request(h, "GET", path, "", nil); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	want := []string{`GET /v1/supply-limits-policy key= `, `GET /v1/node-admissions?limit=200 key= `, `GET /v1/offers/` + id + `/subscribers key= `}
	if got := strings.Join(f.calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("forwarded:\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}
	if w := request(h, "GET", "/v1/admin/market/node-admissions?status=admitted", "", nil); w.Code != 400 {
		t.Fatalf("unknown query: %d", w.Code)
	}
	current = caller("platform", PermissionBrowse)
	if w := request(h, "GET", "/v1/admin/market/supply-limits-policy", "", nil); w.Code != 200 {
		t.Fatalf("browse reads the floor: %d", w.Code)
	}
	for _, path := range []string{"/v1/admin/market/node-admissions", "/v1/admin/market/offers/" + id + "/subscribers"} {
		if w := request(h, "GET", path, "", nil); w.Code != http.StatusForbidden {
			t.Fatalf("browse %s: %d", path, w.Code)
		}
	}
}

// MARKET-03: published agreements relay read-only to GET /v1/agreements for any market browser.
func TestAgreementsRelay(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"items":[{"kind":"privacy","version":"2026-10-25.1","body":"# 隐私"}]}`}
	current := caller("platform", PermissionBrowse)
	h := buyerHandler(&current, f, &fakeStore{})
	if w := request(h, "GET", "/v1/admin/market/agreements", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "2026-10-25.1") {
		t.Fatalf("browse reads agreements: %d %s", w.Code, w.Body)
	}
	if got := strings.Join(f.calls, "\n"); got != `GET /v1/agreements key= ` {
		t.Fatalf("forwarded: %s", got)
	}
	if w := request(h, "GET", "/v1/admin/market/agreements?kind=privacy", "", nil); w.Code != 400 || len(f.calls) != 1 {
		t.Fatalf("unknown query: %d", w.Code)
	}
	if w := request(h, "POST", "/v1/admin/market/agreements", `{}`, nil); w.Code != http.StatusMethodNotAllowed || len(f.calls) != 1 {
		t.Fatalf("write: %d", w.Code)
	}
	current = caller("platform")
	if w := request(h, "GET", "/v1/admin/market/agreements", "", nil); w.Code != http.StatusForbidden || len(f.calls) != 1 {
		t.Fatalf("no permission: %d", w.Code)
	}
}

// ML-12 subscriber pages: offer nodes, subscription limits, unscheduled nodes
// and the prepaid balance read with browse; the alert line needs purchase.
func TestSubscriberPageRelays(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"items":[]}`}
	current := caller("platform", PermissionBrowse)
	h := buyerHandler(&current, f, &fakeStore{})
	id := uuid.NewString()
	for _, path := range []string{"/v1/admin/market/offers/" + id + "/nodes", "/v1/admin/market/subscriptions/" + id + "/limits?hours=168",
		"/v1/admin/market/supply-unscheduled", "/v1/admin/market/prepaid?currency=CNY"} {
		if w := request(h, "GET", path, "", nil); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	want := []string{`GET /v1/offers/` + id + `/nodes key= `, `GET /v1/subscriptions/` + id + `/limits?hours=168 key= `,
		`GET /v1/supply-unscheduled key= `, `GET /v1/prepaid?currency=CNY key= `}
	if got := strings.Join(f.calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("forwarded:\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}
	for _, path := range []string{"/v1/admin/market/subscriptions/" + id + "/limits?hours=169", "/v1/admin/market/prepaid?currency=cny"} {
		if w := request(h, "GET", path, "", nil); w.Code != 400 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if w := request(h, "PUT", "/v1/admin/market/prepaid/alert", `{"currency":"CNY","threshold_minor":1000}`, nil); w.Code != http.StatusForbidden {
		t.Fatalf("browse sets no alert: %d", w.Code)
	}
	current = caller("platform", PermissionPurchase)
	if w := request(h, "PUT", "/v1/admin/market/prepaid/alert", `{"currency":"CNY","threshold_minor":1000}`, nil); w.Code != 200 {
		t.Fatalf("purchase sets the alert: %d %s", w.Code, w.Body)
	}
	if last := f.calls[len(f.calls)-1]; !strings.HasPrefix(last, "PUT /v1/ledger/alerts ") {
		t.Fatalf("alert line goes to the ML-04 route: %s", last)
	}
}

// ADR 0012 ML-16 relays: the subscriber view, notes and the seller hold
// list need sell; the buyer hold list needs browse. No seller stop route.
func TestSubscriberViewRelays(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"items":[]}`}
	current := caller("platform", PermissionSell)
	h := buyerHandler(&current, f, &fakeStore{})
	offer := uuid.NewString()
	for _, path := range []string{"/v1/admin/market/seller/subscribers?offer_id=" + offer + "&limit=20",
		"/v1/admin/market/seller/holds?cursor=abc", "/v1/admin/market/holds"} {
		if w := request(h, "GET", path, "", nil); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	if w := request(h, "PUT", "/v1/admin/market/seller/subscribers/note", `{"subscription_id":"`+offer+`","note":"x"}`, nil); w.Code != 200 {
		t.Fatalf("note: %d %s", w.Code, w.Body)
	}
	want := []string{`GET /v1/seller/subscribers?limit=20&offer_id=` + offer + ` key= `, `GET /v1/seller/holds?cursor=abc key= `,
		`GET /v1/holds key= `, `PUT /v1/seller/subscribers/note key= {"subscription_id":"` + offer + `","note":"x"}`}
	if got := strings.Join(f.calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("forwarded:\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}
	for _, path := range []string{"/v1/admin/market/seller/subscribers?offer_id=nope", "/v1/admin/market/holds?role=seller"} {
		if w := request(h, "GET", path, "", nil); w.Code != 400 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	current = caller("platform", PermissionBrowse)
	if w := request(h, "GET", "/v1/admin/market/holds", "", nil); w.Code != 200 {
		t.Fatalf("browse reads own holds: %d", w.Code)
	}
	for _, path := range []string{"/v1/admin/market/seller/subscribers", "/v1/admin/market/seller/holds"} {
		if w := request(h, "GET", path, "", nil); w.Code != http.StatusForbidden {
			t.Fatalf("browse %s: %d", path, w.Code)
		}
	}
	for pattern := range memberRoutes {
		if strings.Contains(pattern, "/seller/subscribers") && !strings.HasPrefix(pattern, "GET ") && !strings.HasSuffix(pattern, "/note") {
			t.Fatalf("seller write route besides the note: %s", pattern)
		}
	}
}

// ML-11b batch delist / limits: relayed with the idempotency key; the market
// has not mounted them yet, so a bare 404 becomes 501 market_feature_unavailable.
func TestBatchOfferWriteRelays(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"status":"delisted"}`}
	current := caller("platform", PermissionSell)
	h := buyerHandler(&current, f, &fakeStore{})
	id := uuid.NewString()
	key := map[string]string{"Idempotency-Key": "batch-1"}
	if w := request(h, "POST", "/v1/admin/market/offers/"+id+"/delist", `{}`, key); w.Code != 200 {
		t.Fatalf("delist: %d %s", w.Code, w.Body)
	}
	if w := request(h, "PUT", "/v1/admin/market/offers/"+id+"/limits", `{"limits":[]}`, key); w.Code != 200 {
		t.Fatalf("limits: %d %s", w.Code, w.Body)
	}
	if w := request(h, "PUT", "/v1/admin/market/offers/"+id+"/limits", `{"limits":[]}`, nil); w.Code != 400 {
		t.Fatalf("limits without key: %d", w.Code)
	}
	want := []string{`POST /v1/offers/` + id + `/delist key=batch-1 {}`, `PUT /v1/offers/` + id + `/limits key=batch-1 {"limits":[]}`}
	if got := strings.Join(f.calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("forwarded:\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}
	f.status, f.body = 404, "404 page not found\n"
	if w := request(h, "POST", "/v1/admin/market/offers/"+id+"/delist", `{}`, key); w.Code != 501 ||
		!strings.Contains(w.Body.String(), "market_feature_unavailable") {
		t.Fatalf("unmounted: %d %s", w.Code, w.Body)
	}
	current = caller("platform", PermissionBrowse)
	if w := request(h, "POST", "/v1/admin/market/offers/"+id+"/delist", `{}`, key); w.Code != http.StatusForbidden {
		t.Fatalf("browse delist: %d", w.Code)
	}
}

// ADR 0012 ML-17 relays: filing, listing, reading and withdrawing a stop
// complaint need sell; there is no member route that resolves one.
func TestComplaintRelays(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"items":[]}`}
	current := caller("platform", PermissionSell)
	h := buyerHandler(&current, f, &fakeStore{})
	id := uuid.NewString()
	body := `{"offer_id":"` + id + `","target_ref":"d-0123456789abcdef","category":"seller_exit","detail":"x"}`
	if w := request(h, "POST", "/v1/admin/market/supply-complaints", body, nil); w.Code != 200 {
		t.Fatalf("file: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/v1/admin/market/supply-complaints?limit=5", "/v1/admin/market/supply-complaints/" + id} {
		if w := request(h, "GET", path, "", nil); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	if w := request(h, "POST", "/v1/admin/market/supply-complaints/"+id+"/withdraw", "", nil); w.Code != 200 {
		t.Fatalf("withdraw: %d %s", w.Code, w.Body)
	}
	want := []string{`POST /v1/supply-complaints key= ` + body, `GET /v1/supply-complaints?limit=5 key= `,
		`GET /v1/supply-complaints/` + id + ` key= `, `POST /v1/supply-complaints/` + id + `/withdraw key= `}
	if got := strings.Join(f.calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("forwarded:\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}
	if w := request(h, "GET", "/v1/admin/market/supply-complaints/not-a-uuid", "", nil); w.Code == 200 {
		t.Fatalf("bad id relayed: %d", w.Code)
	}
	current = caller("platform", PermissionBrowse, PermissionPurchase)
	for _, c := range [][2]string{{"POST", "/v1/admin/market/supply-complaints"}, {"GET", "/v1/admin/market/supply-complaints"}} {
		if w := request(h, c[0], c[1], body, nil); w.Code != http.StatusForbidden {
			t.Fatalf("non-seller %s %s: %d", c[0], c[1], w.Code)
		}
	}
	for pattern := range memberRoutes {
		if strings.Contains(pattern, "supply-complaints") && (strings.Contains(pattern, "resolve") || strings.Contains(pattern, "release")) {
			t.Fatalf("member route resolves a complaint: %s", pattern)
		}
	}
}

// ML-28: same-site pauses (browse reads, sell resumes) and the commission
// prepaid account (sell only).
func TestSitePauseAndCommissionPrepaidRelays(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"items":[]}`}
	current := caller("platform", PermissionBrowse)
	h := buyerHandler(&current, f, &fakeStore{})
	id := uuid.NewString()
	if w := request(h, "GET", "/v1/admin/market/site-pauses?open=true", "", nil); w.Code != 200 {
		t.Fatalf("browse reads pauses: %d %s", w.Code, w.Body)
	}
	for _, c := range []struct{ method, path string }{{"POST", "/v1/admin/market/site-pauses/" + id + "/resume"},
		{"GET", "/v1/admin/market/commission/prepaid"}} {
		if w := request(h, c.method, c.path, "", nil); w.Code != http.StatusForbidden {
			t.Fatalf("browse %s %s: %d", c.method, c.path, w.Code)
		}
	}
	current = caller("platform", PermissionSell)
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/v1/admin/market/site-pauses/" + id + "/resume", ""},
		{"GET", "/v1/admin/market/commission/prepaid?currency=CNY", ""},
		{"PUT", "/v1/admin/market/commission/prepaid", `{"enabled":true,"currency":"CNY"}`},
		{"PUT", "/v1/admin/market/commission/prepaid/alert", `{"currency":"CNY","threshold_minor":100}`},
		{"GET", "/v1/admin/market/commission/prepaid/deductions?from=2026-10-01T00:00:00Z", ""},
	} {
		if w := request(h, c.method, c.path, c.body, nil); w.Code != 200 {
			t.Fatalf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
	}
	want := []string{`GET /v1/site-pauses?open=true key= `, `POST /v1/site-pauses/` + id + `/resume key= `,
		`GET /v1/commission/prepaid?currency=CNY key= `, `PUT /v1/commission/prepaid key= `, `PUT /v1/commission/prepaid/alert key= `,
		`GET /v1/commission/prepaid/deductions?from=2026-10-01T00%3A00%3A00Z key= `}
	got := make([]string, 0, len(f.calls))
	for _, call := range f.calls {
		got = append(got, call[:strings.Index(call, " key= ")+len(" key= ")])
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("forwarded:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, path := range []string{"/v1/admin/market/site-pauses?open=yes", "/v1/admin/market/commission/prepaid/deductions?from=yesterday"} {
		if w := request(h, "GET", path, "", nil); w.Code != 400 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}

// p1-subscribers2: an offer's subscribers and the direct top-up list page by
// cursor; the relay passes cursor and limit through, nothing else.
func TestPagedSubscriberAndTopupRelays(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"items":[]}`}
	current := caller("platform", PermissionSell, PermissionBrowse)
	h := buyerHandler(&current, f, &fakeStore{})
	offer := uuid.NewString()
	for _, path := range []string{"/v1/admin/market/offers/" + offer + "/subscribers?cursor=1~a~b&limit=100",
		"/v1/admin/market/direct-topups?as=seller&cursor=1~a&limit=50"} {
		if w := request(h, "GET", path, "", nil); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	want := []string{`GET /v1/offers/` + offer + `/subscribers?cursor=1~a~b&limit=100 key= `,
		`GET /v1/direct-topups?as=seller&cursor=1~a&limit=50 key= `}
	if got := strings.Join(f.calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("forwarded:\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}
	for _, path := range []string{"/v1/admin/market/offers/" + offer + "/subscribers?limit=500",
		"/v1/admin/market/direct-topups?as=seller&page=2"} {
		if w := request(h, "GET", path, "", nil); w.Code != 400 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}
