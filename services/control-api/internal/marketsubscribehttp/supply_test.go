package marketsubscribehttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupplyguard"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

type fakeSupply struct {
	put     marketsupply.SupplyGroupWrite
	deleted int64
	nodes   []uuid.UUID
	codes   []string
	err     error
}

func (f *fakeSupply) Put(_ context.Context, _ marketsupply.SupplyActor, w marketsupply.SupplyGroupWrite) (marketsupply.SupplyGroup, error) {
	f.put = w
	id := w.GroupID
	if id == uuid.Nil {
		id = uuid.New()
	}
	return marketsupply.SupplyGroup{ID: id, Revision: w.ExpectedRevision + 1, Name: w.Name}, f.err
}
func (f *fakeSupply) Get(_ context.Context, _ marketsupply.SupplyActor, id uuid.UUID) (marketsupply.SupplyGroup, error) {
	return marketsupply.SupplyGroup{ID: id, Revision: 1}, f.err
}
func (f *fakeSupply) Delete(_ context.Context, _ marketsupply.SupplyActor, _ uuid.UUID, revision int64, _, _ string) error {
	f.deleted = revision
	return f.err
}
func (f *fakeSupply) GroupPlugins(context.Context, marketsupply.SupplyActor, uuid.UUID) ([]marketsupply.SupplyPlugin, error) {
	return []marketsupply.SupplyPlugin{{Code: "ja4"}}, nil
}
func (f *fakeSupply) SupplyPlugins(_ context.Context, _ uuid.UUID, nodes []uuid.UUID) ([]marketsupply.SupplyPlugin, error) {
	f.nodes = nodes
	return []marketsupply.SupplyPlugin{{Code: "module.autodefense"}}, f.err
}

func (f *fakeSupply) PluginNames(_ context.Context, codes []string) ([]marketsupply.SupplyPlugin, error) {
	f.codes = codes
	return []marketsupply.SupplyPlugin{{Code: "ja4", NameZH: "JA4 指纹", NameEN: "JA4 fingerprints"}}, f.err
}

func TestSupplyGroupRoutes(t *testing.T) {
	supply := &fakeSupply{}
	caller := Caller{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionSell}}
	h := New(nil, func(*http.Request) (Caller, error) { return caller, nil }).WithSupplyGroups(supply)
	send := func(method, path, key, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	node := uuid.New()
	w := send("POST", "/v1/admin/market/supply-groups", "k1", `{"name":"单节点","node_ids":["`+node.String()+`"]}`)
	var view struct {
		ID          uuid.UUID `json:"id"`
		NodePoolRef string    `json:"node_pool_ref"`
		Plugins     []struct {
			Code string `json:"code"`
		} `json:"plugins"`
	}
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.NodePoolRef != view.ID.String() ||
		len(view.Plugins) != 1 || supply.put.IdempotencyKey != "k1" || supply.put.NodeIDs[0] != node {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if w := send("POST", "/v1/admin/market/supply-groups", "", `{"name":"x","node_ids":[]}`); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "idempotency_key_required") {
		t.Fatalf("missing key: %d %s", w.Code, w.Body)
	}
	if w := send("POST", "/v1/admin/market/supply-groups", "k2", `{"name":"x","node_ids":[],"expected_revision":3}`); w.Code != 400 {
		t.Fatalf("create with revision: %d", w.Code)
	}
	id := uuid.New().String()
	if w := send("PUT", "/v1/admin/market/supply-groups/"+id, "k3", `{"name":"x","node_ids":[],"expected_revision":1}`); w.Code != 200 ||
		supply.put.GroupID.String() != id {
		t.Fatalf("update: %d %s", w.Code, w.Body)
	}
	if w := send("PUT", "/v1/admin/market/supply-groups/"+id, "k4", `{"name":"x","node_ids":[]}`); w.Code != 400 {
		t.Fatalf("update without revision: %d", w.Code)
	}
	if w := send("GET", "/v1/admin/market/supply-groups/"+id, "", ""); w.Code != 200 {
		t.Fatalf("get: %d", w.Code)
	}
	if w := send("DELETE", "/v1/admin/market/supply-groups/"+id+"?revision=2", "k5", ""); w.Code != 204 || supply.deleted != 2 {
		t.Fatalf("delete: %d", w.Code)
	}
	if w := send("DELETE", "/v1/admin/market/supply-groups/"+id, "k6", ""); w.Code != 400 {
		t.Fatalf("delete without revision: %d", w.Code)
	}
	if w := send("POST", "/v1/admin/market/supply-plugins", "", `{"node_ids":["`+node.String()+`"]}`); w.Code != 200 ||
		!strings.Contains(w.Body.String(), "module.autodefense") || !slices.Equal(supply.nodes, []uuid.UUID{node}) {
		t.Fatalf("plugins: %d %s", w.Code, w.Body)
	}
	if w := send("POST", "/v1/admin/market/plugin-names", "", `{"codes":["ja4","module.x"]}`); w.Code != 200 ||
		!strings.Contains(w.Body.String(), `"name_zh":"JA4 指纹"`) || !slices.Equal(supply.codes, []string{"ja4", "module.x"}) {
		t.Fatalf("plugin names: %d %s", w.Code, w.Body)
	}

	for _, c := range []struct {
		err    error
		status int
		code   string
	}{
		{marketsupply.ErrSupplyNodeUnusable, 422, "node_unusable"},
		{marketsupply.ErrSupplyInvalid, 400, "invalid"},
		{marketsupply.ErrSupplyNotFound, 404, "not_found"},
		{marketsupply.ErrSupplyForbidden, 403, "forbidden"},
		{nodescheduler.ErrMarketSupplyInUse, 409, "supply_in_use"},
		{marketsupply.ErrSupplyConflict, 409, "conflict"},
	} {
		supply.err = c.err
		if w := send("GET", "/v1/admin/market/supply-groups/"+id, "", ""); w.Code != c.status || !strings.Contains(w.Body.String(), c.code) {
			t.Fatalf("%v: %d %s", c.err, w.Code, w.Body)
		}
	}
	// ML-18: a refusal for leaving normal subscribers without an online node carries the counts.
	supply.err = fmt.Errorf("%w: %w", marketsupply.ErrSupplyConflict, fmt.Errorf("%w: %w", nodescheduler.ErrMarketSupplyInUse,
		&marketsupplyguard.InUseError{GroupID: uuid.New(), OnlineAvailable: 0, NormalSubscriptions: 2}))
	if w := send("GET", "/v1/admin/market/supply-groups/"+id, "", ""); w.Code != 409 ||
		strings.TrimSpace(w.Body.String()) != `{"error":"supply_in_use","normal_subscriptions":2,"online_available":0}` {
		t.Fatalf("supply in use counts: %d %s", w.Code, w.Body)
	}

	// A platform member without the seller permission, and tenants, get 403.
	for _, other := range []Caller{
		{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionBrowse}},
		{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", Permissions: []string{PermissionSell}},
	} {
		caller = other
		if w := send("POST", "/v1/admin/market/supply-plugins", "", `{"node_ids":[]}`); w.Code != 403 {
			t.Fatalf("%+v: %d", other, w.Code)
		}
	}
	for _, pattern := range SupplyPatterns {
		if !slices.Contains(MemberPatterns(), pattern) {
			t.Fatalf("%s is not mounted", pattern)
		}
	}
}
