package marketsubscribehttp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupplyguard"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

// listingSupply: groups keyed by idempotency key; plugins per node.
type listingSupply struct {
	fakeSupply
	mu          sync.Mutex
	groups      map[uuid.UUID]marketsupply.SupplyGroup
	puts        int
	plugins     map[uuid.UUID][]string
	subscribers map[uuid.UUID]int
	online      map[uuid.UUID]bool
}

func newListingSupply() *listingSupply {
	return &listingSupply{groups: map[uuid.UUID]marketsupply.SupplyGroup{}, plugins: map[uuid.UUID][]string{},
		subscribers: map[uuid.UUID]int{}, online: map[uuid.UUID]bool{}}
}

func (f *listingSupply) Put(_ context.Context, a marketsupply.SupplyActor, w marketsupply.SupplyGroupWrite) (marketsupply.SupplyGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	id := w.GroupID
	if id == uuid.Nil {
		id = marketsupply.CreatedGroupID(a.UserID, w.IdempotencyKey)
		if g, ok := f.groups[id]; ok {
			if g.Name != w.Name {
				return marketsupply.SupplyGroup{}, marketsupply.ErrSupplyConflict
			}
			return g, nil
		}
	} else if g, ok := f.groups[id]; !ok || g.Revision != w.ExpectedRevision {
		return marketsupply.SupplyGroup{}, marketsupply.ErrSupplyConflict
	} else if err := f.guard(g, w.NodeIDs); err != nil {
		return marketsupply.SupplyGroup{}, err
	}
	g := marketsupply.SupplyGroup{ID: id, Revision: f.groups[id].Revision + 1, Name: w.Name}
	for _, n := range w.NodeIDs {
		g.Nodes = append(g.Nodes, marketsupply.SupplyGroupNode{NodeID: n})
	}
	f.groups[id] = g
	return g, nil
}
func (f *listingSupply) Get(_ context.Context, _ marketsupply.SupplyActor, id uuid.UUID) (marketsupply.SupplyGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.groups[id]
	if !ok {
		return g, marketsupply.ErrSupplyNotFound
	}
	return g, nil
}
func (f *listingSupply) SupplyPlugins(_ context.Context, _ uuid.UUID, nodes []uuid.UUID) ([]marketsupply.SupplyPlugin, error) {
	var common []string
	for i, n := range nodes {
		if i == 0 {
			common = slices.Clone(f.plugins[n])
			continue
		}
		common = slices.DeleteFunc(common, func(c string) bool { return !slices.Contains(f.plugins[n], c) })
	}
	out := []marketsupply.SupplyPlugin{}
	for _, c := range common {
		out = append(out, marketsupply.SupplyPlugin{Code: c})
	}
	return out, nil
}

// guard stands in for marketsupplyguard inside nodescheduler putGroup:
// subscribers are the group's normal ones (stopped/cancelled already left
// out), and the error is what marketsupply.Put returns for a refusal.
func (f *listingSupply) guard(g marketsupply.SupplyGroup, keep []uuid.UUID) error {
	online := func(nodes []uuid.UUID) int {
		n := 0
		for _, id := range nodes {
			if f.online[id] {
				n++
			}
		}
		return n
	}
	var before []uuid.UUID
	for _, n := range g.Nodes {
		before = append(before, n.NodeID)
	}
	if online(before) > 0 && online(keep) == 0 && f.subscribers[g.ID] > 0 {
		return fmt.Errorf("%w: %w", marketsupply.ErrSupplyConflict, fmt.Errorf("%w: %w", nodescheduler.ErrMarketSupplyInUse,
			&marketsupplyguard.InUseError{GroupID: g.ID, NormalSubscriptions: f.subscribers[g.ID]}))
	}
	return nil
}

type memListingStore struct {
	mu        sync.Mutex
	items     map[string]BatchItem
	leases    map[string]time.Time
	templates map[uuid.UUID]ListingTemplate
}

func newMemListingStore() *memListingStore {
	return &memListingStore{items: map[string]BatchItem{}, leases: map[string]time.Time{}, templates: map[uuid.UUID]ListingTemplate{}}
}

func (s *memListingStore) Templates(context.Context, uuid.UUID) ([]ListingTemplate, error) {
	out := []ListingTemplate{}
	for _, t := range s.templates {
		out = append(out, t)
	}
	return out, nil
}
func (s *memListingStore) PutTemplate(_ context.Context, _, _ uuid.UUID, t ListingTemplate) (ListingTemplate, error) {
	if t.Revision == 0 {
		t.ID = uuid.New()
	} else if old, ok := s.templates[t.ID]; !ok {
		return t, ErrStoreNotFound
	} else if old.Revision != t.Revision {
		return t, ErrListingConflict
	}
	t.Revision++
	s.templates[t.ID] = t
	return t, nil
}
func (s *memListingStore) DeleteTemplate(_ context.Context, _, id uuid.UUID, revision int64) error {
	if old, ok := s.templates[id]; !ok {
		return ErrStoreNotFound
	} else if old.Revision != revision {
		return ErrListingConflict
	}
	delete(s.templates, id)
	return nil
}
func (s *memListingStore) ClaimItem(_ context.Context, _, _ uuid.UUID, digest []byte, lease time.Duration) (BatchItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hex.EncodeToString(digest)
	item := s.items[key]
	if item.OfferID != nil {
		return item, nil
	}
	if s.leases[key].After(time.Now()) {
		return item, ErrItemBusy
	}
	s.leases[key] = time.Now().Add(lease)
	return item, nil
}
func (s *memListingStore) SaveItem(_ context.Context, _ uuid.UUID, digest []byte, item BatchItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hex.EncodeToString(digest)
	old := s.items[key]
	if item.GroupID == nil {
		item.GroupID = old.GroupID
	}
	if item.OfferID == nil {
		item.OfferID = old.OfferID
	}
	s.items[key] = item
	if item.OfferID != nil {
		delete(s.leases, key)
	}
	return nil
}
func (s *memListingStore) ReleaseItem(_ context.Context, _ uuid.UUID, digest []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.leases, hex.EncodeToString(digest))
	return nil
}

// offerMarket answers POST /v1/offers (refusing names containing "refuse")
// and publish.
type offerMarket struct {
	mu        sync.Mutex
	offers    []map[string]any
	published []string
	// publishDown: the next publish calls answer 503 (B19/B20).
	publishDown int
}

func (m *offerMarket) Forward(_ context.Context, method, path, _ string, body []byte) (int, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case method == "POST" && path == "/v1/offers":
		var offer map[string]any
		_ = json.Unmarshal(body, &offer)
		if strings.Contains(offer["name"].(string), "refuse") {
			return 400, []byte(`{"error":"load_floor_exceeded","metric":"node_cpu_percent","floor":80}`), nil
		}
		m.offers = append(m.offers, offer)
		return 201, []byte(`{"id":"` + uuid.NewString() + `","status":"draft"}`), nil
	case method == "POST" && strings.HasSuffix(path, "/publish"):
		if m.publishDown > 0 {
			m.publishDown--
			return 503, []byte(`{"error":"unavailable"}`), nil
		}
		// The market refuses to publish what is no longer a draft.
		if slices.Contains(m.published, path) {
			return 409, []byte(`{"error":"conflict"}`), nil
		}
		m.published = append(m.published, path)
		return 200, []byte(`{"status":"listed"}`), nil
	}
	return 404, nil, nil
}

func listingHandler(t *testing.T, supply *listingSupply, store *memListingStore, market *offerMarket) func(method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	caller := Caller{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionSell}}
	h := New(nil, func(*http.Request) (Caller, error) { return caller, nil }).WithListing(supply, store, market)
	return func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w
	}
}

type batchResponse struct {
	Items []BatchResult `json:"items"`
}

func decodeBatch(t *testing.T, w *httptest.ResponseRecorder) []BatchResult {
	t.Helper()
	var out batchResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("batch: %d %s", w.Code, w.Body)
	}
	return out.Items
}

func TestListingBatchSingleNodePluginsAndIdempotency(t *testing.T) {
	supply, store, market := newListingSupply(), newMemListingStore(), &offerMarket{}
	send := listingHandler(t, supply, store, market)
	a, b := uuid.New(), uuid.New()
	supply.plugins[a] = []string{"module.autodefense", "pack.crs"}
	supply.plugins[b] = []string{"module.autodefense"}
	body := `{"mode":"single","publish":true,"node_ids":["` + a.String() + `","` + b.String() + `"],
		"offer":{"name":"香港","billing_model":"daily_bundle","tags":{"plugins":["module.autodefense","pack.crs"]}}}`
	items := decodeBatch(t, send("POST", "/v1/admin/market/listing-batches", body))
	if len(items) != 2 || items[0].Status != "created" || items[1].Status != "created" || items[0].Published != "listed" {
		t.Fatalf("items %+v", items)
	}
	// Node b lacks CRS: left out and reported; node a keeps both.
	if len(items[0].RemovedPlugins) != 0 || !slices.Equal(items[1].RemovedPlugins, []string{"pack.crs"}) {
		t.Fatalf("removed %v / %v", items[0].RemovedPlugins, items[1].RemovedPlugins)
	}
	plugins := func(i int) []any { return market.offers[i]["tags"].(map[string]any)["plugins"].([]any) }
	if len(plugins(0)) != 2 || len(plugins(1)) != 1 || plugins(1)[0] != "module.autodefense" {
		t.Fatalf("offer plugins %v / %v", plugins(0), plugins(1))
	}
	comp := market.offers[0]["components"].([]any)[0].(map[string]any)
	if comp["kind"] != "own_pool" || comp["node_pool_ref"] != items[0].GroupID.String() ||
		market.offers[0]["name"] != "香港 · "+a.String()[:8] {
		t.Fatalf("offer %v", market.offers[0])
	}
	// The same submission again makes nothing new.
	again := decodeBatch(t, send("POST", "/v1/admin/market/listing-batches", body))
	if again[0].Status != "existing" || again[1].Status != "existing" || *again[0].OfferID != *items[0].OfferID ||
		len(market.offers) != 2 || len(market.published) != 2 {
		t.Fatalf("resubmission %+v, %d offers", again, len(market.offers))
	}
}

func TestListingBatchMultiNodeAndRetryReusesGroup(t *testing.T) {
	supply, store, market := newListingSupply(), newMemListingStore(), &offerMarket{}
	send := listingHandler(t, supply, store, market)
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	ids := `["` + a.String() + `","` + b.String() + `","` + c.String() + `"]`
	refused := decodeBatch(t, send("POST", "/v1/admin/market/listing-batches",
		`{"mode":"multi","node_ids":`+ids+`,"offer":{"name":"refuse 合并"}}`))
	if len(refused) != 1 || refused[0].Status != "failed" || refused[0].Error != "load_floor_exceeded" ||
		!strings.Contains(string(refused[0].Detail), `"floor":80`) || len(refused[0].NodeIDs) != 3 {
		t.Fatalf("refused %+v", refused)
	}
	// Retried with a corrected template (another name): the group is reused.
	fixed := decodeBatch(t, send("POST", "/v1/admin/market/listing-batches",
		`{"mode":"multi","node_ids":`+ids+`,"offer":{"name":"合并"}}`))
	if fixed[0].Status != "created" || *fixed[0].GroupID != *refused[0].GroupID || len(supply.groups) != 1 {
		t.Fatalf("retry %+v groups %d", fixed, len(supply.groups))
	}
}

// B19/B20: a created offer whose publish failed is retried on the same
// offer_id by resubmitting; nothing is created twice. A draft made without
// publish is published by the same request with publish set.
func TestListingBatchRetriesPublishOnTheSameOffer(t *testing.T) {
	supply, store, market := newListingSupply(), newMemListingStore(), &offerMarket{publishDown: 1}
	send := listingHandler(t, supply, store, market)
	a := uuid.New()
	body := `{"mode":"single","publish":true,"node_ids":["` + a.String() + `"],"offer":{"name":"重试"}}`
	first := decodeBatch(t, send("POST", "/v1/admin/market/listing-batches", body))
	if first[0].Status != "created" || first[0].Error != "publish_market_unavailable" || first[0].Published != "" {
		t.Fatalf("first %+v", first)
	}
	again := decodeBatch(t, send("POST", "/v1/admin/market/listing-batches", body))
	if again[0].Status != "existing" || *again[0].OfferID != *first[0].OfferID || again[0].Error != "" || again[0].Published != "listed" ||
		len(market.offers) != 1 || !slices.Equal(market.published, []string{"/v1/offers/" + first[0].OfferID.String() + "/publish"}) {
		t.Fatalf("retry %+v offers %d published %v", again, len(market.offers), market.published)
	}
	// Once listed, a resubmission reports it without an error (the market answers 409).
	third := decodeBatch(t, send("POST", "/v1/admin/market/listing-batches", body))
	if third[0].Status != "existing" || third[0].Error != "" || len(market.published) != 1 {
		t.Fatalf("third %+v", third)
	}

	// Draft first, then the same request with publish: the draft is published.
	b := uuid.New()
	draft := `{"mode":"single","publish":false,"node_ids":["` + b.String() + `"],"offer":{"name":"草稿"}}`
	made := decodeBatch(t, send("POST", "/v1/admin/market/listing-batches", draft))
	if made[0].Status != "created" || made[0].Published != "" || len(market.published) != 1 {
		t.Fatalf("draft %+v", made)
	}
	listed := decodeBatch(t, send("POST", "/v1/admin/market/listing-batches", strings.Replace(draft, `"publish":false`, `"publish":true`, 1)))
	if listed[0].Status != "existing" || *listed[0].OfferID != *made[0].OfferID || listed[0].Published != "listed" || len(market.offers) != 2 {
		t.Fatalf("draft → publish %+v", listed)
	}
}

func TestListingBatchRejectsBadRequests(t *testing.T) {
	send := listingHandler(t, newListingSupply(), newMemListingStore(), &offerMarket{})
	a := uuid.New().String()
	for _, body := range []string{
		`{"mode":"each","node_ids":["` + a + `"],"offer":{"name":"x"}}`,
		`{"mode":"single","node_ids":[],"offer":{"name":"x"}}`,
		`{"mode":"single","node_ids":["` + a + `","` + a + `"],"offer":{"name":"x"}}`,
		`{"mode":"single","node_ids":["` + a + `"],"offer":{"name":" "}}`,
		`{"mode":"single","node_ids":["` + a + `"],"offer":{"name":"x","components":[]}}`,
	} {
		if w := send("POST", "/v1/admin/market/listing-batches", body); w.Code != 400 {
			t.Fatalf("%s: %d", body, w.Code)
		}
	}
}

func TestListingTemplates(t *testing.T) {
	send := listingHandler(t, newListingSupply(), newMemListingStore(), &offerMarket{})
	w := send("POST", "/v1/admin/market/listing-templates", `{"name":"香港包天","body":{"price":100}}`)
	var saved ListingTemplate
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &saved) != nil || saved.Revision != 1 {
		t.Fatalf("create %d %s", w.Code, w.Body)
	}
	path := "/v1/admin/market/listing-templates/" + saved.ID.String()
	if w := send("PUT", path, `{"name":"香港包天","body":{"price":120},"revision":1}`); w.Code != 200 {
		t.Fatalf("update %d %s", w.Code, w.Body)
	}
	if w := send("PUT", path, `{"name":"旧","body":{},"revision":1}`); w.Code != 409 {
		t.Fatalf("stale update %d", w.Code)
	}
	if w := send("POST", "/v1/admin/market/listing-templates", `{"name":"x","body":[1]}`); w.Code != 400 {
		t.Fatalf("array body %d", w.Code)
	}
	if w := send("GET", "/v1/admin/market/listing-templates", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"price":120`) {
		t.Fatalf("list %d %s", w.Code, w.Body)
	}
	if w := send("DELETE", path+"?revision=2", ""); w.Code != 204 {
		t.Fatalf("delete %d %s", w.Code, w.Body)
	}
}

// ML-18 (U3): with normal subscribers, at least one online node must stay.
// The check is the shared marketsupplyguard one run inside Put; the batch
// reports its refusal per group as supply_keeps_online_node.
func TestSupplyNodeRemovalsKeepAnOnlineNode(t *testing.T) {
	supply := newListingSupply()
	send := listingHandler(t, supply, newMemListingStore(), &offerMarket{})
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	user := uuid.New()
	sold, _ := supply.Put(t.Context(), marketsupply.SupplyActor{UserID: user}, marketsupply.SupplyGroupWrite{Name: "sold", NodeIDs: []uuid.UUID{a, b}, IdempotencyKey: "s"})
	free, _ := supply.Put(t.Context(), marketsupply.SupplyActor{UserID: user}, marketsupply.SupplyGroupWrite{Name: "free", NodeIDs: []uuid.UUID{a, c}, IdempotencyKey: "f"})
	single, _ := supply.Put(t.Context(), marketsupply.SupplyActor{UserID: user}, marketsupply.SupplyGroupWrite{Name: "one", NodeIDs: []uuid.UUID{a}, IdempotencyKey: "o"})
	supply.subscribers[sold.ID] = 2
	supply.online[a] = true // b is offline: removing a would leave no online node
	body := `{"group_ids":["` + sold.ID.String() + `","` + free.ID.String() + `","` + single.ID.String() + `"],"node_ids":["` + a.String() + `"]}`
	w := send("POST", "/v1/admin/market/supply-node-removals", body)
	var out struct {
		Items []struct {
			GroupID uuid.UUID `json:"group_id"`
			Status  string    `json:"status"`
			Error   string    `json:"error"`
		} `json:"items"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Items) != 3 {
		t.Fatalf("removals %d %s", w.Code, w.Body)
	}
	got := map[uuid.UUID]string{}
	for _, item := range out.Items {
		got[item.GroupID] = item.Status + "/" + item.Error
	}
	if got[sold.ID] != "failed/supply_keeps_online_node" || got[free.ID] != "updated/" || got[single.ID] != "failed/supply_needs_node" {
		t.Fatalf("outcomes %v", got)
	}
	if g := supply.groups[free.ID]; len(g.Nodes) != 1 || g.Nodes[0].NodeID != c {
		t.Fatalf("free group %+v", g)
	}
	if g := supply.groups[sold.ID]; len(g.Nodes) != 2 {
		t.Fatalf("sold group changed %+v", g)
	}
	// Once b is online the sold supply may drop a.
	supply.online[b] = true
	if w := send("POST", "/v1/admin/market/supply-node-removals", `{"group_ids":["`+sold.ID.String()+`"],"node_ids":["`+a.String()+`"]}`); !strings.Contains(w.Body.String(), `"updated"`) {
		t.Fatalf("with b online: %s", w.Body)
	}
}

func TestListingPatternsMounted(t *testing.T) {
	for _, pattern := range ListingPatterns {
		if !slices.Contains(MemberPatterns(), pattern) {
			t.Fatalf("%s not in MemberPatterns", pattern)
		}
	}
}
