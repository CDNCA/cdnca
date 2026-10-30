package errorpagecontrol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/themepack"
	"github.com/google/uuid"
)

// An unbound slot shows the page in effect, not
// an empty editor.
func TestBuiltinSlotContentIsTheThemePage(t *testing.T) {
	rendered := themepack.DefaultRendered()
	for _, key := range ErrorPageSlotKeys {
		body, delivery, err := slotPageFrom(rendered, key, true)
		if err != nil || len(body) == 0 {
			t.Fatalf("%s: %v (%d bytes)", key, err, len(body))
		}
		if ValidateThemedHTML(body) != nil {
			t.Fatalf("%s: built-in page is not a valid themed page:\n%s", key, body)
		}
		page, nodePage := slotNodePages[key]
		if !nodePage {
			// errpage-3: a slot the node answers itself keeps its built-in
			// answer until bound; site_locked has no node response yet.
			want := SlotDeliveryFallback
			if _, own := slotOwnPages[key]; !own {
				want = SlotDeliveryNone
			}
			if delivery != want || SlotReachesNodes(key) != (want == SlotDeliveryFallback) {
				t.Fatalf("%s: delivery %q, want %q", key, delivery, want)
			}
			continue
		}
		if delivery != SlotDeliveryTheme {
			t.Fatalf("%s: delivery %q", key, delivery)
		}
		found := false
		for _, candidate := range rendered.ErrorPages {
			if candidate.Category == page.Category && candidate.Status == page.Status {
				found = bytes.Equal(candidate.Body, body)
			}
		}
		if !found {
			t.Fatalf("%s: content is not the theme's %s %d page", key, page.Category, page.Status)
		}
	}
	// Without a theme only the block page is live on nodes.
	if _, delivery, _ := slotPageFrom(rendered, SlotHTTP502, false); delivery != SlotDeliveryFallback {
		t.Fatalf("unthemed 502 delivery %q", delivery)
	}
	if _, delivery, _ := slotPageFrom(rendered, SlotWAFBlock, false); delivery != SlotDeliveryTheme {
		t.Fatalf("unthemed waf_block delivery %q", delivery)
	}
	body, _, _ := slotPageFrom(rendered, SlotTrafficExceeded, true)
	if !bytes.Contains(body, []byte("网站流量已超出限制")) {
		t.Fatalf("traffic_exceeded page:\n%s", body)
	}
	if _, _, err := slotPageFrom(rendered, "unknown", true); err == nil {
		t.Fatal("unknown slot")
	}
}

// Every built-in theme renders every slot.
func TestBuiltinThemesRenderEverySlot(t *testing.T) {
	for _, entry := range themepack.BuiltinCatalog() {
		rendered, err := themepack.Render(entry.Raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range ErrorPageSlotKeys {
			if body, _, err := slotPageFrom(rendered, key, true); err != nil || ValidateThemedHTML(body) != nil {
				t.Fatalf("%s %s: %v", entry.ID, key, err)
			}
		}
	}
}

// An admin opens a built-in page, changes a few words
// and saves it; the upload validation accepts it for every theme and slot.
func TestEditedBuiltinSlotPagePassesUploadValidation(t *testing.T) {
	for _, entry := range themepack.BuiltinCatalog() {
		rendered, err := themepack.Render(entry.Raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range ErrorPageSlotKeys {
			body, _, err := slotPageFrom(rendered, key, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateStaticBody("text/html", body); err != nil {
				t.Fatalf("%s %s: unedited built-in page rejected: %v", entry.ID, key, err)
			}
			edited := bytes.Replace(body, []byte("</h1>"), []byte("（已修改）</h1>"), 1)
			if bytes.Equal(edited, body) {
				edited = bytes.Replace(body, []byte("</body>"), []byte("<p>请联系客服。</p></body>"), 1)
			}
			if err := validateStaticBody("text/html", edited); err != nil {
				t.Fatalf("%s %s: edited built-in page rejected: %v\n%s", entry.ID, key, err, edited)
			}
		}
	}
}

// A bound slot replaces its theme default page on the node, keeping the theme
// rule ID; a platform global rule for the category still wins; a tenant on its
// own theme keeps that theme's pages.
func TestProductionSnapshotSlotReplacesThemePage(t *testing.T) {
	tenantID, scopeID, platformScopeID := uuid.New(), uuid.New(), uuid.New()
	store := &site13SnapshotStore{objects: make(map[string]struct {
		info ObjectInfo
		body []byte
	})}
	slotBody := []byte("<!doctype html><html><head><title>坏网关</title></head><body><h1>自定义 502</h1></body></html>")
	blockBody := []byte("<!doctype html><html><head><title>拦截</title></head><body><h1>自定义拦截</h1></body></html>")
	hostBody := []byte("<!doctype html><html><head><title>host</title></head><body><p>slot 400</p></body></html>")
	slot := func(key, category string, status int, body []byte) SnapshotSlot {
		rule := site13SnapshotRule(t, "slot", category, status, body)
		site13PutSnapshotObject(store, platformScopeID, nil, rule.Resource, body)
		return SnapshotSlot{Key: key, Category: category, Status: status, Resource: rule.Resource}
	}
	globalBody := []byte("host required\n")
	global := site13SnapshotRule(t, uuid.NewString(), CategoryNoHost, 400, globalBody)
	site13PutSnapshotObject(store, platformScopeID, nil, global.Resource, globalBody)
	compiler, err := NewProductionSnapshotCompiler(store, site13BundleSigner{private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x76}, ed25519.SeedSize))})
	if err != nil {
		t.Fatal(err)
	}
	themePage := themedTestPage(themedTestStyle, "cf-card")
	source := productionSnapshotSource{
		TenantID: tenantID, ScopeID: scopeID, PlatformScopeID: platformScopeID, SiteIDs: map[string]struct{}{},
		Policy: Snapshot{Schema: SchemaV1, Version: "control-9", Revision: 9,
			Global: SnapshotScope{Rules: []SnapshotRule{global}}, ThemePackageSHA256: fmtSHA256([32]byte{1}),
			Slots: []SnapshotSlot{
				slot(SlotHTTP400, CategoryNoHost, 400, hostBody),
				slot(SlotHTTP502, CategoryEdgeConnect, 502, slotBody),
				slot(SlotWAFBlock, CategoryEdgeRoute, 403, blockBody),
			}},
		ThemePages: []ThemeDefaultPage{
			{Category: CategoryEdgeConnect, Status: 502, Body: themePage},
			{Category: CategoryEdgeConnect, Status: 504, Body: themePage},
			{Category: CategoryEdgeRoute, Status: 403, Body: themePage},
		},
	}

	// errpage-ovr: a region override of http_502 is no theme rule; it rides in
	// the document's slots (edgepublish makes it a site page variant)
	region502 := slot(SlotHTTP502, CategoryEdgeConnect, 502, blockBody)
	region502.Region = "cn-east"
	source.Policy.Slots = append(source.Policy.Slots, region502)
	rules := buildSlotTestRules(t, compiler, source)
	if slots := buildSlotTestSlots(t, compiler, source); len(slots) != 1 || slots[0].Key != SlotHTTP502 ||
		slots[0].Region != "cn-east" || slots[0].Category != CategoryEdgeConnect || !bytes.Equal(slots[0].Resource.Body, blockBody) {
		t.Fatalf("region 502 override slots %+v", slots)
	}
	if got := rules["theme.edge_connect.502"]; !bytes.Equal(got, slotBody) {
		t.Fatalf("502 = %s", got)
	}
	if got := rules["theme.edge_route.403"]; !bytes.Equal(got, blockBody) {
		t.Fatalf("block page = %s", got)
	}
	if got := rules["theme.edge_connect.504"]; !bytes.Equal(got, themePage) {
		t.Fatal("unbound 504 lost its theme page")
	}
	if _, found := rules["theme.no_host.400"]; found {
		t.Fatal("slot replaced a category the platform global rule covers")
	}
	if len(rules) != 4 {
		t.Fatalf("rules %d", len(rules))
	}

}

func buildSlotTestSlots(t *testing.T, compiler *ProductionSnapshotCompiler, source productionSnapshotSource) []ProductionSnapshotSlot {
	t.Helper()
	artifact, err := compiler.buildSelected(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	var document ProductionSnapshotDocument
	if err := json.Unmarshal(artifact.WireBytes, &document); err != nil {
		t.Fatal(err)
	}
	return document.Slots
}

func buildSlotTestRules(t *testing.T, compiler *ProductionSnapshotCompiler, source productionSnapshotSource) map[string][]byte {
	t.Helper()
	artifact, err := compiler.buildSelected(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	var document ProductionSnapshotDocument
	if err := json.Unmarshal(artifact.WireBytes, &document); err != nil {
		t.Fatal(err)
	}
	rules := map[string][]byte{}
	for _, rule := range document.Global.Rules {
		if _, dup := rules[rule.ID]; dup {
			t.Fatalf("duplicate rule %s", rule.ID)
		}
		rules[rule.ID] = rule.Resource.Body
	}
	return rules
}

// A revision without slots keeps the canonical bytes it had before.
func TestSnapshotWithoutSlotsKeepsCanonicalBytes(t *testing.T) {
	wire, err := json.Marshal(Snapshot{Schema: SchemaV1, Version: "control-1", Revision: 1,
		Global: SnapshotScope{Rules: []SnapshotRule{}}, Sites: []SnapshotSite{}})
	if err != nil || bytes.Contains(wire, []byte("slots")) {
		t.Fatalf("%s %v", wire, err)
	}
}
