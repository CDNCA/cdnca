package errorpagecontrol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// ADR 0007 §7.3: the theme the publication pins fills the node default pages
// for global categories no platform rule covers; a configured category keeps
// only its own page.
func TestProductionSnapshotAddsThemeDefaultPages(t *testing.T) {
	tenantID, scopeID, platformScopeID := uuid.New(), uuid.New(), uuid.New()
	globalBody := []byte("host required\n")
	global := site13SnapshotRule(t, uuid.NewString(), CategoryNoHost, 400, globalBody)
	store := &site13SnapshotStore{objects: make(map[string]struct {
		info ObjectInfo
		body []byte
	})}
	site13PutSnapshotObject(store, platformScopeID, nil, global.Resource, globalBody)
	compiler, err := NewProductionSnapshotCompiler(store, site13BundleSigner{private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x75}, ed25519.SeedSize))})
	if err != nil {
		t.Fatal(err)
	}
	page502 := themedTestPage(themedTestStyle, "cf-card")
	source := productionSnapshotSource{
		TenantID: tenantID, ScopeID: scopeID, PlatformScopeID: platformScopeID, SiteIDs: map[string]struct{}{},
		Policy: Snapshot{Schema: SchemaV1, Version: "control-9", Revision: 9,
			Global: SnapshotScope{Rules: []SnapshotRule{global}}, ThemePackageSHA256: fmtSHA256([32]byte{1})},
		ThemePages: []ThemeDefaultPage{
			{Category: CategoryEdgeConnect, Status: 502, Body: page502},
			{Category: CategoryNoHost, Status: 400, Body: themedTestPage(themedTestStyle, "cf-card")},
		},
	}
	artifact, err := compiler.buildSelected(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	var document ProductionSnapshotDocument
	if err := json.Unmarshal(artifact.WireBytes, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Global.Rules) != 2 {
		t.Fatalf("global rules = %+v", document.Global.Rules)
	}
	theme := document.Global.Rules[1]
	if theme.ID != "theme.edge_connect.502" || theme.Category != CategoryEdgeConnect ||
		len(theme.Match.Codes) != 1 || theme.Match.Codes[0] != 502 || !bytes.Equal(theme.Resource.Body, page502) ||
		theme.Resource.MIMEType != "text/html" {
		t.Fatalf("theme rule = %+v", theme)
	}
	if !bytes.Equal(document.Global.Rules[0].Resource.Body, globalBody) {
		t.Fatal("platform no_host page was replaced by the theme page")
	}

	source.ThemePages[0].Body = themedTestPage(themedTestStyle, "cf-unknown")
	if _, err := compiler.buildSelected(t.Context(), source); err == nil {
		t.Fatal("unsafe theme page was published")
	}
}
