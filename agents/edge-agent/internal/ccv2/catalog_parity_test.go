package ccv2

import (
	"os"
	"testing"
)

// The fixtures are produced by control-api: securitypolicy.ExpandCCRuleGroup
// ("5秒盾" cc_rule:10001 + "宽松" cc_rule:6) -> CompileRuntimeSnapshot ->
// securitypublication.CompileSiteSecurityBindings. The node must re-derive
// the exact compiled bytes or its release precheck rejects the release.
func TestCompileSourceReproducesControlCatalogChallengeAndPerURI(t *testing.T) {
	source, err := os.ReadFile("testdata/catalog-5s-relaxed.source.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/catalog-5s-relaxed.compiled.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := CompileSource(source, Binding{BindingID: "018f1000-0000-7000-8000-000000000030", BindingRevision: 1,
		PublicationID: "018f1000-0000-7000-8000-000000000031"})
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("edge compile differs from control compile:\n got %s\nwant %s", got, want)
	}
}
