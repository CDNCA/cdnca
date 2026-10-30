package rulepack

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

// sealedOf seals pack as the license service does (Seal computes the CRS
// rule list from the plaintext); sealedWithList forges the list instead.
func sealedOf(t *testing.T, pack *CompiledPack) (control, node *CompiledPack) {
	t.Helper()
	manifest, _ := narrowFixture(t)
	return openSealed(t, func(cek []byte) ([]byte, error) { return Seal(pack.Canonical, cek, manifest) })
}

func sealedWithList(t *testing.T, pack *CompiledPack, ids []int) (control, node *CompiledPack) {
	t.Helper()
	return openSealed(t, func(cek []byte) ([]byte, error) { return SealWithCRSRuleIDs(pack.Canonical, cek, ids) })
}

func openSealed(t *testing.T, seal func(cek []byte) ([]byte, error)) (control, node *CompiledPack) {
	t.Helper()
	cek := make([]byte, CEKSize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	document, err := seal(cek)
	if err != nil {
		t.Fatal(err)
	}
	digest := digestOf(document)
	if control, err = OpenManifest(document, digest); err != nil {
		t.Fatal(err)
	}
	if node, err = Open(document, digest, cek); err != nil {
		t.Fatal(err)
	}
	return control, node
}

// The seller cannot supply the list: the pack document has no such field.
func TestPackDocumentHasNoCRSRuleIDs(t *testing.T) {
	document := map[string]any{}
	_ = json.Unmarshal(readPack(t, "system-crs.json"), &document)
	document["pack_id"] = "system/sqli-narrow"
	document["crs_rule_ids"] = []any{942100}
	encoded, _ := json.Marshal(document)
	if _, err := Compile(encoded); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("seller crs_rule_ids: %v", err)
	}
}

// Seal computes the list from the plaintext; it needs the CRS rule text for
// a modsecurity pack and refuses a forged list that is not CRS numbers.
func TestSealComputesCRSRuleIDs(t *testing.T) {
	manifest, _ := narrowFixture(t)
	pack := modSecurityPack(t, nil)
	control, node := sealedOf(t, pack)
	want := PackCRSRuleIDs(manifest, pack.Pack)
	if len(want) == 0 || !slices.Equal(control.CRSRuleIDs, want) || !slices.Equal(node.CRSRuleIDs, want) {
		t.Fatalf("manifest list %v / node %v, want %v", control.CRSRuleIDs, node.CRSRuleIDs, want)
	}
	cek := make([]byte, CEKSize)
	if _, err := Seal(pack.Canonical, cek, nil); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("no CRS text: %v", err)
	}
	if _, err := SealWithCRSRuleIDs(pack.Canonical, cek, []int{942140, 942100}); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("unsorted list: %v", err)
	}
	waf := wafPack(t, "system/block-a", "block", "/a")
	if sealed, err := Seal(waf.Canonical, cek, nil); err != nil || IsSealed(sealed) == false {
		t.Fatalf("waf pack: %v", err)
	}
}

// A sealed modsecurity pack narrows the profile exactly as its plaintext
// would (manifest only); without the list it is refused.
func TestSealedModSecurityPackNarrowsByItsRuleIDs(t *testing.T) {
	manifest, profile := narrowFixture(t)
	plain := modSecurityPack(t, nil)
	control, node := sealedOf(t, plain)
	if len(control.Pack.Rules) != 0 {
		t.Fatalf("manifest pack = %+v", control.Pack)
	}
	mounts := Resolve([]MountRequest{{Pack: control}}, Target{}).Security.Mounts
	got, ok, err := SiteCRSExclusions(mounts, map[string]*CompiledPack{control.SHA256: control}, manifest, &profile, []int{941100})
	if err != nil || !ok {
		t.Fatalf("sealed listed: %v %v", ok, err)
	}
	plainMounts := Resolve([]MountRequest{{Pack: plain}}, Target{}).Security.Mounts
	want, _, err := SiteCRSExclusions(plainMounts, map[string]*CompiledPack{plain.SHA256: plain}, manifest, &profile, []int{941100})
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("sealed %v, plaintext %v (%v)", got, want, err)
	}
	// The node: the opened rules evaluate the list.
	rules, err := program(mounts, map[string]*CompiledPack{node.SHA256: node}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCRSRuleIDs(manifest, mounts[0], node, rules); err != nil {
		t.Fatalf("node check: %v", err)
	}

	// A list reaching beyond the profile (a paranoia 2 rule) is out of profile.
	beyond := append(slices.Clone(control.CRSRuleIDs), 942200)
	slices.Sort(beyond)
	wideControl, _ := sealedWithList(t, plain, slices.Compact(beyond))
	wideMounts := Resolve([]MountRequest{{Pack: wideControl}}, Target{}).Security.Mounts
	if _, _, err := SiteCRSExclusions(wideMounts, map[string]*CompiledPack{wideControl.SHA256: wideControl}, manifest, &profile,
		nil); !errors.Is(err, ErrOutOfProfile) {
		t.Fatalf("beyond the profile: %v", err)
	}

	unlisted, unlistedNode := sealedWithList(t, plain, nil)
	unlistedMounts := Resolve([]MountRequest{{Pack: unlisted}}, Target{}).Security.Mounts
	if _, _, err := SiteCRSExclusions(unlistedMounts, map[string]*CompiledPack{unlisted.SHA256: unlisted}, manifest, &profile,
		nil); !errors.Is(err, ErrOutOfProfile) {
		t.Fatalf("sealed without list: %v", err)
	}
	unlistedRules, err := program(unlistedMounts, map[string]*CompiledPack{unlistedNode.SHA256: unlistedNode}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCRSRuleIDs(manifest, unlistedMounts[0], unlistedNode, unlistedRules); !errors.Is(err, ErrCRSRuleIDsMismatch) {
		t.Fatalf("node, sealed without list: %v", err)
	}
}

// A list that does not match the rules (one rule left out) is refused by
// the node after opening the pack.
func TestCheckCRSRuleIDsRefusesAListThatDoesNotMatch(t *testing.T) {
	manifest, _ := narrowFixture(t)
	plain := modSecurityPack(t, nil)
	honest := PackCRSRuleIDs(manifest, plain.Pack)
	_, node := sealedWithList(t, plain, slices.Clone(honest[1:]))
	mounts := Resolve([]MountRequest{{Pack: node}}, Target{}).Security.Mounts
	rules, err := program(mounts, map[string]*CompiledPack{node.SHA256: node}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCRSRuleIDs(manifest, mounts[0], node, rules); !errors.Is(err, ErrCRSRuleIDsMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	// Excluded exports leave both sides the same way.
	_, honestNode := sealedOf(t, plain)
	excluded := withSHA(mounts[0], honestNode)
	excluded.Params = Params{ParamExclusions: json.RawMessage(`["942100"]`)}
	honestRules, err := program([]Mount{excluded}, map[string]*CompiledPack{honestNode.SHA256: honestNode}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCRSRuleIDs(manifest, excluded, honestNode, honestRules); err != nil {
		t.Fatalf("with exclusions: %v", err)
	}
}

func withSHA(mount Mount, pack *CompiledPack) Mount {
	mount.SHA256, mount.PackID, mount.Version = pack.SHA256, pack.Pack.PackID, pack.Pack.Version
	return mount
}

// SecurityOf rebuilds exactly what Resolve wrote, with a mount out or back.
func TestSecurityOfMatchesResolve(t *testing.T) {
	pack := modSecurityPack(t, nil)
	waf := wafPack(t, "system/block-a", "block", "/a")
	packs := map[string]*CompiledPack{pack.SHA256: pack, waf.SHA256: waf}
	both := Resolve([]MountRequest{{Pack: waf}, {Pack: pack}}, Target{}).Security
	only := Resolve([]MountRequest{{Pack: waf}}, Target{}).Security
	var wafMount []Mount
	for _, mount := range both.Mounts {
		if mount.Engine != EngineModSecurity {
			wafMount = append(wafMount, mount)
		}
	}
	without, err := SecurityOf(wafMount, packs)
	if err != nil || without.ResolvedSHA256 != only.ResolvedSHA256 {
		t.Fatalf("without = %s, want %s (%v)", without.ResolvedSHA256, only.ResolvedSHA256, err)
	}
	back, err := SecurityOf([]Mount{both.Mounts[1], both.Mounts[0]}, packs)
	if err != nil || back.ResolvedSHA256 != both.ResolvedSHA256 || back.Mounts[0].PackID != both.Mounts[0].PackID {
		t.Fatalf("back = %+v %v", back, err)
	}
	if _, err := Verify(back, packs); err != nil {
		t.Fatalf("node verify: %v", err)
	}
}

// The publisher's quality gate: a pack that resolves alone passes (with
// its computed list for modsecurity); without the CRS text, or sealed, it is
// refused.
func TestCheckPublishable(t *testing.T) {
	manifest, _ := narrowFixture(t)
	pack := modSecurityPack(t, nil)
	ids, err := CheckPublishable(pack, manifest)
	if err != nil || !slices.Equal(ids, PackCRSRuleIDs(manifest, pack.Pack)) {
		t.Fatalf("modsecurity: %v %v", ids, err)
	}
	if _, err := CheckPublishable(pack, nil); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("no CRS text: %v", err)
	}
	if ids, err := CheckPublishable(wafPack(t, "system/block-a", "block", "/a"), nil); err != nil || ids != nil {
		t.Fatalf("waf: %v %v", ids, err)
	}
	control, _ := sealedOf(t, pack)
	if _, err := CheckPublishable(control, manifest); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("sealed: %v", err)
	}
}
