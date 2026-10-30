package rulepack

import "testing"

// Withhold drops the withheld mounts and recomputes the digest Resolve gives
// the remaining ones; all withheld gives the empty document; nothing
// withheld returns the input unchanged.
func TestWithhold(t *testing.T) {
	a := wafPack(t, "system/block-a", "block", "/a")
	b := wafPack(t, "system/block-b", "block", "/b")
	packs := map[string]*CompiledPack{a.SHA256: a, b.SHA256: b}
	both := *Resolve([]MountRequest{{Pack: a}, {Pack: b}}, Target{}).Security
	only := *Resolve([]MountRequest{{Pack: a}}, Target{}).Security
	byID := func(id string) func(Mount) bool { return func(m Mount) bool { return m.PackID == id } }

	got, ok, err := Withhold(both, packs, byID("system/block-b"))
	if err != nil || !ok || got.ResolvedSHA256 != only.ResolvedSHA256 || len(got.Mounts) != 1 || got.Mounts[0].PackID != "system/block-a" {
		t.Fatalf("withhold b = %+v %t %v, want %s", got, ok, err, only.ResolvedSHA256)
	}
	if _, err := Verify(got, packs); err != nil {
		t.Fatalf("node verify: %v", err)
	}
	if got, ok, err := Withhold(both, packs, func(Mount) bool { return true }); err != nil || !ok ||
		len(got.Mounts) != 0 || got.ResolvedSHA256 != "" {
		t.Fatalf("withhold all = %+v %t %v", got, ok, err)
	}
	if got, ok, err := Withhold(both, packs, func(Mount) bool { return false }); err != nil || ok ||
		got.ResolvedSHA256 != both.ResolvedSHA256 {
		t.Fatalf("withhold none = %+v %t %v", got, ok, err)
	}
}
