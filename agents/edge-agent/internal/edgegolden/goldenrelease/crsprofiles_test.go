package goldenrelease

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedCRSProfilePacksMatchRulepack(t *testing.T) {
	paths, err := filepath.Glob("../../../../../libs/rulepack/testdata/crs-profiles/crs-*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("rulepack goldens: %v %v", paths, err)
	}
	entries, _ := crsProfilePacks.ReadDir("crsprofiles")
	if len(entries) != len(paths) {
		t.Fatalf("embedded %d packs, rulepack has %d", len(entries), len(paths))
	}
	for _, path := range paths {
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := crsProfilePacks.ReadFile("crsprofiles/" + filepath.Base(path))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: embedded copy differs from libs/rulepack (copy it again)", filepath.Base(path))
		}
	}
}
