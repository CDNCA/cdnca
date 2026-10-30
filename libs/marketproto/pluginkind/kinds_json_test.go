package pluginkind

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// kinds.json is what the web, seller-portal and operator-console front ends import; it must
// list exactly All in the same order (official_only mirrors market-service plugin.officialKinds).
func TestKindsJSONMatchesAll(t *testing.T) {
	raw, err := os.ReadFile("kinds.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Kinds        []string `json:"kinds"`
		OfficialOnly []string `json:"official_only"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(file.Kinds, All) {
		t.Fatalf("kinds.json kinds=%v want %v", file.Kinds, All)
	}
	for _, kind := range file.OfficialOnly {
		if !Valid(kind) {
			t.Fatalf("official_only has unknown kind %q", kind)
		}
	}
}
