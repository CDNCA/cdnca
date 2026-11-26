package entitlement

import (
	"slices"
	"testing"
)

// the publication gate and GET /v1/modules share one rule.
func TestWithLegacyPublicationModules(t *testing.T) {
	all := []string{ModuleDoH, ModuleRUM, ModuleContentRewrite}
	for _, test := range []struct {
		name  string
		codes []string
		want  []string
	}{
		{name: "earlier lease names none", codes: []string{"pack.crs"}, want: append([]string{"pack.crs"}, all...)},
		{name: "empty", codes: nil, want: all},
		{name: "explicit lease keeps only what it names", codes: []string{"pack.crs", ModuleRUM}, want: []string{"pack.crs", ModuleRUM}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := slices.Clone(test.codes)
			if got := WithLegacyPublicationModules(input); !slices.Equal(got, test.want) {
				t.Fatalf("WithLegacyPublicationModules(%v) = %v, want %v", test.codes, got, test.want)
			}
			if !slices.Equal(input, test.codes) {
				t.Fatalf("input changed to %v", input)
			}
		})
	}
}
