package systemconfig

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestAccessLogFieldsCategoryNormalizesAndRoundTrips(t *testing.T) {
	base := ProjectBootstrapConfiguration()
	if base.AccessLogFields != nil {
		t.Fatal("the bootstrap configuration must not store a selection")
	}
	value, ok := categoryValue(base, CategoryAccessLogFields).(edgeconfig.AccessLogFields)
	if !ok || !slices.Equal(value.Fields, edgeconfig.DefaultAccessLogFields) {
		t.Fatalf("never saved value = %#v", categoryValue(base, CategoryAccessLogFields))
	}
	change := CategoryChange{AccessLogFields: &edgeconfig.AccessLogFields{Fields: []string{"upstream_addr", "referer"}}}
	if !validCategoryChange(CategoryAccessLogFields, change) || validCategoryChange(CategoryDDoSProtection, change) {
		t.Fatal("category change shape")
	}
	if categoryChangeExpands(base, base, CategoryAccessLogFields) {
		t.Fatal("access log fields must not need an expansion entitlement")
	}
	next := applyCategoryChange(base, CategoryAccessLogFields, change)
	normalized, snapshot, _, err := CanonicalSnapshot(next)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(normalized.AccessLogFields.Fields, []string{"referer", "upstream_addr"}) {
		t.Fatalf("normalized = %v", normalized.AccessLogFields.Fields)
	}
	if !strings.Contains(string(snapshot), `"access_log_fields": {`) {
		t.Fatalf("snapshot lacks the category: %s", snapshot)
	}
	normalizedBase, _, _, err := CanonicalSnapshot(base)
	if err != nil {
		t.Fatal(err)
	}
	if got := diffCategories(normalizedBase, normalized); !slices.Equal(got, []string{CategoryAccessLogFields}) {
		t.Fatalf("pending categories = %v", got)
	}
	invalid := applyCategoryChange(base, CategoryAccessLogFields,
		CategoryChange{AccessLogFields: &edgeconfig.AccessLogFields{Fields: []string{"host"}}})
	if _, _, _, err := CanonicalSnapshot(invalid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("a basic field accepted as optional: %v", err)
	}
}
