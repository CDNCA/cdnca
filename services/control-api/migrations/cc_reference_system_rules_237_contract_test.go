package migrations

import (
	"slices"
	"strings"
	"testing"
)

func TestCCReferenceSystemRules237Contract(t *testing.T) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		version    string
		identifier string
	}{
		{"237", "237_l4_stream_user_defaults_lock_grant"},
		{"242", "242_cc_reference_system_rules"},
	} {
		t.Run(test.version, func(t *testing.T) {
			var got []string
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), test.version+"_") && strings.HasSuffix(entry.Name(), ".sql") {
					got = append(got, entry.Name())
				}
			}
			want := []string{test.identifier + ".down.sql", test.identifier + ".up.sql"}
			if !slices.Equal(got, want) {
				t.Fatalf("migration %s files = %v, want exactly %v; superseded CC migration 237 must not return", test.version, got, want)
			}
		})
	}
}
