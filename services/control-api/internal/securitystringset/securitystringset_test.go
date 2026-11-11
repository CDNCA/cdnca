package securitystringset

import (
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

func TestNormalizeCanonicalizesEntries(t *testing.T) {
	input, size, err := Normalize(Input{Name: " 爬虫 UA ", MatchMode: "contains", Entries: []string{" SQLMap", "nikto", "sqlmap "}})
	if err != nil {
		t.Fatal(err)
	}
	if input.Name != "爬虫 UA" || !slices.Equal(input.Entries, []string{"nikto", "sqlmap"}) || size != len("nikto")+len("sqlmap") {
		t.Fatalf("%+v %d", input, size)
	}
}

// A refused entry names entries[i] (input position) with the member reason.
func TestNormalizeLocatesRefusedEntry(t *testing.T) {
	for name, test := range map[string]struct {
		input  Input
		field  string
		reason string
	}{
		"too long": {Input{Name: "a", MatchMode: "exact", CaseSensitive: true, Entries: []string{"ok", strings.Repeat("x", 513)}}, "entries[1]", "too_long"},
		"control":  {Input{Name: "a", MatchMode: "exact", CaseSensitive: true, Entries: []string{"a\tb"}}, "entries[0]", "control_character"},
		"stars":    {Input{Name: "a", MatchMode: "wildcard", CaseSensitive: true, Entries: []string{"/a", "*a*b*c*"}}, "entries[1]", "wildcard_too_many_stars"},
		"none":     {Input{Name: "a", MatchMode: "exact", CaseSensitive: true, Entries: []string{"  "}}, "entries[0]", "empty"},
		"bad mode": {Input{Name: "a", MatchMode: "regex", Entries: []string{"x"}}, "match_mode", fielderr.Invalid},
		"no name":  {Input{Name: " ", MatchMode: "exact", Entries: []string{"x"}}, "name", fielderr.Invalid},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Normalize(test.input)
			located, ok := fielderr.As(err)
			if !ok || located.Field != test.field || located.Reason != test.reason {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
