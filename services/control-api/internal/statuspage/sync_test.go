package statuspage

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestComponentNameFrom(t *testing.T) {
	cases := map[string]string{
		"  华东线路 ": "华东线路",
		"a\x00b\n":  "ab",
		"":          "-",
		"\t":        "-",
	}
	for in, want := range cases {
		if got := componentNameFrom(in); got != want {
			t.Errorf("componentNameFrom(%q) = %q, want %q", in, got, want)
		}
	}
	long := componentNameFrom(strings.Repeat("线", 100))
	if utf8.RuneCountInString(long) != 64 {
		t.Errorf("long name has %d runes, want 64", utf8.RuneCountInString(long))
	}
}

func TestUniqueName(t *testing.T) {
	taken := map[string]bool{"华东": true, "华东 2": true}
	if got := uniqueName("华东", taken); got != "华东 3" {
		t.Errorf("got %q, want 华东 3", got)
	}
	if got := uniqueName("华北", taken); got != "华北" {
		t.Errorf("got %q, want 华北", got)
	}
	base := strings.Repeat("a", 64)
	got := uniqueName(base, map[string]bool{base: true})
	if utf8.RuneCountInString(got) > 64 || got == base {
		t.Errorf("suffixed name %q out of bounds", got)
	}
}
