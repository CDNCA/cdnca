package main

import (
	"strings"
	"testing"
)

func TestParseInstalledReleaseSequence(t *testing.T) {
	for _, test := range []struct {
		name     string
		manifest string
		want     uint64
	}{
		{"line two", "manifest_version=2\nrelease_sequence=17\nversion=1.0.35\n", 17},
		{"missing", "manifest_version=2\nversion=1.0.35\n", 0},
		{"wrong line", "release_sequence=17\nmanifest_version=2\n", 0},
		{"leading zero", "manifest_version=2\nrelease_sequence=017\n", 0},
		{"not a number", "manifest_version=2\nrelease_sequence=x\n", 0},
		{"empty", "", 0},
	} {
		if got := parseInstalledReleaseSequence(strings.NewReader(test.manifest)); got != test.want {
			t.Errorf("%s: got %d, want %d", test.name, got, test.want)
		}
	}
}
