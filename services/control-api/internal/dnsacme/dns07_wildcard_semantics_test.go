package dnsacme

import (
	"slices"
	"testing"
)

func TestDNS07NormalizeDomainsKeepsExplicitWildcardSANsOnly(t *testing.T) {
	got, wildcard, err := normalizeDomains([]string{
		"*.example.com", "example.com", "*.deep.example.com",
	})
	want := []string{"*.deep.example.com", "*.example.com", "example.com"}
	if err != nil || !wildcard || !slices.Equal(got, want) {
		t.Fatalf("normalizeDomains()=(%v,%t,%v) want=(%v,true,nil)", got, wildcard, err, want)
	}
	for _, implicit := range []string{"a.example.com", "a.b.example.com", "deep.example.com"} {
		if slices.Contains(got, implicit) {
			t.Fatalf("normalizeDomains() silently added %q: %v", implicit, got)
		}
	}
}
