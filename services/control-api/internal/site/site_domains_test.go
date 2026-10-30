package site

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestSITE02DomainsAreIDNACanonicalSortedDeduplicatedAndBounded(t *testing.T) {
	got, err := normalizeSiteDomains([]string{
		"BÜCHER.Example.",
		"xn--bcher-kva.example",
		"api.example.com",
		"*.例子.测试",
	})
	want := []string{"*.xn--fsqu00a.xn--0zwm56d", "api.example.com", "xn--bcher-kva.example"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("normalizeSiteDomains() = (%v, %v), want (%v, nil)", got, err, want)
	}

	fields := SiteFields{Domains: got}
	item := Site{Domains: fields.Domains}
	listed := ListItem{Domains: item.Domains}
	if !slices.Equal(listed.Domains, want) {
		t.Fatalf("multi-domain model lost canonical domains: %v", listed.Domains)
	}

	tooMany := make([]string, 101)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("d%03d.example.test", index)
	}
	if _, err := normalizeSiteDomains(tooMany); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("101 domains error = %v, want %v", err, ErrInvalidInput)
	}
	if _, err := normalizeSiteDomains([]string{"*.co.uk"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("public-suffix wildcard error = %v, want %v", err, ErrInvalidInput)
	}
}

func TestSITE02DeletePathsReleaseDomainFacts(t *testing.T) {
	source, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	if calls := strings.Count(string(source), "if err := appendSiteDomainFacts"); calls < 4 {
		t.Fatalf("site delete paths append %d domain-fact transitions, want create/update/delete/batch-delete", calls)
	}
}
