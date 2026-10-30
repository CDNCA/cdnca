package certificateasset

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestSITE02BindingAndPublicationRequireCoverageForEverySiteDomain(t *testing.T) {
	sans := []string{"*.example.test", "xn--bcher-kva.example"}
	if err := RequireCoverage(sans, []string{"api.example.test", "xn--bcher-kva.example"}); err != nil {
		t.Fatalf("all covered domains rejected: %v", err)
	}
	if err := RequireCoverage(sans, []string{"api.example.test", "deep.api.example.test"}); !errors.Is(err, ErrDomainNotCovered) {
		t.Fatalf("one-level wildcard covered a deeper domain: %v", err)
	}

	publication, err := os.ReadFile("publication.go")
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	combined := string(publication) + string(store)
	if strings.Contains(combined, "CoversDomain(sans, site.domain)") ||
		!strings.Contains(combined, "RequireCoverage(sans, site.domains)") {
		t.Fatal("certificate publication is not bound to RequireCoverage for every site domain")
	}
	if !strings.Contains(combined, "RequireCoverage(target.SANs, domains)") {
		t.Fatal("certificate binding is not bound to RequireCoverage for every site domain")
	}
}
