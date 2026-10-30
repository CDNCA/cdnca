package main

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
)

type fixedUnavailableCertificates []dyntls.Unavailable

func (value fixedUnavailableCertificates) UnavailableCertificates() []dyntls.Unavailable {
	return value
}

// The deployment receipt names each site whose certificate the node cannot serve.
func TestSiteCertificateChecksNameTheExpiredSites(t *testing.T) {
	healthy := siteCertificateChecks(fixedUnavailableCertificates(nil))()
	if len(healthy) != 1 || healthy[0].Name != siteCertificateCheckName || !healthy[0].Succeeded {
		t.Fatalf("no expired certificate: %+v", healthy)
	}
	checks := siteCertificateChecks(fixedUnavailableCertificates{{SiteID: "site-a", VersionID: "version-a"}})()
	if len(checks) != 1 || checks[0].Succeeded || !strings.Contains(checks[0].Summary, "site site-a certificate version-a") {
		t.Fatalf("expired certificate: %+v", checks)
	}
	many := make(fixedUnavailableCertificates, 40)
	for index := range many {
		many[index] = dyntls.Unavailable{SiteID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", VersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7102"}
	}
	if summary := siteCertificateChecks(many)()[0].Summary; len(summary) > 500 || !strings.HasPrefix(summary, "40 site certificates") {
		t.Fatalf("bounded summary (%d): %s", len(summary), summary)
	}
}
