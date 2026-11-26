package cnameallocation

import (
	"errors"
	"fmt"
	"testing"
)

func TestFailureCodeNamesTheReason(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{failWith(FailureCNAMEZoneNotConfigured, ErrNotFound), "cname_zone_not_configured"},
		{fmt.Errorf("wrapped: %w", failWith(FailureDNSProviderNotConfigured, ErrNotFound)), "dns_provider_not_configured"},
		{mapError(failWith(FailureNodeGroupUnavailable, ErrNotFound)), "node_group_unavailable"},
		{ErrBlocked, "domain_blocked"},
		{errIntentSuperseded, "intent_superseded"},
		{ErrNotFound, "allocation_rejected"},
	} {
		if got := failureCode(tc.err); got != tc.want {
			t.Errorf("failureCode(%v)=%s want %s", tc.err, got, tc.want)
		}
	}
	// The classified error still reads as the base error for callers.
	if err := mapError(failWith(FailurePlatformDNSSyncFailed, ErrNotFound)); failureCode(err) != "platform_dns_sync_failed" {
		t.Fatalf("platform DNS sync failure code = %s", failureCode(err))
	}
	if err := mapError(failWith(FailurePackageInactive, ErrNotFound)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mapError lost the base error: %v", err)
	}
}

// a CNAME without a domain that finds no zone says whether the
// package lacks a CNAME domain or the site has no package; a missing DNS
// provider and a named domain keep their codes.
func TestSiteZoneFailureNamesTheMissingDomain(t *testing.T) {
	zoneMissing := failWith(FailureCNAMEZoneNotConfigured, ErrNotFound)
	providerMissing := failWith(FailureDNSProviderNotConfigured, ErrNotFound)
	for _, tc := range []struct {
		err      error
		packaged bool
		domain   string
		want     string
	}{
		{zoneMissing, true, "", "cname_package_domain_missing"},
		{zoneMissing, false, "", "cname_no_default_zone"},
		{zoneMissing, true, "cdn.example.com", "cname_zone_not_configured"},
		{providerMissing, true, "", "dns_provider_not_configured"},
		{providerMissing, false, "", "dns_provider_not_configured"},
	} {
		err := siteZoneFailure(tc.err, tc.packaged, tc.domain)
		if got := failureCode(err); got != tc.want {
			t.Errorf("siteZoneFailure(%s, packaged=%v, %q)=%s want %s", failureCode(tc.err), tc.packaged, tc.domain, got, tc.want)
		}
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("siteZoneFailure lost ErrNotFound: %v", err)
		}
	}
}
