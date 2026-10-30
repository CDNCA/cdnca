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
