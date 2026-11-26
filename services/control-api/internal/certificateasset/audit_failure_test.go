package certificateasset

import (
	"fmt"
	"testing"
)

// An unbind refused because the site serves HTTPS is a denial with its own
// reason code, not an internal error.
func TestFailureReasonSiteHTTPSEnabledIsDenied(t *testing.T) {
	result, reason := failureReason(fmt.Errorf("unbind: %w", ErrSiteHTTPSEnabled))
	if result != "denied" || reason != "site_https_enabled" {
		t.Fatalf("failureReason = %q, %q; want denied, site_https_enabled", result, reason)
	}
}
