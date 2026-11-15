package identityverificationhttp

import (
	"fmt"
	"net/http"
	"testing"
)

// a kind turned off on the system settings page is a
// 403 with its own code, not a provider outage.
func TestProviderKindDisabledPublicError(t *testing.T) {
	status, code, _ := providerPublicError(fmt.Errorf("start: %w", ErrProviderKindDisabled))
	if status != http.StatusForbidden || code != "identity_verification_kind_disabled" {
		t.Fatalf("kind disabled = %d %s", status, code)
	}
}
