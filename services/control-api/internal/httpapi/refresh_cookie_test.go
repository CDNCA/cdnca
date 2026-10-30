package httpapi

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// TestRefreshKeepsCookieOnTransientFailure: before the fix every refresh error
// cleared cdnca_refresh, so one database hiccup or upgrade-gate 503 turned the
// next renewal into a 401 with no revocation record and a forced sign-in.
func TestRefreshKeepsCookieOnTransientFailure(t *testing.T) {
	for _, err := range []error{
		identity.ErrInvalidSession, identity.ErrRefreshReplay, identity.ErrAccountDisabled,
		identity.ErrMembershipDisabled, identity.ErrAdminAccessDenied,
		fmt.Errorf("wrapped: %w", identity.ErrInvalidSession),
	} {
		if !refreshRefused(err) {
			t.Errorf("refreshRefused(%v) = false, want true (refusal clears the cookie)", err)
		}
	}
	for _, err := range []error{
		errors.New("begin refresh transaction: connection refused"),
		context.DeadlineExceeded,
		identity.ErrAdminAccessUnavailable,
		fmt.Errorf("find refresh session family scopes: %w", errors.New("timeout")),
	} {
		if refreshRefused(err) {
			t.Errorf("refreshRefused(%v) = true, want false (transient failure keeps the cookie)", err)
		}
	}
}
