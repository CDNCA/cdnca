package edgedeployment

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
)

func TestStableAuthorizationErrorMapsInvalidCredentialToUnauthenticated(t *testing.T) {
	if err := stableAuthorizationError(iamlock.ErrInvalidCredential); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("stableAuthorizationError() = %v, want ErrUnauthenticated", err)
	}
}
