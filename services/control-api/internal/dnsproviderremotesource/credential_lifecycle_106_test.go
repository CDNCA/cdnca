package dnsproviderremotesource

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

func TestCredentialLifecycle106FenceRejectsMissingOrMismatchedVersion(t *testing.T) {
	source := &Source{}
	err := source.CheckCredentialFence(context.Background(), dnsproviderremote.ProviderLookup{
		TenantScopeID: uuid.New(), ProviderID: uuid.New(),
	}, 1)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing pool fence error=%v, want ErrUnavailable", err)
	}
}
