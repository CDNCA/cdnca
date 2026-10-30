package dnsproviderremote

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
)

type providerCredentialLeaseSource struct {
	*staticSource
	active       atomic.Bool
	acquisitions atomic.Int32
	releases     atomic.Int32
}

func (source *providerCredentialLeaseSource) AcquireProviderCredentialLease(
	ctx context.Context,
	lookup ProviderLookup,
	version uint64,
) (ProviderCredentialLease, error) {
	if ctx == nil || ctx.Err() != nil || source.CheckCredentialFence(ctx, lookup, version) != nil ||
		!source.active.CompareAndSwap(false, true) {
		return nil, errors.New("credential lease unavailable")
	}
	source.acquisitions.Add(1)
	return func(releaseCtx context.Context) error {
		if releaseCtx == nil || releaseCtx.Err() != nil || !source.active.CompareAndSwap(true, false) {
			return errors.New("credential lease release failed")
		}
		source.releases.Add(1)
		return nil
	}, nil
}

func TestPresentTXTHoldsRequestScopedCredentialLeaseDuringProviderCall(t *testing.T) {
	var unleasedCalls atomic.Int32
	var source *providerCredentialLeaseSource
	adapter, base := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerCloudflare,
		ZoneName:     testZone,
		Credentials:  map[string]string{"api_token": "secret-token"},
	}, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if source == nil || !source.active.Load() {
			unleasedCalls.Add(1)
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/zones":
			writeTestJSON(t, writer, map[string]any{"success": true, "result": []any{
				map[string]any{"id": "zone-lease", "name": testZone},
			}})
		case request.Method == http.MethodPost && request.URL.Path == "/zones/zone-lease/dns_records":
			writeTestJSON(t, writer, map[string]any{"success": true, "result": map[string]any{
				"id": "record-lease", "zone_id": "zone-lease", "name": testOwner,
				"type": "TXT", "content": testValue,
			}})
		default:
			http.NotFound(writer, request)
		}
	}), requestTimeout)
	source = &providerCredentialLeaseSource{staticSource: base}
	adapter.source = source

	handle, err := adapter.PresentTXT(t.Context(), testChallenge())
	if err != nil || handle == (acmeworker.RemoteTXTHandle{}) {
		t.Fatalf("PresentTXT() = (%+v, %v)", handle, err)
	}
	if unleasedCalls.Load() != 0 || source.acquisitions.Load() != 1 || source.releases.Load() != 1 || source.active.Load() {
		t.Fatalf("lease calls unleased/acquired/released/active = %d/%d/%d/%t, want 0/1/1/false",
			unleasedCalls.Load(), source.acquisitions.Load(), source.releases.Load(), source.active.Load())
	}
}
