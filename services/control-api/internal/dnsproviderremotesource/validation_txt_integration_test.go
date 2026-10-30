//go:build integration

package dnsproviderremotesource

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

type recordingTXTWriter struct {
	config  dnsproviderremote.ProviderConfig
	token   string
	calls   int
	removed string
}

func (writer *recordingTXTWriter) Publish(_ context.Context, config dnsproviderremote.ProviderConfig, owner, value string) (string, error) {
	writer.config, writer.token, writer.calls = config, config.Credentials["api_token"], writer.calls+1
	return "txt1.ref-" + owner + "=" + value, nil
}

func (writer *recordingTXTWriter) Remove(_ context.Context, config dnsproviderremote.ProviderConfig, ref, _, _ string) error {
	writer.config, writer.calls, writer.removed = config, writer.calls+1, ref
	return nil
}

// The validation publisher picks the site tenant's zone with the longest
// matching suffix, decrypts that provider's credentials for the call only,
// and reports names no verified provider of the tenant manages.
func TestValidationPublisherUsesTheLongestManagedZone(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "validation-txt")
	cipher := mustSourceCipher(t, "validation-txt-key", 61)
	parent := insertSourceProvider(t, pool, tenant, "cloudflare", "verified", cipher, `{"api_token":"parent-token"}`)
	child := insertSourceProvider(t, pool, tenant, "cloudflare", "verified", cipher, `{"api_token":"child-token"}`)
	insertSourceZone(t, pool, tenant, parent, "example.test")
	childZone := insertSourceZone(t, pool, tenant, child, "shop.example.test")
	siteID := insertSourceReconcileSite(t, pool, tenant, "www.shop.example.test")

	writer := &recordingTXTWriter{}
	publisher, err := NewValidationPublisher(pool, cipher, writer)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := publisher.Publish(t.Context(), siteID, "_cf-custom-hostname.www.shop.example.test", "own-1")
	if err != nil || ref == "" || writer.config.ProviderID != child || writer.config.ZoneID != childZone ||
		writer.config.ZoneName != "shop.example.test" || writer.token != "child-token" || len(writer.config.Credentials) != 0 {
		t.Fatalf("Publish = %q, %v; config %+v", ref, err, writer.config)
	}
	if err := publisher.Remove(t.Context(), siteID, ref, "_cf-custom-hostname.www.shop.example.test", "own-1"); err != nil ||
		writer.removed != ref {
		t.Fatalf("Remove = %v (removed %q)", err, writer.removed)
	}

	calls := writer.calls
	if _, err := publisher.Publish(t.Context(), siteID, "_acme-challenge.www.other.test", "dcv"); !errors.Is(err, ErrNoManagedZone) {
		t.Fatalf("unmanaged name = %v", err)
	}
	setSourceProviderStatus(t, pool, child, "disabled")
	if _, err := publisher.Publish(t.Context(), siteID, "_cf-custom-hostname.www.shop.example.test", "own-1"); err != nil ||
		writer.config.ProviderID != parent {
		t.Fatalf("disabled child zone did not fall back to the parent zone: %v %+v", err, writer.config.ProviderID)
	}
	if _, err := publisher.Publish(t.Context(), uuid.New(), "_cf-custom-hostname.www.shop.example.test", "own-1"); !errors.Is(err, ErrNoManagedZone) {
		t.Fatalf("unknown site = %v", err)
	}
	if writer.calls != calls+1 {
		t.Fatalf("writer called %d times, want %d", writer.calls, calls+1)
	}
}
