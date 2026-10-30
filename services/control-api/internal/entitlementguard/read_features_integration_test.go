package entitlementguard

import (
	"maps"
	"testing"
	"time"
)

// ReadValidFeatures is artifactsync's lease recheck: the features of a valid,
// unrevoked lease; nothing (never an error) for any other state.
func TestReadValidFeaturesGrantsOnlyAValidUnrevokedLease(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	read := func(guard *Guard) map[string]bool {
		t.Helper()
		tx := fixture.begin(t)
		defer func() { _ = tx.Rollback(t.Context()) }()
		features, err := guard.ReadValidFeatures(t.Context(), tx)
		if err != nil {
			t.Fatalf("ReadValidFeatures() error = %v", err)
		}
		return features
	}
	if got := read(fixture.guard()); len(got) != 0 {
		t.Fatalf("no lease installed: %v", got)
	}
	if got := read(fixture.valid(t, 1)); !maps.Equal(got, map[string]bool{FeatureExtensionsWebhooks: true}) {
		t.Fatalf("valid lease: %v", got)
	}
	if got := read(fixture.missingTrust(t, 2)); len(got) != 0 {
		t.Fatalf("no trust anchor: %v", got)
	}
	if got := read(fixture.invalidSignature(t, 3)); len(got) != 0 {
		t.Fatalf("damaged signature: %v", got)
	}
	// The serial in force is revoked by a newer revocation list.
	guard := fixture.valid(t, 4)
	acceptIntegrationRevocation(t, fixture.pool, fixture.trust, fixture.signer, fixture.now, fixture.now.Add(-time.Second), 2, []uint64{4})
	if got := read(guard); len(got) != 0 {
		t.Fatalf("revoked serial: %v", got)
	}
	// Past expiry and grace.
	expired := NewGuard(fixture.pool, func() time.Time { return fixture.now.Add(400 * 24 * time.Hour) }, fixture.trust)
	fixture.install(t, fixture.lease(5), fixture.now)
	if got := read(expired); len(got) != 0 {
		t.Fatalf("expired lease: %v", got)
	}
}
