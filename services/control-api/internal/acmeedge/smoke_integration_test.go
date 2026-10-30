//go:build integration

package acmeedge

import (
	"errors"
	"testing"
	"time"
)

func TestACMEHTTP01OverlayControlPlaneSmoke(t *testing.T) {
	fixture := newIntegrationFixture(t, 2, 1)
	apply, err := fixture.service.PublishSnapshot(
		t.Context(), fixture.request("smoke-apply", 0, fixture.challenges),
	)
	if err != nil {
		t.Fatal(err)
	}
	makeVersionHealthy(t, fixture, apply)

	if _, err := fixture.pool.Exec(t.Context(), `
		UPDATE nodes SET admin_state='draining' WHERE id=ANY($1::uuid[])`, fixture.nodeIDs); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `
		UPDATE sites SET enabled=false,status='disabled' WHERE id=$1`, fixture.siteID); err != nil {
		t.Fatal(err)
	}
	blocked := &blockedAuthorizer{err: errors.New("license service unavailable")}
	cleanupService := fixture.newServiceWithAuthorizer(t, blocked)
	cleanup, err := cleanupService.PublishSnapshot(
		t.Context(), fixture.cleanupRequest("smoke-cleanup", apply.Revision, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	if blocked.calls.Load() != 0 {
		t.Fatalf("cleanup called entitlement authorizer %d times", blocked.calls.Load())
	}
	deliveries, err := cleanupService.ClaimDeliveries(
		t.Context(), ClaimRequest{Limit: 10, LeaseDuration: time.Minute},
	)
	if err != nil || len(deliveries) != len(fixture.nodeIDs) {
		t.Fatalf("cleanup deliveries = %+v, %v", deliveries, err)
	}
	for _, delivery := range deliveries {
		if delivery.Mode != ModeCleanup || len(delivery.Tokens) != 0 {
			t.Fatalf("cleanup delivery = %+v", delivery)
		}
		completeDeliveryHealthy(t, fixture, delivery)
	}
	latest, err := cleanupService.LatestHealthy(t.Context(), fixture.scopeID, fixture.siteID)
	if err != nil || latest.Revision != cleanup.Revision || latest.VersionID != cleanup.VersionID {
		t.Fatalf("latest healthy cleanup = %+v, %v", latest, err)
	}
}
