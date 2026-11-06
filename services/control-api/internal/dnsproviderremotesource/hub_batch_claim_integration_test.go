//go:build integration

package dnsproviderremotesource

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
)

// POST /v1/dns/hub/records/batch binds its Idempotency-Key to the items digest (migration 639).
func TestHubClaimBatchBindsKeyToDigest(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	tenantA, tenantB := seedSourceTenant(t, pool, "batch-a"), seedSourceTenant(t, pool, "batch-b")
	reader := seedSourceTenant(t, pool, "batch-reader")
	grantSourceTenantPermissions(t, pool, tenantA, "dns.read", "dns.records.manage")
	grantSourceTenantPermissions(t, pool, tenantB, "dns.read", "dns.manage")
	grantSourceTenantPermissions(t, pool, reader, "dns.read")
	hub, err := NewHub(New(pool, mustSourceCipher(t, "batch-key", 59)), &memoryHubRemote{}, audit.New(pool),
		func() time.Time { return time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	first, second := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := hub.ClaimBatch(ctx, hubActor(tenantA), "batch-1", first); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := hub.ClaimBatch(ctx, hubActor(tenantA), "batch-1", first); err != nil {
		t.Fatalf("same digest again: %v", err)
	}
	if err := hub.ClaimBatch(ctx, hubActor(tenantA), "batch-1", second); !errors.Is(err, ErrHubIdempotency) {
		t.Fatalf("other digest = %v, want ErrHubIdempotency", err)
	}
	if err := hub.ClaimBatch(ctx, hubActor(tenantB), "batch-1", second); err != nil {
		t.Fatalf("another tenant's same key: %v", err)
	}
	if err := hub.ClaimBatch(ctx, hubActor(reader), "batch-r", first); !errors.Is(err, ErrHubPermission) {
		t.Fatalf("read-only member = %v, want ErrHubPermission", err)
	}
	if err := hub.ClaimBatch(ctx, hubActor(tenantA), "batch-"+strings.Repeat("k", 115), first); !errors.Is(err, ErrHubInvalid) {
		t.Fatalf("121-byte key = %v, want ErrHubInvalid", err)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_dns_record_batch_requests`).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("batch rows = %d, %v; want 2", rows, err)
	}
}
