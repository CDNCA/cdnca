//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestL4AdditionalListeners248MigrationRoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 247)
	now := time.Now().UTC()
	scope, user, subscription := seedL4DisplayIdentity214(t, pool, "listener-migration", now)
	id := uuid.New()
	seedL4Forward214(t, pool, id, scope, subscription, user, "Legacy primary", 19400, now)
	seedL4WriteReceipt214(t, pool, id, scope, user, "stream.create", "legacy-listener-receipt", now)
	var before string
	if err := pool.QueryRow(t.Context(), `SELECT response_body::text FROM l4_write_requests WHERE idempotency_key='legacy-listener-receipt'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := migrateVersionIsolated(t.Context(), pool, "up", 248); err != nil {
			t.Fatal(err)
		}
		var reserved bool
		var port int
		if err := pool.QueryRow(t.Context(), `SELECT reserved,port FROM l4_forward_listeners WHERE id=$1 AND stream_id=$1`, id).Scan(&reserved, &port); err != nil || !reserved || port != 19400 {
			t.Fatalf("backfill=(%t,%d,%v)", reserved, port, err)
		}
		if err := migrateVersionIsolated(t.Context(), pool, "down", 248); err != nil {
			t.Fatal(err)
		}
	}
	var after string
	if err := pool.QueryRow(t.Context(), `SELECT response_body::text FROM l4_write_requests WHERE idempotency_key='legacy-listener-receipt'`).Scan(&after); err != nil || after != before {
		t.Fatalf("legacy receipt changed: %v", err)
	}
}
