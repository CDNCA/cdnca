//go:build integration

package edgeautopublish_test

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/google/uuid"
)

// defer-small 第 11 项（待出包前全量跑）: every fulfilled order (renewals
// included) writes package_order.fulfilled to package_commerce_outbox in the
// fulfillment transaction; the expiry watcher sees each such event once and
// then sweeps at once instead of waiting for its interval. Other outbox
// events do not wake it; the first read only primes the cursor.
func TestPackageExpiryWatcherSeesFulfillmentEvents(t *testing.T) {
	pool := openAutomaticDatabase(t)
	watcher, err := edgeautopublish.NewPackageExpiryWatcher(pool, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(eventType string) {
		t.Helper()
		id, _ := uuid.NewV7()
		if _, err := pool.Exec(t.Context(), `INSERT INTO package_commerce_outbox
			(id,aggregate_type,aggregate_id,event_type,payload,request_id,trace_id,created_at)
			VALUES($1,'package_order',$2,$3,'{}'::jsonb,$4,'',clock_timestamp())`,
			id, uuid.New(), eventType, "defer-small-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	seen := func(want bool, step string) {
		t.Helper()
		if got, err := edgeautopublish.PackageExpiryWatcherNewFulfillment(t.Context(), watcher); err != nil || got != want {
			t.Fatalf("%s: new fulfillment = %v, %v; want %v", step, got, err, want)
		}
	}
	insert("package_order.fulfilled") // committed before the watcher starts
	seen(false, "prime")
	seen(false, "idle")
	insert("package_order.awaiting_payment")
	seen(false, "other event")
	insert("package_order.fulfilled")
	seen(true, "renewal fulfilled")
	seen(false, "same event again")
	// RunOnce right after its first sweep, within the hour: the event lets it sweep
	if _, err := watcher.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	insert("package_order.fulfilled")
	if _, err := watcher.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	seen(false, "consumed by RunOnce")
}
