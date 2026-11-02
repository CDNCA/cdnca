package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 614: backfill the owner row of subscriptions
// opened by a purchase, which site creation needs.
const (
	migration614ID      = "614_purchased_subscription_owner"
	migration613UpSHA   = "31f4381f7704eaa74bd365dad3f9e6336be01e4657af41b75afbab85be39829e"
	migration613DownSHA = "6d3f5415483f464835fb4dcdc2978999ad85d26d5af5c07f418eaa96e2cc6ca5"
)

func TestPurchasedSubscriptionOwner614Contract(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(read(migration613ID+".up.sql")))); got != migration613UpSHA {
		t.Fatalf("613 up checksum drift: %s", got)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(read(migration613ID+".down.sql")))); got != migration613DownSHA {
		t.Fatalf("613 down checksum drift: %s", got)
	}
	up, down := read(migration614ID+".up.sql"), read(migration614ID+".down.sql")
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 613", "migration_id='" + migration613ID + "'",
		"checksum_sha256='" + migration613UpSHA + "'", "down_checksum_sha256='" + migration613DownSHA + "'",
		"ERRCODE='P6140'", "INSERT INTO package_monitor_subscription_owners",
		"'commerce_fulfillment', fulfillment.id", "package_order.operation = 'purchase'",
		"membership.status = 'active'", "platform_scope.kind = 'platform'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("614 up missing %q", required)
		}
	}
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 614", "migration_id='" + migration614ID + "'", "ERRCODE='P6141'",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("614 down missing %q", required)
		}
	}
	if strings.Contains(down, "DELETE FROM") {
		t.Error("614 down must not delete owner rows (append-only, referenced by sites)")
	}
}
