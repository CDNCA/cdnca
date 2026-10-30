package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestNotificationDeliveryPolicyTrafficWarning202Contract(t *testing.T) {
	t.Parallel()

	up, err := controlmigrations.FS.ReadFile("202_notification_delivery_policy_traffic_warning.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("202_notification_delivery_policy_traffic_warning.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	combined := string(up) + string(down)
	for _, required := range []string{
		"version=201 AND migration_id='201_notification_delivery_policy_unsupported_defaults'",
		"f40139a07ef14cf3e7ea15d17bdde73b859dd12d055002695cc5ede115fb1769",
		"b0664011116cf73e77a8b49efcffbdb1234ed0fd49f51885b0151ded550de204",
		"package.monitor.traffic.warning",
		"supported, updated_at",
		"migration 202 rollback requires a verified 202 release head",
	} {
		if !strings.Contains(combined, required) {
			t.Errorf("202 migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"CASCADE", "DELETE FROM schema_migrations"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("202 migration contains forbidden %q", forbidden)
		}
	}
}
