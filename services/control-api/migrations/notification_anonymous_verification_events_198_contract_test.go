package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestNotificationAnonymousVerificationEvents198Contract(t *testing.T) {
	t.Parallel()

	up, err := controlmigrations.FS.ReadFile("198_notification_anonymous_verification_events.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("198_notification_anonymous_verification_events.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	combined := string(up) + string(down)
	for _, required := range []string{
		"version=197 AND migration_id='197_account_login_challenge'",
		"b3df6e3759ecdee5d726ebe94f7a15f287abc3790c5f84b5137130bbd744bd22",
		"16576a892e38097fdbf078cac3b718161b1753b18e7eb2ab49d106c7a27b9e1d",
		"DROP CONSTRAINT notification_events_recipient_one_of_049",
		"identity.account_recovery",
		"identity.account_registration_verification",
		"identity.account_login_verification",
		"migration 198 rollback requires the exact unused verified release head",
	} {
		if !strings.Contains(combined, required) {
			t.Errorf("198 migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"CASCADE", "DELETE FROM schema_migrations"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("198 migration contains forbidden %q", forbidden)
		}
	}
}
