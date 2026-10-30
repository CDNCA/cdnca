package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// 通知订阅默认值 + 运营者工单通知. Every number the merge renumbering
// touches is here: the version, the previous head it guards on, and the
// script checksums.
const (
	subscriptionDefaultsVersion         = 323
	subscriptionDefaultsID              = "323_notification_subscription_defaults"
	subscriptionDefaultsPreviousID      = "322_domain_ownership_permanent"
	subscriptionDefaultsPreviousUpSHA   = "0a36f436bacd8c9121c8eb0351f95cd13dbbf2bddcecf229d3f21b5954f23bcd"
	subscriptionDefaultsPreviousDownSHA = "09c30b909370ec31691e6fc968902cf70793390838279dacca58dbe5dddcaca3"
	subscriptionDefaultsUpSHA           = "c4e690903f4c234a6c1c3bf67df3a5e932536e4c8b82ca3978561bc6361ec18a"
	subscriptionDefaultsDownSHA         = "84764d52a8d5963f6084d1dddaa718500452debff122b2b7c9a4df096d3808cb"
)

func TestNotificationSubscriptionDefaults323Contract(t *testing.T) {
	previous := subscriptionDefaultsVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{subscriptionDefaultsID + ".up.sql", subscriptionDefaultsUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + subscriptionDefaultsPreviousID + "'",
			"checksum_sha256='" + subscriptionDefaultsPreviousUpSHA + "'",
			"down_checksum_sha256='" + subscriptionDefaultsPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", subscriptionDefaultsVersion),
			"ADD COLUMN default_email boolean NOT NULL DEFAULT false",
			"ADD COLUMN default_sms boolean NOT NULL DEFAULT false",
			"'package.auto_renew.failed', 'package.monitor.traffic.triggered', 'package.monitor.expiration.triggered',",
			"('ticket.staff.created', true, true, true, 1, 24, true, true, false, now())",
		}},
		{subscriptionDefaultsID + ".down.sql", subscriptionDefaultsDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", subscriptionDefaultsVersion),
			"migration_id='" + subscriptionDefaultsID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", subscriptionDefaultsVersion),
			"ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable",
			"DROP COLUMN default_sms, DROP COLUMN default_email",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
