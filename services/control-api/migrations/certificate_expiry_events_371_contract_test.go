package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 371 (PA-24: certificate expiry domain event) is a placeholder
// number: the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is here.
const (
	migration371ID      = "371_certificate_expiry_events"
	migration371UpSHA   = "60dbd16e73b00fd63bead192aecc901118eaf5ab1d507e607da512bae46e0db5"
	migration371DownSHA = "059e2a6a2c3c5498edd5ddb314728ccd3f99a336b731a64d3ec1dd26e353a98e"
)

func TestCertificateExpiryEvents371Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration371ID + ".up.sql", migration371UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 370", "migration_id='" + migration370ID + "'",
			migration370UpSHA, migration370DownSHA, "ERRCODE='P3710'",
			"'io.cdnca.certificate.v1.expiry_reached', 'certificate_asset', 'events.certificate.read', false",
			// One fact per version and stage; the event is appended by the fact insert.
			"PRIMARY KEY (tenant_scope_id, version_id, stage)", "CREATE TRIGGER certificate_expiry_facts_emit_event_371",
			"AFTER INSERT ON certificate_expiry_facts_371", "ERRCODE='P3711'",
			// Notification center events seeded unsupported by 200 become produced.
			"WHERE event_type IN ('certificate.expiring', 'certificate.expired')",
			"('certificate.expiring.zh-cn', 1, 'email'", "('certificate.expired.zh-cn', 1, 'email'",
		}},
		{migration371ID + ".down.sql", migration371DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 371", "migration_id='" + migration371ID + "'",
			"ERRCODE='P3719'", "would discard domain event history", "would discard certificate notification history",
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
		if strings.Contains(string(raw), "CASCADE") {
			t.Errorf("%s uses CASCADE", script.name)
		}
	}
}
