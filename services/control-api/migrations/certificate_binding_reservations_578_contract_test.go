package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 578 (fix-dnscert4, split out of the already-released 570 by
// fix-mig570split): user changes win over an in-flight renewal delivery.
// Renewal deliveries reserve binding revisions, the binding fact guard skips
// them, and a user change marks the delivery superseded_by_user. The 577
// predecessor is pinned by checksum.
const (
	migration578Version         = 578
	migration578PreviousVersion = 577
	migration578PreviousID      = "577_market_node_delivery_state"
	migration578PreviousUpSHA   = "5b9876a08e2db27cc541ca2cbefc8df9bf8dfa52d41e2e3a6a0922104c301875"
	migration578PreviousDownSHA = "f464ba85a833ade3b0eb4e2e1c926a9eda39da504d88a2565bc0f2acedd48e83"
	migration578ID              = "578_certificate_binding_reservations"
)

func TestCertificateBindingReservations578Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration578ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration578PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration578PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration578PreviousVersion),
			"migration_id='" + migration578PreviousID + "'",
			"checksum_sha256='" + migration578PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration578PreviousDownSHA + "'",
			"ERRCODE='P5780'", "''superseded_by_user''",
			"CREATE INDEX certificate_renewal_deliveries_due_578_idx",
			"CREATE TABLE certificate_site_binding_reservations",
			"ERRCODE='P5781'", "CREATE OR REPLACE FUNCTION protect_certificate_site_binding()",
			"NEW.sequence = GREATEST(latest_sequence, COALESCE(reserved, 0)) + 1",
			"NEW.sequence = reserved AND reserved > latest_sequence AND NEW.request_id = reserved_by",
			"NEW.expected_revision <> NEW.sequence - 1",
		}},
		{migration578ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration578Version),
			"migration_id='" + migration578ID + "'",
			"ERRCODE='P5782'", "ERRCODE='P5783'", "ERRCODE='P5784'",
			"DROP TABLE certificate_site_binding_reservations",
			"DROP FUNCTION protect_certificate_site_binding_reservation_578()",
			"CREATE INDEX certificate_renewal_deliveries_due_570_idx",
			"NEW.sequence <> expected_sequence OR NEW.expected_revision <> expected_sequence - 1",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	for suffix, want := range map[string]string{".up.sql": migration578PreviousUpSHA, ".down.sql": migration578PreviousDownSHA} {
		raw, err := FS.ReadFile(migration578PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration578PreviousID, suffix, got, want)
		}
	}
}
