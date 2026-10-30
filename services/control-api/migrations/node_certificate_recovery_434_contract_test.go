package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 434 (ADR 0013 GW-02: expired node certificate
// self-recovery; ADR placeholder 434), guarded on 433 (market-listing-batches).
// Everything that changes with the renumbering is here.
const (
	migration434Version         = 434
	migration434PreviousVersion = 433
	migration434ID              = "434_node_certificate_recovery"
	migration434PreviousID      = "433_market_listing_batches"
	migration434PreviousUpSHA   = "838793e1383693ab9e443b7d64cacef15dac90213b186ecdbd7de0137a20387f"
	migration434PreviousDownSHA = "c3d43c6a5a7740499102c0b4d510203ae6cf3a37c70780d74b52502f446e1a3a"
	migration434UpSHA           = "9213fec1fc5f7be37590c698594ddf787fbdcf2d870f042025eb897832e58b81"
	migration434DownSHA         = "ae56e51e2cf3bb831ff4f7206423dced4ff93de0027daeacdcc66171df9b5a45"
)

func TestNodeCertificateRecovery434Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration434ID + ".up.sql", migration434UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration434PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration434PreviousVersion),
			"migration_id='" + migration434PreviousID + "'", migration434PreviousUpSHA, migration434PreviousDownSHA,
			"ERRCODE='P4340'", "nonce bytea NOT NULL UNIQUE", "'recovered'", "node_purge_permits(OLD.node_id)",
			"'node.certificate.recovered'", "'node.certificate.recovered.zh-cn'",
		}},
		{migration434ID + ".down.sql", migration434DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration434Version),
			"migration_id='" + migration434ID + "'", "ERRCODE='P4341'", "ERRCODE='P4342'",
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
