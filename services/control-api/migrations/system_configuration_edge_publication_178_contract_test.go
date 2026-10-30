package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestOPS02SystemConfigurationEdgePublication178Contract(t *testing.T) {
	predecessorUp, err := controlmigrations.FS.ReadFile("177_site_ingress_source_origin.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	predecessorDown, err := controlmigrations.FS.ReadFile("177_site_ingress_source_origin.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upBytes, err := controlmigrations.FS.ReadFile("178_system_configuration_edge_publication.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("178_system_configuration_edge_publication.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 178 requires the exact verified 177 release head",
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)), fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"CREATE TABLE system_configuration_edge_publications",
		"system_snapshot_sha256 bytea NOT NULL", "tenant_source_revision bigint NOT NULL",
		"publication_id uuid NOT NULL", "config_version_id uuid NOT NULL", "rollout_id uuid NOT NULL",
		"reason_code text NOT NULL", "append-only", "cannot be truncated",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("178 up missing %q", required)
		}
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 178 rollback requires the exact verified 178 head", upSHA,
		"rollback would discard system configuration edge publication facts",
		"DROP TABLE system_configuration_edge_publications",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("178 down missing %q", required)
		}
	}
}
