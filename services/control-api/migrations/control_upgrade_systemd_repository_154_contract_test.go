package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	nodeRevocation153UpSHA256   = "625a59e7f6be7ebe73877550e87ac230f7fb118aeb8e69243553fe16574d1fbf"
	nodeRevocation153DownSHA256 = "837e31ebeb2aa9cb3cf11e3bf58666f50b01fa7eefa29e5cfd8e80a05ec2c87b"
)

func TestOPS06ControlUpgradeSystemdRepository154Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("154_control_upgrade_systemd_repository.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("154_control_upgrade_systemd_repository.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 154 requires the exact verified 153 release head",
		"version=153 AND migration_id='153_node_revocation_checkpoint'",
		nodeRevocation153UpSHA256, nodeRevocation153DownSHA256,
		"CREATE TABLE control_upgrade_systemd_repository_154",
		"PRIMARY KEY(installation_id,operation)",
		"CHECK(snapshot_sha256=sha256(snapshot_bytes))",
		"CHECK(bundle_sha256=sha256(bundle_bytes))",
		"guard_control_upgrade_systemd_repository_154",
		"NEW.revision<>OLD.revision+1",
		"NEW.installation_id IS DISTINCT FROM OLD.installation_id",
		"NEW.operation IS DISTINCT FROM OLD.operation",
		"NEW.publication_revision<OLD.publication_revision",
		"control upgrade publication revision cannot change without a new bundle",
		"control upgrade systemd repository cannot be deleted or truncated",
		"BEFORE INSERT OR UPDATE OR DELETE",
		"BEFORE TRUNCATE",
		"REVOKE ALL ON control_upgrade_systemd_repository_154 FROM PUBLIC",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("154 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 154 requires the exact verified 153 release head"), strings.Index(up, "CREATE TABLE control_upgrade_systemd_repository_154"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("154 predecessor guard must precede the first mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 154 rollback requires the exact verified 154 head",
		"version=154 AND migration_id='154_control_upgrade_systemd_repository'",
		upSHA,
		"migration 154 rollback would discard durable control upgrade state",
		"EXISTS(SELECT 1 FROM control_upgrade_systemd_repository_154)",
		"DROP TABLE control_upgrade_systemd_repository_154",
		"version=153 AND migration_id='153_node_revocation_checkpoint'",
		nodeRevocation153UpSHA256, nodeRevocation153DownSHA256,
	} {
		if !strings.Contains(down, required) {
			t.Errorf("154 down missing %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 154 rollback requires the exact verified 154 head"), strings.Index(down, "DROP TRIGGER"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("154 rollback guard must precede the first mutation")
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "DROP SCHEMA", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("154 migration contains forbidden marker %q", forbidden)
		}
	}
}
