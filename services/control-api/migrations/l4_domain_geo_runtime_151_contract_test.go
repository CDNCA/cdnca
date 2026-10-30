package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	l403Node150UpSHA256   = "bfa06ab9348dd9791060bd7624747234507d8dca015934070e0bdf6f04b89a65"
	l403Node150DownSHA256 = "c9702eddf7dbe49c1404da9acdcf4a8e26ce72adf599cb898dde355fd5903d22"
)

func TestL403DomainGeoRuntime151Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("151_l4_domain_geo_runtime.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("151_l4_domain_geo_runtime.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 151 requires the exact verified 150 release head",
		"version = 150 AND migration_id = '150_node_metrics'", l403Node150UpSHA256, l403Node150DownSHA256,
		"ADD COLUMN site_id uuid", "FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id)",
		"ALTER COLUMN upstream_address DROP NOT NULL", "ADD COLUMN upstream_host text",
		"ADD COLUMN remark text", "ADD COLUMN dns_policy jsonb", "ADD COLUMN geo_policy jsonb",
		"ADD COLUMN proxy_protocol_inbound boolean", "l4_forwards_endpoint_151",
		"CREATE FUNCTION validate_l4_runtime_spec_151", "validate_l4_runtime_spec_092(target_stream_id, runtime_spec)",
		"cdnca.edge.l4/v2", "l4_publish_intents_stream_scope_site_151",
		"CHECK (validate_l4_runtime_spec_151(stream_id, scope_id, site_id, runtime_spec))",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("151 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 151 requires the exact verified 150 release head"), strings.Index(up, "ALTER TABLE l4_forwards"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("151 predecessor guard must run before the first mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 151 rollback requires the exact verified 151 head",
		"version = 151 AND migration_id = '151_l4_domain_geo_runtime'", upSHA,
		"migration 151 rollback would discard L4 domain, geo, or site scope facts",
		"DROP FUNCTION validate_l4_runtime_spec_151", "ALTER COLUMN upstream_address SET NOT NULL",
		"version = 150 AND migration_id = '150_node_metrics'", l403Node150UpSHA256, l403Node150DownSHA256,
	} {
		if !strings.Contains(down, required) {
			t.Errorf("151 down missing %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 151 rollback requires the exact verified 151 head"), strings.Index(down, "ALTER TABLE l4_publish_intents"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("151 rollback guard must run before the first mutation")
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("151 migration contains forbidden marker %q", forbidden)
		}
	}
}
