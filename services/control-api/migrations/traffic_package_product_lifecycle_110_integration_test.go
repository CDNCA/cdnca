package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestTrafficPackageProductLifecycle110StaticContract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("110_traffic_package_product_lifecycle.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("110_traffic_package_product_lifecycle.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 110 requires the exact verified 109 release head",
		"d6b3a67fa2504b048f969317c7605868ebe3ad4edf122286d546edfb023310c2",
		"098fd79ed88641247b2f787b18cd170a5082c42f717b1e907491ceb6ecb61719",
		"CREATE TABLE traffic_package_product_lifecycle_watermarks",
		"CREATE TABLE traffic_package_product_lifecycle_facts",
		"PRIMARY KEY(product_id, revision)",
		"CREATE UNIQUE INDEX traffic_package_product_lifecycle_sequence_110",
		"CHECK ((action='baseline' AND sequence=0 AND enabled)",
		"AFTER INSERT ON traffic_package_product_snapshots",
		"BEFORE INSERT ON traffic_package_grants",
		"CREATE TABLE traffic_package_product_lifecycle_audit_links_110",
		"DEFERRABLE INITIALLY DEFERRED",
		"BEFORE UPDATE OR DELETE ON traffic_package_product_lifecycle_facts",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("migration 110 up is missing %q", required)
		}
	}
	for _, required := range []string{
		"rollback would discard product lifecycle history",
		"WHERE sequence > 0",
		"DROP TABLE traffic_package_product_lifecycle_facts",
		"DROP TABLE traffic_package_product_lifecycle_watermarks",
	} {
		if !strings.Contains(down, required) {
			t.Fatalf("migration 110 down is missing %q", required)
		}
	}
	if strings.Contains(up, "UPDATE traffic_package_product_snapshots") ||
		strings.Contains(up, "ALTER TABLE traffic_package_product_snapshots ADD COLUMN enabled") {
		t.Fatal("migration 110 mutates immutable product snapshots")
	}
}
