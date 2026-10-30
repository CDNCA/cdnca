package migrations

import (
	"strings"
	"testing"
)

// Migration 549: paid add-on purchases. The 548
// predecessor is pinned by checksum.
const (
	packageAddonPurchase549Prev        = "548_promotion_addon_user_groups"
	packageAddonPurchase549PrevUp      = "948706da9f42113170916a92b1388e8b76212a7a8184fa26f89005e83093219f"
	packageAddonPurchase549PrevDown    = "585d3a2e7fa4e713eda4ac40d11c6f9f8f5ebda07cc002e689bd36f64a3c82e3"
	packageAddonPurchase549MigrationID = "549_package_addon_purchase"
)

func TestPackageAddonPurchase549Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{packageAddonPurchase549MigrationID + ".up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 548", "(SELECT max(version) FROM schema_migrations) <> 548",
			"migration_id='" + packageAddonPurchase549Prev + "'",
			"checksum_sha256='" + packageAddonPurchase549PrevUp + "'",
			"down_checksum_sha256='" + packageAddonPurchase549PrevDown + "'",
			"ERRCODE='P5490'", "ERRCODE='P5493'", "ERRCODE='P5494'", "ERRCODE='P5496'",
			"CREATE TABLE package_addon_orders",
			"ADD COLUMN addon_order_id uuid REFERENCES package_addon_orders(id)",
			"'package_addon_purchase'",
			"OR (operation='package_addon_purchase' AND addon_order_id IS NOT NULL AND commercial_order_id IS NULL",
			"'migrate_import_credit', 'reseller_sale', 'reseller_wholesale',\n                         'package_addon_purchase') THEN",
			"action='package.addon.assignment.purchase'",
		}},
		{packageAddonPurchase549MigrationID + ".down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 549", "migration_id='" + packageAddonPurchase549MigrationID + "'",
			"ERRCODE='P5497'", "ERRCODE='P5498'", "DROP TABLE package_addon_orders", "DROP COLUMN addon_order_id",
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
	down, _ := FS.ReadFile(packageAddonPurchase549MigrationID + ".down.sql")
	if strings.Contains(string(down), "package_addon_purchase'") && strings.Contains(string(down), "'reseller_wholesale',\n        'package_addon_purchase'") {
		t.Error("549 down must restore the 483 operation set without package_addon_purchase")
	}
}
