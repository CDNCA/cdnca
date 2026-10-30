package migrations

import (
	"strings"
	"testing"
)

// Migration 548: discounts gain the package_addon
// category (automatic, purchase-only) and user group targets. The 547
// predecessor is pinned by checksum (547 is reserved; the
// merge re-pins the guard).
const (
	promotionAddonUserGroups548Prev        = "547_node_ip_location_resolution"
	promotionAddonUserGroups548PrevUp      = "965d0aeec3e1d2f3c700ee775f2503dd711e1be03df397e6a1898d91a2ed8eed"
	promotionAddonUserGroups548PrevDown    = "63a505680163337f7c7e8ddd210170911eaeebea8091e79e71eb7f402af80925"
	promotionAddonUserGroups548PrevVersion = "547"
	promotionAddonUserGroups548MigrationID = "548_promotion_addon_user_groups"
)

func TestPromotionAddonUserGroups548Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{promotionAddonUserGroups548MigrationID + ".up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> " + promotionAddonUserGroups548PrevVersion,
			"(SELECT max(version) FROM schema_migrations) <> " + promotionAddonUserGroups548PrevVersion,
			"migration_id='" + promotionAddonUserGroups548Prev + "'",
			"checksum_sha256='" + promotionAddonUserGroups548PrevUp + "'",
			"down_checksum_sha256='" + promotionAddonUserGroups548PrevDown + "'",
			"ERRCODE='P5480'", "ERRCODE='P5481'",
			"CHECK (product_kind IN ('package_subscription', 'traffic_package', 'package_addon'))",
			"CHECK (product_kind <> 'package_addon' OR (use_purchase AND NOT use_renewal AND NOT renewal_same_price))",
			"CREATE TABLE promotion_policy_user_group_targets",
			"FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation()",
			"SELECT 1 FROM package_addon_products WHERE id = NEW.product_id AND deleted_at IS NULL",
		}},
		{promotionAddonUserGroups548MigrationID + ".down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 548",
			"migration_id='" + promotionAddonUserGroups548MigrationID + "'",
			"ERRCODE='P5482'", "ERRCODE='P5483'", "DROP TABLE promotion_policy_user_group_targets",
			"CHECK (product_kind IN ('package_subscription', 'traffic_package'))",
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
}
