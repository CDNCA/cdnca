package migrations

import (
	"strings"
	"testing"
)

// Migration 537 (fix-autorenew): certificate auto-renew moves to the asset;
// the 048 order snapshot stays immutable. The 536 predecessor is pinned at merge.
func TestCertificateAssetAutoRenew537Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"537_certificate_asset_auto_renew.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 536", "(SELECT max(version) FROM schema_migrations) <> 536",
			"ERRCODE='P5370'",
			"ALTER TABLE certificate_assets ADD COLUMN auto_renew boolean NOT NULL DEFAULT false;",
			"CHECK (source = 'acme' OR NOT auto_renew)",
			"cert_order.issued_asset_id = asset.id",
			"'certificate.auto_renew.update'",
			"CREATE FUNCTION certificate_asset_auto_renew_537(scope_id uuid, asset_id uuid)",
			"OR NOT certificate_asset_auto_renew_537(source_order.scope_id, source_order.issued_asset_id)",
			"OR NOT renewal_order.auto_renew",
		}},
		{"537_certificate_asset_auto_renew.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 537", "migration_id='537_certificate_asset_auto_renew'",
			"ERRCODE='P5371'", "ERRCODE='P5372'",
			"OR NOT source_order.auto_renew",
			"DROP FUNCTION certificate_asset_auto_renew_537(uuid, uuid);",
			"ALTER TABLE certificate_assets DROP COLUMN auto_renew;",
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
	// 048 订单 auto_renew 仍不可变：537 不得重定义订单保护触发器。
	raw, _ := FS.ReadFile("537_certificate_asset_auto_renew.up.sql")
	if strings.Contains(string(raw), "protect_certificate_order_runtime_048") {
		t.Fatal("537 must keep the 048 order auto_renew snapshot immutable")
	}
}
