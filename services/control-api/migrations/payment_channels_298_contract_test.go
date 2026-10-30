package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 298 (M9 收款通道, renumbered from 293 on merge) sits on the exact
// verified 297 head (CNAME 目标 scope 默认值).
func TestPaymentChannels298Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"298_payment_channels.up.sql", "cb59bdfe8ad4b3e4f24c83f7ae98d3f443e2f77475c5518695a61e64c0fab155", []string{
			"(SELECT count(*) FROM schema_migrations) <> 297", "(SELECT max(version) FROM schema_migrations) <> 297",
			"297_cname_target_scope_default",
			"8c947a2ba91cb8a6245788916c8ced7145e4410ec4321b6df3241df074f05a1d", "ERRCODE='P2980'",
			"'billing.payment_channels.manage'", "CREATE TABLE payment_channels",
			"CHECK (NOT enabled OR provider NOT IN ('epay', 'codepay') OR risk_acknowledged_at IS NOT NULL)",
			"CREATE UNIQUE INDEX payment_channels_primary_298_idx ON payment_channels (method) WHERE enabled AND role = 'primary'",
			"CREATE TABLE payment_channel_reconcile_schedule", "'recharge_payment', 'recharge_refund', 'recharge_void'",
		}},
		{"298_payment_channels.down.sql", "f34e609b85ce1fd697586b4645c8fe17189af972a758b490fac9827bffe68513", []string{
			"(SELECT count(*) FROM schema_migrations) <> 298", "298_payment_channels", "ERRCODE='P2981'",
			"DROP TABLE payment_channels", "IF NEW.operation = 'manual_adjustment' THEN",
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
