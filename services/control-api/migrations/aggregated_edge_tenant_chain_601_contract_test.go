package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 601 (tenant automatic switching, ADR 0020 §5). Everything that
// changes if a merge renumbers it or re-pins 600 is here.
const (
	migration601PreviousVersion = 600
	migration601PreviousID      = "600_aggregated_edge_owner_scope"
	migration601PreviousUpSHA   = "f42271710f0966a3ff0290d90e71fd35d31884f6fceb986e7f8e36f60147950a"
	migration601PreviousDownSHA = "0f7ae94ba04bcfae97accd5f3802db3ee2583173ac091cac9f00ed951dfc7af3"
	migration601ID              = "601_aggregated_edge_tenant_chain"
)

func TestAggregatedEdgeTenantChain601Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration601ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration601PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration601PreviousVersion),
			"migration_id='" + migration601PreviousID + "'",
			"checksum_sha256='" + migration601PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration601PreviousDownSHA + "'",
			"ERRCODE='P6010'",
			"CREATE TABLE fallback_chain_tenant_choices",
			"auto_switch boolean NOT NULL DEFAULT true",
			"use_own_cdn boolean NOT NULL DEFAULT true",
			"VALUES ('aggregated_edge.tenant.switch', true, true, true, 1, 1, true, true, false, now())",
			"('aggregated_edge.tenant.switch.zh-cn', 1, 'sms'",
			"('aggregated_edge.tenant.switch.zh-cn', 1, 'email'",
			"ARRAY['site_domain','alert_text','switch_from','switch_to','link']",
		}},
		{migration601ID + ".down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 601", "migration_id='" + migration601ID + "'",
			"ERRCODE='P6011'", "ERRCODE='P6012'",
			"DROP TABLE fallback_chain_tenant_choices",
			"DELETE FROM notification_event_policies WHERE event_type = 'aggregated_edge.tenant.switch'",
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
	for suffix, want := range map[string]string{".up.sql": migration601PreviousUpSHA, ".down.sql": migration601PreviousDownSHA} {
		raw, err := FS.ReadFile(migration601PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration601PreviousID, suffix, got, want)
		}
	}
}
