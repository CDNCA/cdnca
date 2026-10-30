package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 507: DNS reconcile tasks, provider mutation claims
// and the CNAME facts of a stream's own allocation are anchored at the stream
// (a stream may have no website). 507 follows 506; renumber/repin at merge.
const (
	migration507Version         = 507
	migration507PreviousVersion = 506
	migration507ID              = "507_dns_reconcile_stream_anchor"
	migration507UpSHA           = "20bf64648ec52edeab0e7680347d5d9def5b41fb9e3081cdd132e25527865f6a"
	migration507DownSHA         = "d63e3d754b78657212894423824bf81faf05310a5f95565566a932480b99bd0b"
)

func TestDNSReconcileStreamAnchor507Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
		forbidden []string
	}{
		{migration507ID + ".up.sql", migration507UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration507PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration507PreviousVersion),
			"migration_id='" + migration506ID + "'", migration506UpSHA, migration506DownSHA, "ERRCODE='P5070'",
			// Exactly one anchor on every DNS task / claim / CNAME fact row.
			"dns_reconcile_tasks_anchor_507 CHECK (num_nonnulls(site_id,stream_id)=1)",
			"dns_reconcile_provider_mutation_claims_anchor_507 CHECK (num_nonnulls(site_id,stream_id)=1)",
			"cname_allocation_targets_anchor_507", "cname_allocation_requests_anchor_507",
			"cname_record_retirements_anchor_507", "dns_cname_retargets_anchor_507",
			"dns_reconcile_tasks_stream_507_fk FOREIGN KEY (stream_id,tenant_scope_id)",
			"dns_cname_retargets_stream_507_fk FOREIGN KEY (stream_id,tenant_scope_id)",
			"cname_allocation_requests_stream_507_uidx",
			"CREATE FUNCTION dns_reconcile_anchor_507(", "CREATE FUNCTION dns_reconcile_stream_config_digest_507(",
			"CREATE OR REPLACE FUNCTION bind_dns_reconcile_task_site_089()",
			"CREATE OR REPLACE FUNCTION protect_dns_reconcile_provider_mutation_claim_089()",
			"CREATE OR REPLACE FUNCTION protect_dns_reconcile_provider_recovery_continuation_089()",
			"CREATE OR REPLACE FUNCTION validate_dns_reconcile_cancel_fact_076()",
			"CREATE OR REPLACE FUNCTION dns_reconcile_background_job_cancel_094(",
			"CREATE OR REPLACE FUNCTION dns_reconcile_cancel_final_094(",
			"l4_forwards_provider_mutation_claim_guard_507",
			// The site anchor keeps 089's digests bit for bit (live claims stay valid).
			"dns_reconcile_authority_digest_089(tenant_scope_id,site,checked_zone,checked_provider)",
		}, []string{"JOIN sites site\n          ON site.scope_id=task.tenant_scope_id"}},
		{migration507ID + ".down.sql", migration507DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration507Version),
			"migration_id='" + migration507ID + "'", "ERRCODE='P5071'", "ERRCODE='P5072'",
			"DROP FUNCTION dns_reconcile_anchor_507(uuid,uuid,uuid,dns_zones,dns_providers)",
			"ALTER COLUMN site_id SET NOT NULL",
		}, nil},
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
		for _, forbidden := range script.forbidden {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("%s still contains %q", script.name, forbidden)
			}
		}
	}
}
