package migrations

import (
	"strings"
	"testing"
)

// Migration 580 (fix-logowner LOG-01): access-log export ownership and
// idempotency move from the login session to account + query scope. The
// predecessor 574 is pinned by checksum (re-pinned by the merge task).
func TestAnalyticsLogExportOwner580Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"580_analytics_log_export_owner.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 579", "(SELECT max(version) FROM schema_migrations) <> 579",
			"migration_id='579_background_job_producer_cancellation'",
			"checksum_sha256='12bd4565101e5f39836d9ead33891c378c08ad080b385a8bdbad5fe456cea40e'",
			"down_checksum_sha256='4ce4db2e03c79289a21f326a7a99d5a4943de123caec831f8d38f6752ae0fd07'",
			"ERRCODE='P5800'", "ERRCODE='P5801'",
			"UNIQUE (actor_scope_id, actor_user_id, credential_kind, credential_id, idempotency_key)",
			"UNIQUE (actor_scope_id,actor_user_id,idempotency_key)",
			"UNIQUE (actor_scope_id,actor_user_id,scope_id,request_digest,scope_generation)",
			"scope_generation integer NOT NULL DEFAULT 1 CHECK (scope_generation > 0)",
			"analytics_log.export.retry",
		}},
		{"580_analytics_log_export_owner.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 580", "migration_id='580_analytics_log_export_owner'",
			"ERRCODE='P5802'", "scope_generation > 1", "ERRCODE='P5803'",
			"ADD UNIQUE (actor_scope_id,actor_user_id,credential_kind,credential_id,idempotency_key)",
		}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
	}
}
