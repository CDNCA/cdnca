package migrations

import (
	"strings"
	"testing"
)

// Migration 619: site_publication_outcome_618 decides
// failed / serving_nodes_undelivered, not pending, when the nodes now serving
// the site have no deployment of the latest publication and no scope
// republication is in flight, so 重新发布 (refused while pending) works again.
func TestSitePublicationUndelivered619Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"619_site_publication_undelivered.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 618", "(SELECT max(version) FROM schema_migrations) <> 618",
			"migration_id='618_site_publication_outcome'", "to_regprocedure('site_publication_outcome_618(uuid,uuid)') IS NULL",
			"ERRCODE='P6190'", "CREATE OR REPLACE FUNCTION site_publication_outcome_618(scope_id uuid, site_id uuid",
			// 618's rules stay
			"JOIN serving ON serving.node_id=latest.node_id",
			"covering.source_revision>=request.source_revision",
			"WHEN summary.total > 0 AND summary.healthy=summary.total THEN 'succeeded'",
			// 619: serving nodes the latest publication never reached, nothing publishing
			"serving_active AS (", "request_row.target_scope_id=$1\n              AND latest.state IN ('pending','leased','retry_wait','reconciling')",
			"WHEN summary.total = 0 AND serving_active.total > 0 AND NOT scope_request.in_flight THEN 'undelivered'",
			"WHEN 'undelivered' THEN 'serving_nodes_undelivered'",
		}, []string{"UPDATE ", "DELETE FROM", "DROP TABLE", "DROP FUNCTION"}},
		{"619_site_publication_undelivered.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 619", "migration_id='619_site_publication_undelivered'",
			"ERRCODE='P6191'", "CREATE OR REPLACE FUNCTION site_publication_outcome_618(scope_id uuid, site_id uuid",
		}, []string{"serving_nodes_undelivered", "DROP FUNCTION"}},
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
		for _, fragment := range script.forbidden {
			if strings.Contains(string(body), fragment) {
				t.Errorf("%s must not contain %q", script.name, fragment)
			}
		}
	}
}
