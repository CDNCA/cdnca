package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestHTTPPolicyEdgeSourceRevision167Contract(t *testing.T) {
	predecessorUp := mustReadHTTPPolicyEdgeRevisionMigration(t, "166_identity_managed_password_reset.up.sql")
	predecessorDown := mustReadHTTPPolicyEdgeRevisionMigration(t, "166_identity_managed_password_reset.down.sql")
	upBytes := mustReadHTTPPolicyEdgeRevisionMigration(t, "167_http_policy_edge_source_revision.up.sql")
	downBytes := mustReadHTTPPolicyEdgeRevisionMigration(t, "167_http_policy_edge_source_revision.down.sql")
	up, down := string(upBytes), string(downBytes)

	for _, required := range []string{
		"migration 167 requires the exact verified 166 release head",
		"version=166 AND migration_id='166_identity_managed_password_reset'",
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)),
		fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"LOCK TABLE schema_migrations,http_policy_revisions,http_policy_publication_heads,edge_configuration_scopes IN ACCESS EXCLUSIVE MODE",
		"CREATE FUNCTION advance_http_policy_edge_source_revision_167()",
		"PERFORM advance_edge_configuration_scope_revision(NEW.tenant_scope_id)",
		"CREATE TRIGGER zz_http_policy_edge_source_revision_167",
		"AFTER INSERT ON http_policy_revisions",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("167 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 167 requires the exact verified 166 release head"),
		strings.Index(up, "CREATE FUNCTION advance_http_policy_edge_source_revision_167"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("167 predecessor guard must precede the first schema mutation")
	}
	if project, bump := "http_policy_revisions_project_056", "zz_http_policy_edge_source_revision_167"; project >= bump {
		t.Fatalf("trigger names do not preserve projection-before-bump order: %q >= %q", project, bump)
	}
	for _, forbidden := range []string{"CASCADE", "DROP SCHEMA", "__UP_SHA256__", "CREATE TABLE"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("167 migration contains forbidden marker %q", forbidden)
		}
	}
	for _, required := range []string{
		"migration 167 rollback requires the exact verified 167 head",
		"version=167 AND migration_id='167_http_policy_edge_source_revision'",
		fmt.Sprintf("%x", sha256.Sum256(upBytes)),
		"migration 167 rollback would detach HTTP policy revisions from published edge source revisions",
		"FROM edge_config_publications publication",
		"JOIN http_policy_revisions revision",
		"DROP TRIGGER zz_http_policy_edge_source_revision_167 ON http_policy_revisions",
		"DROP FUNCTION advance_http_policy_edge_source_revision_167()",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("167 down missing %q", required)
		}
	}
	if refusal, drop := strings.Index(down, "migration 167 rollback would detach HTTP policy revisions from published edge source revisions"),
		strings.Index(down, "DROP TRIGGER"); refusal < 0 || drop < 0 || refusal > drop {
		t.Fatal("167 rollback refusal must precede trigger removal")
	}
}

func mustReadHTTPPolicyEdgeRevisionMigration(t *testing.T, name string) []byte {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}
