package migrations

import (
	"strings"
	"testing"
)

// Migration 618: site_publication_outcome_618 decides a
// site's 已发布到节点 and sync_status from the current publication on the
// nodes now serving the site; site_sync_status_503 reads it. The predecessor
// is pinned by checksum.
const (
	sitePublicationOutcome618PreviousID   = "617_node_ssh_install_allow_cidrs"
	sitePublicationOutcome618PreviousUp   = "0b9f2ed8a9607f426be2b68d3b1b0fff53e5b62bf43a5a9e51c84c4fc4bdf697"
	sitePublicationOutcome618PreviousDown = "ce8baf327543f174aac8864dc76a93c2654af7bf66251a712f1f8532b9417bc9"
)

func TestSitePublicationOutcome618Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"618_site_publication_outcome.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 617", "(SELECT max(version) FROM schema_migrations) <> 617",
			"migration_id='" + sitePublicationOutcome618PreviousID + "'",
			"checksum_sha256='" + sitePublicationOutcome618PreviousUp + "'",
			"down_checksum_sha256='" + sitePublicationOutcome618PreviousDown + "'",
			"ERRCODE='P6180'", "CREATE FUNCTION site_publication_outcome_618(scope_id uuid, site_id uuid",
			// only active nodes still serving the site count
			"node.admin_state='active'", "JOIN serving ON serving.node_id=latest.node_id",
			"endpoint.config_revision=line_group.current_revision",
			// a failed request is final only while no publication covers it
			"covering.source_revision>=request.source_revision",
			"config_state.current_config_version_id=latest.config_version_id",
			"CREATE OR REPLACE FUNCTION site_sync_status_503(scope_id uuid, site_id uuid)",
			"FROM site_publication_outcome_618($1, $2) outcome",
		}, []string{"UPDATE ", "DELETE FROM", "DROP TABLE"}},
		{"618_site_publication_outcome.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 618", "migration_id='618_site_publication_outcome'",
			"ERRCODE='P6181'", "CREATE OR REPLACE FUNCTION site_sync_status_503(scope_id uuid, site_id uuid)",
			"DROP FUNCTION site_publication_outcome_618(uuid, uuid)",
		}, nil},
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
