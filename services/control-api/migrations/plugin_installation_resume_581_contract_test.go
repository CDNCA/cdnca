package migrations

import (
	"strings"
	"testing"
)

// Migration 581 (fix-plugresume, placeholder number): symmetric resume of a plugin the tenant paused (report B).
// The 574 predecessor is pinned by checksum and is re-pinned to the actual head when merged with 600.
func TestPluginInstallationResume581Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"581_plugin_installation_resume.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 580", "migration_id='580_analytics_log_export_owner'",
			"checksum_sha256='c784eea1457d4d3638fea1f67d7ae5e28a7ff270a0e1daa6cfadc4f510ef22f3'",
			"down_checksum_sha256='b76f75bbaf1f76773efc831d94e75deee31fc379d080fd6bcf99e51c9bb3087e'",
			"ERRCODE='P5810'", "CHECK (action IN ('confirm','upgrade','disable','resume','uninstall'))",
			"'disabled','resumed','uninstalled'", "(action = 'resume') = (result = 'resumed')",
			"(OLD.status = 'disabled' AND NEW.status NOT IN ('disabled','enabled','uninstalled'))",
			"NEW.identity_generation <> OLD.identity_generation + 1", "ERRCODE = 'P5811'",
			"DROP TRIGGER plugin_installation_heads_transition_145", "CREATE TRIGGER plugin_installation_heads_transition_581",
		}},
		{"581_plugin_installation_resume.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 581", "migration_id='581_plugin_installation_resume'",
			"ERRCODE='P5812'", "action='resume'", "ERRCODE='P5813'",
			"EXECUTE FUNCTION validate_plugin_installation_head_145()",
			"CHECK (action IN ('confirm','upgrade','disable','uninstall'))",
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
	up, _ := FS.ReadFile("581_plugin_installation_resume.up.sql")
	if guard, mutation := strings.Index(string(up), "ERRCODE='P5810'"), strings.Index(string(up), "ALTER TABLE"); guard < 0 || guard > mutation {
		t.Fatal("581 predecessor guard must run before the first mutation")
	}
}
