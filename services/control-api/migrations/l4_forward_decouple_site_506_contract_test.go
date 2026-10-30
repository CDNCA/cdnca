package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 506: a stream belongs to no
// website. 506 follows stream-cname 505 (the merge renumbered it); the guard
// pins 505 — renumber/repin at merge (shift-migrations.py + cascade-all.sh).
const (
	migration506Version         = 506
	migration506PreviousVersion = 505
	migration506ID              = "506_l4_forward_decouple_site"
	migration506PreviousID      = migration505ID
	migration506PreviousUpSHA   = migration505UpSHA
	migration506PreviousDownSHA = migration505DownSHA
	migration506UpSHA           = "aea7c594de3d95bb4021ab384c97186cd8410a6c2398e4bb4547fd58207b8c7f"
	migration506DownSHA         = "20e9febbfb1fb7b08d69bdf5303c88ca624843843da9b6a78d9cafa702aeee0b"
)

func TestL4ForwardDecoupleSite506Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
		forbidden []string
	}{
		{migration506ID + ".up.sql", migration506UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration506PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration506PreviousVersion),
			"migration_id='" + migration506PreviousID + "'", migration506PreviousUpSHA, migration506PreviousDownSHA,
			"ERRCODE='P5060'", "ERRCODE='P5061'",
			// stream-cname's stream intents hang on the stream + scope, not the site.
			"cname_stream_intents_stream_506_fk FOREIGN KEY (stream_id,tenant_scope_id)",
			"CREATE OR REPLACE FUNCTION validate_cname_stream_intent_505()",
			// Every check naming site_id is dropped explicitly and re-added without it.
			"DROP CONSTRAINT l4_forwards_endpoint_151", "DROP CONSTRAINT l4_forwards_runtime_facts_151",
			"DROP CONSTRAINT l4_forwards_tls_passthrough_293", "DROP CONSTRAINT l4_forwards_new_connection_rate_300",
			"DROP CONSTRAINT l4_forwards_toa_316", "DROP CONSTRAINT l4_forwards_session_log_328",
			"DROP CONSTRAINT l4_forwards_port_range_334", "DROP CONSTRAINT l4_forwards_guard_rules_341",
			"DROP CONSTRAINT l4_forwards_origins_496", "DROP CONSTRAINT l4_forwards_acl_496",
			"DROP CONSTRAINT l4_forwards_line_cname_499",
			"DROP CONSTRAINT l4_forwards_site_scope_151", "DROP CONSTRAINT l4_forwards_id_scope_site_151",
			"DROP CONSTRAINT l4_publish_intents_stream_scope_site_151", "DROP CONSTRAINT l4_publish_intents_site_schema_151",
			"DROP CONSTRAINT l4_publish_intents_runtime_spec_496",
			"l4_forwards_line_cname_506", "l4_forwards_acl_506", "l4_forwards_origins_506",
			"CREATE OR REPLACE FUNCTION protect_l4_listener_334()", "CREATE OR REPLACE FUNCTION check_l4_listener_facts_334()",
			"CREATE OR REPLACE FUNCTION check_l4_passthrough_facts_293()",
			"CREATE FUNCTION validate_l4_runtime_spec_506(", "runtime_spec ? 'site_id'",
			"CHECK(validate_l4_runtime_spec_506(stream_id,scope_id,runtime_spec)) NOT VALID",
			"INSERT INTO l4_publish_intents (",
		}, []string{"forward_row.site_id", "forward.site_id", "intent.stream_id=NEW.stream_id AND intent.site_id=NEW.site_id"}},
		{migration506ID + ".down.sql", migration506DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration506Version),
			"migration_id='" + migration506ID + "'", "ERRCODE='P5062'", "ERRCODE='P5063'",
			"DROP FUNCTION validate_l4_runtime_spec_506(uuid,uuid,jsonb)", "ADD COLUMN site_id uuid",
			"l4_forwards_line_cname_499", "l4_publish_intents_runtime_spec_496",
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
