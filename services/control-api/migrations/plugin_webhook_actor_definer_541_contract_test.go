package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 541 (fix-finalgaps2): restores 084's SECURITY DEFINER and
// search_path on validate_plugin_webhook_actor_target_084, which 532 up's
// CREATE OR REPLACE dropped. Its predecessor is 540 (access_log_fields),
// pinned by checksum; checksums in the guard.
const (
	migration541ID      = "541_plugin_webhook_actor_definer"
	migration541UpSHA   = "cd2de7278778f876b787ce96cae349df7cf8fe37ec391e7e33658bbda1f153c1"
	migration541DownSHA = "511539fd73c838689d1d660146b387c4ee591ff5fc29451c26140043aa5b6253"
)

func TestPluginWebhookActorDefiner541Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration541ID + ".up.sql", migration541UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 540", "(SELECT max(version) FROM schema_migrations) <> 540",
			"migration_id='540_access_log_fields'", migration540UpSHA, migration540DownSHA, "ERRCODE='P5410'",
			"validate_plugin_webhook_actor_target_084() SET search_path = %I, pg_catalog",
			"validate_plugin_webhook_actor_target_084() SECURITY DEFINER",
		}},
		{migration541ID + ".down.sql", migration541DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 541", "migration_id='" + migration541ID + "'", "ERRCODE='P5411'",
			"validate_plugin_webhook_actor_target_084() SECURITY INVOKER",
			"validate_plugin_webhook_actor_target_084() RESET search_path",
			// The 531 rollback note: 532 down leaves 047 at its pre-531 body.
			"validate_acme_issuance_operation_snapshot_047", "acme_runtime_actor_is_active_048",
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
