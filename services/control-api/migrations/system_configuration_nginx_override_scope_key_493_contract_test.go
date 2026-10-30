package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 493: system_configuration_v2_nginx_is_valid
// built its scope key as item->>'scope' || E'\x1f' || item->>'scope_id', which
// parses as (... || item) ->> 'scope_id' (text ->> text) and always failed, so
// no revision with nginx overrides could be stored. Local placeholder 490,
// renumbered to 493 at merge (predecessor 492).
const (
	migration493Version         = 493
	migration493PreviousVersion = 492
	migration493ID              = "493_system_configuration_nginx_override_scope_key"
	migration493PreviousID      = "492_tenant_site_defaults_auto_dns"
	migration493PreviousUpSHA   = "53389281060ad1dd6b5616b3f8b2b137ff568674459b57fedcde97b4995cf3c5"
	migration493PreviousDownSHA = "4378935fb9b80acc14a6390888f4545adb07bc467f175b8f33d07b8a581171d6"
	migration493UpSHA           = "fa961053ca5cc3d43427db05819f3c367d4df16578dc72a937c0c43b0ddba1a5"
	migration493DownSHA         = "73b0a06256b2c413c8bea9a3e8eca6cf6162110f2882fa9a6a5fb224d97c7572"
)

func TestSystemConfigurationNginxOverrideScopeKey493Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration493ID + ".up.sql", migration493UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration493PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration493PreviousVersion),
			"migration_id='" + migration493PreviousID + "'", migration493PreviousUpSHA, migration493PreviousDownSHA,
			"ERRCODE='P4930'", "CREATE OR REPLACE FUNCTION system_configuration_v2_nginx_is_valid(candidate jsonb)",
			"scope_key := (item->>'scope') || E'\\x1f' || (item->>'scope_id');",
		}},
		{migration493ID + ".down.sql", migration493DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration493Version),
			"migration_id='" + migration493ID + "'", "ERRCODE='P4931'",
			"scope_key := item->>'scope' || E'\\x1f' || item->>'scope_id';",
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
	// Apart from the parentheses the function is 219's.
	original, err := FS.ReadFile("219_system_configuration_canonical_v2.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, _ := FS.ReadFile(migration493ID + ".up.sql")
	start := strings.Index(string(original), "CREATE FUNCTION system_configuration_v2_nginx_is_valid")
	end := start + strings.Index(string(original)[start:], "$$;\n") + 4
	want := strings.Replace(strings.Replace(string(original)[start:end], "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1),
		"scope_key := item->>'scope' || E'\\x1f' || item->>'scope_id';",
		"scope_key := (item->>'scope') || E'\\x1f' || (item->>'scope_id');", 1)
	if !strings.HasSuffix(string(up), want) {
		t.Fatal("493 changes more than the scope key of 219's function")
	}
}
