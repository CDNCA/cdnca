//go:build integration

package migrations_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidatorSearchPath273NativeRestore(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 272)
	schema, key, point := validatorSearchPath273Seed(t, pool)
	before := validatorSearchPath273Snapshot(t, pool, false)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 273); err != nil {
		t.Fatal(err)
	}
	if got := validatorSearchPath273Snapshot(t, pool, false); got != before {
		t.Fatal("migration changed validator attributes/ACLs, CHECKs, or stored facts")
	}
	for _, test := range []struct {
		name, query string
		value       any
		want        bool
	}{
		{"site group name", `site_group_name_is_valid_082($1)`, "nonempty group", true},
		{"public key decode", `plugin_webhook_ed25519_decode_084($1) IS NOT NULL`, key, true},
		{"public key prime order", `plugin_webhook_ed25519_prime_order_point_084($1::numeric[])`, point, true},
		{"invalid group name stays rejected", `site_group_name_is_valid_082($1)`, " invalid ", false},
		{"short public key stays rejected", `plugin_webhook_ed25519_decode_084($1) IS NOT NULL`, []byte{1}, false},
		{"low order point stays rejected", `plugin_webhook_ed25519_prime_order_point_084($1::numeric[])`, "{0,1,1,0}", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			if _, err := tx.Exec(t.Context(), `SET LOCAL search_path = ''`); err != nil {
				t.Fatal(err)
			}
			var valid bool
			if err := tx.QueryRow(t.Context(), "SELECT "+pgx.Identifier{schema}.Sanitize()+"."+test.query, test.value).Scan(&valid); err != nil || valid != test.want {
				t.Fatalf("CHECK under the native restore search_path: valid=%v err=%v", valid, err)
			}
			var path string
			if err := tx.QueryRow(t.Context(), `SHOW search_path`).Scan(&path); err != nil || path != `""` {
				t.Fatalf("caller search_path changed: %q %v", path, err)
			}
		})
	}
	t.Run("native custom archive with nonempty data", func(t *testing.T) {
		for _, tool := range []string{"pg_dump", "pg_restore"} {
			if version := validatorSearchPath273Command(t, pool, tool, "--version"); !strings.Contains(version, "PostgreSQL) 17.") {
				t.Fatalf("%s must be PostgreSQL 17", tool)
			}
		}
		archive := filepath.Join(t.TempDir(), "full-schema.dump")
		validatorSearchPath273Command(t, pool, "pg_dump", "--format=custom", "--schema="+schema, "--file="+archive)
		restored := validatorSearchPath273RestoreDB(t, pool)
		validatorSearchPath273Command(t, restored, "pg_restore", "--exit-on-error", "--single-transaction",
			"--dbname="+restored.Config().ConnConfig.Database, archive)
		assertSiteGroup082Head(t, restored, 273)
		if got, want := validatorSearchPath273Snapshot(t, restored, true), validatorSearchPath273Snapshot(t, pool, true); got != want {
			t.Fatal("native restore changed function metadata/ACLs, CHECKs, group/receipt/Ed25519 facts, or the display-ID sequence")
		}
		var valid bool
		if err := restored.QueryRow(t.Context(), `SELECT bool_and(site_group_name_is_valid_082(name)) FROM site_groups`).Scan(&valid); err != nil || !valid {
			t.Fatalf("restored group CHECK: %v %v", valid, err)
		}
		if err := restored.QueryRow(t.Context(), `SELECT bool_and(plugin_webhook_ed25519_prime_order_point_084(
			plugin_webhook_ed25519_decode_084(public_key))) FROM entitlement_signing_keyset_current_keys`).Scan(&valid); err != nil || !valid {
			t.Fatalf("restored entitlement public key CHECK: %v %v", valid, err)
		}
		for _, direction := range []string{"down", "up"} {
			if err := migrateVersionIsolated(t.Context(), restored, direction, 273); err != nil {
				t.Fatalf("%s after native restore: %v", direction, err)
			}
		}
		if validatorSearchPath273Snapshot(t, restored, true) != validatorSearchPath273Snapshot(t, pool, true) {
			t.Fatal("restored database rollback/reapply changed validated facts")
		}
	})
}

func TestValidatorSearchPath273GuardsAndRollback(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 272)
	schema, key, point := validatorSearchPath273Seed(t, pool)
	before := validatorSearchPath273Snapshot(t, pool, true)
	up, err := controlmigrations.FS.ReadFile("273_validator_search_path.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, sql, code string }{
		{"ledger drift", `UPDATE schema_migrations SET checksum_sha256=repeat('0',64) WHERE version=272`, "P2730"},
		{"entry body drift", `CREATE OR REPLACE FUNCTION site_group_name_is_valid_082(value text) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS 'SELECT true'`, "P2731"},
		{"transitive helper drift", `CREATE OR REPLACE FUNCTION plugin_webhook_mod_084(value numeric,modulus numeric) RETURNS numeric LANGUAGE sql IMMUTABLE STRICT AS 'SELECT 0::numeric'`, "P2731"},
		{"function local settings drift", `ALTER FUNCTION site_group_name_is_valid_082(text) SET statement_timeout='1s'`, "P2731"},
		{"security definer drift", `ALTER FUNCTION plugin_webhook_ed25519_decode_084(bytea) SECURITY DEFINER`, "P2731"},
		{"volatility drift", `ALTER FUNCTION site_group_trim_name_082(text) STABLE`, "P2731"},
		{"owner drift", `ALTER FUNCTION site_group_name_is_valid_082(text) OWNER TO cdnca_control_app`, "P2731"},
		{"helper overload", `CREATE FUNCTION plugin_webhook_mod_084(numeric,numeric,numeric DEFAULT 0) RETURNS numeric LANGUAGE sql AS 'SELECT 0::numeric'`, "P2731"},
		{"runtime writable schema", `GRANT CREATE ON SCHEMA ` + pgx.Identifier{schema}.Sanitize() + ` TO cdnca_control_app`, "P2731"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			if _, err := tx.Exec(t.Context(), test.sql); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(t.Context(), string(up))
			assertSiteGroup082Code(t, err, test.code)
		})
	}
	if got := validatorSearchPath273Snapshot(t, pool, true); got != before {
		t.Fatal("rejected migration changed the original facts")
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 273); err != nil {
		t.Fatal(err)
	}
	t.Run("only the three local paths change", func(t *testing.T) {
		var fixed int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_proc WHERE pronamespace=current_schema()::regnamespace
			AND proname IN ('site_group_name_is_valid_082','plugin_webhook_ed25519_decode_084','plugin_webhook_ed25519_prime_order_point_084')
			AND proconfig=ARRAY[format('search_path=pg_catalog, %I, pg_temp',current_schema())]`).Scan(&fixed); err != nil || fixed != 3 {
			t.Fatalf("fixed paths=%d %v", fixed, err)
		}
	})
	t.Run("caller-controlled helper and builtin shadows are ignored", func(t *testing.T) {
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		shadow := pgx.Identifier{"validator_shadow_273_" + strings.ReplaceAll(uuid.NewString(), "-", "")}.Sanitize()
		if _, err := tx.Exec(t.Context(), `CREATE SCHEMA `+shadow+`;
			CREATE FUNCTION `+shadow+`.site_group_trim_name_082(text) RETURNS text LANGUAGE sql AS 'SELECT $1';
			CREATE FUNCTION `+shadow+`.char_length(text) RETURNS integer LANGUAGE sql AS 'SELECT 0';
			CREATE FUNCTION `+shadow+`.plugin_webhook_le_numeric_084(bytea) RETURNS numeric LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'shadow invoked'; END$$;
			CREATE FUNCTION `+shadow+`.plugin_webhook_mod_084(numeric,numeric) RETURNS numeric LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'shadow invoked'; END$$;
			CREATE TEMP TABLE site_groups(name text);
			SET LOCAL search_path=`+shadow+`,pg_temp,pg_catalog`); err != nil {
			t.Fatal(err)
		}
		prefix := pgx.Identifier{schema}.Sanitize() + "."
		var valid, invalid, decoded, prime bool
		if err := tx.QueryRow(t.Context(), `SELECT `+prefix+`site_group_name_is_valid_082('valid'),`+
			prefix+`site_group_name_is_valid_082(' invalid '),`+prefix+`plugin_webhook_ed25519_decode_084($1) IS NOT NULL,`+
			prefix+`plugin_webhook_ed25519_prime_order_point_084($2::numeric[])`, key, point).Scan(&valid, &invalid, &decoded, &prime); err != nil || !valid || invalid || !decoded || !prime {
			t.Fatalf("shadow protection: %v/%v/%v/%v %v", valid, invalid, decoded, prime, err)
		}
	})
	for _, role := range []string{"cdnca_control_app", "cdnca_plugin_webhook_runtime"} {
		t.Run(role+" cannot alter validators", func(t *testing.T) {
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			if _, err := tx.Exec(t.Context(), `SET LOCAL ROLE `+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(t.Context(), `ALTER FUNCTION `+pgx.Identifier{schema, "site_group_name_is_valid_082"}.Sanitize()+`(text) RESET search_path`)
			assertSiteGroup082Code(t, err, "42501")
		})
	}
	for _, signature := range []string{"plugin_webhook_ed25519_decode_084(bytea)", "plugin_webhook_ed25519_prime_order_point_084(numeric[])"} {
		assertPluginWebhookPublicExecute084(t, pool, signature, false)
	}
	t.Run("rollback refuses changed local configuration", func(t *testing.T) {
		down, err := controlmigrations.FS.ReadFile("273_validator_search_path.down.sql")
		if err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `ALTER FUNCTION site_group_name_is_valid_082(text) SET search_path=pg_catalog`); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), string(down))
		assertSiteGroup082Code(t, err, "P2731")
	})
	if err := migrateVersionIsolated(t.Context(), pool, "down", 273); err != nil {
		t.Fatal(err)
	}
	assertSiteGroup082Head(t, pool, 272)
	if got := validatorSearchPath273Snapshot(t, pool, true); got != before {
		t.Fatal("rollback did not exactly preserve original attributes, privileges, constraints, and nonempty data")
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 273); err != nil {
		t.Fatal(err)
	}
}

func validatorSearchPath273Seed(t *testing.T, pool *pgxpool.Pool) (string, []byte, string) {
	t.Helper()
	f := seedSiteGroup082Identity(t, pool, "restore273")
	group := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO site_groups(id,scope_id,name,remark)
		VALUES($1,$2,'nonempty group',E'preserved\nremark')`, group, f.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO site_group_write_requests(id,actor_user_id,actor_scope_id,target_scope_id,
		operation,idempotency_key,request_digest,resource_id,response_status,response_body,completed_at)
		VALUES($1,$2,$3,$3,'site_group.create','restore273',$4,$5,201,'{"name":"nonempty group"}',now())`,
		uuid.New(), f.userID, f.scopeID, make([]byte, 32), group); err != nil {
		t.Fatal(err)
	}
	attestation := seedPluginWebhookRuntimeAttestation084(t, pool)
	seedPluginWebhookEntitlement084(t, pool, true, 10, nil)
	var schema, point string
	if err := pool.QueryRow(t.Context(), `SELECT current_schema(),plugin_webhook_ed25519_decode_084(public_key)::text
		FROM plugin_webhook_runtime_attestation_keys`).Scan(&schema, &point); err != nil {
		t.Fatal(err)
	}
	return schema, []byte(attestation.privateKey[32:]), point
}

func validatorSearchPath273Snapshot(t *testing.T, pool *pgxpool.Pool, includeConfig bool) string {
	t.Helper()
	// PostgreSQL's pretty deparser removes only redundant AND grouping introduced by
	// BETWEEN expansion/reparsing. Do not strip parentheses or rewrite dumped SQL.
	var snapshot string
	if err := pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
		'functions',(SELECT jsonb_agg((to_jsonb(p)-'oid'-'pronamespace')-
			CASE WHEN $1 THEN ARRAY[]::text[] ELSE ARRAY['proconfig'] END ORDER BY p.proname)
			FROM pg_proc p WHERE p.pronamespace=current_schema()::regnamespace AND p.proname IN
			('site_group_trim_name_082','site_group_name_is_valid_082','plugin_webhook_mod_084','plugin_webhook_le_numeric_084',
			'plugin_webhook_mod_pow_084','plugin_webhook_ed25519_decode_084','plugin_webhook_ed25519_add_084',
			'plugin_webhook_ed25519_double_084','plugin_webhook_ed25519_scalarmult_084','plugin_webhook_ed25519_prime_order_point_084')),
		'checks',(SELECT jsonb_agg(jsonb_build_array(c.conname,pg_get_constraintdef(c.oid,true),c.convalidated) ORDER BY c.conname)
			FROM pg_constraint c WHERE c.connamespace=current_schema()::regnamespace AND c.contype='c'),
		'groups',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM site_groups r),
		'ids',(SELECT jsonb_agg(to_jsonb(r) ORDER BY display_id) FROM site_group_display_ids r),
		'sequence',(SELECT jsonb_build_object('last_value',last_value,'is_called',is_called) FROM site_group_display_ids_display_id_seq),
		'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM site_group_write_requests r),
		'attestation_keys',(SELECT jsonb_agg(to_jsonb(r) ORDER BY key_generation) FROM plugin_webhook_runtime_attestation_keys r),
		'attestation_head',(SELECT jsonb_agg(to_jsonb(r)) FROM plugin_webhook_runtime_attestation_head r),
		'entitlement_keys',(SELECT jsonb_agg(to_jsonb(r) ORDER BY key_id) FROM entitlement_signing_keyset_current_keys r),
		'leases',(SELECT jsonb_agg(to_jsonb(r) ORDER BY serial) FROM entitlement_cached_leases r),
		'revocations',(SELECT jsonb_agg(to_jsonb(r)) FROM control_entitlement_revocation_lkg r)
	)::text`, includeConfig).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func validatorSearchPath273RestoreDB(t *testing.T, source *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	config := source.Config().Copy()
	if host := config.ConnConfig.Host; !filepath.IsAbs(host) && host != "127.0.0.1" && host != "::1" {
		t.Fatal("native restore test requires an explicitly isolated local PostgreSQL 17")
	}
	var serverVersion int
	if err := source.QueryRow(t.Context(), `SELECT current_setting('server_version_num')::int`).Scan(&serverVersion); err != nil || serverVersion/10000 != 17 {
		t.Fatalf("PostgreSQL 17 required: version=%d %v", serverVersion, err)
	}
	name := "validator_restore_273_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err := source.Exec(t.Context(), "CREATE DATABASE "+identifier+" TEMPLATE template0 ENCODING 'UTF8'"); err != nil {
		t.Fatal(err)
	}
	var restored *pgxpool.Pool
	t.Cleanup(func() {
		if restored != nil {
			restored.Close()
		}
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := source.Exec(ctx, "DROP DATABASE "+identifier); err != nil {
			t.Errorf("drop owned restore database: %v", err)
		}
	})
	config.ConnConfig.Database = name
	var err error
	restored, err = pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	return restored
}

func validatorSearchPath273Command(t *testing.T, pool *pgxpool.Pool, tool string, args ...string) string {
	t.Helper()
	config := pool.Config().ConnConfig
	if (!filepath.IsAbs(config.Host) && config.Host != "127.0.0.1" && config.Host != "::1") || (tool != "pg_dump" && tool != "pg_restore") {
		t.Fatal("native restore command is restricted to this local fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...)
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "PG") {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	cmd.Env = append(cmd.Env, "PGHOST="+config.Host, "PGPORT="+strconv.Itoa(int(config.Port)),
		"PGDATABASE="+config.Database, "PGUSER="+config.User, "PGPASSWORD="+config.Password,
		"PGSSLMODE=disable", "PGCONNECT_TIMEOUT=5")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", tool, err, output)
	}
	return string(output)
}
