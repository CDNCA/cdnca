//go:build integration

package migrations_test

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestPluginWebhookActorDefiner541: 532 up left
// validate_plugin_webhook_actor_target_084 as SECURITY INVOKER without a
// pinned search_path (73's state); 541 restores 084's settings, and its
// up/down/up is exact. Rolling 541 -> 532 -> 531 back leaves 047 at its
// pre-531 body and 084 without its settings (532 down's defects, which 541
// cannot reach); applying 541 down's note restores 531's schema.
func TestPluginWebhookActorDefiner541(t *testing.T) {
	const version = 541
	pool := migrationSnapshotPool(t, version-1)
	ctx := t.Context()
	settings := func() (bool, []string) {
		t.Helper()
		var definer bool
		var config []string
		if err := pool.QueryRow(ctx, `SELECT prosecdef,COALESCE(proconfig,'{}') FROM pg_proc
			WHERE oid='validate_plugin_webhook_actor_target_084()'::regprocedure`).Scan(&definer, &config); err != nil {
			t.Fatal(err)
		}
		return definer, config
	}
	var schema string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if definer, config := settings(); definer || len(config) != 0 {
		t.Fatalf("540 head: definer=%v config=%v, want 532's invoker without search_path", definer, config)
	}
	before := migrationSchemaFingerprint(t, pool)
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	wantConfig := []string{"search_path=" + schema + ", pg_catalog"}
	if definer, config := settings(); !definer || !slices.Equal(config, wantConfig) {
		t.Fatalf("541 head: definer=%v config=%v, want definer %v", definer, config, wantConfig)
	}
	applied := migrationSchemaFingerprint(t, pool)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	assertMigrationSchemaEqual(t, "down 541 vs 540", before, migrationSchemaFingerprint(t, pool))
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again %d: %v", version, err)
	}
	assertMigrationSchemaEqual(t, "up again 541 vs first up", applied, migrationSchemaFingerprint(t, pool))

	// Back to 531 through 541 down (540, 535-539 downs run in between).
	for target := int64(version); target > 531; target-- {
		if err := migrateVersionIsolated(ctx, pool, "down", target); err != nil {
			t.Fatalf("down %d: %v", target, err)
		}
	}
	fresh531 := migrationSnapshotPool(t, 531)
	want := migrationSchemaFingerprint(t, fresh531)
	const acme047 = "function validate_acme_issuance_operation_snapshot_047() "
	got := migrationSchemaFingerprint(t, pool)
	if bodyOf(got, acme047) == bodyOf(want, acme047) {
		t.Fatal("532 down now restores 531's 047 body: update 541's rollback note")
	}
	if strings.Contains(bodyOf(got, acme047), "acme_runtime_actor_is_active_048") {
		t.Fatal("rolled back 047 already calls acme_runtime_actor_is_active_048")
	}
	// 532 down re-creates 084 without 084's settings as well.
	if definer, config := settings(); definer || len(config) != 0 {
		t.Fatalf("rolled back 084: definer=%v config=%v, want 532 down's invoker", definer, config)
	}
	// 541 down's note: re-create 047 from 531 up and re-apply 541 up's
	// settings to 084.
	if _, err := pool.Exec(ctx, function047From531Up(t)); err != nil {
		t.Fatalf("re-create 047 from 531 up: %v", err)
	}
	if _, err := pool.Exec(ctx, `ALTER FUNCTION validate_plugin_webhook_actor_target_084() SET search_path = `+
		schema+`, pg_catalog`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `ALTER FUNCTION validate_plugin_webhook_actor_target_084() SECURITY DEFINER`); err != nil {
		t.Fatal(err)
	}
	assertMigrationSchemaEqual(t, "541 -> 531 rollback with the note applied vs fresh 531",
		want, migrationSchemaFingerprint(t, pool))
}

func bodyOf(items []string, prefix string) string {
	for _, item := range items {
		if strings.HasPrefix(item, prefix) {
			return item
		}
	}
	return ""
}

// function047From531Up is the CREATE OR REPLACE of
// validate_acme_issuance_operation_snapshot_047 in 531's up script.
func function047From531Up(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("531_acme_platform_actor.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?s)CREATE OR REPLACE FUNCTION validate_acme_issuance_operation_snapshot_047\(\).*?\n\$\$;`).Find(raw)
	if match == nil {
		t.Fatal("531 up has no validate_acme_issuance_operation_snapshot_047")
	}
	return string(match)
}
