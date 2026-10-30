//go:build integration

package migrations_test

import (
	"strconv"
	"strings"
	"testing"
)

// TestRulePackProtectionMigration rolls 363 up, down and up on a 362 schema:
// an install_wrapped entry must carry its wrapped key, a sealed pack artifact
// must come from the catalog, node key wraps go with the node key and the
// sealed artifact, and rollback is refused once an encrypted pack exists.
func TestRulePackProtectionMigration(t *testing.T) {
	const version = 363
	pool := migrationPoolAt(t, 362)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var present bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass(current_schema()||'.node_rule_pack_keys') IS NOT NULL`).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if present != (step == "up") {
			t.Fatalf("after %s: node_rule_pack_keys present=%v", step, present)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_app','node_rule_pack_keys','INSERT') AND
		has_table_privilege('cdnca_control_runtime','node_rule_pack_keys','SELECT') AND
		NOT has_table_privilege('cdnca_control_runtime','node_rule_pack_keys','INSERT')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("grants = %v, %v", granted, err)
	}
	digest := func(char string) string { return strings.Repeat(char, 64) }
	wrapped := strings.Repeat("A", 107)
	entry := func(encryption, key string) string {
		return `INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,resident,encryption,
			wrapped_key,status,delivery_id,first_seen_at,updated_at) VALUES('rule_pack/dev:acme:x-` + encryption + `','rule_pack',
			'1.0.0',1,'` + digest("a") + `',1,'application/vnd.cdnca.rule-pack+json;version=1',false,'` + encryption + `','` + key +
			`','active',gen_random_uuid(),now(),now())`
	}
	for name, statement := range map[string]string{
		"wrapped entry without key": entry("install_wrapped", ""),
		"plain entry with key":      entry("none", wrapped),
	} {
		if _, err := pool.Exec(ctx, statement); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := pool.Exec(ctx, entry("install_wrapped", wrapped)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO rule_packs(pack_id,layer,current_version,update_policy,created_at,updated_at)
		VALUES('dev/acme/sealed','developer',NULL,'manual',now(),now())`); err != nil {
		t.Fatalf("catalog pack without a creating user: %v", err)
	}
	artifact := func(source, sealedKey, sha string, size int) string {
		return `INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,size_bytes,content,source,
			state,downloaded_at,created_at,sealed,wrapped_key) VALUES('dev/acme/sealed','1.0.` + sha[:1] + `','waf_v2',1,'sealed','` + sha +
			`',` + strconv.Itoa(size) + `,decode(repeat('7b',` + strconv.Itoa(size) + `),'hex'),'` + source + `','downloaded',now(),now(),` +
			map[bool]string{true: "true", false: "false"}[sealedKey != ""] + `,'` + sealedKey + `')`
	}
	for name, statement := range map[string]string{
		"sealed import":               artifact("import", wrapped, digest("b"), 10),
		"catalog pack with a creator": strings.Replace(artifact("catalog", "", digest("c"), 10), "created_at,sealed", "created_by_user_id,created_at,sealed", 1),
	} {
		if _, err := pool.Exec(ctx, statement); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// An unencrypted catalog pack (CRS profile, encryption none) is plain.
	if _, err := pool.Exec(ctx, artifact("catalog", "", digest("e"), 10)); err != nil {
		t.Fatalf("plain catalog artifact: %v", err)
	}
	// A sealed pack over the 1 MiB plaintext limit (base64 + manifest) fits.
	if _, err := pool.Exec(ctx, artifact("catalog", wrapped, digest("d"), 1<<20+4096)); err != nil {
		t.Fatalf("sealed catalog artifact: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil || !strings.Contains(err.Error(), "rollback of 363 is unsafe") {
		t.Fatalf("rollback with sealed packs: %v", err)
	}
}
