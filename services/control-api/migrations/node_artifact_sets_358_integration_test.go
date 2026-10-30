//go:build integration

package migrations_test

import "testing"

// TestNodeArtifactSetsMigration rolls 358 up, down and up: the artifact set
// tables and trigger exist only while it is applied, and a down restores
// 329's ip-intel trigger and tables.
func TestNodeArtifactSetsMigration(t *testing.T) {
	const version = 358
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var sets, applied, trigger358, trigger329, distributions bool
		if err := pool.QueryRow(t.Context(), `SELECT
			to_regclass(current_schema() || '.node_artifact_sets') IS NOT NULL,
			to_regclass(current_schema() || '.node_artifact_applied_items') IS NOT NULL,
			EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='configuration_artifacts_node_artifact_358'),
			EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='configuration_artifacts_node_artifact_329'),
			to_regclass(current_schema() || '.ip_intel_node_distributions') IS NOT NULL`).Scan(
			&sets, &applied, &trigger358, &trigger329, &distributions); err != nil {
			t.Fatal(err)
		}
		up := step == "up"
		if sets != up || applied != up || trigger358 != up || trigger329 == up || distributions == up {
			t.Fatalf("after %s: sets=%v applied=%v trigger358=%v trigger329=%v distributions=%v",
				step, sets, applied, trigger358, trigger329, distributions)
		}
	}
}

// The 358 trigger keeps node artifact media types in the platform scope,
// alone and plaintext; a tenant scope configuration cannot carry one.
func TestNodeArtifactSetsTriggerScopesMediaTypes(t *testing.T) {
	const version = 358
	pool := migrationPoolAt(t, version)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) SELECT gen_random_uuid(),'platform'
		WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `WITH tenant AS (INSERT INTO tenants(id,display_name) VALUES(gen_random_uuid(),'pa01 358')
		RETURNING id) INSERT INTO access_scopes(id,kind,tenant_id) SELECT gen_random_uuid(),'tenant',id FROM tenant`); err != nil {
		t.Fatal(err)
	}
	insertConfig := func(kind string) string {
		t.Helper()
		var scopeID, configID string
		if err := pool.QueryRow(ctx, `SELECT id::text FROM access_scopes WHERE kind=$1 ORDER BY created_at DESC LIMIT 1`,
			kind).Scan(&scopeID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,
			canonical_snapshot_sha256,generator_name,generator_version,status,idempotency_key,request_digest,created_at)
			VALUES(gen_random_uuid(),$1,'{}'::bytea,sha256('{}'::bytea),'test','1','building',gen_random_uuid()::text,
			sha256('x'::bytea),now()) RETURNING id::text`, scopeID).Scan(&configID); err != nil {
			t.Fatal(err)
		}
		return configID
	}
	insertArtifact := func(configID string, ordinal int, mediaType string) error {
		_, err := pool.Exec(ctx, `INSERT INTO artifact_signing_keys(id,algorithm,public_key,created_at)
			VALUES('pa01-test-key','ed25519',decode(repeat('00',32),'hex'),now()) ON CONFLICT DO NOTHING`)
		if err != nil {
			t.Fatalf("signing key: %v", err)
		}
		_, err = pool.Exec(ctx, `INSERT INTO configuration_artifacts(id,config_version_id,ordinal,kind,wire_bytes,size_bytes,
			sha256,signature,signing_key_id,signature_algorithm,compression,media_type,encryption_algorithm,created_at)
			VALUES(gen_random_uuid(),$1,$2,'configuration','x'::bytea,1,sha256('x'::bytea),decode(repeat('00',64),'hex'),
			'pa01-test-key','ed25519','none',$3,'none',now())`, configID, ordinal, mediaType)
		return err
	}
	const setType = "application/vnd.cdnca.edge.artifact-set+json;version=1"
	platform := insertConfig("platform")
	if err := insertArtifact(platform, 1, setType); err != nil {
		t.Fatalf("platform set artifact: %v", err)
	}
	if err := insertArtifact(platform, 2, "application/vnd.cdnca.edge.artifact-segment;version=1"); err == nil {
		t.Fatal("a second node artifact in the same configuration was accepted")
	}
	tenant := insertConfig("tenant")
	if err := insertArtifact(tenant, 1, setType); err == nil {
		t.Fatal("a tenant scope configuration accepted a node artifact")
	}
}
