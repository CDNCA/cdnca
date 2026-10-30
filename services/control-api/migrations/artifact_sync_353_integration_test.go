//go:build integration

package migrations_test

import "testing"

// TestArtifactSyncMigration rolls 353 up, down and up on a 352 schema: the
// old catalog / IP library consumer tables exist only while it is not
// applied; downloaded revisions only move forward and objects are immutable.
func TestArtifactSyncMigration(t *testing.T) {
	const version = 353
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var newTables, oldTables bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass(current_schema()||'.local_artifacts') IS NOT NULL,
			to_regclass(current_schema()||'.ip_intel_library') IS NOT NULL OR
			to_regclass(current_schema()||'.security_rule_catalog_consumer_state') IS NOT NULL`).Scan(&newTables, &oldTables); err != nil {
			t.Fatal(err)
		}
		if want := step == "up"; newTables != want || oldTables == want {
			t.Fatalf("after %s: new=%v old=%v", step, newTables, oldTables)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_runtime','local_artifacts','UPDATE') AND
		has_table_privilege('cdnca_control_runtime','artifact_objects','INSERT') AND
		NOT has_table_privilege('cdnca_control_runtime','artifact_objects','UPDATE') AND
		NOT has_table_privilege('cdnca_control_app','local_artifacts','DELETE')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("grants = %v, %v", granted, err)
	}
	digest := func(char string) string {
		value := ""
		for range 64 {
			value += char
		}
		return value
	}
	for _, statement := range []string{
		`INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,resident,encryption,
			status,delivery_id,first_seen_at,updated_at) VALUES('ruleset/cc_rule:6','ruleset','2',2,'` + digest("b") + `',1,
			'application/vnd.cdnca.ruleset-item+json;version=1',true,'none','active',gen_random_uuid(),now(),now())`,
		`INSERT INTO artifact_objects(sha256,size,content,stored_at) VALUES('` + digest("a") + `',1,'\x01',now()),
			('` + digest("b") + `',1,'\x02',now())`,
		`INSERT INTO local_artifacts(artifact_id,current_revision,current_sha256,current_version,downloaded_at,updated_at)
			VALUES('ruleset/cc_rule:6',2,'` + digest("b") + `','2',now(),now())`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	for name, statement := range map[string]string{
		"older revision":  `UPDATE local_artifacts SET current_revision=1,current_sha256='` + digest("a") + `'`,
		"same revision":   `UPDATE local_artifacts SET current_sha256='` + digest("a") + `'`,
		"clear":           `UPDATE local_artifacts SET current_revision=NULL,current_sha256=NULL,current_version=NULL,downloaded_at=NULL`,
		"delete":          `DELETE FROM local_artifacts`,
		"mutate object":   `UPDATE artifact_objects SET stored_at=now()`,
		"wrong size":      `INSERT INTO artifact_objects(sha256,size,content,stored_at) VALUES('` + digest("c") + `',2,'\x01',now())`,
		"bad kind prefix": `INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,resident,encryption,status,delivery_id,first_seen_at,updated_at) VALUES('ruleset/x','ipintel','1',1,'` + digest("a") + `',1,'x',true,'none','active',gen_random_uuid(),now(),now())`,
	} {
		if _, err := pool.Exec(ctx, statement); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE local_artifacts SET current_revision=3,current_sha256='`+digest("a")+`',current_version='3'`); err != nil {
		t.Fatalf("forward move refused: %v", err)
	}
}
