//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestSecurityActivationNodeArtifactsMigration rolls 333 up, down and up, and
// checks the node digest lookup keeps v1 (no node rows) on the candidate digest.
func TestSecurityActivationNodeArtifactsMigration(t *testing.T) {
	const version = 333
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	for _, signature := range []string{
		"validate_security_policy_activation_rollout_088()",
		"security_policy_activation_phase_healthy_088(uuid,text)",
		"validate_security_policy_activation_recovery_rollout_088()",
	} {
		var definition string
		if err := pool.QueryRow(t.Context(), `SELECT pg_get_functiondef($1::regprocedure)`, signature).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		if strings.Count(definition, "security_policy_activation_node_artifact_sha256_333(") != 1 {
			t.Fatalf("%s does not compare node digests through the 333 lookup", signature)
		}
	}
	fallback := sha256.Sum256([]byte("v1 candidate artifact"))
	var got []byte
	if err := pool.QueryRow(t.Context(), `SELECT security_policy_activation_node_artifact_sha256_333($1,$2,$3,$4)`,
		uuid.New(), uuid.New(), uuid.New(), fallback[:]).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(fallback[:]) {
		t.Fatalf("v1 node digest = %x, want the candidate digest", got)
	}

	// A v2 capability wait would be lost by the rollback: refuse it.
	tenantID, scopeID := uuid.New(), uuid.New()
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'333 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO security_activation_capability_waits(id,tenant_scope_id,site_id,policy_id,policy_kind,
		policy_version,expected_binding_revision,expected_active_policy_version,target_node_ids,canary_size,actor_user_id,
		actor_scope_id,actor_scope_kind,capability,required_api_version,blocking_node_ids,created_at,updated_at,site_runtime_schema)
		VALUES($1,$2,$3,$4,'waf',2,1,1,ARRAY[$5::uuid],1,$6,$2,'tenant',13,1,ARRAY[$5::uuid],$7,$7,'cdnca.edge.site-runtime/v2')`,
		uuid.New(), scopeID, uuid.New(), uuid.New(), uuid.New(), uuid.New(), now)
	err := migrateVersionIsolated(t.Context(), pool, "down", version)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P3331" {
		t.Fatalf("down with a v2 wait = %v, want P3331", err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO security_activation_capability_waits(id,tenant_scope_id,site_id,policy_id,
		policy_kind,policy_version,expected_binding_revision,expected_active_policy_version,target_node_ids,canary_size,
		actor_user_id,actor_scope_id,actor_scope_kind,capability,required_api_version,blocking_node_ids,created_at,updated_at,
		site_runtime_schema) VALUES($1,$2,$3,$4,'waf',2,1,1,ARRAY[$5::uuid],1,$6,$2,'tenant',13,1,ARRAY[$5::uuid],$7,$7,'v3')`,
		uuid.New(), scopeID, uuid.New(), uuid.New(), uuid.New(), uuid.New(), now); err == nil {
		t.Fatal("capability wait accepted an unknown site runtime schema")
	}
}
