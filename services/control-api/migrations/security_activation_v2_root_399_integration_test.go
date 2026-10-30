//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// TestSecurityActivationV2Root399 rolls the migration up, down and up: the
// 333 node artifact trigger accepts the v2 dynamic routing root only while it
// is applied (the v1 root throughout). The acceptance of a real v9 candidate
// is TestSiteRuntimeV2ActivationOnDynamicRoutingNodes (securityactivation).
func TestSecurityActivationV2Root399(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_security_activation_v2_root.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("v2 root migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var definition string
		if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef(
			'validate_security_policy_activation_node_artifact_333()'::regprocedure)`).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		v1 := strings.Contains(definition, "application/vnd.cdnca.edge-site-root+json;version=1")
		v2 := strings.Contains(definition, "application/vnd.cdnca.edge-site-root+json;version=2")
		if !v1 || v2 != (step == "up") {
			t.Fatalf("after %s: trigger accepts v1 root %v, v2 root %v", step, v1, v2)
		}
	}
}
