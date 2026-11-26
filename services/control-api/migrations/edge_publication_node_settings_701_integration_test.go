//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestEdgePublicationNodeSettings701UpDownUp rolls
// the publication kind columns, their check and the insert trigger up, down
// and up again on the 700 head; the site sync functions read the kind only
// while 701 is applied. (The trigger's base and content checks run in the
// edgepublish node settings redelivery integration tests.)
func TestEdgePublicationNodeSettings701UpDownUp(t *testing.T) {
	const version = 701
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	state := func() (columns int, trigger bool, outcomeReadsKind, batchReadsKind bool) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema()
			  AND table_name='edge_config_publications'
			  AND column_name IN ('publication_kind','node_settings_base_config_version_id','content_refusal')),
			EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='edge_config_publications_node_settings_701'
			  AND tgrelid=(current_schema() || '.edge_config_publications')::regclass),
			position('publication_kind' IN pg_get_functiondef((current_schema() || '.site_publication_outcome_618(uuid,uuid)')::regprocedure))>0,
			position('publication_kind' IN pg_get_functiondef((current_schema() || '.site_sync_status_batch_663(uuid[])')::regprocedure))>0`).
			Scan(&columns, &trigger, &outcomeReadsKind, &batchReadsKind); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, step := range []struct {
		direction string
		present   bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		columns, trigger, outcome, batch := state()
		want := 0
		if step.present {
			want = 3
		}
		if columns != want || trigger != step.present || outcome != step.present || batch != step.present {
			t.Fatalf("after %s: columns=%d trigger=%v outcome reads kind=%v batch reads kind=%v",
				step.direction, columns, trigger, outcome, batch)
		}
	}
	var definition, kindDefault string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(constraint_row.oid),
		(SELECT column_default FROM information_schema.columns WHERE table_schema=current_schema()
		  AND table_name='edge_config_publications' AND column_name='publication_kind')
		FROM pg_constraint constraint_row WHERE constraint_row.conname='edge_config_publications_node_settings_701_check'
		  AND constraint_row.conrelid=(current_schema() || '.edge_config_publications')::regclass`).Scan(&definition, &kindDefault); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"node_settings", "content_refusal", "package_resource_quota_exceeded", "sdk_shield_port_shared"} {
		if !strings.Contains(definition, fragment) {
			t.Fatalf("701 check %s lacks %q", definition, fragment)
		}
	}
	if !strings.Contains(kindDefault, "'content'") {
		t.Fatalf("publication_kind default = %s, want content", kindDefault)
	}
}
