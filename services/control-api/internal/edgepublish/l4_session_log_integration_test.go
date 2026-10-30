//go:build integration

package edgepublish

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckL4SessionLogPublication saves a stream with and without a session log
// through save and checks the artifact and the required tcp version (v12 for
// every live stream since the 1.0.35 baseline, l4StreamCapabilityVersion).
func CheckL4SessionLogPublication(t *testing.T, save func(pool *pgxpool.Pool, scopeID, userID, subscriptionID, siteID uuid.UUID, enabled bool) int64) {
	fixture := newL4DrainLimitFixture(t)
	site := fixture.createSite(t, "l4-session-log.example.com", 18082, false).Site
	compile := func(revision int64) (bool, uint32) {
		t.Helper()
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		compiled := fixture.compileSiteRuntimeL4(t, tx, revision)
		bundle, capabilities := compiled.Bundle(), compiled.Capabilities
		var wire struct {
			Streams []edgeconfig.L4StreamRuntimeV2 `json:"streams"`
		}
		if err := json.Unmarshal(bundle.Files[edgeconfig.L4RuntimeV2ArtifactPath], &wire); err != nil || len(wire.Streams) != 1 {
			t.Fatalf("L4 artifact: %+v %v", wire, err)
		}
		tcp := uint32(0)
		for _, capability := range capabilities {
			if capability.Name.String() == "CAPABILITY_NAME_TCP_PROXY" {
				tcp = capability.ApiVersion
			}
		}
		return wire.Streams[0].SessionLog, tcp
	}
	if logged, tcp := compile(save(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID, true)); !logged || tcp != 12 {
		t.Fatalf("logged stream: tcp v%d session_log=%v", tcp, logged)
	}
	for name, mutation := range map[string]string{"false": `'false'`, "string": `'"true"'`, "object": `'{}'`} {
		_, err := fixture.pool.Exec(t.Context(), `INSERT INTO l4_publish_intents(id,scope_id,stream_id,version,operation,
			desired_state,resource_revision,configuration_source_revision,runtime_spec,created_by_user_id,created_at)
			SELECT gen_random_uuid(),scope_id,stream_id,version+1000,operation,desired_state,resource_revision,
			       configuration_source_revision,jsonb_set(runtime_spec,'{session_log}',`+mutation+`::jsonb),created_by_user_id,now()
			FROM l4_publish_intents WHERE scope_id=$1 AND runtime_spec ? 'session_log' ORDER BY version DESC LIMIT 1`, fixture.scopeID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.ConstraintName != l4RuntimeSpecConstraint {
			t.Errorf("intent with session_log %s: err=%v", name, err)
		}
	}
	if logged, tcp := compile(save(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID, false)); logged || tcp != 12 {
		t.Fatalf("unlogged stream: tcp v%d session_log=%v", tcp, logged)
	}
}
