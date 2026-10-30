//go:build integration

package edgepublish

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// l4RuntimeSpecConstraint is the current L4 publish intent CHECK; each
// migration that extends the intent shape renames it (293, 300, 316 l4_toa,
// 328 l4_session_log, 334 l4_port_range, 341 l4_guard_rules, 496 l4_origin_pool_acl,
// now 506 l4_forward_decouple_site), so merge renumbering touches only this line.
const l4RuntimeSpecConstraint = "l4_publish_intents_runtime_spec_506"

// CheckL4TOAPublication: a stream with 回源携带客户端 IP = TOA, saved through
// l4forward, reaches the published L4 artifact as toa and requires L4_TOA
// v1; cleared, no L4_TOA. The live stream requires tcp v12 either way (1.0.35
// baseline, l4StreamCapabilityVersion). save(toa) creates or updates the
// stream and returns the configuration source revision.
func CheckL4TOAPublication(t *testing.T, save func(pool *pgxpool.Pool, scopeID, userID, subscriptionID, siteID uuid.UUID, toa bool) int64) {
	t.Helper()
	fixture := newL4DrainLimitFixture(t)
	site := fixture.createSite(t, "l4-toa.example.com", 18081, false).Site
	compile := func(revision int64) (bool, uint32, uint32) {
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
		var tcp, toa uint32
		for _, capability := range capabilities {
			switch capability.Name {
			case agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY:
				tcp = capability.ApiVersion
			case agentv1.CapabilityName_CAPABILITY_NAME_L4_TOA:
				toa = capability.ApiVersion
			}
		}
		return wire.Streams[0].TOA, tcp, toa
	}
	enabled := save(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID, true)
	if toa, tcp, capability := compile(enabled); !toa || tcp != 12 || capability != 1 {
		t.Fatalf("TOA stream: toa=%t tcp v%d L4_TOA v%d", toa, tcp, capability)
	}
	// The intent constraint accepts toa only as true on a TCP stream without PROXY.
	for name, mutation := range map[string]string{
		"toa false":        `jsonb_set(runtime_spec,'{toa}','false')`,
		"toa string":       `jsonb_set(runtime_spec,'{toa}','"true"')`,
		"outbound PROXY":   `jsonb_set(runtime_spec,'{proxy_protocol_outbound}','true')`,
		"UDP listener":     `jsonb_set(runtime_spec,'{listener,protocol}','"udp"')`,
		"UDP extra socket": `jsonb_set(runtime_spec,'{additional_listeners}','[{"id":"44444444-4444-4444-8444-444444444444","protocol":"udp","address":"*","port":18444}]')`,
	} {
		_, err := fixture.pool.Exec(t.Context(), `INSERT INTO l4_publish_intents(id,scope_id,stream_id,version,operation,
			desired_state,resource_revision,configuration_source_revision,runtime_spec,created_by_user_id,created_at)
			SELECT gen_random_uuid(),scope_id,stream_id,version+1000,operation,desired_state,resource_revision,
			       configuration_source_revision,`+mutation+`,created_by_user_id,now()
			FROM l4_publish_intents WHERE scope_id=$1 AND runtime_spec ? 'toa' ORDER BY version DESC LIMIT 1`, fixture.scopeID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.ConstraintName != l4RuntimeSpecConstraint {
			t.Errorf("intent with %s: err=%v", name, err)
		}
	}
	cleared := save(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID, false)
	if toa, tcp, capability := compile(cleared); toa || tcp != 12 || capability != 0 {
		t.Fatalf("cleared stream: toa=%t tcp v%d L4_TOA v%d", toa, tcp, capability)
	}
}
