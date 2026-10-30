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

// CheckL4NewConnRatePublication: a stream's 单 IP 新建连接速率, saved through
// l4forward, reaches the published L4 artifact as new_conn_rate; cleared, it
// is gone. Every live stream requires tcp v12 (1.0.35 baseline,
// l4StreamCapabilityVersion) with or without the rate.
// save(rate, burst, ban) creates or updates the stream and returns the
// configuration source revision.
func CheckL4NewConnRatePublication(t *testing.T, save func(pool *pgxpool.Pool, scopeID, userID, subscriptionID, siteID uuid.UUID, rate, burst, ban int) int64) {
	t.Helper()
	fixture := newL4DrainLimitFixture(t)
	site := fixture.createSite(t, "l4-new-conn-rate.example.com", 18081, false).Site
	compile := func(revision int64) (*edgeconfig.L4NewConnRateV2, uint32) {
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
		return wire.Streams[0].NewConnRate, tcp
	}
	limited := save(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID, 20, 5, 60)
	if rate, tcp := compile(limited); tcp != 12 || rate == nil || *rate != (edgeconfig.L4NewConnRateV2{RatePerSecond: 20, Burst: 5, BanSeconds: 60}) {
		t.Fatalf("limited stream: tcp v%d rate=%+v", tcp, rate)
	}
	// The intent constraint (migration 300) accepts only the edge contract's shape.
	for name, mutation := range map[string]string{
		"extra key":     `'{"rate_per_second":20,"burst":5,"ban_seconds":60,"x":1}'`,
		"missing ban":   `'{"rate_per_second":20,"burst":5}'`,
		"zero rate":     `'{"rate_per_second":0,"burst":0,"ban_seconds":0}'`,
		"string burst":  `'{"rate_per_second":20,"burst":"5","ban_seconds":60}'`,
		"fraction rate": `'{"rate_per_second":1.5,"burst":0,"ban_seconds":0}'`,
		"rate too high": `'{"rate_per_second":100001,"burst":0,"ban_seconds":0}'`,
		"ban too long":  `'{"rate_per_second":1,"burst":0,"ban_seconds":86401}'`,
		"not an object": `'[1]'`,
	} {
		_, err := fixture.pool.Exec(t.Context(), `INSERT INTO l4_publish_intents(id,scope_id,stream_id,version,operation,
			desired_state,resource_revision,configuration_source_revision,runtime_spec,created_by_user_id,created_at)
			SELECT gen_random_uuid(),scope_id,stream_id,version+1000,operation,desired_state,resource_revision,
			       configuration_source_revision,jsonb_set(runtime_spec,'{new_conn_rate}',`+mutation+`::jsonb),created_by_user_id,now()
			FROM l4_publish_intents WHERE scope_id=$1 AND runtime_spec ? 'new_conn_rate' ORDER BY version DESC LIMIT 1`, fixture.scopeID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.ConstraintName != l4RuntimeSpecConstraint {
			t.Errorf("intent with %s: err=%v", name, err)
		}
	}
	cleared := save(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID, 0, 0, 0)
	if rate, tcp := compile(cleared); tcp != 12 || rate != nil {
		t.Fatalf("cleared stream: tcp v%d rate=%+v", tcp, rate)
	}
}
