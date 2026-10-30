//go:build integration

package edgepublish

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckL4DrainLimitPublication: the platform L4 drain limit (系统设置 > 其它配置)
// reaches every v2 stream of a publication as drain_max_ms; at its default
// the release is unchanged. Every live stream requires tcp v12 (1.0.35
// baseline, l4StreamCapabilityVersion), whatever the limit.
func CheckL4DrainLimitPublication(t *testing.T, create func(*pgxpool.Pool, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) int64) {
	t.Helper()
	fixture := newL4DrainLimitFixture(t)
	site := fixture.createSite(t, "l4-drain-limit.example.com", 18081, false).Site
	revision := create(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID)
	compile := func(settings string) (compiledSiteRuntimeL4, edgeconfig.Bundle, uint32) {
		t.Helper()
		if settings != "" {
			if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO platform_system_other_settings(platform_scope_id,revision,settings,updated_at)
				SELECT id,1,$1::jsonb,now() FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL
				ON CONFLICT (platform_scope_id) DO UPDATE SET settings=EXCLUDED.settings,revision=platform_system_other_settings.revision+1`,
				settings); err != nil {
				t.Fatal(err)
			}
		}
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		compiled := fixture.compileSiteRuntimeL4(t, tx, revision)
		return compiled, compiled.Bundle(), capabilityVersion(compiled.Capabilities, agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY)
	}
	wireLimit := func(bundle edgeconfig.Bundle) *int {
		t.Helper()
		var wire struct {
			Streams []edgeconfig.L4StreamRuntimeV2 `json:"streams"`
		}
		if err := json.Unmarshal(bundle.Files[edgeconfig.L4RuntimeV2ArtifactPath], &wire); err != nil || len(wire.Streams) != 1 {
			t.Fatalf("L4 artifact: %+v %v", wire, err)
		}
		return wire.Streams[0].DrainMaxMS
	}

	_, unset, tcp := compile("")
	if tcp != 12 || wireLimit(unset) != nil {
		t.Fatalf("no setting row: tcp v%d limit=%v", tcp, wireLimit(unset))
	}
	base := `{"source_ip_header":"X-Real-IP","api_key_enabled":true,"dns_protection":"","record_repair_mode":"repair","sync_batch":1000,"sync_scope":"line_group","disable_failed_sync_nodes":false,"resource_rank":100,"http_proxy":"","tcp_factor":1.1`
	_, defaulted, tcp := compile(base + `,"l4_drain_max_seconds":86400}`)
	if tcp != 12 || !bytes.Equal(defaulted.Files[edgeconfig.L4RuntimeV2ArtifactPath], unset.Files[edgeconfig.L4RuntimeV2ArtifactPath]) {
		t.Fatalf("default drain limit changed the release: tcp v%d", tcp)
	}
	_, limited, tcp := compile(base + `,"l4_drain_max_seconds":3600}`)
	if tcp != 12 || wireLimit(limited) == nil || *wireLimit(limited) != 3_600_000 {
		t.Fatalf("1 h drain limit: tcp v%d limit=%v", tcp, wireLimit(limited))
	}
	_, unlimited, tcp := compile(base + `,"l4_drain_max_seconds":0}`)
	if tcp != 12 || wireLimit(unlimited) == nil || *wireLimit(unlimited) != 0 {
		t.Fatalf("unlimited drain: tcp v%d limit=%v", tcp, wireLimit(unlimited))
	}
}

// newL4DrainLimitFixture is newL4V2ContractFixture whose package grants
// unlimited stream ports (the shared fixture predates stream_ports quotas).
// The grant supersedes whatever entitlement head the base fixture created.
func newL4DrainLimitFixture(t *testing.T) *publishFixture {
	t.Helper()
	fixture := newPublishFixture(t)
	if fixture.tenantID == fixture.scopeID {
		t.Fatal("fixture must distinguish tenant identity from access scope")
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		SELECT id,'streams.manage' FROM roles WHERE scope_id=$1 AND name='tenant_owner'
		ON CONFLICT DO NOTHING`, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO package_subscription_entitlement_versions(
		subscription_id,revision,supersedes_subscription_id,supersedes_revision,
		tenant_scope_id,effective_at,effective_until,product_id,product_revision,product_snapshot,
		site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,custom_cycle_days,
		tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,
		entitlement_status,source_order_id,operation,created_by_user_id,created_at)
		SELECT subscription.id,COALESCE(head.revision,0)+1,head.subscription_id,head.revision,subscription.tenant_scope_id,
		GREATEST(subscription.starts_at,COALESCE(head.effective_at,subscription.starts_at)),NULL,
		subscription.product_id,subscription.product_revision,subscription.product_snapshot||jsonb_build_object('spec',coalesce(subscription.product_snapshot->'spec','{}'::jsonb)||
		jsonb_build_object('limits',coalesce(subscription.product_snapshot#>'{spec,limits}','{}'::jsonb)||'{"stream_ports":-1}'::jsonb)),
		subscription.site_limit,subscription.domain_limit,subscription.node_limit,subscription.traffic_limit_bytes,
		subscription.timezone,subscription.cycle_kind,subscription.custom_cycle_days,
		subscription.tcp_factor_numerator,subscription.tcp_factor_denominator,NULL,NULL,'CNY',
		'active',NULL,'migration_backfill',$2,clock_timestamp()
		FROM package_subscriptions subscription
		LEFT JOIN LATERAL (SELECT subscription_id,revision,effective_at FROM package_subscription_entitlement_versions
			WHERE subscription_id=subscription.id ORDER BY revision DESC LIMIT 1) head ON true
		WHERE subscription.id=$1`, fixture.subscriptionID, fixture.userID); err != nil {
		t.Fatal(err)
	}
	return fixture
}
