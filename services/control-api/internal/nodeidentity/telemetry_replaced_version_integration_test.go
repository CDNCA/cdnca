//go:build integration

package nodeidentity

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// 遥测授权的 90 天窗口按“版本最后在节点上生效的时间”算。
// 一个在节点上生效了 100 天、昨天才被新发布替换的版本，其退役 worker 上的
// 长连接仍在上报检查点/结束行；只按它自己的部署时间（100 天前）算会被立即
// 移出授权，网关拒收，长连接计量丢失。
func TestTelemetryAuthorizesVersionReplacedWithinWindow(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 10, 28, 8, 0, 0, 0, time.UTC)
	fixture := seedIdentityNode(t, pool, now.Add(-200*24*time.Hour), "active", "initial_enrollment")

	oldSite, newSite, staleSite := uuid.New(), uuid.New(), uuid.New()
	staleID := seedTelemetryConfig(t, pool, fixture, staleSite, now.Add(-200*24*time.Hour))
	seedTelemetryDeploymentFactWithPrevious(t, pool, fixture, staleID, nil, "apply", "healthy", "healthy", now.Add(-190*24*time.Hour))
	oldID := seedTelemetryConfig(t, pool, fixture, oldSite, now.Add(-101*24*time.Hour))
	seedTelemetryDeploymentFactWithPrevious(t, pool, fixture, oldID, &staleID, "apply", "healthy", "healthy", now.Add(-100*24*time.Hour))
	newID := seedTelemetryConfig(t, pool, fixture, newSite, now.Add(-25*time.Hour))
	seedTelemetryDeploymentFactWithPrevious(t, pool, fixture, newID, &oldID, "apply", "healthy", "healthy", now.Add(-24*time.Hour))
	if _, err := pool.Exec(context.Background(), `INSERT INTO node_config_state
		(node_id,configuration_scope_id,current_config_version_id,previous_config_version_id,revision,updated_at)
		VALUES($1,$2,$3,$4,1,$5)`, fixture.nodeID, fixture.scopeID, newID, oldID, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	sites, err := TelemetrySiteScopesForTest(context.Background(), pool, fixture.nodeID, fixture.scopeID, fixture.tenantID, now)
	if err != nil {
		t.Fatal(err)
	}
	assertTelemetryBindings(t, sites, map[TelemetrySiteScope]struct{}{
		{SiteID: newSite, TenantID: fixture.tenantID, ConfigurationScopeID: fixture.scopeID, ConfigVersionID: newID}: {},
		// 昨天才退役：窗口内仍生效过，必须保留。
		{SiteID: oldSite, TenantID: fixture.tenantID, ConfigurationScopeID: fixture.scopeID, ConfigVersionID: oldID}: {},
		// staleID 100 天前已被替换：超出窗口，仍排除。
	})
}
