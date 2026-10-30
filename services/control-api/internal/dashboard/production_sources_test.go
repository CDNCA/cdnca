package dashboard

import (
	"slices"
	"strings"
	"testing"
)

func TestTenantDashboardBasePermissionsExcludeOptionalNodeFacts(t *testing.T) {
	if slices.Contains(tenantReadPermissions, "nodes.read") {
		t.Fatal("tenant dashboard must keep node facts optional for roles without nodes.read")
	}
}

func TestTenantSubscriptionsSQLBindsCurrentPolicyAndAuthoritativePeriod(t *testing.T) {
	query := strings.ToLower(strings.Join(strings.Fields(tenantSubscriptionsSQL), " "))
	required := []string{
		"from package_monitor_policy_heads head",
		"head.tenant_scope_id=subscription.tenant_scope_id",
		"head.subscription_id=subscription.id",
		"head.metric='traffic_bytes'",
		"head.current_revision",
		"join package_monitor_policy_versions policy",
		"policy.policy_id=head.policy_id",
		"policy.revision=head.current_revision",
		"policy.enabled",
		"package_monitor_resolve_period_114(",
		"observation.policy_id=policy.policy_id",
		"observation.policy_revision=policy.revision",
		"observation.period_key=period.period_key",
		"observation.committed_at<=$2",
		"observation.finalized_through<=$2",
	}
	for _, fragment := range required {
		if !strings.Contains(query, fragment) {
			t.Errorf("tenant subscription query does not enforce %q", fragment)
		}
	}
}
