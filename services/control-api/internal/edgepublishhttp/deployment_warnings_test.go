package edgepublishhttp

import (
	"slices"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

// PJ-E02/E03/E04: a healthy deployment whose node reported a
// failed maintenance or DDoS protection check shows warnings to the platform.
func TestDeploymentWarningsFromTheTerminalStatus(t *testing.T) {
	payload, err := proto.Marshal(&agentv1.DeploymentStatus{
		State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		Checks: []*agentv1.CheckResult{
			{Name: "edge_active_config_probe", Succeeded: true},
			{Name: "edge_post_activation_maintenance", Succeeded: false, Summary: "generation 9 active, post-activation retain failed"},
			{Name: "edge_ddos_protection", Succeeded: false, Summary: "DDoS protection unavailable (nft_missing)"},
			{Name: "edge_site_certificates", Succeeded: false},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	warnings := edgedeployment.DeploymentWarnings(payload)
	if !slices.Equal(warnings, []string{edgedeployment.WarningDDoSProtection, edgedeployment.WarningPostActivationMaintenance}) {
		t.Fatalf("warnings %v", warnings)
	}
	healthy, _ := proto.Marshal(&agentv1.DeploymentStatus{Checks: []*agentv1.CheckResult{{Name: "edge_ddos_protection", Succeeded: true}}})
	if got := edgedeployment.DeploymentWarnings(healthy); len(got) != 0 {
		t.Fatalf("warnings %v", got)
	}
	if got := edgedeployment.DeploymentWarnings([]byte{0xff}); got != nil {
		t.Fatalf("undecodable payload: %v", got)
	}

	now := time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)
	item := edgedeployment.DeploymentSnapshot{ID: uuid.New(), NodeID: uuid.New(), Attempt: 1, MaxAttempts: 3,
		State: "healthy", CreatedAt: now, UpdatedAt: now, Warnings: warnings}
	platform, err := deploymentView(item, AudiencePlatform)
	if err != nil || !slices.Equal(platform.Warnings, warnings) {
		t.Fatalf("platform view %+v %v", platform, err)
	}
	tenant, err := deploymentView(item, AudienceTenant)
	if err != nil || tenant.Warnings != nil {
		t.Fatalf("tenant view %+v %v", tenant, err)
	}
}
