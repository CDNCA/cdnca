package edgepublishhttp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

// a failed deployment shows the node's own failure text beside
// its error code, to the platform and the tenant; superseded and frozen
// deployments are no failures and show none.
func TestDeploymentViewCarriesTheNodeFailureText(t *testing.T) {
	cause := "L4 configuration precheck failed: OpenResty command failed: nginx: [emerg] bind() to 0.0.0.0:7001 failed\n(98: Address in use)"
	payload, err := proto.Marshal(&agentv1.DeploymentStatus{
		State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, RunningConfigUnchanged: true,
		Error: &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, Message: cause},
	})
	if err != nil {
		t.Fatal(err)
	}
	message := edgedeployment.DeploymentErrorMessage(payload)
	want := "L4 configuration precheck failed: OpenResty command failed: nginx: [emerg] bind() to 0.0.0.0:7001 failed (98: Address in use)"
	if message != want {
		t.Fatalf("message %q", message)
	}

	now := time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)
	item := edgedeployment.DeploymentSnapshot{ID: uuid.New(), NodeID: uuid.New(), Attempt: 1, MaxAttempts: 3,
		State: "failed", ErrorCode: "ERROR_CODE_FAILED_PRECONDITION", ErrorMessage: message, CreatedAt: now, UpdatedAt: now}
	for _, audience := range []string{AudiencePlatform, AudienceTenant} {
		view, err := deploymentView(item, audience)
		if err != nil || view.ErrorMessage != want {
			t.Fatalf("%s view %+v %v", audience, view, err)
		}
		encoded, _ := json.Marshal(view)
		if !strings.Contains(string(encoded), `"error_message":`) {
			t.Fatalf("%s json %s", audience, encoded)
		}
	}
	superseded, frozen := item, item
	superseded.Superseded, frozen.Frozen = true, true
	for _, quiet := range []edgedeployment.DeploymentSnapshot{superseded, frozen} {
		view, err := deploymentView(quiet, AudiencePlatform)
		if err != nil || view.ErrorMessage != "" {
			t.Fatalf("not a failure: %+v %v", view, err)
		}
	}
}

func TestDeploymentErrorMessageBoundsAndFallsBack(t *testing.T) {
	long, _ := proto.Marshal(&agentv1.DeploymentStatus{
		State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
		Error: &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_INTERNAL, Message: strings.Repeat("节", 300)},
	})
	if got := edgedeployment.DeploymentErrorMessage(long); len(got) > edgedeployment.MaxDeploymentErrorMessageBytes || len(got) != 510 {
		t.Fatalf("bounded length %d", len(got))
	}
	check, _ := proto.Marshal(&agentv1.DeploymentStatus{
		State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
		Error: &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_INTERNAL},
		Checks: []*agentv1.CheckResult{{Name: "edge_active_config_probe", Succeeded: true, Summary: "ok"},
			{Name: "edge_openresty_test", Succeeded: false, Summary: "release precheck failed"}},
	})
	if got := edgedeployment.DeploymentErrorMessage(check); got != "release precheck failed" {
		t.Fatalf("check fallback %q", got)
	}
	healthy, _ := proto.Marshal(&agentv1.DeploymentStatus{State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		Checks: []*agentv1.CheckResult{{Name: "edge_ddos_protection", Succeeded: false, Summary: "nft missing"}}})
	if got := edgedeployment.DeploymentErrorMessage(healthy); got != "" {
		t.Fatalf("no error: %q", got)
	}
	if got := edgedeployment.DeploymentErrorMessage([]byte{0xff}); got != "" {
		t.Fatalf("undecodable: %q", got)
	}
}
