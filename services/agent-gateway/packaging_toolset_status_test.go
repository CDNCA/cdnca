package gateway

import (
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EdgeRuntimeStatus.packaging_toolset (field 10, capability 83).
func TestHeartbeatPackagingToolsetValidation(t *testing.T) {
	if agentv1.CapabilityName_CAPABILITY_NAME_PACKAGING_TOOLSET_REPORT != 83 {
		t.Fatalf("PACKAGING_TOOLSET_REPORT = %d", agentv1.CapabilityName_CAPABILITY_NAME_PACKAGING_TOOLSET_REPORT)
	}
	gateway := newHeartbeatGateway(t, &fakeHeartbeatSink{}, nil)
	at, sha := timestamppb.Now(), strings.Repeat("0", 64)
	for _, test := range []struct {
		name   string
		status *agentv1.PackagingToolsetStatus
		valid  bool
	}{
		{"absent (older agent)", nil, true},
		{"never refreshed", &agentv1.PackagingToolsetStatus{RefreshStatus: "none", ScriptsSha256: sha, HelperSha256: sha}, true},
		{"refreshed", &agentv1.PackagingToolsetStatus{RefreshStatus: "ok", RefreshVersion: "1.0.36", RefreshTime: at,
			HelperStatus: "ok", ScriptsSha256: sha, HelperSha256: sha}, true},
		{"helper failed", &agentv1.PackagingToolsetStatus{RefreshStatus: "ok", RefreshVersion: "1.0.36", RefreshTime: at,
			HelperStatus: "failed", HelperReason: "transient unit could not replace the packaging helper"}, true},
		{"unknown status", &agentv1.PackagingToolsetStatus{RefreshStatus: "maybe"}, false},
		{"record without time", &agentv1.PackagingToolsetStatus{RefreshStatus: "ok", RefreshVersion: "1.0.36"}, false},
		{"bad digest", &agentv1.PackagingToolsetStatus{RefreshStatus: "none", HelperSha256: "XYZ"}, false},
	} {
		heartbeat := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString()).GetHeartbeat()
		heartbeat.Runtime = &agentv1.EdgeRuntimeStatus{PackagingToolset: test.status}
		err := gateway.validateHeartbeat(heartbeat, 1, 0, false, "")
		if (err == nil) != test.valid {
			t.Errorf("%s: err = %v, want valid=%v", test.name, err, test.valid)
		}
	}
}
