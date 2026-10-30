package gateway

import (
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// node-runtime-upgrade: EdgeRuntimeStatus.native_runtime (field 7).
func TestHeartbeatNativeRuntimeValidation(t *testing.T) {
	gateway := newHeartbeatGateway(t, &fakeHeartbeatSink{}, nil)
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, test := range []struct {
		name   string
		status *agentv1.NativeRuntimeStatus
		valid  bool
	}{
		{"absent", nil, true},
		{"switched", &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_SWITCHED, Release: b, PreviousRelease: a}, true},
		{"unchanged", &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_UNCHANGED, Release: a}, true},
		{"rolled back", &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK, Release: b,
			PreviousRelease: a, ErrorCode: "RUNTIME_PRECHECK_FAILED"}, true},
		{"unspecified", &agentv1.NativeRuntimeStatus{}, false},
		{"unknown state", &agentv1.NativeRuntimeStatus{State: 9}, false},
		// 4 was WAITING_OLD_SESSIONS (withdrawn, reserved): unknown now.
		{"withdrawn waiting state", &agentv1.NativeRuntimeStatus{State: 4, Release: b, PreviousRelease: a}, false},
		{"release not sha256", &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_UNCHANGED, Release: "releases/" + a}, false},
		{"uppercase release", &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_UNCHANGED, Release: strings.ToUpper(a)}, false},
		{"code without rollback", &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_SWITCHED, ErrorCode: "RUNTIME_SWITCH_FAILED"}, false},
		{"lowercase code", &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK, ErrorCode: "runtime_failed"}, false},
		{"long code", &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK, ErrorCode: "R" + strings.Repeat("X", 64)}, false},
	} {
		heartbeat := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString()).GetHeartbeat()
		heartbeat.Runtime = &agentv1.EdgeRuntimeStatus{NativeRuntime: test.status}
		err := gateway.validateHeartbeat(heartbeat, 1, 0, false, "")
		if (err == nil) != test.valid {
			t.Errorf("%s: err = %v, want valid=%v", test.name, err, test.valid)
		}
	}
}
