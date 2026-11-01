package gateway

import (
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// EdgeRuntimeStatus.telemetry (field 8).
func TestHeartbeatTelemetryHealthValidation(t *testing.T) {
	gateway := newHeartbeatGateway(t, &fakeHeartbeatSink{}, nil)
	first := timestamppb.New(time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC))
	last := timestamppb.New(first.AsTime().Add(time.Minute))
	for _, test := range []struct {
		name   string
		health *agentv1.TelemetryHealth
		valid  bool
	}{
		{"absent", nil, true},
		{"ledger full", &agentv1.TelemetryHealth{ErrorCode: "L4_USAGE_LEDGER_FULL", FirstSeenTime: first, LastSeenTime: last, Count: 3}, true},
		{"same time", &agentv1.TelemetryHealth{ErrorCode: "TELEMETRY_BACKPRESSURE", FirstSeenTime: first, LastSeenTime: first, Count: 1}, true},
		{"empty code", &agentv1.TelemetryHealth{FirstSeenTime: first, LastSeenTime: last, Count: 1}, false},
		{"lowercase code", &agentv1.TelemetryHealth{ErrorCode: "l4_usage", FirstSeenTime: first, LastSeenTime: last, Count: 1}, false},
		{"long code", &agentv1.TelemetryHealth{ErrorCode: "L" + strings.Repeat("X", 64), FirstSeenTime: first, LastSeenTime: last, Count: 1}, false},
		{"zero count", &agentv1.TelemetryHealth{ErrorCode: "L4_USAGE_LEDGER_FULL", FirstSeenTime: first, LastSeenTime: last}, false},
		{"missing first", &agentv1.TelemetryHealth{ErrorCode: "L4_USAGE_LEDGER_FULL", LastSeenTime: last, Count: 1}, false},
		{"last before first", &agentv1.TelemetryHealth{ErrorCode: "L4_USAGE_LEDGER_FULL", FirstSeenTime: last, LastSeenTime: first, Count: 1}, false},
		{"invalid time", &agentv1.TelemetryHealth{ErrorCode: "L4_USAGE_LEDGER_FULL", FirstSeenTime: &timestamppb.Timestamp{Nanos: -1}, LastSeenTime: last, Count: 1}, false},
	} {
		heartbeat := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString()).GetHeartbeat()
		heartbeat.Runtime = &agentv1.EdgeRuntimeStatus{Telemetry: test.health}
		err := gateway.validateHeartbeat(heartbeat, 1, 0, false, "")
		if (err == nil) != test.valid {
			t.Errorf("%s: err = %v, want valid=%v", test.name, err, test.valid)
		}
	}
}
