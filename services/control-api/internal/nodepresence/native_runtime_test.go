package nodepresence

import (
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// node-runtime-upgrade: EdgeRuntimeStatus.native_runtime → node_presence
// native_runtime_* (migration 468).
func TestNativeRuntimeColumnsAndValidation(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if columns := nativeRuntimeColumns(nil); columns != (NativeRuntime{}) {
		t.Fatalf("absent: %+v", columns)
	}
	rolledBack := &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK,
		Release: b, PreviousRelease: a, ErrorCode: "RUNTIME_RELOAD_FAILED"}
	columns := nativeRuntimeColumns(rolledBack)
	if !validNativeRuntime(rolledBack) || *columns.State != NativeRuntimeRolledBack || *columns.Release != b ||
		*columns.PreviousRelease != a || *columns.ErrorCode != "RUNTIME_RELOAD_FAILED" {
		t.Fatalf("rolled back: %+v", columns)
	}
	unchanged := &agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_UNCHANGED, Release: a}
	if columns := nativeRuntimeColumns(unchanged); !validNativeRuntime(unchanged) || *columns.State != NativeRuntimeUnchanged ||
		columns.PreviousRelease != nil || columns.ErrorCode != nil {
		t.Fatalf("unchanged: %+v", columns)
	}
	for name, status := range map[string]*agentv1.NativeRuntimeStatus{
		"unspecified":           {},
		"unknown state":         {State: 7},
		"release not sha256":    {State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_SWITCHED, Release: "releases/" + a},
		"code without rollback": {State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_SWITCHED, ErrorCode: "RUNTIME_SWITCH_FAILED"},
		"lowercase code":        {State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK, ErrorCode: "runtime"},
	} {
		if validNativeRuntime(status) {
			t.Errorf("%s accepted", name)
		}
	}
}
