package nodepresence

import (
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EdgeRuntimeStatus.telemetry → node_presence telemetry_*
// (migration 592).
func TestTelemetryHealthColumnsAndValidation(t *testing.T) {
	first := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	last := first.Add(time.Minute)
	if columns := telemetryHealthColumns(nil); columns != (TelemetryHealth{}) {
		t.Fatalf("absent: %+v", columns)
	}
	health := &agentv1.TelemetryHealth{ErrorCode: "L4_USAGE_LEDGER_FULL", FirstSeenTime: timestamppb.New(first),
		LastSeenTime: timestamppb.New(last), Count: 4}
	columns := telemetryHealthColumns(health)
	if !validTelemetryHealth(health) || *columns.ErrorCode != "L4_USAGE_LEDGER_FULL" || !columns.FirstSeenAt.Equal(first) ||
		!columns.LastSeenAt.Equal(last) || *columns.Count != 4 {
		t.Fatalf("reported: %+v", columns)
	}
	for name, health := range map[string]*agentv1.TelemetryHealth{
		"empty code":        {FirstSeenTime: timestamppb.New(first), LastSeenTime: timestamppb.New(last), Count: 1},
		"lowercase code":    {ErrorCode: "l4", FirstSeenTime: timestamppb.New(first), LastSeenTime: timestamppb.New(last), Count: 1},
		"long code":         {ErrorCode: "L" + strings.Repeat("X", 64), FirstSeenTime: timestamppb.New(first), LastSeenTime: timestamppb.New(last), Count: 1},
		"zero count":        {ErrorCode: "L4_USAGE_LEDGER_FULL", FirstSeenTime: timestamppb.New(first), LastSeenTime: timestamppb.New(last)},
		"count overflow":    {ErrorCode: "L4_USAGE_LEDGER_FULL", FirstSeenTime: timestamppb.New(first), LastSeenTime: timestamppb.New(last), Count: 1 << 63},
		"missing last":      {ErrorCode: "L4_USAGE_LEDGER_FULL", FirstSeenTime: timestamppb.New(first), Count: 1},
		"last before first": {ErrorCode: "L4_USAGE_LEDGER_FULL", FirstSeenTime: timestamppb.New(last), LastSeenTime: timestamppb.New(first), Count: 1},
	} {
		if validTelemetryHealth(health) {
			t.Errorf("%s accepted", name)
		}
	}
}
