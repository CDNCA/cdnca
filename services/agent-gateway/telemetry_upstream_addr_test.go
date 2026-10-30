package gateway

import (
	"strings"
	"testing"
	"time"
)

// fix-upstreamaddr：节点访问事件带回源地址 upstream_addr，网关接受（≤64 字节、无首尾空白），
// 超长拒绝。
func TestTelemetryV2AcceptsUpstreamAddr(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for value, ok := range map[string]bool{"10.0.0.1:80, 10.0.0.2:80": true, strings.Repeat("a", 65): false, " 10.0.0.1:80": false} {
		batch := telemetryV2Batch(t, telemetryKindAccessV2, now)
		mutateTelemetryV2Payload(t, batch.Records[0], func(_ map[string]any, event map[string]any) {
			event["upstream_addr"] = value
		})
		batch.BatchId = telemetryBatchID(batch.Records)
		_, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(),
			DefaultTelemetryConfig(), now)
		if (err == nil) != ok {
			t.Fatalf("upstream_addr %q: err=%v, want accepted=%v", value, err, ok)
		}
	}
}
