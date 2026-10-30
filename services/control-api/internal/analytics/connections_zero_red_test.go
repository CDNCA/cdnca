package analytics

import (
	"crypto/sha256"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDecodeConnectionsMetricAcceptsFinalizedZeroWindow(t *testing.T) {
	windowEnd := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	canonical := sha256.Sum256([]byte("canonical-zero-connections"))
	evidence := sha256.Sum256([]byte("finalized-empty-connection-source"))
	envelope := &agentv1.ConnectionsMetricEnvelopeV1{
		SchemaVersion: 1,
		Event:         &commonv1.EventMetadata{EventId: "connections-zero-window-1", OccurredTime: timestamppb.New(windowEnd)},
		TenantId:      "20000000-0000-4000-8000-000000000001", InstallationId: "installation-1",
		SiteId: "30000000-0000-4000-8000-000000000001", PackageSubscriptionId: "40000000-0000-4000-8000-000000000001",
		Connections: 0, CanonicalEventSha256: canonical[:],
		DependencyState:  agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY,
		FinalizedThrough: timestamppb.New(windowEnd), EvidenceSha256: evidence[:], SourceWatermark: 18,
		NodeId: "50000000-0000-4000-8000-000000000001", Domain: "cdn.example.test", ListenPort: 443,
	}
	payload, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	metric, err := DecodeConnectionsMetric(payload)
	if err != nil || metric.Connections != 0 {
		t.Fatalf("DecodeConnectionsMetric(zero) = %+v, %v", metric, err)
	}
}
