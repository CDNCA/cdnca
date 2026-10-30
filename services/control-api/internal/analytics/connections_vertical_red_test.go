package analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDecodeConnectionsMetricRequiresStrictReadyEvidence(t *testing.T) {
	now := time.Date(2026, 8, 7, 2, 0, 0, 0, time.UTC)
	canonical := sha256.Sum256([]byte("canonical-connections-event"))
	evidence := sha256.Sum256([]byte("finalized-connections-evidence"))
	envelope := &agentv1.ConnectionsMetricEnvelopeV1{
		SchemaVersion: 1,
		Event:         &commonv1.EventMetadata{EventId: "connections-event-1", OccurredTime: timestamppb.New(now)},
		TenantId:      "20000000-0000-4000-8000-000000000001", InstallationId: "installation-1",
		SiteId: "30000000-0000-4000-8000-000000000001", PackageSubscriptionId: "40000000-0000-4000-8000-000000000001",
		Connections: 7, CanonicalEventSha256: canonical[:],
		DependencyState:  agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY,
		FinalizedThrough: timestamppb.New(now), EvidenceSha256: evidence[:], SourceWatermark: 17,
		NodeId: "50000000-0000-4000-8000-000000000001", Domain: "cdn.example.test", ListenPort: 443,
	}
	payload, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	metric, err := DecodeConnectionsMetric(payload)
	if err != nil {
		t.Fatalf("DecodeConnectionsMetric() error = %v", err)
	}
	if metric.EventID != "connections-event-1" || metric.Connections != 7 || metric.SourceWatermark != 17 ||
		metric.OccurredAt != now || metric.FinalizedThrough != now || metric.CanonicalEventSHA256 != canonical || metric.EvidenceSHA256 != evidence ||
		metric.NodeID != envelope.NodeId || metric.Domain != envelope.Domain || metric.ListenPort != uint16(envelope.ListenPort) {
		t.Fatalf("decoded metric = %#v", metric)
	}

	for _, test := range []struct {
		name   string
		mutate func(*agentv1.ConnectionsMetricEnvelopeV1)
	}{
		{name: "unknown dependency", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) {
			value.DependencyState = agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_UNKNOWN
		}},
		{name: "short evidence", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.EvidenceSha256 = value.EvidenceSha256[:31] }},
		{name: "unfinalized", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) {
			value.FinalizedThrough = timestamppb.New(now.Add(-time.Second))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := proto.Clone(envelope).(*agentv1.ConnectionsMetricEnvelopeV1)
			test.mutate(candidate)
			encoded, err := proto.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeConnectionsMetric(encoded); err == nil {
				t.Fatal("accepted invalid connections evidence")
			}
		})
	}
}

func TestPackageMetricConnectionsUsesDurableFactQuery(t *testing.T) {
	now := time.Date(2026, 8, 7, 2, 0, 0, 0, time.UTC)
	evidence := sha256.Sum256([]byte("connection-evidence"))
	client := mustClient(t, Config{Endpoint: "https://clickhouse.example.test", Database: "analytics_test"}, &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			body := new(bytes.Buffer)
			if _, err := body.ReadFrom(request.Body); err != nil {
				return nil, err
			}
			if !strings.Contains(body.String(), "package_metric_connection_facts_v1") || !strings.Contains(body.String(), "active_connections") {
				t.Fatalf("connections query = %q", body.String())
			}
			response := `{"value":7,"observed_at_ms":` + formatUnixMilli(now) + `,"finalized_through_ms":` + formatUnixMilli(now) + `,"source_evidence_digest":"` + hex.EncodeToString(evidence[:]) + `"}` + "\n"
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}, nil
		}),
	})
	result, err := client.PackageMetric(context.Background(), PackageMetricRequest{
		TenantScopeID: "20000000-0000-4000-8000-000000000001", SubscriptionID: "40000000-0000-4000-8000-000000000001",
		Metric: "connections", PeriodStart: now.Add(-time.Hour), PeriodEnd: now,
	})
	if err != nil {
		t.Fatalf("PackageMetric() error = %v", err)
	}
	if result.Value != 7 || !result.ObservedAt.Equal(now) || !result.FinalizedThrough.Equal(now) || result.SourceEvidenceDigest != evidence {
		t.Fatalf("PackageMetric() = %#v", result)
	}
}

func formatUnixMilli(value time.Time) string { return strconv.FormatInt(value.UnixMilli(), 10) }
