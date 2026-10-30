package eventspool

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestConnectionsPublicationRequiresReadyAuthorityAndDurableAck(t *testing.T) {
	config := testConfig(t.TempDir())
	spool := newTestSpool(t, config)

	unknown := connectionsEnvelope(1, "11111111-1111-4111-8111-111111111111", 10)
	unknown.DependencyState = agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_UNKNOWN
	if _, err := spool.AppendConnections(context.Background(), unknown); !errors.Is(err, ErrConnectionsUnavailable) {
		t.Fatalf("unknown dependency error = %v, want ErrConnectionsUnavailable", err)
	}

	missingFinalized := connectionsEnvelope(1, "22222222-2222-4222-8222-222222222222", 10)
	missingFinalized.FinalizedThrough = nil
	if _, err := spool.AppendConnections(context.Background(), missingFinalized); !errors.Is(err, ErrInvalidConnections) {
		t.Fatalf("missing finalized error = %v, want ErrInvalidConnections", err)
	}

	first := connectionsEnvelope(1, "33333333-3333-4333-8333-333333333333", 10)
	appendResult, err := spool.AppendConnections(context.Background(), first)
	if err != nil || appendResult.Duplicate || appendResult.SourceWatermark != 10 {
		t.Fatalf("first append = %#v, %v", appendResult, err)
	}
	duplicate, err := spool.AppendConnections(context.Background(), proto.Clone(first).(*agentv1.ConnectionsMetricEnvelopeV1))
	if err != nil || !duplicate.Duplicate || duplicate.SourceWatermark != 10 {
		t.Fatalf("duplicate append = %#v, %v", duplicate, err)
	}
	conflict := proto.Clone(first).(*agentv1.ConnectionsMetricEnvelopeV1)
	conflict.CanonicalEventSha256[0] ^= 0xff
	if _, err := spool.AppendConnections(context.Background(), conflict); !errors.Is(err, ErrConnectionsConflict) {
		t.Fatalf("digest conflict error = %v, want ErrConnectionsConflict", err)
	}
	listenerConflict := proto.Clone(first).(*agentv1.ConnectionsMetricEnvelopeV1)
	listenerConflict.Domain = "other.example.test"
	if _, err := spool.AppendConnections(context.Background(), listenerConflict); !errors.Is(err, ErrConnectionsConflict) {
		t.Fatalf("listener identity conflict error = %v, want ErrConnectionsConflict", err)
	}
	lower := connectionsEnvelope(1, "44444444-4444-4444-8444-444444444444", 9)
	if _, err := spool.AppendConnections(context.Background(), lower); !errors.Is(err, ErrConnectionsWatermark) {
		t.Fatalf("watermark regression error = %v, want ErrConnectionsWatermark", err)
	}

	failing := &connectionsScriptedPublisher{err: errors.New("publisher unavailable")}
	if publishResult, err := spool.FlushConnections(context.Background(), failing, 10); err == nil || publishResult.Published != 0 {
		t.Fatalf("failed publication = %#v, %v", publishResult, err)
	}
	restarted := newTestSpool(t, config)
	publisher := &connectionsScriptedPublisher{}
	publishResult, err := restarted.FlushConnections(context.Background(), publisher, 10)
	if err != nil || publishResult.Published != 1 || publishResult.LastSourceWatermark != 10 || len(publisher.publications) != 1 {
		t.Fatalf("restart publication = %#v, %v, publications=%d", publishResult, err, len(publisher.publications))
	}
	publication := publisher.publications[0]
	if !ValidConnectionsPublication(publication) || publication.Subject != connectionsSubjectPrefix+"."+first.InstallationId {
		t.Fatalf("invalid connections publication = %#v", publication)
	}
	var published agentv1.ConnectionsMetricEnvelopeV1
	if err := proto.Unmarshal(publication.Payload, &published); err != nil {
		t.Fatal(err)
	}
	if published.GetConnections() != first.GetConnections() || published.GetSourceWatermark() != 10 ||
		published.GetNodeId() != first.GetNodeId() || published.GetDomain() != first.GetDomain() ||
		published.GetListenPort() != first.GetListenPort() ||
		published.GetDependencyState() != agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY {
		t.Fatalf("published envelope fields: connections=%d watermark=%d dependency=%s", published.GetConnections(),
			published.GetSourceWatermark(), published.GetDependencyState())
	}

	if duplicate, err := restarted.AppendConnections(context.Background(), first); err != nil || !duplicate.Duplicate {
		t.Fatalf("post-ack duplicate = %#v, %v", duplicate, err)
	}
	if _, err := restarted.AppendConnections(context.Background(), lower); !errors.Is(err, ErrConnectionsWatermark) {
		t.Fatalf("post-restart watermark regression = %v", err)
	}

	second := connectionsEnvelope(1, "55555555-5555-4555-8555-555555555555", 11)
	third := connectionsEnvelope(1, "66666666-6666-4666-8666-666666666666", 12)
	if _, err := restarted.AppendConnections(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.AppendConnections(context.Background(), third); err != nil {
		t.Fatal(err)
	}
	partial := &connectionsScriptedPublisher{ack: 1, err: errors.New("connection lost after durable ack")}
	publishResult, err = restarted.FlushConnections(context.Background(), partial, 10)
	if err == nil || publishResult.Published != 1 || publishResult.LastSourceWatermark != 11 {
		t.Fatalf("partial publication = %#v, %v", publishResult, err)
	}
	restarted = newTestSpool(t, config)
	publisher = &connectionsScriptedPublisher{}
	publishResult, err = restarted.FlushConnections(context.Background(), publisher, 10)
	if err != nil || publishResult.Published != 1 || publishResult.LastSourceWatermark != 12 || len(publisher.publications) != 1 {
		t.Fatalf("remaining publication = %#v, %v", publishResult, err)
	}
}

func TestConnectionsPublicationRejectsMissingListenerIdentity(t *testing.T) {
	spool := newTestSpool(t, testConfig(t.TempDir()))
	envelope := connectionsEnvelope(1, "77777777-7777-4777-8777-777777777777", 13)
	envelope.NodeId, envelope.Domain, envelope.ListenPort = "", "", 0
	if _, err := spool.AppendConnections(context.Background(), envelope); !errors.Is(err, ErrInvalidConnections) {
		t.Fatalf("missing listener identity error = %v, want ErrInvalidConnections", err)
	}
}

func connectionsEnvelope(connections uint64, eventID string, watermark uint64) *agentv1.ConnectionsMetricEnvelopeV1 {
	now := time.Unix(1_700_000_000, 0).UTC()
	return &agentv1.ConnectionsMetricEnvelopeV1{
		SchemaVersion: 1,
		Event:         &commonv1.EventMetadata{EventId: eventID, OccurredTime: timestamppb.New(now)},
		TenantId:      tenantOne, InstallationId: nodeOne, SiteId: siteOne, PackageSubscriptionId: siteOne,
		NodeId: nodeOne, Domain: "edge.example.test", ListenPort: 443,
		Connections: connections, CanonicalEventSha256: bytes32(1),
		DependencyState:  agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY,
		FinalizedThrough: timestamppb.New(now.Add(time.Minute)), EvidenceSha256: bytes32(2), SourceWatermark: watermark,
	}
}

func bytes32(value byte) []byte {
	result := make([]byte, 32)
	for index := range result {
		result[index] = value
	}
	return result
}

type connectionsScriptedPublisher struct {
	ack          int
	err          error
	publications []Publication
}

func (publisher *connectionsScriptedPublisher) Publish(_ context.Context, publications []Publication) (PublishAck, error) {
	publisher.publications = append(publisher.publications, publications...)
	ack := publisher.ack
	if ack == 0 && publisher.err == nil {
		ack = len(publications)
	}
	return PublishAck{Acknowledged: ack}, publisher.err
}
