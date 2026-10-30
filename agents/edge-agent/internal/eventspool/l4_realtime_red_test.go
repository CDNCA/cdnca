package eventspool

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func TestL4SourceBindsIdentityAndPublishesDeterministicProto(t *testing.T) {
	identity := TrustedIdentity{
		EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne,
		ConfigVersionID: "55555555-5555-4555-8555-555555555555",
		StreamID: "66666666-6666-4666-8666-666666666666",
		ListenerID: "77777777-7777-4777-8777-777777777777", ConfigRevision: 9,
	}
	line := []byte("{\"time\":\"2026-08-08T12:00:05Z\",\"connection\":\"42\",\"protocol\":\"TCP\",\"server_port\":\"18080\",\"status\":\"200\",\"bytes_sent\":1200,\"bytes_received\":300,\"session_time\":5.25}")
	event, err := ParseL4SourceLineBound(line, identity)
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != EventL4Session || event.TenantID != tenantOne || event.SiteID != siteOne || event.NodeID != nodeOne ||
		event.StreamID != identity.StreamID || event.ListenerID != identity.ListenerID || event.ConfigRevision != 9 ||
		event.Protocol != "tcp" || event.ListenPort != 18080 || event.SessionID != "42" ||
		event.RequestBytes != 300 || event.ResponseBytes != 1200 || event.StatusCode != 200 ||
		!event.StartedAt.Equal(time.Date(2026, 8, 8, 12, 0, 0, -250_000_000, time.UTC)) ||
		!event.FinalizedAt.Equal(time.Date(2026, 8, 8, 12, 0, 5, 0, time.UTC)) {
		t.Fatalf("bound L4 event = %#v", event)
	}
	event.EventID = "l4evt_test"

	config := testConfig(t.TempDir())
	config.Now = func() time.Time { return time.Date(2026, 8, 8, 12, 1, 0, 0, time.UTC) }
	spool := newTestSpool(t, config)
	if _, err := spool.AppendBatch(context.Background(), []Envelope{event}); err != nil {
		t.Fatal(err)
	}
	records, err := spool.nextBatch(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	publications, err := buildPublications(records)
	if err != nil || len(publications) != 1 || !ValidL4Publication(publications[0]) {
		t.Fatalf("L4 publications = %#v, error=%v", publications, err)
	}
	if publications[0].Subject != "cdnca.l4.sessions.v1."+nodeOne {
		t.Fatalf("L4 publication subject = %q", publications[0].Subject)
	}
	var envelope agentv1.L4SessionEnvelopeV1
	if err := proto.Unmarshal(publications[0].Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.GetSchemaVersion() != 1 || envelope.GetTenantId() != tenantOne || envelope.GetNodeId() != nodeOne ||
		envelope.GetSourceWatermark() != publications[0].LastSequence || len(envelope.GetEvidenceSha256()) != 32 ||
		len(envelope.GetEvents()) != 1 || envelope.GetEvents()[0].GetStreamId() != identity.StreamID ||
		envelope.GetEvents()[0].GetBytesUp() != 300 || envelope.GetEvents()[0].GetBytesDown() != 1200 {
		t.Fatalf("L4 protobuf envelope = %#v", &envelope)
	}
	rebuilt, err := buildPublications(records)
	if err != nil || len(rebuilt) != 1 || string(rebuilt[0].Payload) != string(publications[0].Payload) || rebuilt[0].MessageID != publications[0].MessageID {
		t.Fatal("L4 publication is not deterministic across retry")
	}
}
