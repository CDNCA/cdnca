package cccoord

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

func TestDecodeCoordinationEnvelopeRequiresExactSubjectHeadersAndStandardEvent(t *testing.T) {
	tenant, site, node, config := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	envelope := Envelope{
		SchemaVersion: 1, Type: "security.cccoord.v1", MessageID: "msg-1",
		ProducedAt: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC), TenantScopeID: tenant,
		SiteID: site, NodeID: node, ConfigVersionID: config,
		Events: []Fact{{
			EventID: "event-1", OccurredAt: time.Date(2026, 8, 7, 11, 59, 59, 0, time.UTC),
			RuleID: uuid.New(), ClientCIDR: "203.0.113.8", Host: "edge.example.test", Path: "/login",
			Method: "POST", ListenerPort: 443, Protocol: "https", RequestClass: RequestClassStandard,
			Action: "block", StatusCode: 429,
		}},
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	headers := nats.Header{}
	headers.Set(nats.MsgIdHdr, envelope.MessageID)
	headers.Set("Cdnca-Tenant-Id", tenant.String())
	headers.Set("Cdnca-Site-Id", site.String())
	headers.Set("Cdnca-Node-Id", node.String())
	headers.Set("Cdnca-Config-Version-Id", config.String())
	subject := CoordinationSubjectPrefix + "." + tenant.String() + "." + site.String()
	decoded, err := decodeCoordinationEnvelope(subject, headers, payload)
	if err != nil || len(decoded.Events) != 1 || decoded.Events[0].RequestClass != RequestClassStandard ||
		decoded.Events[0].ListenerPort != 443 {
		t.Fatalf("decodeCoordinationEnvelope() = (%+v, %v)", decoded, err)
	}
	changed := nats.Header{}
	for name, values := range headers {
		changed[name] = append([]string(nil), values...)
	}
	changed.Set("Cdnca-Site-Id", uuid.NewString())
	if _, err := decodeCoordinationEnvelope(subject, changed, payload); err == nil {
		t.Fatal("mismatched site header accepted")
	}
	duplicate := append([]byte(`{"schema_version":1,`), payload[1:]...)
	if _, err := decodeCoordinationEnvelope(subject, headers, duplicate); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
}

func TestSameCoordinationConsumerRequiresExactDurableContract(t *testing.T) {
	config := DefaultNATSConfig()
	info := &nats.ConsumerInfo{Config: nats.ConsumerConfig{
		Durable: config.Durable, FilterSubject: config.SubjectPrefix + ".*.*",
		DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy, AckWait: config.AckWait,
		MaxDeliver: -1, ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: config.MaxAckPending,
		MaxRequestBatch: 1, MaxRequestExpires: config.FetchTimeout,
	}}
	if !sameCoordinationConsumer(info, config) {
		t.Fatal("exact durable consumer rejected")
	}
	changed := *info
	changed.Config = info.Config
	changed.Config.AckPolicy = nats.AckNonePolicy
	if sameCoordinationConsumer(&changed, config) {
		t.Fatal("consumer without explicit ACK accepted")
	}
}
