package analytics

import (
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

const testConfigVersionID = "018f47a2-5b9c-7d31-8a60-104c9c0b7182"

func TestJetStreamContractHasBoundedDurableSettings(t *testing.T) {
	t.Parallel()
	config := DefaultJetStreamConfig()
	if err := validateJetStreamConfig(config); err != nil {
		t.Fatal(err)
	}
	stream := expectedIngestStream(config)
	if stream.Retention != nats.WorkQueuePolicy || stream.Storage != nats.FileStorage ||
		stream.Subjects[0] != IngestSubjectPrefix+".*" || stream.MaxMsgSize != DefaultMaxIngestMessageBytes ||
		stream.MaxAge != 0 || stream.MaxBytes <= 0 || stream.MaxMsgs <= 0 ||
		stream.MaxMsgsPerSubject != -1 || stream.Duplicates <= 0 || stream.Replicas != 1 || stream.Discard != nats.DiscardNew {
		t.Fatalf("ingest stream = %#v", stream)
	}
	consumer := expectedConsumer(config)
	if consumer.Durable != DefaultIngestDurable || consumer.AckPolicy != nats.AckExplicitPolicy ||
		consumer.DeliverPolicy != nats.DeliverAllPolicy || consumer.MaxDeliver != -1 || config.MaxDeliver < 2 ||
		consumer.AckWait != 2*time.Minute || consumer.MaxAckPending != 256 || consumer.MaxWaiting != 16 ||
		consumer.MaxRequestBatch != 32 || consumer.MaxRequestExpires != 2*time.Second ||
		consumer.FilterSubject != IngestSubjectPrefix+".*" || consumer.MaxRequestMaxBytes != 32*DefaultMaxIngestMessageBytes {
		t.Fatalf("ingest consumer = %#v", consumer)
	}
	isolation := expectedIsolationStream(config)
	if isolation.Retention != nats.LimitsPolicy || isolation.Subjects[0] != IsolationSubject ||
		isolation.MaxAge != 30*24*time.Hour || isolation.MaxBytes <= 0 || isolation.MaxMsgsPerSubject != -1 ||
		isolation.Discard != nats.DiscardNew {
		t.Fatalf("isolation stream = %#v", isolation)
	}
}

func TestJetStreamContractRejectsUnboundedOrMismatchedSettings(t *testing.T) {
	t.Parallel()
	valid := DefaultJetStreamConfig()
	tests := []struct {
		name   string
		mutate func(*JetStreamConfig)
	}{
		{"invalid stream", func(config *JetStreamConfig) { config.Stream = "bad.stream" }},
		{"same streams", func(config *JetStreamConfig) { config.IsolationStream = config.Stream }},
		{"short ack wait", func(config *JetStreamConfig) { config.AckWait = config.OperationTimeout }},
		{"unbounded delivery", func(config *JetStreamConfig) { config.MaxDeliver = -1 }},
		{"ack pending below fetch", func(config *JetStreamConfig) { config.MaxAckPending = config.FetchBatch - 1 }},
		{"message batch too large", func(config *JetStreamConfig) { config.FetchBatch = 257 }},
		{"evicting retention", func(config *JetStreamConfig) { config.StreamMaxAge = time.Hour }},
		{"undersized stream", func(config *JetStreamConfig) { config.StreamMaxBytes = 1 }},
		{"invalid replicas", func(config *JetStreamConfig) { config.Replicas = 6 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if err := validateJetStreamConfig(config); err == nil {
				t.Fatalf("configuration unexpectedly accepted: %#v", config)
			}
		})
	}

	expectedStream := expectedIngestStream(valid)
	matchingStream := &nats.StreamInfo{Config: *expectedStream}
	if !sameStream(matchingStream, expectedStream) {
		t.Fatal("matching stream was rejected")
	}
	matchingStream.Config.Description = "server-managed description"
	matchingStream.Config.Metadata = map[string]string{"owner": "server"}
	if !sameStream(matchingStream, expectedStream) {
		t.Fatal("stream description or metadata difference was rejected")
	}
	for _, test := range []struct {
		name   string
		mutate func(*nats.StreamConfig)
	}{
		{"headers only", func(config *nats.StreamConfig) { config.Sources = []*nats.StreamSource{{Name: "SOURCE"}} }},
		{"subject transform", func(config *nats.StreamConfig) {
			config.SubjectTransform = &nats.SubjectTransformConfig{Source: ">", Destination: "archive.>"}
		}},
		{"republish", func(config *nats.StreamConfig) {
			config.RePublish = &nats.RePublish{Source: ">", Destination: "archive.>"}
		}},
		{"max messages per subject", func(config *nats.StreamConfig) { config.MaxMsgsPerSubject = 1 }},
		{"allow message ttl", func(config *nats.StreamConfig) { config.AllowMsgTTL = true }},
	} {
		t.Run("stream "+test.name, func(t *testing.T) {
			actual := *expectedIngestStream(valid)
			test.mutate(&actual)
			if sameStream(&nats.StreamInfo{Config: actual}, expectedIngestStream(valid)) {
				t.Fatalf("stream drift %q was accepted", test.name)
			}
		})
	}

	expected := expectedConsumer(valid)
	matching := &nats.ConsumerInfo{Config: *expected}
	if !sameIngestConsumer(matching, expected) {
		t.Fatal("matching consumer was rejected")
	}
	matching.Config.Name = "server-generated-name"
	matching.Config.Description = "server-managed description"
	matching.Config.Metadata = map[string]string{"owner": "server"}
	if !sameIngestConsumer(matching, expected) {
		t.Fatal("consumer server name, description, or metadata difference was rejected")
	}
	for _, test := range []struct {
		name   string
		mutate func(*nats.ConsumerConfig)
	}{
		{"headers only", func(config *nats.ConsumerConfig) { config.HeadersOnly = true }},
		{"backoff", func(config *nats.ConsumerConfig) { config.BackOff = []time.Duration{time.Second} }},
		{"filter subjects", func(config *nats.ConsumerConfig) {
			config.FilterSubject = ""
			config.FilterSubjects = []string{IngestSubjectPrefix + ".*"}
		}},
		{"no ack", func(config *nats.ConsumerConfig) { config.AckPolicy = nats.AckNonePolicy }},
		{"max deliver", func(config *nats.ConsumerConfig) { config.MaxDeliver++ }},
	} {
		t.Run("consumer "+test.name, func(t *testing.T) {
			actual := *expectedConsumer(valid)
			test.mutate(&actual)
			if sameIngestConsumer(&nats.ConsumerInfo{Config: actual}, expectedConsumer(valid)) {
				t.Fatalf("consumer drift %q was accepted", test.name)
			}
		})
	}
}

func TestIsolationMessageIdentityBindsExactEvidence(t *testing.T) {
	t.Parallel()
	record := IsolationRecord{
		SchemaVersion: IngestSchemaVersion, ReasonCode: RejectInvalidJSON, MessageID: "message",
		Subject:       IngestSubjectPrefix + "." + testNodeID,
		PayloadSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PayloadBytes:  100, Attempts: 2, StreamSequence: 42,
		IsolatedAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		WireKeyID:  "kek-v1", WireNonce: "nonce", WireCiphertext: "ciphertext",
		WireSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	first := isolationMessageID(record)
	for name, mutate := range map[string]func(*IsolationRecord){
		"subject":    func(value *IsolationRecord) { value.Subject += ".wrong" },
		"timestamp":  func(value *IsolationRecord) { value.IsolatedAt = value.IsolatedAt.Add(time.Hour) },
		"attempts":   func(value *IsolationRecord) { value.Attempts++ },
		"nonce":      func(value *IsolationRecord) { value.WireNonce += "wrong" },
		"ciphertext": func(value *IsolationRecord) { value.WireCiphertext += "wrong" },
		"wire digest": func(value *IsolationRecord) {
			value.WireSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		},
	} {
		changed := record
		mutate(&changed)
		if isolationMessageID(changed) == first {
			t.Fatalf("%s reused exact evidence message ID", name)
		}
	}
	if second := isolationMessageID(record); first != second {
		t.Fatalf("identical evidence message ID changed: %q != %q", first, second)
	}
}

func TestNATSDeliveryRequiresAuthoritativeIdentityHeaders(t *testing.T) {
	const (
		nodeHeader         = "Cdnca-Node-Id"
		tenantHeader       = "Cdnca-Tenant-Id"
		siteHeader         = "Cdnca-Site-Id"
		configHeader       = "Cdnca-Config-Version-Id"
		installationHeader = "Cdnca-Installation-Id"
	)
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	event := validAccessEvent("authority-event")
	event.ConfigVersion = testConfigVersionID
	subject, _ := IngestSubject(testNodeID)
	newMessage := func() *nats.Msg {
		message := nats.NewMsg(subject)
		message.Data = marshalAccessEnvelope(t, "authority-message", now, []AccessEvent{event})
		message.Header.Set(nats.MsgIdHdr, "authority-message")
		message.Header.Set(nodeHeader, testNodeID)
		message.Header.Set(tenantHeader, testTenantID)
		message.Header.Set(siteHeader, testSiteID)
		message.Header.Set(configHeader, event.ConfigVersion)
		message.Header.Set(installationHeader, "installation-v1")
		return message
	}

	if got := (&natsIngestDelivery{message: newMessage()}).Subject(); got != subject {
		t.Fatalf("valid authority subject=%q want=%q", got, subject)
	}
	tests := map[string]func(*nats.Msg){
		"missing_node":   func(message *nats.Msg) { message.Header.Del(nodeHeader) },
		"missing_tenant": func(message *nats.Msg) { message.Header.Del(tenantHeader) },
		"missing_site":   func(message *nats.Msg) { message.Header.Del(siteHeader) },
		"missing_config": func(message *nats.Msg) { message.Header.Del(configHeader) },
		"missing_installation": func(message *nats.Msg) {
			message.Header.Del(installationHeader)
		},
		"malformed_node": func(message *nats.Msg) { message.Header.Set(nodeHeader, "not-a-uuid") },
		"malformed_installation": func(message *nats.Msg) {
			message.Header.Set(installationHeader, "installation/invalid")
		},
		"malformed_config": func(message *nats.Msg) {
			changed := event
			changed.ConfigVersion = "config-v1"
			message.Header.Set(configHeader, changed.ConfigVersion)
			message.Data = marshalAccessEnvelope(t, "authority-message", now, []AccessEvent{changed})
		},
		"uppercase_config": func(message *nats.Msg) {
			changed := event
			changed.ConfigVersion = "018F47A2-5B9C-7D31-8A60-104C9C0B7182"
			message.Header.Set(configHeader, changed.ConfigVersion)
			message.Data = marshalAccessEnvelope(t, "authority-message", now, []AccessEvent{changed})
		},
		"nil_config": func(message *nats.Msg) {
			changed := event
			changed.ConfigVersion = "00000000-0000-0000-0000-000000000000"
			message.Header.Set(configHeader, changed.ConfigVersion)
			message.Data = marshalAccessEnvelope(t, "authority-message", now, []AccessEvent{changed})
		},
		"conflicting_node": func(message *nats.Msg) {
			message.Header.Set(nodeHeader, "30000000-0000-0000-0000-000000000002")
		},
		"conflicting_tenant": func(message *nats.Msg) {
			message.Header.Set(tenantHeader, "10000000-0000-0000-0000-000000000002")
		},
		"conflicting_site": func(message *nats.Msg) {
			message.Header.Set(siteHeader, "20000000-0000-0000-0000-000000000002")
		},
		"conflicting_config": func(message *nats.Msg) {
			message.Header.Set(configHeader, "018f47a2-5b9c-7d31-8a60-104c9c0b7183")
		},
		"duplicate_site": func(message *nats.Msg) { message.Header.Add(siteHeader, testSiteID) },
		"duplicate_node": func(message *nats.Msg) { message.Header.Add(nodeHeader, testNodeID) },
		"duplicate_tenant": func(message *nats.Msg) {
			message.Header.Add(tenantHeader, testTenantID)
		},
		"duplicate_config": func(message *nats.Msg) {
			message.Header.Add(configHeader, event.ConfigVersion)
		},
		"duplicate_installation": func(message *nats.Msg) {
			message.Header.Add(installationHeader, "installation-v1")
		},
		"extra_header": func(message *nats.Msg) { message.Header.Set("X-Untrusted", "value") },
		"uppercase_config_payload": func(message *nats.Msg) {
			changed := event
			changed.ConfigVersion = strings.ToUpper(event.ConfigVersion)
			message.Data = marshalAccessEnvelope(t, "authority-message", now, []AccessEvent{changed})
		},
		"payload_site": func(message *nats.Msg) {
			changed := event
			changed.SiteID = "20000000-0000-0000-0000-000000000002"
			message.Data = marshalAccessEnvelope(t, "authority-message", now, []AccessEvent{changed})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			message := newMessage()
			mutate(message)
			if got := (&natsIngestDelivery{message: message}).Subject(); got != "" {
				t.Fatalf("untrusted authority subject=%q", got)
			}
		})
	}
}

func TestNATSDeliveryRequiresUniqueBrokerMessageIDHeader(t *testing.T) {
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	event := validAccessEvent("authority-event")
	event.ConfigVersion = testConfigVersionID
	subject, _ := IngestSubject(testNodeID)
	newMessage := func() *nats.Msg {
		message := nats.NewMsg(subject)
		message.Data = marshalAccessEnvelope(t, "authority-message", now, []AccessEvent{event})
		message.Header.Set(nats.MsgIdHdr, "authority-message")
		message.Header.Set(ingestNodeHeader, testNodeID)
		message.Header.Set(ingestTenantHeader, testTenantID)
		message.Header.Set(ingestSiteHeader, testSiteID)
		message.Header.Set(ingestConfigHeader, event.ConfigVersion)
		message.Header.Set(ingestInstallHeader, "installation-v1")
		return message
	}

	for name, mutate := range map[string]func(*nats.Msg){
		"missing":   func(message *nats.Msg) { message.Header.Del(nats.MsgIdHdr) },
		"duplicate": func(message *nats.Msg) { message.Header.Add(nats.MsgIdHdr, "authority-message") },
		"invalid":   func(message *nats.Msg) { message.Header.Set(nats.MsgIdHdr, "authority message") },
	} {
		t.Run(name, func(t *testing.T) {
			message := newMessage()
			mutate(message)
			if got := (&natsIngestDelivery{message: message}).Subject(); got != "" {
				t.Fatalf("untrusted message ID subject=%q", got)
			}
		})
	}
}
