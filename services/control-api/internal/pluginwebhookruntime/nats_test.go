package pluginwebhookruntime

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

func TestDeliverySubjectBindsBrokerMessageIdentity(t *testing.T) {
	prefix := DefaultDeliverySubjectPrefix
	tenantScope := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	subscription := uuid.MustParse("223e4567-e89b-12d3-a456-426614174001")
	delivery := uuid.MustParse("323e4567-e89b-12d3-a456-426614174002")
	message := nats.NewMsg(deliverySubject(prefix, tenantScope, subscription, delivery))
	message.Header.Set("X-CDNCA-Webhook-Id", delivery.String())
	actualScope, actualSubscription, err := (&runtimeMessage{message: message}).Scope(prefix)
	if err != nil || actualScope != tenantScope || actualSubscription != subscription {
		t.Fatalf("delivery-bound subject rejected: scope=%s subscription=%s err=%v", actualScope, actualSubscription, err)
	}
	for name, subject := range map[string]string{
		"legacy subscription-only": prefix + "." + tenantScope.String() + "." + subscription.String(),
		"different delivery":       deliverySubject(prefix, tenantScope, subscription, uuid.New()),
	} {
		message.Subject = subject
		if _, _, err = (&runtimeMessage{message: message}).Scope(prefix); err == nil {
			t.Fatalf("%s subject identity was accepted", name)
		}
	}
	for name, mutate := range map[string]func(*nats.Msg){
		"compact tenant": func(message *nats.Msg) {
			message.Subject = deliverySubject(prefix, tenantScope, subscription, delivery)
			message.Subject = strings.Replace(message.Subject, tenantScope.String(), strings.ReplaceAll(tenantScope.String(), "-", ""), 1)
		},
		"uppercase subscription": func(message *nats.Msg) {
			message.Subject = deliverySubject(prefix, tenantScope, subscription, delivery)
			message.Subject = strings.Replace(message.Subject, subscription.String(), strings.ToUpper(subscription.String()), 1)
		},
		"compact subject delivery": func(message *nats.Msg) {
			message.Subject = deliverySubject(prefix, tenantScope, subscription, delivery)
			message.Subject = strings.Replace(message.Subject, delivery.String(), strings.ReplaceAll(delivery.String(), "-", ""), 1)
		},
		"uppercase delivery header": func(message *nats.Msg) {
			message.Subject = deliverySubject(prefix, tenantScope, subscription, delivery)
			message.Header.Set("X-CDNCA-Webhook-Id", strings.ToUpper(delivery.String()))
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := nats.NewMsg(deliverySubject(prefix, tenantScope, subscription, delivery))
			candidate.Header.Set("X-CDNCA-Webhook-Id", delivery.String())
			mutate(candidate)
			if _, _, candidateErr := (&runtimeMessage{message: candidate}).Scope(prefix); candidateErr == nil {
				t.Fatal("noncanonical broker identity was accepted")
			}
		})
	}
}

func TestStoredDeliveryMessageRequiresPositiveExactBrokerIdentity(t *testing.T) {
	delivery := uuid.New()
	expected := nats.NewMsg(deliverySubject(DefaultDeliverySubjectPrefix, uuid.New(), uuid.New(), delivery))
	expected.Data = []byte(`{"test":true}`)
	expected.Header.Set(nats.MsgIdHdr, "plugin-webhook-v2-"+fmt.Sprintf("%064x", 1))
	expected.Header.Set("X-CDNCA-Webhook-Id", delivery.String())
	digest := sha256.Sum256(expected.Data)
	expected.Header.Set("X-CDNCA-Webhook-Queue-Sha256", fmt.Sprintf("%x", digest[:]))
	stored := &nats.RawStreamMsg{Subject: expected.Subject, Sequence: 1, Header: expected.Header, Data: expected.Data}
	if !storedDeliveryMessageMatches(stored, expected) {
		t.Fatal("exact positive broker identity was rejected")
	}
	stored.Sequence = 0
	if storedDeliveryMessageMatches(stored, expected) {
		t.Fatal("zero broker sequence was accepted")
	}
	stored.Sequence = 1
	clonedHeader := make(nats.Header, len(stored.Header))
	for name, values := range stored.Header {
		clonedHeader[name] = append([]string(nil), values...)
	}
	stored.Header = clonedHeader
	stored.Header.Set(nats.MsgIdHdr, "plugin-webhook-v2-"+fmt.Sprintf("%064x", 2))
	if storedDeliveryMessageMatches(stored, expected) {
		t.Fatal("different stable message identity was accepted")
	}
}

func TestStoredDeadLetterMessageRequiresExactCASWire(t *testing.T) {
	delivery := uuid.New()
	expected := nats.NewMsg(DefaultDeadLetterSubject)
	expected.Data = []byte(`{"delivery_id":"` + delivery.String() + `"}`)
	expected.Header.Set(nats.MsgIdHdr, "plugin-webhook-dlq-v1-"+fmt.Sprintf("%064x", 1))
	expected.Header.Set(nats.ExpectedStreamHdr, DefaultDeadLetterStream)
	digest := sha256.Sum256(expected.Data)
	expected.Header.Set("X-CDNCA-Webhook-DLQ-Payload-Sha256", fmt.Sprintf("%x", digest[:]))

	stored := &nats.RawStreamMsg{
		Subject: expected.Subject, Sequence: 8, Data: expected.Data,
		Header: cloneNATSHeader(expected.Header),
	}
	stored.Header.Set(nats.ExpectedLastSeqHdr, "7")
	if !storedDeadLetterMessageMatches(stored, expected) {
		t.Fatal("exact DLQ CAS wire was rejected")
	}

	tests := map[string]func(*nats.RawStreamMsg){
		"missing CAS header": func(message *nats.RawStreamMsg) {
			message.Header.Del(nats.ExpectedLastSeqHdr)
		},
		"non-adjacent CAS sequence": func(message *nats.RawStreamMsg) {
			message.Sequence++
		},
		"invalid CAS sequence": func(message *nats.RawStreamMsg) {
			message.Header.Set(nats.ExpectedLastSeqHdr, "invalid")
		},
		"extra header": func(message *nats.RawStreamMsg) {
			message.Header.Set("X-Unexpected", "1")
		},
		"uppercase digest": func(message *nats.RawStreamMsg) {
			message.Header.Set("X-CDNCA-Webhook-DLQ-Payload-Sha256", strings.ToUpper(message.Header.Get("X-CDNCA-Webhook-DLQ-Payload-Sha256")))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := &nats.RawStreamMsg{
				Subject: stored.Subject, Sequence: stored.Sequence, Data: append([]byte(nil), stored.Data...),
				Header: cloneNATSHeader(stored.Header),
			}
			mutate(candidate)
			if storedDeadLetterMessageMatches(candidate, expected) {
				t.Fatal("invalid DLQ CAS wire was accepted")
			}
		})
	}
}

func cloneNATSHeader(header nats.Header) nats.Header {
	clone := make(nats.Header, len(header))
	for name, values := range header {
		clone[name] = append([]string(nil), values...)
	}
	return clone
}

func TestSameStreamRejectsBehavioralMismatches(t *testing.T) {
	expected := deliveryStreamConfig(DefaultJetStreamConfig())
	if !sameStream(&nats.StreamInfo{Config: *expected}, expected) {
		t.Fatal("matching stream was rejected")
	}
	serverDecorated := *expected
	serverDecorated.Metadata = map[string]string{"_nats.level": "1", "_nats.req.level": "0", "_nats.ver": "2.11.4"}
	if !sameStream(&nats.StreamInfo{Config: serverDecorated}, expected) {
		t.Fatal("server-reserved stream metadata was rejected")
	}
	tests := map[string]func(*nats.StreamConfig){
		"description":               func(config *nats.StreamConfig) { config.Description = "unexpected" },
		"metadata":                  func(config *nats.StreamConfig) { config.Metadata = map[string]string{"owner": "unexpected"} },
		"unknown reserved metadata": func(config *nats.StreamConfig) { config.Metadata = map[string]string{"_nats.unexpected": "1"} },
		"template":                  func(config *nats.StreamConfig) { config.Template = "unexpected" },
		"no ack":                    func(config *nats.StreamConfig) { config.NoAck = true },
		"placement":                 func(config *nats.StreamConfig) { config.Placement = &nats.Placement{Tags: []string{"ssd"}} },
		"compression":               func(config *nats.StreamConfig) { config.Compression = nats.S2Compression },
		"deny delete":               func(config *nats.StreamConfig) { config.DenyDelete = true },
		"deny purge":                func(config *nats.StreamConfig) { config.DenyPurge = true },
		"sealed":                    func(config *nats.StreamConfig) { config.Sealed = true },
		"allow rollup":              func(config *nats.StreamConfig) { config.AllowRollup = true },
		"allow message ttl":         func(config *nats.StreamConfig) { config.AllowMsgTTL = true },
		"first sequence":            func(config *nats.StreamConfig) { config.FirstSeq = 7 },
		"messages per subject":      func(config *nats.StreamConfig) { config.MaxMsgsPerSubject = 1 },
		"discard new per subject":   func(config *nats.StreamConfig) { config.DiscardNewPerSubject = true },
		"mirror":                    func(config *nats.StreamConfig) { config.Mirror = &nats.StreamSource{Name: "OTHER"} },
		"sources":                   func(config *nats.StreamConfig) { config.Sources = []*nats.StreamSource{{Name: "OTHER"}} },
		"allow direct":              func(config *nats.StreamConfig) { config.AllowDirect = true },
		"mirror direct":             func(config *nats.StreamConfig) { config.MirrorDirect = true },
		"consumer limits": func(config *nats.StreamConfig) {
			config.ConsumerLimits = nats.StreamConsumerLimits{InactiveThreshold: time.Minute, MaxAckPending: 1}
		},
		"subject delete marker ttl": func(config *nats.StreamConfig) { config.SubjectDeleteMarkerTTL = time.Minute },
		"subject transform": func(config *nats.StreamConfig) {
			config.SubjectTransform = &nats.SubjectTransformConfig{Destination: "cdnca.transformed"}
		},
		"republish": func(config *nats.StreamConfig) {
			config.RePublish = &nats.RePublish{Destination: "cdnca.republished"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			actual := *expected
			mutate(&actual)
			if sameStream(&nats.StreamInfo{Config: actual}, expected) {
				t.Fatal("behavioral stream mismatch was accepted")
			}
		})
	}
}

func TestSameConsumerRejectsBehavioralMismatches(t *testing.T) {
	expected := consumerConfig(DefaultJetStreamConfig())
	if !sameConsumer(&nats.ConsumerInfo{Config: *expected}, expected) {
		t.Fatal("matching consumer was rejected")
	}
	serverDecorated := *expected
	serverDecorated.Metadata = map[string]string{"_nats.level": "1", "_nats.req.level": "0", "_nats.ver": "2.11.4"}
	if !sameConsumer(&nats.ConsumerInfo{Config: serverDecorated}, expected) {
		t.Fatal("server-reserved consumer metadata was rejected")
	}
	tests := map[string]func(*nats.ConsumerConfig){
		"name":                      func(config *nats.ConsumerConfig) { config.Name = "unexpected" },
		"description":               func(config *nats.ConsumerConfig) { config.Description = "unexpected" },
		"metadata":                  func(config *nats.ConsumerConfig) { config.Metadata = map[string]string{"owner": "unexpected"} },
		"unknown reserved metadata": func(config *nats.ConsumerConfig) { config.Metadata = map[string]string{"_nats.unexpected": "1"} },
		"start sequence": func(config *nats.ConsumerConfig) {
			config.DeliverPolicy, config.OptStartSeq = nats.DeliverByStartSequencePolicy, 2
		},
		"start time": func(config *nats.ConsumerConfig) {
			value := time.Unix(1700000000, 0).UTC()
			config.DeliverPolicy, config.OptStartTime = nats.DeliverByStartTimePolicy, &value
		},
		"backoff":              func(config *nats.ConsumerConfig) { config.BackOff = []time.Duration{config.AckWait} },
		"headers only":         func(config *nats.ConsumerConfig) { config.HeadersOnly = true },
		"rate limit":           func(config *nats.ConsumerConfig) { config.RateLimit = 1 },
		"inactive threshold":   func(config *nats.ConsumerConfig) { config.InactiveThreshold = time.Minute },
		"replicas":             func(config *nats.ConsumerConfig) { config.Replicas = 1 },
		"force memory storage": func(config *nats.ConsumerConfig) { config.MemoryStorage = true },
		"filter subjects": func(config *nats.ConsumerConfig) {
			config.FilterSubject = ""
			config.FilterSubjects = []string{"cdnca.plugin-webhook.delivery.v2.*.*"}
		},
		"sample frequency":    func(config *nats.ConsumerConfig) { config.SampleFrequency = "100%" },
		"flow control":        func(config *nats.ConsumerConfig) { config.FlowControl = true },
		"heartbeat":           func(config *nats.ConsumerConfig) { config.Heartbeat = time.Second },
		"deliver subject":     func(config *nats.ConsumerConfig) { config.DeliverSubject = "cdnca.delivery.push" },
		"deliver group":       func(config *nats.ConsumerConfig) { config.DeliverGroup = "workers" },
		"max request batch":   func(config *nats.ConsumerConfig) { config.MaxRequestBatch = 2 },
		"max request expires": func(config *nats.ConsumerConfig) { config.MaxRequestExpires++ },
		"max request bytes":   func(config *nats.ConsumerConfig) { config.MaxRequestMaxBytes++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			actual := *expected
			mutate(&actual)
			if sameConsumer(&nats.ConsumerInfo{Config: actual}, expected) {
				t.Fatal("behavioral consumer mismatch was accepted")
			}
		})
	}
}
