package pluginwebhook

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestJetStreamContractIsDurableBoundedAndFileBacked(t *testing.T) {
	t.Parallel()
	config := DefaultJetStreamConfig()
	if err := validateJetStreamConfig(config); err != nil {
		t.Fatal(err)
	}
	delivery := expectedDeliveryStream(config)
	if delivery.Retention != nats.WorkQueuePolicy || delivery.Storage != nats.FileStorage ||
		delivery.Subjects[0] != DefaultDeliverySubjectPrefix+".*.*" || delivery.MaxConsumers != 1 ||
		delivery.MaxAge <= 0 || delivery.MaxBytes <= 0 || delivery.MaxMsgs <= 0 ||
		delivery.MaxMsgSize != MaxQueueMessageBytes || delivery.Duplicates <= 0 || delivery.Discard != nats.DiscardNew {
		t.Fatalf("delivery stream = %#v", delivery)
	}
	consumer := expectedDeliveryConsumer(config)
	if consumer.Durable != DefaultDeliveryDurable || consumer.AckPolicy != nats.AckExplicitPolicy ||
		consumer.DeliverPolicy != nats.DeliverAllPolicy || consumer.AckWait != 2*time.Minute ||
		consumer.MaxDeliver != config.ConsumerMaxDeliver || consumer.MaxAckPending <= 0 ||
		consumer.FilterSubject != DefaultDeliverySubjectPrefix+".*.*" {
		t.Fatalf("consumer = %#v", consumer)
	}
	dead := expectedDeadLetterStream(config)
	if dead.Retention != nats.LimitsPolicy || dead.Storage != nats.FileStorage ||
		dead.Subjects[0] != DefaultDeadLetterSubject || dead.MaxAge < 30*24*time.Hour {
		t.Fatalf("dead-letter stream = %#v", dead)
	}
}

func TestJetStreamContractRejectsMismatchedOrUnboundedSettings(t *testing.T) {
	t.Parallel()
	valid := DefaultJetStreamConfig()
	tests := []struct {
		name   string
		mutate func(*JetStreamConfig)
	}{
		{"invalid stream", func(c *JetStreamConfig) { c.DeliveryStream = "bad.stream" }},
		{"overlapping stream", func(c *JetStreamConfig) { c.DeadLetterStream = c.DeliveryStream }},
		{"unbounded max bytes", func(c *JetStreamConfig) { c.StreamMaxBytes = -1 }},
		{"short retention", func(c *JetStreamConfig) { c.StreamMaxAge = 0 }},
		{"short ack wait", func(c *JetStreamConfig) { c.AckWait = c.OperationTimeout }},
		{"too few deliveries", func(c *JetStreamConfig) { c.ConsumerMaxDeliver = 1 }},
		{"wildcard dead subject", func(c *JetStreamConfig) { c.DeadLetterSubject = "cdnca.>" }},
		{"bad replicas", func(c *JetStreamConfig) { c.Replicas = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if err := validateJetStreamConfig(config); err == nil {
				t.Fatalf("configuration accepted: %#v", config)
			}
		})
	}
}
