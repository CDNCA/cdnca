package edgestatus

import (
	"testing"

	"github.com/nats-io/nats.go"
)

func TestStatusConsumerRequiresOrderedLegacyAndEventFilters(t *testing.T) {
	config := DefaultNATSConsumerConfig()
	want := []string{config.SubjectPrefix + ".*", config.SubjectPrefix + ".generic-v2.*.*"}
	consumer := &nats.ConsumerInfo{Config: nats.ConsumerConfig{
		Durable: config.Durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		AckWait: config.AckWait, MaxDeliver: -1, FilterSubjects: append([]string(nil), want...),
		ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: config.MaxAckPending,
		MaxWaiting: config.MaxWaiting, MaxRequestBatch: 1, MaxRequestExpires: config.FetchTimeout,
	}}
	if !sameStatusConsumer(consumer, config) {
		t.Fatal("canonical legacy/event deployment status filters were rejected")
	}

	for name, filters := range map[string][]string{
		"legacy only": {want[0]},
		"event only":  {want[1]},
		"reordered":   {want[1], want[0]},
		"extra":       {want[0], want[1], config.SubjectPrefix + ".>"},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *consumer
			candidate.Config = consumer.Config
			candidate.Config.FilterSubjects = filters
			if sameStatusConsumer(&candidate, config) {
				t.Fatal("drifted deployment status filters were accepted")
			}
		})
	}

	legacy := *consumer
	legacy.Config = consumer.Config
	legacy.Config.FilterSubject = want[0]
	legacy.Config.FilterSubjects = nil
	if sameStatusConsumer(&legacy, config) {
		t.Fatal("legacy-only FilterSubject was accepted")
	}
}
