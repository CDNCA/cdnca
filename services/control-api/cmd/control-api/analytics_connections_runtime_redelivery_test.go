package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/nats-io/nats.go"
)

type analyticsConnectionsJetStreamStub struct {
	streams       map[string]*nats.StreamInfo
	consumers     map[string]*nats.ConsumerInfo
	streamInfoErr error
	consumerErr   error
	operations    []string
}

func (stub *analyticsConnectionsJetStreamStub) StreamInfo(name string, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	stub.operations = append(stub.operations, "stream-info:"+name)
	if stub.streamInfoErr != nil {
		return nil, stub.streamInfoErr
	}
	info := stub.streams[name]
	if info == nil {
		return nil, nats.ErrStreamNotFound
	}
	return info, nil
}

func (stub *analyticsConnectionsJetStreamStub) AddStream(config *nats.StreamConfig, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	stub.operations = append(stub.operations, "stream-add:"+config.Name)
	info := &nats.StreamInfo{Config: *config}
	stub.streams[config.Name] = info
	return info, nil
}

func (stub *analyticsConnectionsJetStreamStub) ConsumerInfo(stream, durable string, _ ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	stub.operations = append(stub.operations, "consumer-info:"+stream+":"+durable)
	if stub.consumerErr != nil {
		return nil, stub.consumerErr
	}
	info := stub.consumers[stream+":"+durable]
	if info == nil {
		return nil, nats.ErrConsumerNotFound
	}
	return info, nil
}

func (stub *analyticsConnectionsJetStreamStub) AddConsumer(stream string, config *nats.ConsumerConfig, _ ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	stub.operations = append(stub.operations, "consumer-add:"+stream+":"+config.Durable)
	info := &nats.ConsumerInfo{Stream: stream, Name: config.Durable, Config: *config}
	stub.consumers[stream+":"+config.Durable] = info
	return info, nil
}

func TestAnalyticsConnectionsRuntimeCreatesFiniteDurableTopologyBeforeBinding(t *testing.T) {
	config := analyticsConnectionsRedeliveryConfig()
	stub := &analyticsConnectionsJetStreamStub{
		streams: make(map[string]*nats.StreamInfo), consumers: make(map[string]*nats.ConsumerInfo),
	}
	if err := ensureAnalyticsConnectionsJetStreamObjects(context.Background(), stub, config); err != nil {
		t.Fatalf("ensure topology: %v", err)
	}
	wantOperations := []string{
		"stream-info:CONNECTIONS_INGEST_V1", "stream-add:CONNECTIONS_INGEST_V1",
		"stream-info:CONNECTIONS_DEAD_V1", "stream-add:CONNECTIONS_DEAD_V1",
		"consumer-info:CONNECTIONS_INGEST_V1:control_api_connections",
		"consumer-add:CONNECTIONS_INGEST_V1:control_api_connections",
	}
	if !reflect.DeepEqual(stub.operations, wantOperations) {
		t.Fatalf("operations = %v", stub.operations)
	}
	consumer := stub.consumers[config.Stream+":"+config.Durable].Config
	if consumer.MaxDeliver < 2 || consumer.AckWait <= 0 || consumer.AckWait > time.Minute || len(consumer.BackOff) < 2 ||
		consumer.AckPolicy != nats.AckExplicitPolicy || consumer.FilterSubject != analyticsconnections.ConnectionsSubject {
		t.Fatalf("consumer is not finite and authoritative: %#v", consumer)
	}
}

func TestAnalyticsConnectionsRuntimeRejectsExistingTopologyDriftWithoutMutation(t *testing.T) {
	config := analyticsConnectionsRedeliveryConfig()
	tests := []struct {
		name   string
		mutate func(*nats.StreamConfig, *nats.StreamConfig, *nats.ConsumerConfig)
	}{
		{name: "source wildcard", mutate: func(source, _ *nats.StreamConfig, _ *nats.ConsumerConfig) {
			source.Subjects = []string{"cdnca.connections.v1.>"}
		}},
		{name: "source discard", mutate: func(source, _ *nats.StreamConfig, _ *nats.ConsumerConfig) { source.Discard = nats.DiscardOld }},
		{name: "dead letter retention", mutate: func(_, dead *nats.StreamConfig, _ *nats.ConsumerConfig) { dead.Retention = nats.WorkQueuePolicy }},
		{name: "unbounded max deliver", mutate: func(_, _ *nats.StreamConfig, consumer *nats.ConsumerConfig) { consumer.MaxDeliver = -1 }},
		{name: "missing backoff", mutate: func(_, _ *nats.StreamConfig, consumer *nats.ConsumerConfig) { consumer.BackOff = nil }},
		{name: "consumer subject", mutate: func(_, _ *nats.StreamConfig, consumer *nats.ConsumerConfig) {
			consumer.FilterSubject = "cdnca.connections.v1.>"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := analyticsConnectionsSourceStreamConfig(config)
			dead := analyticsConnectionsDeadLetterStreamConfig()
			consumer := analyticsConnectionsConsumerConfig(config)
			test.mutate(&source, &dead, &consumer)
			stub := &analyticsConnectionsJetStreamStub{
				streams: map[string]*nats.StreamInfo{
					config.Stream: {Config: source}, analyticsConnectionsDeadLetterStream: {Config: dead},
				},
				consumers: map[string]*nats.ConsumerInfo{
					config.Stream + ":" + config.Durable: {Stream: config.Stream, Name: config.Durable, Config: consumer},
				},
			}
			if err := ensureAnalyticsConnectionsJetStreamObjects(context.Background(), stub, config); err == nil {
				t.Fatal("drifted topology was accepted")
			}
			for _, operation := range stub.operations {
				if strings.Contains(operation, "-add:") {
					t.Fatalf("existing drift was mutated: %v", stub.operations)
				}
			}
		})
	}
}

func TestAnalyticsConnectionsRuntimeTopologyFailureIsSecretSafe(t *testing.T) {
	stub := &analyticsConnectionsJetStreamStub{
		streams: make(map[string]*nats.StreamInfo), consumers: make(map[string]*nats.ConsumerInfo),
		streamInfoErr: errors.New("dial failed password=secret-value"),
	}
	err := ensureAnalyticsConnectionsJetStreamObjects(context.Background(), stub, analyticsConnectionsRedeliveryConfig())
	if err == nil || strings.Contains(strings.ToLower(err.Error()), "secret-value") || strings.Contains(strings.ToLower(err.Error()), "password") {
		t.Fatalf("unsafe topology error = %v", err)
	}
}

func TestAnalyticsConnectionsRuntimeEnsuresTopologyBeforeSubscriberAndDocumentsContract(t *testing.T) {
	source, err := os.ReadFile("analytics_connections_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	ensureAt := strings.Index(string(source), "ensureAnalyticsConnectionsJetStream(ctx, connection, runtimeConfig)")
	subscriberAt := strings.Index(string(source), "analyticsconnections.NewNATSSubscriber(connection, runtimeConfig)")
	if ensureAt < 0 || subscriberAt < 0 || ensureAt > subscriberAt {
		t.Fatalf("topology is not ensured before subscriber binding")
	}
	for _, forbidden := range []string{"Attempt:", "PubAck:"} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("composition fabricated broker fact %q", forbidden)
		}
	}

	runbook, err := os.ReadFile("../../../../docs/runbooks/analytics-storage.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"CONNECTIONS_INGEST_V1", "CONNECTIONS_DEAD_V1", "control_api_connections",
		"MaxDeliver=8", "AckWait=30s", "BackOff", "DLQ PubAck", "Term",
	} {
		if !strings.Contains(string(runbook), required) {
			t.Fatalf("runbook missing %q", required)
		}
	}
}

func analyticsConnectionsRedeliveryConfig() analyticsconnections.RuntimeConfig {
	return analyticsconnections.RuntimeConfig{
		Enabled: true, Stream: "CONNECTIONS_INGEST_V1", Durable: "control_api_connections",
		Subject: analyticsconnections.ConnectionsSubject, OperationTimeout: time.Second,
	}
}
