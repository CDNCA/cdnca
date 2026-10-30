package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

const testStatusTraceparent = "00-11111111111111111111111111111111-2222222222222222-01"

func TestDeploymentStatusCorrelationHeadersComeFromEvent(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	stream := &deploymentStatusPubAckJetStream{ack: &nats.PubAck{Stream: config.StatusStream, Sequence: 73}}
	bus := &NATSCommandBus{js: stream, config: config}
	status := correlatedDeploymentStatus()

	if _, err := bus.PublishStatus(t.Context(), testNodeID, status); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		nats.MsgIdHdr:          status.Event.EventId,
		"Cdnca-Request-Id":     status.Event.RequestId,
		"Cdnca-Task-Id":        status.Event.GetTaskId(),
		"traceparent":          status.Event.Traceparent,
		"Cdnca-Correlation-Id": status.Event.CorrelationId,
	}
	for key, value := range want {
		if got := stream.published.Header.Values(key); len(got) != 1 || got[0] != value {
			t.Fatalf("header %s = %q, want one exact event value", key, got)
		}
	}
}

func TestDeploymentStatusCorrelationRejectsInvalidMetadataBeforePublish(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	for _, test := range []struct {
		name   string
		mutate func(*agentv1.DeploymentStatus)
		secret string
	}{
		{name: "request", mutate: func(value *agentv1.DeploymentStatus) { value.Event.RequestId = "forged-request" }, secret: "forged-request"},
		{name: "correlation", mutate: func(value *agentv1.DeploymentStatus) { value.Event.CorrelationId = strings.Repeat("c", 129) }, secret: strings.Repeat("c", 129)},
		{name: "traceparent", mutate: func(value *agentv1.DeploymentStatus) { value.Event.Traceparent = strings.Repeat("t", 129) }, secret: strings.Repeat("t", 129)},
		{name: "empty task", mutate: func(value *agentv1.DeploymentStatus) { task := ""; value.Event.TaskId = &task }},
		{name: "task", mutate: func(value *agentv1.DeploymentStatus) { task := strings.Repeat("k", 129); value.Event.TaskId = &task }, secret: strings.Repeat("k", 129)},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := &deploymentStatusPubAckJetStream{ack: &nats.PubAck{Stream: config.StatusStream, Sequence: 73}}
			bus := &NATSCommandBus{js: stream, config: config}
			status := correlatedDeploymentStatus()
			test.mutate(status)
			_, err := bus.PublishStatus(t.Context(), testNodeID, status)
			if err == nil || stream.publishes != 0 || (test.secret != "" && strings.Contains(err.Error(), test.secret)) {
				t.Fatalf("invalid metadata err=%v publishes=%d", err, stream.publishes)
			}
		})
	}
}

func TestDeploymentStatusCorrelationReplayRequiresExactHeaders(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	status := correlatedDeploymentStatus()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	subject := config.StatusSubjectPrefix + ".generic-v2." + testNodeID + "." + status.Event.EventId
	exact := deploymentStatusCorrelationHeaders(status, config)
	tests := []struct {
		name   string
		mutate func(nats.Header)
	}{
		{name: "exact"},
		{name: "missing request", mutate: func(header nats.Header) { header.Del("Cdnca-Request-Id") }},
		{name: "duplicate task", mutate: func(header nats.Header) { header.Add("Cdnca-Task-Id", status.Event.GetTaskId()) }},
		{name: "wrong trace", mutate: func(header nats.Header) {
			header.Set("traceparent", "00-33333333333333333333333333333333-4444444444444444-01")
		}},
		{name: "wrong correlation", mutate: func(header nats.Header) { header.Set("Cdnca-Correlation-Id", uuid.NewString()) }},
		{name: "extra task when absent", mutate: func(header nats.Header) { header.Set("Cdnca-Task-Id", "other-task") }},
		{name: "unapproved header", mutate: func(header nats.Header) { header.Set("X-Forwarded-Secret", "must-not-pass") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := proto.Clone(status).(*agentv1.DeploymentStatus)
			header := cloneStatusHeaders(exact)
			if test.name == "extra task when absent" {
				candidate.Event.TaskId = nil
				payload, err = proto.MarshalOptions{Deterministic: true}.Marshal(candidate)
				if err != nil {
					t.Fatal(err)
				}
				header = deploymentStatusCorrelationHeaders(candidate, config)
			}
			if test.mutate != nil {
				test.mutate(header)
			}
			stream := &deploymentStatusPubAckJetStream{messages: map[string]*nats.RawStreamMsg{subject: {
				Subject: subject, Sequence: 73, Data: payload, Header: header,
			}}}
			bus := &NATSCommandBus{js: stream, config: config}
			publication, err := bus.PublishStatus(context.Background(), testNodeID, candidate)
			if test.name == "exact" {
				if err != nil || publication.Sequence != 73 || stream.publishes != 0 {
					t.Fatalf("exact replay=(%+v,%v) publishes=%d", publication, err, stream.publishes)
				}
				return
			}
			if err == nil || stream.publishes != 0 || strings.Contains(err.Error(), status.Event.RequestId) ||
				strings.Contains(err.Error(), status.Event.CorrelationId) || strings.Contains(err.Error(), status.Event.GetTaskId()) {
				t.Fatalf("conflicting replay=(%+v,%v) publishes=%d", publication, err, stream.publishes)
			}
		})
	}
}

func TestDeploymentStatusCorrelationHealthCountsBoundedOutcomes(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	status := correlatedDeploymentStatus()
	health := NewCorrelationHealth()
	acceptedStream := &deploymentStatusPubAckJetStream{ack: &nats.PubAck{Stream: config.StatusStream, Sequence: 73}}
	acceptedBus := &NATSCommandBus{js: acceptedStream, config: config, correlationHealth: health}
	if _, err := acceptedBus.PublishStatus(t.Context(), testNodeID, status); err != nil {
		t.Fatal(err)
	}

	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	subject := config.StatusSubjectPrefix + ".generic-v2." + testNodeID + "." + status.Event.EventId
	replayStream := &deploymentStatusPubAckJetStream{messages: map[string]*nats.RawStreamMsg{subject: {
		Subject: subject, Sequence: 73, Data: payload, Header: deploymentStatusCorrelationHeaders(status, config),
	}}}
	replayBus := &NATSCommandBus{js: replayStream, config: config, correlationHealth: health}
	if _, err := replayBus.PublishStatus(t.Context(), testNodeID, status); err != nil {
		t.Fatal(err)
	}

	rejected := proto.Clone(status).(*agentv1.DeploymentStatus)
	rejected.Event.RequestId = "not-a-uuid"
	if _, err := replayBus.PublishStatus(t.Context(), testNodeID, rejected); err == nil {
		t.Fatal("invalid correlation metadata was accepted")
	}

	failedStream := &deploymentStatusPubAckJetStream{err: errors.New("nats unavailable")}
	failedBus := &NATSCommandBus{js: failedStream, config: config, correlationHealth: health}
	if _, err := failedBus.PublishStatus(t.Context(), testNodeID, status); err == nil {
		t.Fatal("publish failure was accepted")
	}

	succeeded := correlatedDeploymentStatus()
	succeeded.Event.EventId = uuid.NewString()
	succeeded.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY
	if _, err := acceptedBus.PublishStatus(t.Context(), testNodeID, succeeded); err != nil {
		t.Fatal(err)
	}
	failed := correlatedDeploymentStatus()
	failed.Event.EventId = uuid.NewString()
	failed.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED
	if _, err := acceptedBus.PublishStatus(t.Context(), testNodeID, failed); err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(health.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var snapshot map[string]any
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"accepted": 3.0, "replayed": 1.0, "rejected": 1.0, "publish_failed": 1.0,
		"terminal_succeeded": 1.0, "terminal_failed": 1.0,
		"last_result_code": "EDGE_ACTIVATION_FAILED",
	}
	for key, value := range want {
		if snapshot[key] != value {
			t.Fatalf("correlation health[%s] = %#v, want %#v; snapshot=%s", key, snapshot[key], value, encoded)
		}
	}
}

func correlatedDeploymentStatus() *agentv1.DeploymentStatus {
	status := validDeploymentStatus(validDeploymentCommand())
	status.Event.Traceparent = testStatusTraceparent
	task := "deployment-task"
	status.Event.TaskId = &task
	return status
}

func cloneStatusHeaders(source nats.Header) nats.Header {
	cloned := nats.Header{}
	for key, values := range source {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}
