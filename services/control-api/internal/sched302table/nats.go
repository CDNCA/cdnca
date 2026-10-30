package sched302table

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

// NATSPublisher publishes to the stream agent-gateway owns
// (sched302.CommandStream, one newest table per node). Until the gateway
// has created it every publish fails and the worker retries next tick.
type NATSPublisher struct {
	js      nats.JetStreamContext
	timeout time.Duration
}

func NewNATSPublisher(connection *nats.Conn, timeout time.Duration) (*NATSPublisher, error) {
	if connection == nil || connection.IsClosed() || timeout <= 0 {
		return nil, errors.New("schedule302 NATS publisher requires an active connection")
	}
	js, err := connection.JetStream(nats.MaxWait(timeout))
	if err != nil {
		return nil, err
	}
	return &NATSPublisher{js: js, timeout: timeout}, nil
}

func (publisher *NATSPublisher) Publish(ctx context.Context, nodeID string, table *agentv1.Sched302Table) error {
	if table == nil || table.NodeId != nodeID || table.Event == nil {
		return fmt.Errorf("schedule302 table does not belong to %s", nodeID)
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(table)
	if err != nil || len(payload) > sched302.MaxCarrierBytes {
		return errors.New("encode schedule302 table carrier")
	}
	message := nats.NewMsg(sched302.CommandSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, table.Event.EventId)
	operation, cancel := context.WithTimeout(ctx, publisher.timeout)
	defer cancel()
	ack, err := publisher.js.PublishMsg(message, nats.Context(operation), nats.ExpectStream(sched302.CommandStream))
	if err != nil || ack == nil || ack.Stream != sched302.CommandStream || ack.Sequence == 0 {
		return fmt.Errorf("persist schedule302 table: %w", err)
	}
	return nil
}
