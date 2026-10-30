package edgeoutbox

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

type messagePublisher interface {
	publish(context.Context, string, []byte, string, string) (publishAck, error)
}

type natsPublisher struct {
	jetstream nats.JetStreamContext
}

func newNATSPublisher(connection *nats.Conn, operationTimeout time.Duration) (*natsPublisher, error) {
	if connection == nil || connection.IsClosed() {
		return nil, fmt.Errorf("active NATS connection is required")
	}
	jetstream, err := connection.JetStream(nats.MaxWait(operationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create edge command JetStream context: %w", err)
	}
	return &natsPublisher{jetstream: jetstream}, nil
}

func (p *natsPublisher) publish(ctx context.Context, subject string, payload []byte, messageID, expectedStream string) (publishAck, error) {
	message := nats.NewMsg(subject)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, messageID)
	acknowledgement, err := p.jetstream.PublishMsg(message, nats.Context(ctx), nats.ExpectStream(expectedStream))
	if err != nil {
		return publishAck{}, err
	}
	if acknowledgement == nil {
		return publishAck{}, fmt.Errorf("JetStream returned no publish acknowledgement")
	}
	return publishAck{stream: acknowledgement.Stream, duplicate: acknowledgement.Duplicate}, nil
}
