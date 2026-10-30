package firewalldispatch

// Default production contract: AGENT_FIREWALL_COMMANDS / AGENT_FIREWALL_STATUS,
// cdnca.agent.firewall.commands / cdnca.agent.firewall.status.

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type statusDelivery interface {
	payload() []byte
	ack(context.Context) error
	nak(context.Context) error
	term(context.Context) error
}

type messageTransport interface {
	publish(context.Context, string, []byte, string, string) (*publishAck, error)
}

type statusTransport interface {
	nextStatus(context.Context) (statusDelivery, error)
}

type natsTransport struct {
	js       nats.JetStreamContext
	statuses *nats.Subscription
	config   Config
}

func newNATSTransport(connection *nats.Conn, config Config) (*natsTransport, error) {
	if connection == nil || connection.IsClosed() {
		return nil, fmt.Errorf("%w: active NATS connection is required", ErrInvalidConfig)
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create firewall JetStream context: %w", err)
	}
	consumer := &nats.ConsumerConfig{Durable: config.StatusConsumer, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: config.LeaseTimeout, MaxDeliver: -1,
		FilterSubject: config.StatusSubjectPrefix + ".>", ReplayPolicy: nats.ReplayInstantPolicy,
		MaxWaiting: 16, MaxAckPending: config.BatchSize, MaxRequestBatch: 1,
		MaxRequestExpires: config.OperationTimeout}
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	_, err = js.AddConsumer(config.StatusStream, consumer, nats.Context(operationCtx))
	cancel()
	if err != nil {
		operationCtx, cancel = context.WithTimeout(context.Background(), config.OperationTimeout)
		info, infoErr := js.ConsumerInfo(config.StatusStream, config.StatusConsumer, nats.Context(operationCtx))
		cancel()
		if infoErr != nil || info == nil || info.Config.Durable != consumer.Durable ||
			info.Config.FilterSubject != consumer.FilterSubject || info.Config.AckPolicy != consumer.AckPolicy {
			return nil, fmt.Errorf("bind firewall status consumer: %w", err)
		}
	}
	subscription, err := js.PullSubscribe(consumer.FilterSubject, consumer.Durable, nats.Bind(config.StatusStream, consumer.Durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe firewall status stream: %w", err)
	}
	return &natsTransport{js: js, statuses: subscription, config: config}, nil
}

func (t *natsTransport) publish(ctx context.Context, subject string, payload []byte, messageID, stream string) (*publishAck, error) {
	message := nats.NewMsg(subject)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, messageID)
	ack, err := t.js.PublishMsg(message, nats.Context(ctx), nats.ExpectStream(stream))
	if err != nil {
		return nil, err
	}
	if ack == nil {
		return nil, nil
	}
	return &publishAck{stream: ack.Stream, sequence: ack.Sequence, duplicate: ack.Duplicate}, nil
}

func (t *natsTransport) nextStatus(ctx context.Context) (statusDelivery, error) {
	messages, err := t.statuses.Fetch(1, nats.Context(ctx))
	if err != nil {
		return nil, err
	}
	if len(messages) != 1 || messages[0] == nil ||
		!strings.HasPrefix(messages[0].Subject, t.config.StatusSubjectPrefix+".") ||
		len(messages[0].Data) == 0 || len(messages[0].Data) > t.config.MaxStatusBytes {
		if len(messages) == 1 && messages[0] != nil {
			_ = messages[0].Term()
		}
		return nil, ErrStatusConflict
	}
	status := new(agentv1.FirewallStatus)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, status); err != nil ||
		messages[0].Subject != t.config.StatusSubjectPrefix+"."+status.NodeId+"."+status.TaskId+"."+hex.EncodeToString(status.CommandSha256) {
		_ = messages[0].Term()
		return nil, ErrStatusConflict
	}
	return &natsStatusDelivery{message: messages[0], operationTimeout: t.config.OperationTimeout}, nil
}

type natsStatusDelivery struct {
	message          *nats.Msg
	operationTimeout time.Duration
}

func (d *natsStatusDelivery) payload() []byte { return d.message.Data }

func (d *natsStatusDelivery) ack(ctx context.Context) error {
	operationCtx, cancel := context.WithTimeout(ctx, d.operationTimeout)
	defer cancel()
	return d.message.Ack(nats.Context(operationCtx))
}

func (d *natsStatusDelivery) nak(ctx context.Context) error {
	operationCtx, cancel := context.WithTimeout(ctx, d.operationTimeout)
	defer cancel()
	return d.message.Nak(nats.Context(operationCtx))
}

func (d *natsStatusDelivery) term(ctx context.Context) error {
	operationCtx, cancel := context.WithTimeout(ctx, d.operationTimeout)
	defer cancel()
	return d.message.Term(nats.Context(operationCtx))
}
