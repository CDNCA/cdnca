package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

func (b *NATSCommandBus) SubscribePortTransitions(ctx context.Context, nodeID string) (PortTransitionCommandSubscription, error) {
	if ctx == nil {
		return nil, fmt.Errorf("gateway port transition subscription context is required")
	}
	parsed, err := uuid.Parse(nodeID)
	if err != nil || parsed.String() != nodeID {
		return nil, fmt.Errorf("gateway port transition node ID must be canonical")
	}
	subject := b.config.PortTransitionCommandSubjectPrefix + "." + nodeID
	durable := b.config.PortTransitionConsumerPrefix + "_" + strings.ReplaceAll(nodeID, "-", "_")
	consumer := &nats.ConsumerConfig{Durable: durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		AckWait: b.config.AckWait, MaxDeliver: -1, FilterSubject: subject, ReplayPolicy: nats.ReplayInstantPolicy,
		MaxWaiting: b.config.MaxWaiting, MaxAckPending: b.config.MaxAckPending, MaxRequestBatch: 1, MaxRequestExpires: b.config.OperationTimeout}
	opCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	_, err = b.js.AddConsumer(b.config.CommandStream, consumer, nats.Context(opCtx))
	cancel()
	if err != nil {
		opCtx, cancel = context.WithTimeout(ctx, b.config.OperationTimeout)
		info, infoErr := b.js.ConsumerInfo(b.config.CommandStream, durable, nats.Context(opCtx))
		cancel()
		if infoErr != nil || !sameConsumerConfig(info, consumer) {
			return nil, fmt.Errorf("bind durable gateway port transition consumer: %w", err)
		}
	}
	subscription, err := b.js.PullSubscribe(subject, durable, nats.Bind(b.config.CommandStream, durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to gateway port transitions: %w", err)
	}
	return &natsPortTransitionSubscription{subscription: subscription, maxBytes: b.config.MaxPortTransitionCommandBytes, fetchTimeout: b.config.OperationTimeout, operationTimeout: b.config.OperationTimeout}, nil
}

func (b *NATSCommandBus) PublishPortTransitionStatus(ctx context.Context, nodeID string, value *agentv1.GatewayPortTransitionStatus) (PortTransitionStatusPublication, error) {
	if ctx == nil || value == nil || value.NodeId != nodeID || !validGatewayPortTransitionEvent(value.Event) {
		return PortTransitionStatusPublication{}, fmt.Errorf("gateway port transition status publication is invalid")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(value)
	if err != nil || len(payload) > b.config.MaxPortTransitionStatusBytes {
		return PortTransitionStatusPublication{}, fmt.Errorf("marshal gateway port transition status")
	}
	subject := fmt.Sprintf("%s.%s_%s_%d", b.config.PortTransitionStatusSubjectPrefix, nodeID, value.TransitionId, value.StatusRevision)
	if publication, found, loadErr := b.loadPortTransitionStatus(ctx, subject, payload); loadErr != nil {
		return PortTransitionStatusPublication{}, loadErr
	} else if found {
		return publication, nil
	}
	message := nats.NewMsg(subject)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, value.Event.EventId)
	opCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	ack, err := b.js.PublishMsg(message, nats.Context(opCtx), nats.ExpectStream(b.config.StatusStream), nats.ExpectLastSequencePerSubject(0))
	cancel()
	if err != nil {
		if publication, found, loadErr := b.loadPortTransitionStatus(ctx, subject, payload); loadErr == nil && found {
			return publication, nil
		}
		return PortTransitionStatusPublication{}, fmt.Errorf("publish gateway port transition status: %w", err)
	}
	if ack == nil || ack.Stream != b.config.StatusStream || ack.Sequence == 0 {
		return PortTransitionStatusPublication{}, fmt.Errorf("gateway port transition status returned invalid PubAck")
	}
	return PortTransitionStatusPublication{Stream: ack.Stream, Sequence: ack.Sequence}, nil
}

func (b *NATSCommandBus) loadPortTransitionStatus(ctx context.Context, subject string, payload []byte) (PortTransitionStatusPublication, bool, error) {
	opCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	message, err := b.js.GetLastMsg(b.config.StatusStream, subject, nats.Context(opCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return PortTransitionStatusPublication{}, false, nil
	}
	if err != nil {
		return PortTransitionStatusPublication{}, false, err
	}
	if message == nil || message.Subject != subject || message.Sequence == 0 || !bytes.Equal(message.Data, payload) {
		return PortTransitionStatusPublication{}, false, fmt.Errorf("gateway port transition status conflicts with durable state")
	}
	return PortTransitionStatusPublication{Stream: b.config.StatusStream, Sequence: message.Sequence, Replayed: true}, true, nil
}

type natsPortTransitionSubscription struct {
	subscription                   *nats.Subscription
	maxBytes                       int
	fetchTimeout, operationTimeout time.Duration
}

func (s *natsPortTransitionSubscription) Next(ctx context.Context) (PortTransitionCommandDelivery, error) {
	for {
		fetchCtx, cancel := context.WithTimeout(ctx, s.fetchTimeout)
		messages, err := s.subscription.Fetch(1, nats.Context(fetchCtx))
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
				continue
			}
			return nil, err
		}
		if len(messages) != 1 || messages[0] == nil {
			return nil, fmt.Errorf("pull consumer returned unexpected gateway port transition batch")
		}
		delivery := &natsPortTransitionDelivery{message: messages[0]}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > s.maxBytes {
			retryCtx, cancel := context.WithTimeout(context.Background(), s.operationTimeout)
			_ = delivery.Retry(retryCtx, time.Second)
			cancel()
			return nil, fmt.Errorf("gateway port transition payload exceeds its limit")
		}
		command := new(agentv1.GatewayPortTransitionCommand)
		if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, command); err != nil {
			return nil, fmt.Errorf("decode gateway port transition command: %w", err)
		}
		delivery.command = command
		return delivery, nil
	}
}
func (s *natsPortTransitionSubscription) Close() error { return s.subscription.Unsubscribe() }

type natsPortTransitionDelivery struct {
	message *nats.Msg
	command *agentv1.GatewayPortTransitionCommand
}

func (d *natsPortTransitionDelivery) Command() *agentv1.GatewayPortTransitionCommand {
	return d.command
}
func (d *natsPortTransitionDelivery) Ack(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("gateway port transition acknowledgement context is required")
	}
	if err := d.message.AckSync(nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return err
	}
	return nil
}
func (d *natsPortTransitionDelivery) Retry(ctx context.Context, delay time.Duration) error {
	if ctx == nil || delay <= 0 {
		return fmt.Errorf("gateway port transition retry policy is invalid")
	}
	if err := d.message.NakWithDelay(delay, nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return err
	}
	return nil
}

var _ PortTransitionCommandBus = (*NATSCommandBus)(nil)
