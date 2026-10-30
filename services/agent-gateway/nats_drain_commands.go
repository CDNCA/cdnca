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

func (b *NATSCommandBus) SubscribeDrain(ctx context.Context, nodeID string) (DrainCommandSubscription, error) {
	if ctx == nil {
		return nil, fmt.Errorf("drain command subscription context is required")
	}
	parsed, err := uuid.Parse(nodeID)
	if err != nil || parsed == uuid.Nil || parsed.String() != nodeID {
		return nil, fmt.Errorf("drain node ID must be a canonical UUID")
	}
	subject := b.config.DrainCommandSubjectPrefix + "." + nodeID
	durable := b.config.DrainConsumerPrefix + "_" + strings.ReplaceAll(nodeID, "-", "_")
	consumer := &nats.ConsumerConfig{Durable: durable, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: b.config.AckWait, MaxDeliver: -1,
		FilterSubject: subject, ReplayPolicy: nats.ReplayInstantPolicy, MaxWaiting: b.config.MaxWaiting,
		MaxAckPending: b.config.MaxAckPending, MaxRequestBatch: 1, MaxRequestExpires: b.config.OperationTimeout}
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	_, err = b.js.AddConsumer(b.config.CommandStream, consumer, nats.Context(operationCtx))
	cancel()
	if err != nil {
		operationCtx, cancel = context.WithTimeout(ctx, b.config.OperationTimeout)
		info, infoErr := b.js.ConsumerInfo(b.config.CommandStream, durable, nats.Context(operationCtx))
		cancel()
		if infoErr != nil || !sameConsumerConfig(info, consumer) {
			return nil, fmt.Errorf("bind durable drain command consumer: %w", err)
		}
	}
	subscription, err := b.js.PullSubscribe(subject, durable, nats.Bind(b.config.CommandStream, durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to durable drain commands: %w", err)
	}
	return &natsDrainCommandSubscription{subscription: subscription, maxCommandBytes: b.config.MaxDrainCommandBytes,
		fetchTimeout: b.config.OperationTimeout, operationTimeout: b.config.OperationTimeout}, nil
}

func (b *NATSCommandBus) PublishDrainStatus(ctx context.Context, nodeID string, value *agentv1.DrainStatus) (DrainStatusPublication, error) {
	if ctx == nil || value == nil || value.NodeId != nodeID {
		return DrainStatusPublication{}, fmt.Errorf("drain status publication is invalid")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(value)
	if err != nil || len(payload) > b.config.MaxDrainStatusBytes {
		return DrainStatusPublication{}, fmt.Errorf("marshal drain status")
	}
	subject := fmt.Sprintf("%s.%s_%s_%d", b.config.DrainStatusSubjectPrefix, nodeID, value.CommandId, value.StatusRevision)
	if publication, found, err := b.loadDrainStatus(ctx, subject, payload); err != nil {
		return DrainStatusPublication{}, err
	} else if found {
		return DrainStatusPublication{Stream: publication.Stream, Sequence: publication.Sequence, Replayed: true}, nil
	}
	message := nats.NewMsg(subject)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, value.Event.EventId)
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	ack, err := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(b.config.StatusStream), nats.ExpectLastSequencePerSubject(0))
	cancel()
	if err != nil {
		if publication, found, loadErr := b.loadDrainStatus(ctx, subject, payload); loadErr != nil {
			return DrainStatusPublication{}, loadErr
		} else if found {
			return DrainStatusPublication{Stream: publication.Stream, Sequence: publication.Sequence, Replayed: true}, nil
		}
		return DrainStatusPublication{}, fmt.Errorf("publish drain status: %w", err)
	}
	if ack == nil || ack.Stream != b.config.StatusStream || ack.Sequence == 0 {
		return DrainStatusPublication{}, fmt.Errorf("publish drain status returned an invalid acknowledgement")
	}
	return DrainStatusPublication{Stream: ack.Stream, Sequence: ack.Sequence}, nil
}

func (b *NATSCommandBus) loadDrainStatus(ctx context.Context, subject string, payload []byte) (DeploymentStatusPublication, bool, error) {
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	message, err := b.js.GetLastMsg(b.config.StatusStream, subject, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return DeploymentStatusPublication{}, false, nil
	}
	if err != nil {
		return DeploymentStatusPublication{}, false, fmt.Errorf("load drain status publication: %w", err)
	}
	if message == nil || message.Subject != subject || message.Sequence == 0 || !bytes.Equal(message.Data, payload) {
		return DeploymentStatusPublication{}, false, fmt.Errorf("drain status conflicts with durable state")
	}
	return DeploymentStatusPublication{Stream: b.config.StatusStream, Sequence: message.Sequence}, true, nil
}

type natsDrainCommandSubscription struct {
	subscription     *nats.Subscription
	maxCommandBytes  int
	fetchTimeout     time.Duration
	operationTimeout time.Duration
}

func (s *natsDrainCommandSubscription) Next(ctx context.Context) (DrainCommandDelivery, error) {
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
			return nil, fmt.Errorf("pull consumer returned an unexpected drain command batch")
		}
		delivery := &natsDrainCommandDelivery{message: messages[0]}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > s.maxCommandBytes {
			retryCtx, cancel := context.WithTimeout(context.Background(), s.operationTimeout)
			_ = delivery.Retry(retryCtx, time.Second)
			cancel()
			return nil, fmt.Errorf("drain command payload is missing or exceeds its size limit")
		}
		command := new(agentv1.DrainCommand)
		if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, command); err != nil {
			return nil, fmt.Errorf("decode drain command: %w", err)
		}
		delivery.command = command
		return delivery, nil
	}
}

func (s *natsDrainCommandSubscription) Close() error { return s.subscription.Unsubscribe() }

type natsDrainCommandDelivery struct {
	message *nats.Msg
	command *agentv1.DrainCommand
}

func (d *natsDrainCommandDelivery) Command() *agentv1.DrainCommand { return d.command }

func (d *natsDrainCommandDelivery) Ack(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("drain command acknowledgement context is required")
	}
	if err := d.message.AckSync(nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return fmt.Errorf("acknowledge drain command: %w", err)
	}
	return nil
}

func (d *natsDrainCommandDelivery) Retry(ctx context.Context, delay time.Duration) error {
	if ctx == nil || delay <= 0 {
		return fmt.Errorf("drain command retry policy is invalid")
	}
	if err := d.message.NakWithDelay(delay, nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return fmt.Errorf("retry drain command: %w", err)
	}
	return nil
}
