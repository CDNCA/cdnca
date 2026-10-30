package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

const (
	CacheCommandSubjectPrefix    = "cdnca.agent.commands.cache"
	CacheStatusSubjectPrefix     = "cdnca.agent.deployment-status.cache"
	CacheDeadLetterSubjectPrefix = "cdnca.agent.commands.cache-dlq"
	// CacheMessageKindHeader marks a cache cancel (on the command subject)
	// and its receipt (on the status subject); a message without it is a
	// command or a status (fz-x3, CACHE-ADD-07). The control plane writes
	// the same values (cachecontrolruntime).
	CacheMessageKindHeader        = "CDNCA-Cache-Message"
	CacheMessageKindCancel        = "cancel"
	CacheMessageKindCancelReceipt = "cancel-receipt"
	cacheConsumerPrefix          = "node_cache"
	cacheMaximumDeliveries       = 20
)

type NATSCacheCommandBus struct {
	js               nats.JetStreamContext
	commandStream    string
	statusStream     string
	maxCommandBytes  int
	maxStatusBytes   int
	maxAckPending    int
	maxWaiting       int
	ackWait          time.Duration
	operationTimeout time.Duration
}

func NewNATSCacheCommandBus(connection *nats.Conn, config NATSCommandBusConfig) (*NATSCacheCommandBus, error) {
	base, err := NewNATSCommandBus(connection, config)
	if err != nil {
		return nil, err
	}
	return &NATSCacheCommandBus{
		js: base.js, commandStream: config.CommandStream, statusStream: config.StatusStream,
		maxCommandBytes: config.MaxCommandBytes, maxStatusBytes: config.MaxStatusBytes,
		maxAckPending: config.MaxAckPending, maxWaiting: config.MaxWaiting,
		ackWait: config.AckWait, operationTimeout: config.OperationTimeout,
	}, nil
}

func (b *NATSCacheCommandBus) SubscribeCache(ctx context.Context, nodeID string) (CacheCommandSubscription, error) {
	if ctx == nil || !canonicalNodeID(nodeID) {
		return nil, fmt.Errorf("cache command subscription requires a canonical node ID")
	}
	subject := CacheCommandSubjectPrefix + "." + nodeID
	durable := cacheConsumerPrefix + "_" + strings.ReplaceAll(nodeID, "-", "_")
	consumer := &nats.ConsumerConfig{
		Durable: durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		AckWait: b.ackWait, MaxDeliver: cacheMaximumDeliveries, FilterSubject: subject, ReplayPolicy: nats.ReplayInstantPolicy,
		MaxWaiting: b.maxWaiting, MaxAckPending: b.maxAckPending, MaxRequestBatch: 1,
		MaxRequestExpires: b.operationTimeout,
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	_, err := b.js.AddConsumer(b.commandStream, consumer, nats.Context(operationCtx))
	cancel()
	if err != nil {
		operationCtx, cancel = context.WithTimeout(ctx, b.operationTimeout)
		info, infoErr := b.js.ConsumerInfo(b.commandStream, durable, nats.Context(operationCtx))
		cancel()
		if infoErr != nil || !sameConsumerConfig(info, consumer) {
			return nil, fmt.Errorf("bind durable cache command consumer: %w", err)
		}
	}
	subscription, err := b.js.PullSubscribe(subject, durable, nats.Bind(b.commandStream, durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to durable cache commands: %w", err)
	}
	return &natsCacheCommandSubscription{
		subscription: subscription, maxCommandBytes: b.maxCommandBytes,
		fetchTimeout: b.operationTimeout, operationTimeout: b.operationTimeout,
		js: b.js, commandStream: b.commandStream, deadLetterSubject: CacheDeadLetterSubjectPrefix + "." + nodeID,
	}, nil
}

func (b *NATSCacheCommandBus) PublishCacheStatus(ctx context.Context, nodeID string, status *agentv1.CacheControlStatus) error {
	if ctx == nil || !canonicalNodeID(nodeID) {
		return fmt.Errorf("cache status publication requires a canonical node ID")
	}
	if status == nil || status.Event == nil || status.Event.EventId == "" {
		return fmt.Errorf("cache status event ID is required")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		return fmt.Errorf("marshal cache status: %w", err)
	}
	if len(payload) == 0 || len(payload) > b.maxStatusBytes {
		return fmt.Errorf("cache status exceeds its size limit")
	}
	message := nats.NewMsg(CacheStatusSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, status.Event.EventId)
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	defer cancel()
	if _, err := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(b.statusStream)); err != nil {
		return fmt.Errorf("publish cache status: %w", err)
	}
	return nil
}

func (b *NATSCacheCommandBus) PublishCacheCancelReceipt(ctx context.Context, nodeID string, receipt *agentv1.CacheControlCancelReceipt) error {
	if ctx == nil || !canonicalNodeID(nodeID) || receipt == nil || receipt.Event == nil || receipt.Event.EventId == "" {
		return fmt.Errorf("cache cancel receipt publication requires a canonical node ID and event")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil || len(payload) == 0 || len(payload) > b.maxStatusBytes {
		return fmt.Errorf("marshal cache cancel receipt: %w", err)
	}
	message := nats.NewMsg(CacheStatusSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, receipt.Event.EventId)
	message.Header.Set(CacheMessageKindHeader, CacheMessageKindCancelReceipt)
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	defer cancel()
	if _, err := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(b.statusStream)); err != nil {
		return fmt.Errorf("publish cache cancel receipt: %w", err)
	}
	return nil
}

func canonicalNodeID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

type natsCacheCommandSubscription struct {
	subscription      *nats.Subscription
	maxCommandBytes   int
	fetchTimeout      time.Duration
	operationTimeout  time.Duration
	js                nats.JetStreamContext
	commandStream     string
	deadLetterSubject string
}

func (s *natsCacheCommandSubscription) Next(ctx context.Context) (CacheCommandDelivery, error) {
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
		if len(messages) != 1 {
			return nil, fmt.Errorf("pull consumer returned an unexpected cache command batch")
		}
		delivery := &natsCacheCommandDelivery{
			message: messages[0], js: s.js, commandStream: s.commandStream,
			deadLetterSubject: s.deadLetterSubject, operationTimeout: s.operationTimeout,
		}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > s.maxCommandBytes {
			nakCtx, nakCancel := context.WithTimeout(context.Background(), s.operationTimeout)
			_ = delivery.Nak(nakCtx)
			nakCancel()
			return nil, fmt.Errorf("cache command payload is missing or exceeds its size limit")
		}
		if messages[0].Header.Get(CacheMessageKindHeader) == CacheMessageKindCancel {
			cancel := new(agentv1.CacheControlCancel)
			if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, cancel); err != nil {
				nakCtx, nakCancel := context.WithTimeout(context.Background(), s.operationTimeout)
				_ = delivery.Nak(nakCtx)
				nakCancel()
				return nil, fmt.Errorf("decode cache cancel: %w", err)
			}
			delivery.cancel = cancel
			return delivery, nil
		}
		command := new(agentv1.CacheControlCommand)
		if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, command); err != nil {
			nakCtx, nakCancel := context.WithTimeout(context.Background(), s.operationTimeout)
			_ = delivery.Nak(nakCtx)
			nakCancel()
			return nil, fmt.Errorf("decode cache command: %w", err)
		}
		delivery.command = command
		return delivery, nil
	}
}

func (s *natsCacheCommandSubscription) Close() error { return s.subscription.Unsubscribe() }

type natsCacheCommandDelivery struct {
	message           *nats.Msg
	command           *agentv1.CacheControlCommand
	cancel            *agentv1.CacheControlCancel
	js                nats.JetStreamContext
	commandStream     string
	deadLetterSubject string
	operationTimeout  time.Duration
}

func (d *natsCacheCommandDelivery) Command() *agentv1.CacheControlCommand { return d.command }
func (d *natsCacheCommandDelivery) Cancel() *agentv1.CacheControlCancel   { return d.cancel }

func (d *natsCacheCommandDelivery) Ack(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("cache command acknowledgement context is required")
	}
	if err := d.message.AckSync(nats.Context(ctx)); err != nil {
		return fmt.Errorf("acknowledge cache command: %w", err)
	}
	return nil
}

func (d *natsCacheCommandDelivery) Nak(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("cache command negative acknowledgement context is required")
	}
	metadata, metadataErr := d.message.Metadata()
	if metadataErr == nil && metadata.NumDelivered >= cacheMaximumDeliveries {
		deadLetter := cacheDeadLetterMessage(d.message, d.deadLetterSubject)
		if _, err := d.js.PublishMsg(deadLetter, nats.Context(ctx), nats.ExpectStream(d.commandStream)); err != nil {
			return fmt.Errorf("publish exhausted cache command to dead letter subject: %w", err)
		}
		if err := d.message.Term(nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
			return fmt.Errorf("terminate exhausted cache command: %w", err)
		}
		return nil
	}
	delay := cacheNakDelay(1)
	if metadataErr == nil {
		delay = cacheNakDelay(metadata.NumDelivered)
	}
	if err := d.message.NakWithDelay(delay, nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return fmt.Errorf("negative acknowledge cache command: %w", err)
	}
	return nil
}

func cacheNakDelay(delivery uint64) time.Duration {
	delay := 250 * time.Millisecond
	for attempt := uint64(1); attempt < delivery && delay < 30*time.Second; attempt++ {
		delay *= 2
	}
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func cacheDeadLetterMessage(original *nats.Msg, subject string) *nats.Msg {
	message := nats.NewMsg(subject)
	message.Data = append([]byte(nil), original.Data...)
	for name, values := range original.Header {
		for _, value := range values {
			message.Header.Add(name, value)
		}
	}
	messageID := original.Header.Get(nats.MsgIdHdr)
	if messageID == "" {
		digest := sha256.Sum256(original.Data)
		messageID = hex.EncodeToString(digest[:])
	}
	message.Header.Set(nats.MsgIdHdr, messageID+".dlq")
	message.Header.Set("X-CDNCA-Dead-Letter-Reason", "delivery_attempts_exhausted")
	return message
}
