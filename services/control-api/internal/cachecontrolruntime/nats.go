package cachecontrolruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type delivery interface {
	Subject() string
	Data() []byte
	// Kind is the CDNCA-Cache-Message header: "" for a status,
	// cancelReceiptKind for a node's cancel receipt (CACHE-ADD-07).
	Kind() string
	NumDelivered() uint64
	Ack(context.Context) error
	Nak(context.Context, time.Duration) error
	Term(context.Context) error
}

type statusConsumer interface {
	Next(context.Context) (delivery, error)
	Close() error
}

type messageBus interface {
	PublishCommand(context.Context, string, *agentv1.CacheControlCommand) (bool, error)
	PublishCancel(context.Context, string, *agentv1.CacheControlCancel) error
	PublishDLQ(context.Context, delivery, string) error
}

type natsBus struct {
	js             nats.JetStreamContext
	commandStream  string
	statusStream   string
	commandPrefix  string
	dlqPrefix      string
	maxPayload     int
	operationLimit time.Duration
}

type natsConsumer struct {
	subscription *nats.Subscription
	fetchTimeout time.Duration
}

type natsDelivery struct{ message *nats.Msg }

func newNATS(connection *nats.Conn, config Config) (*natsBus, *natsConsumer, error) {
	if connection == nil || connection.IsClosed() {
		return nil, nil, ErrInvalidConfig
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, nil, natsStageError("context")
	}
	return bindVerifiedNATS(js, config)
}

func bindVerifiedNATS(js nats.JetStreamContext, config Config) (*natsBus, *natsConsumer, error) {
	if js == nil || config.validate() != nil {
		return nil, nil, ErrInvalidConfig
	}
	for _, required := range requiredStreams(config) {
		operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
		info, err := js.StreamInfo(required.name, nats.Context(operationCtx))
		cancel()
		if err != nil {
			return nil, nil, natsStageError("stream_info")
		}
		if !sharedStreamCovers(info, required, config) {
			return nil, nil, natsStageError("stream_validation")
		}
	}
	consumerConfig := expectedConsumer(config)
	if !verifiedConsumer(js, config, consumerConfig) {
		return nil, nil, natsStageError("consumer_validation")
	}
	subscription, err := js.PullSubscribe(consumerConfig.FilterSubject, config.Durable,
		nats.Bind(config.StatusStream, config.Durable))
	if err != nil {
		return nil, nil, natsStageError("consumer_bind")
	}
	for _, required := range requiredStreams(config) {
		operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
		info, err := js.StreamInfo(required.name, nats.Context(operationCtx))
		cancel()
		if err != nil || !sharedStreamCovers(info, required, config) {
			_ = subscription.Unsubscribe()
			return nil, nil, natsStageError("stream_post_bind_validation")
		}
	}
	if !verifiedConsumer(js, config, consumerConfig) {
		_ = subscription.Unsubscribe()
		return nil, nil, natsStageError("consumer_post_bind_validation")
	}
	return &natsBus{
		js: js, commandStream: config.CommandStream, statusStream: config.StatusStream,
		commandPrefix: config.CommandSubjectPrefix, dlqPrefix: config.DLQSubjectPrefix,
		maxPayload: config.MaxPayloadBytes, operationLimit: config.OperationTimeout,
	}, &natsConsumer{subscription: subscription, fetchTimeout: config.FetchTimeout}, nil
}

func verifiedConsumer(js nats.JetStreamContext, config Config, expected *nats.ConsumerConfig) bool {
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	info, err := js.ConsumerInfo(config.StatusStream, config.Durable, nats.Context(operationCtx))
	cancel()
	return err == nil && sameConsumer(info, config.StatusStream, expected)
}

// streamRequirement names a stream the cache runtime publishes to or consumes
// from and the per-node subjects ("<prefix>.*") it must carry.
type streamRequirement struct {
	name     string
	subjects []string
}

// requiredStreams lists the shared Agent streams (AGENT_COMMANDS /
// AGENT_DEPLOYMENT_STATUS by default) the cache runtime binds to. They are
// owned by the installer profile and the Agent Gateway, which carry many other
// subjects, so the runtime only checks that its own subjects are covered.
func requiredStreams(config Config) []streamRequirement {
	return []streamRequirement{
		{name: config.CommandStream, subjects: []string{config.CommandSubjectPrefix + ".*"}},
		{name: config.StatusStream, subjects: []string{
			config.StatusSubjectPrefix + ".*", config.DLQSubjectPrefix + ".*",
		}},
	}
}

// sharedStreamCovers applies the Agent Gateway readiness rule
// (agent-gateway/cmd/agent-gateway/runtime.go validateStreamInfo): durable
// file storage, a positive duplicate window for Nats-Msg-Id idempotency, only
// single-token "*" patterns, and every required subject listed explicitly.
// Retention must keep messages for the other consumers on the same stream.
func sharedStreamCovers(info *nats.StreamInfo, required streamRequirement, config Config) bool {
	if info == nil || info.Config.Name != required.name || info.Config.Storage != nats.FileStorage ||
		info.Config.Retention != nats.LimitsPolicy || info.Config.Replicas < config.Replicas ||
		info.Config.Duplicates <= 0 || info.Config.Sealed || info.Config.NoAck ||
		info.Config.Mirror != nil || len(info.Config.Sources) != 0 ||
		info.Config.SubjectTransform != nil || info.Config.RePublish != nil ||
		info.Config.MaxMsgSize > 0 && int(info.Config.MaxMsgSize) < config.MaxPayloadBytes {
		return false
	}
	for _, subject := range info.Config.Subjects {
		if strings.Contains(subject, ">") {
			return false
		}
	}
	for _, subject := range required.subjects {
		if !slices.Contains(info.Config.Subjects, subject) {
			return false
		}
	}
	return true
}

func expectedConsumer(config Config) *nats.ConsumerConfig {
	return &nats.ConsumerConfig{
		Durable: config.Durable, Name: config.Durable, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: config.AckWait,
		MaxDeliver: config.MaxDeliver, FilterSubject: config.StatusSubjectPrefix + ".*",
		ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: config.MaxAckPending,
		MaxWaiting: config.MaxWaiting, MaxRequestBatch: 1,
		MaxRequestExpires: config.FetchTimeout, MaxRequestMaxBytes: config.MaxPayloadBytes,
	}
}

func (bus *natsBus) PublishCommand(ctx context.Context, nodeID string, command *agentv1.CacheControlCommand) (bool, error) {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil || len(payload) == 0 || len(payload) > bus.maxPayload {
		return false, fmt.Errorf("marshal cache command: %w", firstError(err, ErrInvalidConfig))
	}
	message := nats.NewMsg(bus.commandPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, command.TaskId)
	operationCtx, cancel := context.WithTimeout(ctx, bus.operationLimit)
	defer cancel()
	ack, err := bus.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(bus.commandStream))
	if err != nil {
		return false, fmt.Errorf("publish cache command: %w", err)
	}
	if ack == nil {
		return false, fmt.Errorf("publish cache command: missing acknowledgement")
	}
	return ack.Duplicate, nil
}

// PublishCancel puts a cancel on the node's cache command subject after the
// command it cancels (same subject, so the gateway reads them in order).
func (bus *natsBus) PublishCancel(ctx context.Context, nodeID string, cancel *agentv1.CacheControlCancel) error {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(cancel)
	if err != nil || len(payload) == 0 || len(payload) > bus.maxPayload {
		return fmt.Errorf("marshal cache cancel: %w", firstError(err, ErrInvalidConfig))
	}
	message := nats.NewMsg(bus.commandPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, "cache-cancel-"+cancel.CancelId)
	message.Header.Set(cacheMessageKindHeader, cancelKind)
	operationCtx, cancelOperation := context.WithTimeout(ctx, bus.operationLimit)
	defer cancelOperation()
	if _, err := bus.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(bus.commandStream)); err != nil {
		return fmt.Errorf("publish cache cancel: %w", err)
	}
	return nil
}

func (bus *natsBus) PublishDLQ(ctx context.Context, source delivery, reason string) error {
	digest := sha256.Sum256(append([]byte(source.Subject()+"\x00"), source.Data()...))
	message := nats.NewMsg(bus.dlqPrefix + "." + fmt.Sprintf("%x", digest[:16]))
	message.Data = append([]byte(nil), source.Data()...)
	message.Header.Set(nats.MsgIdHdr, "cache-dlq-"+fmt.Sprintf("%x", digest[:]))
	message.Header.Set("CDNCA-Source-Subject", source.Subject())
	message.Header.Set("CDNCA-Delivery-Count", strconv.FormatUint(source.NumDelivered(), 10))
	message.Header.Set("CDNCA-Quarantine-Reason", reason)
	operationCtx, cancel := context.WithTimeout(ctx, bus.operationLimit)
	defer cancel()
	_, err := bus.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(bus.statusStream))
	if err != nil {
		return fmt.Errorf("quarantine cache status: %w", err)
	}
	return nil
}

func (consumer *natsConsumer) Next(ctx context.Context) (delivery, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, consumer.fetchTimeout)
	messages, err := consumer.subscription.Fetch(1, nats.Context(fetchCtx))
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
			return nil, ErrNoMessage
		}
		return nil, fmt.Errorf("fetch cache status: %w", err)
	}
	if len(messages) != 1 {
		return nil, fmt.Errorf("fetch cache status returned %d messages", len(messages))
	}
	return &natsDelivery{message: messages[0]}, nil
}

func (consumer *natsConsumer) Close() error {
	if consumer == nil || consumer.subscription == nil {
		return nil
	}
	return consumer.subscription.Unsubscribe()
}

func (source *natsDelivery) Subject() string { return source.message.Subject }
func (source *natsDelivery) Kind() string    { return source.message.Header.Get(cacheMessageKindHeader) }
func (source *natsDelivery) Data() []byte    { return source.message.Data }

func (source *natsDelivery) NumDelivered() uint64 {
	metadata, err := source.message.Metadata()
	if err != nil {
		return 1
	}
	return metadata.NumDelivered
}

func (source *natsDelivery) Ack(ctx context.Context) error {
	return source.message.AckSync(nats.Context(ctx))
}

func (source *natsDelivery) Nak(ctx context.Context, delay time.Duration) error {
	return source.message.NakWithDelay(delay, nats.Context(ctx))
}

func (source *natsDelivery) Term(ctx context.Context) error {
	return source.message.Term(nats.Context(ctx))
}

func sameConsumer(info *nats.ConsumerInfo, stream string, expected *nats.ConsumerConfig) bool {
	if info == nil || expected == nil {
		return false
	}
	actual := info.Config
	return info.Stream == stream && info.Name == expected.Durable &&
		actual.Durable == expected.Durable && actual.Name == expected.Name &&
		actual.Description == expected.Description && sameNATSMetadata(actual.Metadata, expected.Metadata) &&
		actual.DeliverPolicy == expected.DeliverPolicy && actual.OptStartSeq == expected.OptStartSeq &&
		reflect.DeepEqual(actual.OptStartTime, expected.OptStartTime) && actual.AckPolicy == expected.AckPolicy &&
		actual.AckWait == expected.AckWait && actual.MaxDeliver == expected.MaxDeliver &&
		reflect.DeepEqual(actual.BackOff, expected.BackOff) && actual.FilterSubject == expected.FilterSubject &&
		sameSubjectSet(actual.FilterSubjects, expected.FilterSubjects) && actual.ReplayPolicy == expected.ReplayPolicy &&
		actual.RateLimit == expected.RateLimit && actual.SampleFrequency == expected.SampleFrequency &&
		actual.MaxWaiting == expected.MaxWaiting && actual.MaxAckPending == expected.MaxAckPending &&
		actual.FlowControl == expected.FlowControl && actual.Heartbeat == expected.Heartbeat &&
		actual.HeadersOnly == expected.HeadersOnly && actual.MaxRequestBatch == expected.MaxRequestBatch &&
		actual.MaxRequestExpires == expected.MaxRequestExpires &&
		actual.MaxRequestMaxBytes == expected.MaxRequestMaxBytes &&
		actual.DeliverSubject == expected.DeliverSubject && actual.DeliverGroup == expected.DeliverGroup &&
		actual.InactiveThreshold == expected.InactiveThreshold && actual.Replicas == expected.Replicas &&
		actual.MemoryStorage == expected.MemoryStorage
}

func sameSubjectSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	counts := make(map[string]int, len(expected))
	for _, subject := range expected {
		counts[subject]++
	}
	for _, subject := range actual {
		if counts[subject] == 0 {
			return false
		}
		counts[subject]--
	}
	return true
}

func sameNATSMetadata(actual, expected map[string]string) bool {
	actualCount, expectedCount := 0, 0
	for name, value := range actual {
		if name == "_nats.req.level" && value != "0" {
			return false
		}
		if serverManagedNATSMetadata(name) {
			continue
		}
		actualCount++
		if expectedValue, ok := expected[name]; !ok || expectedValue != value {
			return false
		}
	}
	for name := range expected {
		if !serverManagedNATSMetadata(name) {
			expectedCount++
		}
	}
	return actualCount == expectedCount
}

func serverManagedNATSMetadata(name string) bool {
	return name == "_nats.level" || name == "_nats.req.level" || name == "_nats.ver"
}

func natsStageError(stage string) error {
	return fmt.Errorf("cache control JetStream initialization failed: %s", stage)
}

func firstError(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}
