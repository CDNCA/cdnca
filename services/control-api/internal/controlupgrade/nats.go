package controlupgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

var (
	ErrPublishOutcomeUnknown = errors.New("control upgrade publish outcome unknown")
	ErrPublishRejected       = errors.New("control upgrade publish rejected")
	upgradeNATSNamePattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	upgradeSubjectPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$`)
)

const (
	upgradeCommandStream         = "AGENT_COMMANDS"
	upgradeStatusStream          = "AGENT_DEPLOYMENT_STATUS"
	upgradeStatusConsumer        = "control_api_upgrade_status"
	upgradeCommandSubjectPrefix  = "cdnca.agent.commands.upgrade"
	upgradeStatusSubjectPrefix   = "cdnca.agent.deployment-status.upgrade"
	upgradeStatusV2SubjectPrefix = "cdnca.agent.deployment-status.upgrade-v2"
	upgradePayloadSHA256Header   = "X-CDNCA-Payload-SHA256"
	upgradeMessageKeyHeader      = "X-CDNCA-Message-Key"
	natsRequiredLevelMetadataKey = "_nats.req.level"
	natsServerLevelMetadataKey   = "_nats.level"
	natsServerVersionMetadataKey = "_nats.ver"
)

var natsServerAPILevels = map[string]string{"2.11.4": "1", "2.12.15-cdnca.1": "3"}

type CommandBus struct {
	jetstream nats.JetStreamContext
	stream    string
}

type PublishResult struct {
	Stream    string
	Sequence  uint64
	Duplicate bool
}

func NewCommandBus(jetstream nats.JetStreamContext, stream string) (*CommandBus, error) {
	if jetstream == nil || stream != upgradeCommandStream {
		return nil, ErrInvalidInput
	}
	return &CommandBus{jetstream: jetstream, stream: stream}, nil
}

func (bus *CommandBus) Publish(ctx context.Context, message RolloutOutboxMessage) (PublishResult, error) {
	if bus == nil || bus.jetstream == nil || !validCanonicalPlanUUID(message.ID) ||
		!validUpgradeCommandSubject(message.Topic) || message.MessageKey != message.ID ||
		len(message.PayloadBytes) == 0 || !rolloutWireDigestMatches(message.PayloadBytes, message.PayloadSHA256) {
		return PublishResult{}, ErrPublishRejected
	}
	wire := nats.NewMsg(message.Topic)
	wire.Data = append([]byte(nil), message.PayloadBytes...)
	wire.Header.Set(nats.MsgIdHdr, commandMessageID(message.PayloadBytes))
	wire.Header.Set(nats.ExpectedStreamHdr, bus.stream)
	wire.Header.Set(upgradePayloadSHA256Header, message.PayloadSHA256)
	wire.Header.Set(upgradeMessageKeyHeader, message.MessageKey)
	ack, err := bus.jetstream.PublishMsg(wire, nats.Context(ctx))
	if err != nil {
		var apiError *nats.APIError
		if errors.As(err, &apiError) && apiError.Code >= 400 && apiError.Code < 500 {
			return PublishResult{}, fmt.Errorf("%w: %d/%d", ErrPublishRejected, apiError.Code, apiError.ErrorCode)
		}
		return PublishResult{}, fmt.Errorf("%w: %v", ErrPublishOutcomeUnknown, err)
	}
	if ack == nil || ack.Stream != bus.stream || ack.Sequence == 0 {
		return PublishResult{}, ErrPublishRejected
	}
	return PublishResult{Stream: ack.Stream, Sequence: ack.Sequence, Duplicate: ack.Duplicate}, nil
}

func (bus *CommandBus) Stream() string {
	if bus == nil {
		return ""
	}
	return bus.stream
}

func validUpgradeCommandSubject(subject string) bool {
	const prefix = upgradeCommandSubjectPrefix + "."
	return len(subject) > len(prefix) && subject[:len(prefix)] == prefix &&
		validCanonicalPlanUUID(subject[len(prefix):])
}

func commandMessageID(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "control-upgrade-v1-" + hex.EncodeToString(digest[:])
}

func rolloutWireDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

type StatusConsumerConfig struct {
	Stream           string
	Durable          string
	AckWait          time.Duration
	FetchTimeout     time.Duration
	OperationTimeout time.Duration
	MaxAckPending    int
	MaxWaiting       int
	MaxPayloadBytes  int
}

func DefaultStatusConsumerConfig() StatusConsumerConfig {
	return StatusConsumerConfig{Stream: upgradeStatusStream, Durable: upgradeStatusConsumer,
		AckWait: 2 * time.Minute, FetchTimeout: 2 * time.Second, OperationTimeout: 5 * time.Second,
		MaxAckPending: 64, MaxWaiting: 16, MaxPayloadBytes: 256 << 10}
}

func (config StatusConsumerConfig) valid() bool {
	return config.Stream == upgradeStatusStream && upgradeNATSNamePattern.MatchString(config.Durable) &&
		config.AckWait > 0 && config.FetchTimeout > 0 && config.OperationTimeout > 0 &&
		config.MaxAckPending > 0 && config.MaxWaiting > 0 && config.MaxPayloadBytes > 0 &&
		config.MaxPayloadBytes <= 1<<20
}

func expectedUpgradeStatusConsumer(config StatusConsumerConfig) *nats.ConsumerConfig {
	return &nats.ConsumerConfig{Durable: config.Durable, Name: config.Durable,
		DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy, AckWait: config.AckWait,
		MaxDeliver: -1, FilterSubjects: []string{upgradeStatusSubjectPrefix + ".*", upgradeStatusV2SubjectPrefix + ".*"},
		ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: config.MaxAckPending,
		MaxWaiting: config.MaxWaiting, MaxRequestBatch: 1, MaxRequestExpires: config.FetchTimeout,
		MaxRequestMaxBytes: config.MaxPayloadBytes}
}

func sameUpgradeStatusConsumer(info *nats.ConsumerInfo, stream string, expected *nats.ConsumerConfig) bool {
	if info == nil || expected == nil || info.Stream != stream || info.Name != expected.Durable {
		return false
	}
	actual := info.Config
	return actual.Durable == expected.Durable && actual.Name == expected.Name &&
		actual.Description == expected.Description && sameUpgradeNATSMetadata(actual.Metadata, expected.Metadata) &&
		actual.DeliverPolicy == expected.DeliverPolicy && actual.OptStartSeq == expected.OptStartSeq &&
		reflect.DeepEqual(actual.OptStartTime, expected.OptStartTime) && actual.AckPolicy == expected.AckPolicy &&
		actual.AckWait == expected.AckWait && actual.MaxDeliver == expected.MaxDeliver &&
		reflect.DeepEqual(actual.BackOff, expected.BackOff) && actual.FilterSubject == expected.FilterSubject &&
		reflect.DeepEqual(actual.FilterSubjects, expected.FilterSubjects) && actual.ReplayPolicy == expected.ReplayPolicy &&
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

func sameUpgradeNATSMetadata(actual, expected map[string]string) bool {
	actualUser, ok := upgradeNATSUserMetadata(actual)
	if !ok {
		return false
	}
	expectedUser, ok := upgradeNATSUserMetadata(expected)
	if !ok || len(actualUser) != len(expectedUser) {
		return false
	}
	for key, expectedValue := range expectedUser {
		if actualUser[key] != expectedValue {
			return false
		}
	}
	return true
}

func upgradeNATSUserMetadata(metadata map[string]string) (map[string]string, bool) {
	user := make(map[string]string, len(metadata))
	serverKeys := 0
	for key, value := range metadata {
		if !strings.HasPrefix(key, "_nats.") {
			user[key] = value
			continue
		}
		serverKeys++
		switch key {
		case natsRequiredLevelMetadataKey:
			if value != "0" {
				return nil, false
			}
		case natsServerLevelMetadataKey, natsServerVersionMetadataKey:
		default:
			return nil, false
		}
	}
	if serverKeys == 0 {
		return user, true
	}
	// Each pinned server reports its own JetStream API level: 2.11.4 is the e2e
	// pin, 2.12.15-cdnca.1 the signed native profile server.
	level, ok := natsServerAPILevels[metadata[natsServerVersionMetadataKey]]
	if serverKeys != 3 || !ok || metadata[natsServerLevelMetadataKey] != level {
		return nil, false
	}
	return user, true
}

type natsStatusConsumer struct {
	subscription *nats.Subscription
	fetchTimeout time.Duration
	stream       string
	consumer     string
}

type natsStatusDelivery struct {
	message        *nats.Msg
	stream         string
	consumer       string
	streamSequence uint64
	numDelivered   uint64
}

func BindUpgradeStatusConsumer(jetstream nats.JetStreamContext,
	config StatusConsumerConfig) (statusConsumer, error) {
	if jetstream == nil || !config.valid() {
		return nil, ErrInvalidInput
	}
	expected := expectedUpgradeStatusConsumer(config)
	if !verifyUpgradeStatusNATS(jetstream, config, expected) {
		return nil, ErrRuntimeUnavailable
	}
	subscription, err := jetstream.PullSubscribe("", config.Durable,
		nats.Bind(config.Stream, config.Durable))
	if err != nil {
		return nil, fmt.Errorf("bind control upgrade status consumer: %w", err)
	}
	if !verifyUpgradeStatusNATS(jetstream, config, expected) {
		_ = subscription.Unsubscribe()
		return nil, ErrRuntimeUnavailable
	}
	return &natsStatusConsumer{subscription: subscription, fetchTimeout: config.FetchTimeout,
		stream: config.Stream, consumer: config.Durable}, nil
}

func verifyUpgradeStatusNATS(jetstream nats.JetStreamContext, config StatusConsumerConfig,
	expected *nats.ConsumerConfig) bool {
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	defer cancel()
	stream, err := jetstream.StreamInfo(config.Stream, nats.Context(operationCtx))
	if err != nil || stream == nil || stream.Config.Name != config.Stream ||
		!streamAcceptsSubject(stream.Config.Subjects, upgradeStatusSubjectPrefix+".00000000-0000-4000-8000-000000000001") ||
		!streamAcceptsSubject(stream.Config.Subjects, upgradeStatusV2SubjectPrefix+".00000000-0000-4000-8000-000000000002") {
		return false
	}
	info, err := jetstream.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	return err == nil && sameUpgradeStatusConsumer(info, config.Stream, expected)
}

func streamAcceptsSubject(filters []string, subject string) bool {
	for _, filter := range filters {
		if natsSubjectMatches(filter, subject) {
			return true
		}
	}
	return false
}

func natsSubjectMatches(filter, subject string) bool {
	filterTokens, subjectTokens := splitSubject(filter), splitSubject(subject)
	if filterTokens == nil || subjectTokens == nil {
		return false
	}
	for index, token := range filterTokens {
		if token == ">" {
			return index == len(filterTokens)-1 && index < len(subjectTokens)
		}
		if index >= len(subjectTokens) || token != "*" && token != subjectTokens[index] {
			return false
		}
	}
	return len(filterTokens) == len(subjectTokens)
}

func splitSubject(subject string) []string {
	if !upgradeSubjectPattern.MatchString(subject) {
		if len(subject) > 2 && subject[len(subject)-2:] == ".>" &&
			upgradeSubjectPattern.MatchString(subject[:len(subject)-2]) {
			return append(splitSubject(subject[:len(subject)-2]), ">")
		}
		if len(subject) > 2 && subject[len(subject)-2:] == ".*" &&
			upgradeSubjectPattern.MatchString(subject[:len(subject)-2]) {
			return append(splitSubject(subject[:len(subject)-2]), "*")
		}
		return nil
	}
	var tokens []string
	start := 0
	for index := range subject {
		if subject[index] == '.' {
			tokens = append(tokens, subject[start:index])
			start = index + 1
		}
	}
	return append(tokens, subject[start:])
}

func (consumer *natsStatusConsumer) Next(ctx context.Context) (statusDelivery, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, consumer.fetchTimeout)
	defer cancel()
	messages, err := consumer.subscription.Fetch(1, nats.Context(fetchCtx))
	if err != nil {
		return nil, err
	}
	if len(messages) != 1 {
		return nil, ErrRuntimeUnavailable
	}
	metadata, err := messages[0].Metadata()
	if err != nil || metadata.Stream != consumer.stream || metadata.Consumer != consumer.consumer ||
		metadata.Sequence.Stream == 0 || metadata.NumDelivered == 0 {
		return nil, ErrRuntimeUnavailable
	}
	return &natsStatusDelivery{message: messages[0], stream: metadata.Stream, consumer: metadata.Consumer,
		streamSequence: metadata.Sequence.Stream, numDelivered: metadata.NumDelivered}, nil
}

func (consumer *natsStatusConsumer) Close() error {
	if consumer == nil || consumer.subscription == nil {
		return nil
	}
	return consumer.subscription.Unsubscribe()
}

func (delivery *natsStatusDelivery) Subject() string        { return delivery.message.Subject }
func (delivery *natsStatusDelivery) Data() []byte           { return delivery.message.Data }
func (delivery *natsStatusDelivery) Header() nats.Header    { return delivery.message.Header }
func (delivery *natsStatusDelivery) Stream() string         { return delivery.stream }
func (delivery *natsStatusDelivery) Consumer() string       { return delivery.consumer }
func (delivery *natsStatusDelivery) StreamSequence() uint64 { return delivery.streamSequence }
func (delivery *natsStatusDelivery) NumDelivered() uint64   { return delivery.numDelivered }
func (delivery *natsStatusDelivery) Ack(ctx context.Context) error {
	return delivery.message.AckSync(nats.Context(ctx))
}
func (delivery *natsStatusDelivery) Nak(ctx context.Context, delay time.Duration) error {
	return delivery.message.NakWithDelay(delay, nats.Context(ctx))
}
func (delivery *natsStatusDelivery) Term(ctx context.Context) error {
	return delivery.message.Term(nats.Context(ctx))
}
