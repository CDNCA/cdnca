package pluginwebhookruntime

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const (
	DefaultDeliveryStream        = "PLUGIN_WEBHOOK_DELIVERY_V2"
	DefaultDeliveryDurable       = "control_api_plugin_webhook_v2"
	DefaultDeliverySubjectPrefix = "cdnca.plugin-webhook.delivery.v2"
	DefaultDeadLetterStream      = "PLUGIN_WEBHOOK_DLQ"
	DefaultDeadLetterSubject     = "cdnca.plugin-webhook.dead-letter.v1"
	MaxMessageBytes              = 262144
)

var natsTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type JetStreamConfig struct {
	DeliveryStream        string
	DeliveryDurable       string
	DeliverySubjectPrefix string
	DeadLetterStream      string
	DeadLetterSubject     string
	AckWait               time.Duration
	FetchTimeout          time.Duration
	OperationTimeout      time.Duration
	ConsumerMaxDeliver    int
	MaxAckPending         int
	MaxWaiting            int
	StreamMaxAge          time.Duration
	StreamMaxBytes        int64
	StreamMaxMessages     int64
	DeadLetterMaxAge      time.Duration
	DeadLetterMaxBytes    int64
	DuplicateWindow       time.Duration
	Replicas              int
	ReadinessMaxPending   uint64
}

func DefaultJetStreamConfig() JetStreamConfig {
	return JetStreamConfig{
		DeliveryStream: DefaultDeliveryStream, DeliveryDurable: DefaultDeliveryDurable,
		DeliverySubjectPrefix: DefaultDeliverySubjectPrefix,
		DeadLetterStream:      DefaultDeadLetterStream, DeadLetterSubject: DefaultDeadLetterSubject,
		AckWait: 2 * time.Minute, FetchTimeout: 500 * time.Millisecond, OperationTimeout: 10 * time.Second,
		ConsumerMaxDeliver: -1, MaxAckPending: 32, MaxWaiting: 8,
		StreamMaxAge: 7 * 24 * time.Hour, StreamMaxBytes: 2 << 30, StreamMaxMessages: 2_000_000,
		DeadLetterMaxAge: 30 * 24 * time.Hour, DeadLetterMaxBytes: 1 << 30,
		DuplicateWindow: 10 * time.Minute, Replicas: 1, ReadinessMaxPending: 1024,
	}
}

type runtimeConsumer struct {
	subscription *nats.Subscription
	config       JetStreamConfig
}

type runtimeMessage struct {
	message        *nats.Msg
	attempts       uint64
	streamSequence uint64
}

func (message *runtimeMessage) DeliveryID() (uuid.UUID, error) {
	if message == nil || message.message == nil {
		return uuid.Nil, ErrNATSUnavailable
	}
	value := message.message.Header.Get("X-CDNCA-Webhook-Id")
	if value == "" {
		return uuid.Nil, fmt.Errorf("missing plugin webhook delivery id")
	}
	id, err := parseCanonicalUUID(value)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid plugin webhook delivery id")
	}
	return id, nil
}

func (message *runtimeMessage) Scope(prefix string) (uuid.UUID, uuid.UUID, error) {
	if message == nil || message.message == nil || !strings.HasPrefix(message.message.Subject, prefix+".") {
		return uuid.Nil, uuid.Nil, ErrNATSUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(message.message.Subject, prefix+"."), ".")
	if len(parts) != 2 {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid plugin webhook runtime subject")
	}
	identity := strings.Split(parts[1], "_")
	if len(identity) != 2 {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid plugin webhook runtime subject identity")
	}
	tenantScope, tenantErr := parseCanonicalUUID(parts[0])
	subscription, subscriptionErr := parseCanonicalUUID(identity[0])
	delivery, deliveryErr := parseCanonicalUUID(identity[1])
	headerDelivery, headerErr := message.DeliveryID()
	if tenantErr != nil || subscriptionErr != nil || deliveryErr != nil || headerErr != nil || delivery != headerDelivery {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid plugin webhook runtime subject scope")
	}
	return tenantScope, subscription, nil
}

func parseCanonicalUUID(value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || value != id.String() {
		return uuid.Nil, fmt.Errorf("invalid canonical UUID")
	}
	return id, nil
}

func deliverySubject(prefix string, tenantScope, subscription, delivery uuid.UUID) string {
	return prefix + "." + tenantScope.String() + "." + subscription.String() + "_" + delivery.String()
}

func newRuntimeConsumer(connection *nats.Conn, config JetStreamConfig) (*runtimeConsumer, error) {
	if connection == nil || connection.IsClosed() || !validJetStreamConfig(config) {
		return nil, ErrInvalidConfig
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create plugin webhook runtime consumer: %w", err)
	}
	return bindRuntimeConsumer(jetstream, config)
}

func bindRuntimeConsumer(jetstream nats.JetStreamContext, config JetStreamConfig) (*runtimeConsumer, error) {
	if jetstream == nil || !validJetStreamConfig(config) {
		return nil, ErrInvalidConfig
	}
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	info, err := jetstream.ConsumerInfo(config.DeliveryStream, config.DeliveryDurable, nats.Context(operationCtx))
	cancel()
	if err != nil || !sameConsumer(info, consumerConfig(config)) {
		return nil, fmt.Errorf("plugin webhook runtime durable consumer configuration does not match")
	}
	subscription, err := jetstream.PullSubscribe(config.DeliverySubjectPrefix+".*.*", config.DeliveryDurable,
		nats.Bind(config.DeliveryStream, config.DeliveryDurable))
	if err != nil {
		return nil, fmt.Errorf("bind plugin webhook runtime consumer: %w", err)
	}
	operationCtx, cancel = context.WithTimeout(context.Background(), config.OperationTimeout)
	info, err = jetstream.ConsumerInfo(config.DeliveryStream, config.DeliveryDurable, nats.Context(operationCtx))
	cancel()
	if err != nil || !sameConsumer(info, consumerConfig(config)) {
		_ = subscription.Unsubscribe()
		return nil, fmt.Errorf("plugin webhook runtime post-bind durable consumer configuration does not match")
	}
	return &runtimeConsumer{subscription: subscription, config: config}, nil
}

func (consumer *runtimeConsumer) next(ctx context.Context) (*runtimeMessage, error) {
	if consumer == nil || consumer.subscription == nil || ctx == nil {
		return nil, ErrInvalidConfig
	}
	fetchCtx, cancel := context.WithTimeout(ctx, consumer.config.FetchTimeout)
	messages, err := consumer.subscription.Fetch(1, nats.Context(fetchCtx))
	cancel()
	if len(messages) == 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err == nil || errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			return nil, errNoMessage
		}
		return nil, fmt.Errorf("fetch plugin webhook runtime message: %w", err)
	}
	metadata, err := messages[0].Metadata()
	if err != nil {
		return nil, fmt.Errorf("read plugin webhook runtime message metadata: %w", err)
	}
	return &runtimeMessage{message: messages[0], attempts: metadata.NumDelivered, streamSequence: metadata.Sequence.Stream}, nil
}

func (message *runtimeMessage) ack(ctx context.Context) error {
	if message == nil || message.message == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if err := message.message.AckSync(nats.Context(ctx)); err != nil {
		return fmt.Errorf("ack plugin webhook runtime message: %w", err)
	}
	return nil
}

func (message *runtimeMessage) nak(ctx context.Context, delay time.Duration) error {
	if message == nil || message.message == nil || ctx == nil || delay <= 0 {
		return ErrInvalidConfig
	}
	if err := message.message.NakWithDelay(delay, nats.Context(ctx)); err != nil {
		return fmt.Errorf("nak plugin webhook runtime message: %w", err)
	}
	return nil
}

func (consumer *runtimeConsumer) Close() error {
	if consumer == nil || consumer.subscription == nil {
		return nil
	}
	return consumer.subscription.Unsubscribe()
}

func EnsureJetStream(ctx context.Context, connection *nats.Conn, config JetStreamConfig) error {
	if ctx == nil || connection == nil || connection.IsClosed() || !validJetStreamConfig(config) {
		return ErrInvalidConfig
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return fmt.Errorf("create plugin webhook runtime JetStream: %w", err)
	}
	if err := verifyStream(ctx, jetstream, deliveryStreamConfig(config), config.OperationTimeout); err != nil {
		return err
	}
	if err := verifyStream(ctx, jetstream, deadLetterStreamConfig(config), config.OperationTimeout); err != nil {
		return err
	}
	return verifyConsumer(ctx, jetstream, config)
}

func checkJetStreamReady(ctx context.Context, jetstream nats.JetStreamContext, config JetStreamConfig) error {
	if ctx == nil || jetstream == nil || !validJetStreamConfig(config) {
		return ErrInvalidConfig
	}
	if _, err := jetstream.AccountInfo(nats.Context(ctx)); err != nil {
		return fmt.Errorf("plugin webhook runtime JetStream account ACL check: %w", err)
	}
	for _, expected := range []*nats.StreamConfig{deliveryStreamConfig(config), deadLetterStreamConfig(config)} {
		info, err := jetstream.StreamInfo(expected.Name, nats.Context(ctx))
		if err != nil || !sameStream(info, expected) {
			return fmt.Errorf("plugin webhook runtime stream %s readiness check failed: %w", expected.Name, err)
		}
	}
	info, err := jetstream.ConsumerInfo(config.DeliveryStream, config.DeliveryDurable, nats.Context(ctx))
	if err != nil || !sameConsumer(info, consumerConfig(config)) {
		return fmt.Errorf("plugin webhook runtime consumer readiness check failed: %w", err)
	}
	if info.NumAckPending < 0 || uint64(info.NumAckPending) > config.ReadinessMaxPending ||
		info.NumPending > config.ReadinessMaxPending-uint64(info.NumAckPending) {
		return fmt.Errorf("plugin webhook runtime consumer lag exceeds readiness limit")
	}
	return nil
}

func verifyStream(ctx context.Context, jetstream nats.JetStreamContext, expected *nats.StreamConfig, timeout time.Duration) error {
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	info, err := jetstream.StreamInfo(expected.Name, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return fmt.Errorf("inspect precreated plugin webhook runtime stream %s: %w", expected.Name, err)
	}
	if !sameStream(info, expected) {
		return fmt.Errorf("precreated plugin webhook runtime stream %s configuration does not match", expected.Name)
	}
	return nil
}

func verifyConsumer(ctx context.Context, jetstream nats.JetStreamContext, config JetStreamConfig) error {
	expected := consumerConfig(config)
	operationCtx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
	info, err := jetstream.ConsumerInfo(config.DeliveryStream, config.DeliveryDurable, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return fmt.Errorf("inspect precreated plugin webhook runtime consumer: %w", err)
	}
	if !sameConsumer(info, expected) {
		return fmt.Errorf("precreated plugin webhook runtime consumer configuration does not match")
	}
	return nil
}

func deliveryStreamConfig(config JetStreamConfig) *nats.StreamConfig {
	return &nats.StreamConfig{Name: config.DeliveryStream,
		Subjects: []string{config.DeliverySubjectPrefix + ".*.*"}, Retention: nats.WorkQueuePolicy,
		MaxConsumers: 1, MaxMsgs: config.StreamMaxMessages, MaxBytes: config.StreamMaxBytes,
		Discard: nats.DiscardNew, MaxAge: config.StreamMaxAge, MaxMsgsPerSubject: -1, MaxMsgSize: MaxMessageBytes,
		Storage: nats.FileStorage, Replicas: config.Replicas, Duplicates: config.DuplicateWindow}
}

func deadLetterStreamConfig(config JetStreamConfig) *nats.StreamConfig {
	return &nats.StreamConfig{Name: config.DeadLetterStream,
		Subjects: []string{config.DeadLetterSubject}, Retention: nats.LimitsPolicy,
		MaxConsumers: -1, MaxMsgs: config.StreamMaxMessages, MaxBytes: config.DeadLetterMaxBytes,
		Discard: nats.DiscardNew, MaxAge: config.DeadLetterMaxAge, MaxMsgsPerSubject: -1, MaxMsgSize: MaxMessageBytes,
		Storage: nats.FileStorage, Replicas: config.Replicas, Duplicates: config.DuplicateWindow}
}

func consumerConfig(config JetStreamConfig) *nats.ConsumerConfig {
	return &nats.ConsumerConfig{Name: config.DeliveryDurable, Durable: config.DeliveryDurable, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: config.AckWait, MaxDeliver: config.ConsumerMaxDeliver,
		FilterSubject: config.DeliverySubjectPrefix + ".*.*", ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: config.MaxAckPending, MaxWaiting: config.MaxWaiting, MaxRequestBatch: 1,
		MaxRequestExpires: config.FetchTimeout, MaxRequestMaxBytes: MaxMessageBytes}
}

func sameStream(info *nats.StreamInfo, expected *nats.StreamConfig) bool {
	if info == nil || expected == nil {
		return false
	}
	a := info.Config
	return a.Name == expected.Name && a.Description == expected.Description &&
		sameUserMetadata(a.Metadata, expected.Metadata) && a.Template == expected.Template &&
		sameStrings(a.Subjects, expected.Subjects) &&
		a.Retention == expected.Retention && a.MaxConsumers == expected.MaxConsumers && a.MaxMsgs == expected.MaxMsgs &&
		a.MaxBytes == expected.MaxBytes && a.Discard == expected.Discard &&
		a.DiscardNewPerSubject == expected.DiscardNewPerSubject && a.MaxAge == expected.MaxAge &&
		a.MaxMsgsPerSubject == expected.MaxMsgsPerSubject && a.MaxMsgSize == expected.MaxMsgSize &&
		a.Storage == expected.Storage && a.Replicas == expected.Replicas && a.NoAck == expected.NoAck &&
		a.Duplicates == expected.Duplicates && reflect.DeepEqual(a.Placement, expected.Placement) &&
		reflect.DeepEqual(a.Mirror, expected.Mirror) && sameStreamSources(a.Sources, expected.Sources) &&
		a.Sealed == expected.Sealed && a.DenyDelete == expected.DenyDelete && a.DenyPurge == expected.DenyPurge &&
		a.AllowRollup == expected.AllowRollup && a.Compression == expected.Compression && a.FirstSeq == expected.FirstSeq &&
		reflect.DeepEqual(a.SubjectTransform, expected.SubjectTransform) && reflect.DeepEqual(a.RePublish, expected.RePublish) &&
		a.AllowDirect == expected.AllowDirect && a.MirrorDirect == expected.MirrorDirect &&
		a.ConsumerLimits == expected.ConsumerLimits && a.AllowMsgTTL == expected.AllowMsgTTL &&
		a.SubjectDeleteMarkerTTL == expected.SubjectDeleteMarkerTTL
}

func sameStreamSources(actual, expected []*nats.StreamSource) bool {
	if len(actual) != len(expected) {
		return false
	}
	if len(actual) == 0 {
		return true
	}
	return reflect.DeepEqual(actual, expected)
}

func sameConsumer(info *nats.ConsumerInfo, expected *nats.ConsumerConfig) bool {
	if info == nil || expected == nil {
		return false
	}
	a := info.Config
	return a.Name == expected.Name && a.Durable == expected.Durable && a.Description == expected.Description &&
		sameUserMetadata(a.Metadata, expected.Metadata) && a.DeliverPolicy == expected.DeliverPolicy &&
		a.OptStartSeq == expected.OptStartSeq && reflect.DeepEqual(a.OptStartTime, expected.OptStartTime) &&
		a.AckPolicy == expected.AckPolicy && a.AckWait == expected.AckWait && a.MaxDeliver == expected.MaxDeliver &&
		sameDurations(a.BackOff, expected.BackOff) && a.FilterSubject == expected.FilterSubject &&
		sameStrings(a.FilterSubjects, expected.FilterSubjects) && a.ReplayPolicy == expected.ReplayPolicy &&
		a.RateLimit == expected.RateLimit && a.SampleFrequency == expected.SampleFrequency &&
		a.MaxAckPending == expected.MaxAckPending && a.MaxWaiting == expected.MaxWaiting &&
		a.MaxRequestBatch == expected.MaxRequestBatch &&
		a.MaxRequestExpires == expected.MaxRequestExpires && a.MaxRequestMaxBytes == expected.MaxRequestMaxBytes &&
		a.FlowControl == expected.FlowControl && a.Heartbeat == expected.Heartbeat &&
		a.DeliverSubject == expected.DeliverSubject && a.DeliverGroup == expected.DeliverGroup &&
		a.InactiveThreshold == expected.InactiveThreshold && a.Replicas == expected.Replicas &&
		a.MemoryStorage == expected.MemoryStorage && a.HeadersOnly == expected.HeadersOnly
}

func sameUserMetadata(actual, expected map[string]string) bool {
	actualCount, expectedCount := 0, 0
	for name, value := range actual {
		if serverManagedMetadata(name) {
			continue
		}
		actualCount++
		if expectedValue, ok := expected[name]; !ok || expectedValue != value {
			return false
		}
	}
	for name := range expected {
		if !serverManagedMetadata(name) {
			expectedCount++
		}
	}
	return actualCount == expectedCount
}

func serverManagedMetadata(name string) bool {
	return name == "_nats.level" || name == "_nats.req.level" || name == "_nats.ver"
}

func sameStrings(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func sameDurations(actual, expected []time.Duration) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func validJetStreamConfig(config JetStreamConfig) bool {
	return natsTokenPattern.MatchString(config.DeliveryStream) && natsTokenPattern.MatchString(config.DeliveryDurable) &&
		config.DeadLetterStream == DefaultDeadLetterStream && config.DeliveryStream != config.DeadLetterStream &&
		validSubject(config.DeliverySubjectPrefix) && config.DeadLetterSubject == DefaultDeadLetterSubject &&
		config.AckWait > 3*config.OperationTimeout && config.FetchTimeout > 0 && config.FetchTimeout <= config.AckWait &&
		config.OperationTimeout > 0 && config.ConsumerMaxDeliver == -1 &&
		config.MaxAckPending >= 1 && config.MaxAckPending <= 1024 && config.MaxWaiting >= 1 &&
		config.StreamMaxAge > 0 && config.StreamMaxBytes >= MaxMessageBytes && config.StreamMaxMessages > 0 &&
		config.DeadLetterMaxAge > 0 && config.DeadLetterMaxBytes >= MaxMessageBytes && config.DuplicateWindow > 0 &&
		config.DuplicateWindow <= config.StreamMaxAge && config.Replicas >= 1 && config.Replicas <= 5 &&
		config.ReadinessMaxPending > 0 && config.ReadinessMaxPending <= uint64(config.StreamMaxMessages)
}

func validSubject(value string) bool {
	if value == "" || len(value) > 240 {
		return false
	}
	start := 0
	for index := 0; index <= len(value); index++ {
		if index < len(value) && value[index] != '.' {
			continue
		}
		if index == start || !natsTokenPattern.MatchString(value[start:index]) {
			return false
		}
		start = index + 1
	}
	return true
}
