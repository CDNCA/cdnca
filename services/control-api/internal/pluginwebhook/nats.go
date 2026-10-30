package pluginwebhook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const (
	DefaultDeliveryStream        = "PLUGIN_WEBHOOK_DELIVERY_V1"
	DefaultDeliveryDurable       = "control_api_plugin_webhook_v1"
	DefaultDeliverySubjectPrefix = "cdnca.plugin.webhook.delivery.v1"
	DefaultDeadLetterStream      = "PLUGIN_WEBHOOK_DEAD_V1"
	DefaultDeadLetterSubject     = "cdnca.plugin.webhook.dead.v1"
	MaxQueueMessageBytes         = 320 * 1024
	DeadLetterSchemaV1           = "cdnca.plugin-webhook.dead-letter/v1"
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
}

func DefaultJetStreamConfig() JetStreamConfig {
	return JetStreamConfig{
		DeliveryStream: DefaultDeliveryStream, DeliveryDurable: DefaultDeliveryDurable,
		DeliverySubjectPrefix: DefaultDeliverySubjectPrefix,
		DeadLetterStream:      DefaultDeadLetterStream, DeadLetterSubject: DefaultDeadLetterSubject,
		AckWait: 2 * time.Minute, FetchTimeout: 2 * time.Second, OperationTimeout: 10 * time.Second,
		ConsumerMaxDeliver: 32, MaxAckPending: 64, MaxWaiting: 16,
		StreamMaxAge: 7 * 24 * time.Hour, StreamMaxBytes: 2 << 30, StreamMaxMessages: 2_000_000,
		DeadLetterMaxAge: 30 * 24 * time.Hour, DeadLetterMaxBytes: 1 << 30,
		DuplicateWindow: 10 * time.Minute, Replicas: 1,
	}
}

type PublishResult struct {
	DeliveryID     uuid.UUID
	IdempotencyKey string
	StreamSequence uint64
	Duplicate      bool
}

type Publisher struct {
	jetstream nats.JetStreamContext
	config    JetStreamConfig
}

func EnsureJetStream(ctx context.Context, connection *nats.Conn, config JetStreamConfig) error {
	if ctx == nil || connection == nil || connection.IsClosed() || validateJetStreamConfig(config) != nil {
		return ErrInvalidConfig
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return fmt.Errorf("create plugin webhook JetStream context: %w", err)
	}
	if err := ensureWebhookStream(ctx, jetstream, expectedDeliveryStream(config), config.OperationTimeout); err != nil {
		return err
	}
	if err := ensureWebhookStream(ctx, jetstream, expectedDeadLetterStream(config), config.OperationTimeout); err != nil {
		return err
	}
	return ensureWebhookConsumer(ctx, jetstream, config)
}

func NewPublisher(connection *nats.Conn, config JetStreamConfig) (*Publisher, error) {
	if connection == nil || connection.IsClosed() || validateJetStreamConfig(config) != nil {
		return nil, ErrInvalidConfig
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create plugin webhook publisher: %w", err)
	}
	if err := verifyWebhookStream(jetstream, expectedDeliveryStream(config), config.OperationTimeout); err != nil {
		return nil, err
	}
	return &Publisher{jetstream: jetstream, config: config}, nil
}

func (publisher *Publisher) Publish(ctx context.Context, request PublishRequest) (PublishResult, error) {
	if publisher == nil || ctx == nil {
		return PublishResult{}, ErrInvalidConfig
	}
	item, err := newQueueItem(request)
	if err != nil {
		return PublishResult{}, err
	}
	acknowledgement, err := publishQueueItem(ctx, publisher.jetstream, publisher.config, item)
	if err != nil {
		return PublishResult{}, err
	}
	return PublishResult{
		DeliveryID: item.DeliveryID, IdempotencyKey: item.IdempotencyKey,
		StreamSequence: acknowledgement.Sequence, Duplicate: acknowledgement.Duplicate,
	}, nil
}

type queueDelivery interface {
	Data() []byte
	Attempts() uint64
	StreamSequence() uint64
	Ack(context.Context) error
	Nak(context.Context, time.Duration) error
}

type queueConsumer interface {
	Next(context.Context) (queueDelivery, error)
	Close() error
}

type NATSConsumer struct {
	subscription *nats.Subscription
	config       JetStreamConfig
}

type natsQueueDelivery struct {
	message        *nats.Msg
	attempts       uint64
	streamSequence uint64
}

func newNATSConsumer(connection *nats.Conn, config JetStreamConfig) (*NATSConsumer, error) {
	if connection == nil || connection.IsClosed() || validateJetStreamConfig(config) != nil {
		return nil, ErrInvalidConfig
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create plugin webhook consumer: %w", err)
	}
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	info, err := jetstream.ConsumerInfo(config.DeliveryStream, config.DeliveryDurable, nats.Context(operationCtx))
	cancel()
	if err != nil || !sameWebhookConsumer(info, expectedDeliveryConsumer(config)) {
		return nil, fmt.Errorf("plugin webhook durable consumer configuration does not match")
	}
	subscription, err := jetstream.PullSubscribe(
		config.DeliverySubjectPrefix+".*.*", config.DeliveryDurable,
		nats.Bind(config.DeliveryStream, config.DeliveryDurable),
	)
	if err != nil {
		return nil, fmt.Errorf("bind plugin webhook durable consumer: %w", err)
	}
	return &NATSConsumer{subscription: subscription, config: config}, nil
}

func (consumer *NATSConsumer) Next(ctx context.Context) (queueDelivery, error) {
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
			return nil, ErrNoDelivery
		}
		return nil, fmt.Errorf("fetch plugin webhook delivery: %w", err)
	}
	metadata, err := messages[0].Metadata()
	if err != nil {
		return nil, fmt.Errorf("read plugin webhook delivery metadata: %w", err)
	}
	return &natsQueueDelivery{
		message: messages[0], attempts: metadata.NumDelivered, streamSequence: metadata.Sequence.Stream,
	}, nil
}

func (consumer *NATSConsumer) Close() error {
	if consumer == nil || consumer.subscription == nil {
		return nil
	}
	return consumer.subscription.Unsubscribe()
}

func (delivery *natsQueueDelivery) Data() []byte           { return delivery.message.Data }
func (delivery *natsQueueDelivery) Attempts() uint64       { return delivery.attempts }
func (delivery *natsQueueDelivery) StreamSequence() uint64 { return delivery.streamSequence }
func (delivery *natsQueueDelivery) Ack(ctx context.Context) error {
	if err := delivery.message.AckSync(nats.Context(ctx)); err != nil {
		return fmt.Errorf("ack plugin webhook delivery: %w", err)
	}
	return nil
}
func (delivery *natsQueueDelivery) Nak(ctx context.Context, delay time.Duration) error {
	if err := delivery.message.NakWithDelay(delay, nats.Context(ctx)); err != nil {
		return fmt.Errorf("nak plugin webhook delivery: %w", err)
	}
	return nil
}

type DeadLetterRecord struct {
	Schema          string            `json:"schema"`
	DeadLetterID    uuid.UUID         `json:"dead_letter_id"`
	Item            *QueueItem        `json:"item,omitempty"`
	RawSHA256       string            `json:"raw_sha256,omitempty"`
	RawBytes        int               `json:"raw_bytes,omitempty"`
	Attempts        uint64            `json:"attempts"`
	SourceSequence  uint64            `json:"source_sequence"`
	ReasonCode      string            `json:"reason_code"`
	StatusCode      int               `json:"status_code,omitempty"`
	RequestSHA256   string            `json:"request_sha256,omitempty"`
	RequestBytes    int               `json:"request_bytes,omitempty"`
	ResponseSHA256  string            `json:"response_sha256,omitempty"`
	ResponseBytes   int               `json:"response_bytes,omitempty"`
	ResponsePreview string            `json:"response_preview,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	FailedAt        time.Time         `json:"failed_at"`
}

type deadLetterSink interface {
	put(context.Context, DeadLetterRecord) error
}

type NATSDeadLetters struct {
	jetstream nats.JetStreamContext
	config    JetStreamConfig
}

func NewDeadLetterStore(connection *nats.Conn, config JetStreamConfig) (*NATSDeadLetters, error) {
	if connection == nil || connection.IsClosed() || validateJetStreamConfig(config) != nil {
		return nil, ErrInvalidConfig
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create plugin webhook dead-letter store: %w", err)
	}
	if err := verifyWebhookStream(jetstream, expectedDeadLetterStream(config), config.OperationTimeout); err != nil {
		return nil, err
	}
	return &NATSDeadLetters{jetstream: jetstream, config: config}, nil
}

func (store *NATSDeadLetters) put(ctx context.Context, record DeadLetterRecord) error {
	if store == nil || ctx == nil || record.Schema != DeadLetterSchemaV1 || record.DeadLetterID == uuid.Nil ||
		record.Attempts == 0 || record.SourceSequence == 0 || !eventIDPattern.MatchString(record.ReasonCode) || record.FailedAt.IsZero() {
		return ErrInvalidInput
	}
	payload, err := json.Marshal(record)
	if err != nil || len(payload) > MaxQueueMessageBytes {
		return ErrInvalidInput
	}
	message := nats.NewMsg(store.config.DeadLetterSubject)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, "plugin-webhook-dead-v1-"+record.DeadLetterID.String())
	operationCtx, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	defer cancel()
	acknowledgement, err := store.jetstream.PublishMsg(
		message, nats.Context(operationCtx), nats.ExpectStream(store.config.DeadLetterStream),
	)
	if err != nil || acknowledgement == nil || acknowledgement.Stream != store.config.DeadLetterStream {
		return fmt.Errorf("persist plugin webhook dead letter")
	}
	return nil
}

func (store *NATSDeadLetters) get(ctx context.Context, sequence uint64) (DeadLetterRecord, error) {
	if store == nil || ctx == nil || sequence == 0 {
		return DeadLetterRecord{}, ErrInvalidInput
	}
	operationCtx, cancel := context.WithTimeout(ctx, store.config.OperationTimeout)
	message, err := store.jetstream.GetMsg(store.config.DeadLetterStream, sequence, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return DeadLetterRecord{}, ErrDeadLetterMissing
	}
	if err != nil {
		return DeadLetterRecord{}, fmt.Errorf("read plugin webhook dead letter: %w", err)
	}
	var record DeadLetterRecord
	if json.Unmarshal(message.Data, &record) != nil || record.Schema != DeadLetterSchemaV1 || record.DeadLetterID == uuid.Nil {
		return DeadLetterRecord{}, ErrInvalidInput
	}
	return record, nil
}

func (store *NATSDeadLetters) Read(
	ctx context.Context,
	sequence uint64,
	tenantID uuid.UUID,
	installationID uuid.UUID,
) (DeadLetterRecord, error) {
	if tenantID == uuid.Nil || installationID == uuid.Nil {
		return DeadLetterRecord{}, ErrInvalidInput
	}
	record, err := store.get(ctx, sequence)
	if err != nil {
		return DeadLetterRecord{}, err
	}
	if !recordMatchesScope(record, tenantID, installationID) {
		return DeadLetterRecord{}, ErrTenantScopeDenied
	}
	return record, nil
}

type ReplayRequest struct {
	DeadLetterSequence uint64
	TenantID           uuid.UUID
	InstallationID     uuid.UUID
	ReplayRequestID    string
}

func (store *NATSDeadLetters) Replay(ctx context.Context, request ReplayRequest) (PublishResult, error) {
	if request.DeadLetterSequence == 0 || request.TenantID == uuid.Nil || request.InstallationID == uuid.Nil ||
		!eventIDPattern.MatchString(request.ReplayRequestID) {
		return PublishResult{}, ErrInvalidInput
	}
	record, err := store.Read(ctx, request.DeadLetterSequence, request.TenantID, request.InstallationID)
	if err != nil {
		return PublishResult{}, err
	}
	if record.Item == nil || validateQueueItem(*record.Item) != nil {
		return PublishResult{}, ErrInvalidInput
	}
	item := *record.Item
	originalID := item.DeliveryID
	item.ReplayOf = &originalID
	item.ReplayRequestID = request.ReplayRequestID
	item.DeliveryID = uuid.NewHash(sha256.New(), deliveryNamespace, []byte("replay\x00"+originalID.String()+"\x00"+request.ReplayRequestID), 5)
	digest := sha256.Sum256([]byte("replay\x00" + originalID.String() + "\x00" + request.ReplayRequestID))
	item.IdempotencyKey = "plugin-webhook-replay-v1-" + hex.EncodeToString(digest[:])
	acknowledgement, err := publishQueueItem(ctx, store.jetstream, store.config, item)
	if err != nil {
		return PublishResult{}, err
	}
	return PublishResult{
		DeliveryID: item.DeliveryID, IdempotencyKey: item.IdempotencyKey,
		StreamSequence: acknowledgement.Sequence, Duplicate: acknowledgement.Duplicate,
	}, nil
}

func recordMatchesScope(record DeadLetterRecord, tenantID, installationID uuid.UUID) bool {
	return record.Item != nil && record.Item.Event.TenantID == tenantID.String() &&
		record.Item.Event.InstallationID == installationID.String() && validateQueueItem(*record.Item) == nil
}

func publishQueueItem(ctx context.Context, jetstream nats.JetStreamContext, config JetStreamConfig, item QueueItem) (*nats.PubAck, error) {
	if ctx == nil || validateQueueItem(item) != nil {
		return nil, ErrInvalidInput
	}
	payload, err := json.Marshal(item)
	if err != nil || len(payload) > MaxQueueMessageBytes {
		return nil, ErrInvalidInput
	}
	message := nats.NewMsg(config.DeliverySubjectPrefix + "." + item.Event.TenantID + "." + item.Event.InstallationID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, item.IdempotencyKey)
	operationCtx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
	defer cancel()
	acknowledgement, err := jetstream.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(config.DeliveryStream))
	if err != nil || acknowledgement == nil || acknowledgement.Stream != config.DeliveryStream {
		return nil, fmt.Errorf("persist plugin webhook delivery")
	}
	return acknowledgement, nil
}

func ensureWebhookStream(ctx context.Context, jetstream nats.JetStreamContext, expected *nats.StreamConfig, timeout time.Duration) error {
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	info, err := jetstream.StreamInfo(expected.Name, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrStreamNotFound) {
		operationCtx, cancel = context.WithTimeout(ctx, timeout)
		info, err = jetstream.AddStream(expected, nats.Context(operationCtx))
		cancel()
	}
	if err != nil {
		return fmt.Errorf("ensure plugin webhook stream %s: %w", expected.Name, err)
	}
	if !sameWebhookStream(info, expected) {
		return fmt.Errorf("plugin webhook stream %s configuration does not match", expected.Name)
	}
	return nil
}

func verifyWebhookStream(jetstream nats.JetStreamContext, expected *nats.StreamConfig, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	info, err := jetstream.StreamInfo(expected.Name, nats.Context(ctx))
	if err != nil || !sameWebhookStream(info, expected) {
		return fmt.Errorf("plugin webhook stream %s configuration does not match", expected.Name)
	}
	return nil
}

func ensureWebhookConsumer(ctx context.Context, jetstream nats.JetStreamContext, config JetStreamConfig) error {
	expected := expectedDeliveryConsumer(config)
	operationCtx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
	info, err := jetstream.ConsumerInfo(config.DeliveryStream, config.DeliveryDurable, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrConsumerNotFound) {
		operationCtx, cancel = context.WithTimeout(ctx, config.OperationTimeout)
		info, err = jetstream.AddConsumer(config.DeliveryStream, expected, nats.Context(operationCtx))
		cancel()
	}
	if err != nil {
		return fmt.Errorf("ensure plugin webhook consumer: %w", err)
	}
	if !sameWebhookConsumer(info, expected) {
		return fmt.Errorf("plugin webhook durable consumer configuration does not match")
	}
	return nil
}

func expectedDeliveryStream(config JetStreamConfig) *nats.StreamConfig {
	return &nats.StreamConfig{
		Name: config.DeliveryStream, Subjects: []string{config.DeliverySubjectPrefix + ".*.*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: config.StreamMaxMessages,
		MaxBytes: config.StreamMaxBytes, Discard: nats.DiscardNew, MaxAge: config.StreamMaxAge,
		MaxMsgSize: MaxQueueMessageBytes, Storage: nats.FileStorage, Replicas: config.Replicas,
		Duplicates: config.DuplicateWindow,
	}
}

func expectedDeadLetterStream(config JetStreamConfig) *nats.StreamConfig {
	return &nats.StreamConfig{
		Name: config.DeadLetterStream, Subjects: []string{config.DeadLetterSubject},
		Retention: nats.LimitsPolicy, MaxConsumers: -1, MaxMsgs: config.StreamMaxMessages,
		MaxBytes: config.DeadLetterMaxBytes, Discard: nats.DiscardNew, MaxAge: config.DeadLetterMaxAge,
		MaxMsgSize: MaxQueueMessageBytes, Storage: nats.FileStorage, Replicas: config.Replicas,
		Duplicates: config.DuplicateWindow,
	}
}

func expectedDeliveryConsumer(config JetStreamConfig) *nats.ConsumerConfig {
	return &nats.ConsumerConfig{
		Durable: config.DeliveryDurable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		AckWait: config.AckWait, MaxDeliver: config.ConsumerMaxDeliver,
		FilterSubject: config.DeliverySubjectPrefix + ".*.*", ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: config.MaxAckPending, MaxWaiting: config.MaxWaiting,
		MaxRequestBatch: 1, MaxRequestExpires: config.FetchTimeout, MaxRequestMaxBytes: MaxQueueMessageBytes,
	}
}

func sameWebhookStream(info *nats.StreamInfo, expected *nats.StreamConfig) bool {
	if info == nil || expected == nil {
		return false
	}
	actual := info.Config
	return actual.Name == expected.Name && slices.Equal(actual.Subjects, expected.Subjects) &&
		actual.Retention == expected.Retention && actual.MaxConsumers == expected.MaxConsumers &&
		actual.MaxMsgs == expected.MaxMsgs && actual.MaxBytes == expected.MaxBytes && actual.Discard == expected.Discard &&
		actual.MaxAge == expected.MaxAge && actual.MaxMsgSize == expected.MaxMsgSize &&
		actual.Storage == expected.Storage && actual.Replicas == expected.Replicas && actual.Duplicates == expected.Duplicates
}

func sameWebhookConsumer(info *nats.ConsumerInfo, expected *nats.ConsumerConfig) bool {
	if info == nil || expected == nil {
		return false
	}
	actual := info.Config
	return actual.Durable == expected.Durable && actual.DeliverPolicy == expected.DeliverPolicy &&
		actual.AckPolicy == expected.AckPolicy && actual.AckWait == expected.AckWait &&
		actual.MaxDeliver == expected.MaxDeliver && actual.FilterSubject == expected.FilterSubject &&
		actual.ReplayPolicy == expected.ReplayPolicy && actual.MaxAckPending == expected.MaxAckPending &&
		actual.MaxWaiting == expected.MaxWaiting && actual.MaxRequestBatch == expected.MaxRequestBatch &&
		actual.MaxRequestExpires == expected.MaxRequestExpires && actual.MaxRequestMaxBytes == expected.MaxRequestMaxBytes
}

func validateJetStreamConfig(config JetStreamConfig) error {
	if !natsTokenPattern.MatchString(config.DeliveryStream) || !natsTokenPattern.MatchString(config.DeliveryDurable) ||
		!natsTokenPattern.MatchString(config.DeadLetterStream) || config.DeliveryStream == config.DeadLetterStream ||
		!validSubjectPrefix(config.DeliverySubjectPrefix) || !validSubjectPrefix(config.DeadLetterSubject) ||
		subjectMatchesDelivery(config.DeadLetterSubject, config.DeliverySubjectPrefix) || config.AckWait <= 3*config.OperationTimeout ||
		config.FetchTimeout <= 0 || config.FetchTimeout > config.AckWait || config.OperationTimeout <= 0 ||
		config.ConsumerMaxDeliver < 2 || config.ConsumerMaxDeliver > 1000 || config.MaxAckPending < 1 || config.MaxAckPending > 1024 ||
		config.MaxWaiting < 1 || config.StreamMaxAge <= 0 || config.StreamMaxBytes < MaxQueueMessageBytes ||
		config.StreamMaxMessages <= 0 || config.DeadLetterMaxAge <= 0 || config.DeadLetterMaxBytes < MaxQueueMessageBytes ||
		config.DuplicateWindow <= 0 || config.DuplicateWindow > config.StreamMaxAge || config.Replicas < 1 || config.Replicas > 5 {
		return ErrInvalidConfig
	}
	return nil
}

func subjectMatchesDelivery(subject, prefix string) bool {
	if !strings.HasPrefix(subject, prefix+".") {
		return false
	}
	return len(strings.Split(strings.TrimPrefix(subject, prefix+"."), ".")) == 2
}

func validSubjectPrefix(value string) bool {
	if value == "" || len(value) > 240 {
		return false
	}
	start := 0
	for index := 0; index <= len(value); index++ {
		if index != len(value) && value[index] != '.' {
			continue
		}
		if index == start || !natsTokenPattern.MatchString(value[start:index]) {
			return false
		}
		start = index + 1
	}
	return true
}
