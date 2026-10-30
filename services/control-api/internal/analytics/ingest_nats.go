package analytics

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const (
	DefaultIngestStream                 = "ANALYTICS_INGEST_V1"
	DefaultIngestDurable                = "control_api_analytics_ingest_v1"
	DefaultIsolationStream              = "ANALYTICS_ISOLATION_V1"
	IsolationSubject                    = "cdnca.analytics.isolation.v1"
	ingestNodeHeader                    = "Cdnca-Node-Id"
	ingestTenantHeader                  = "Cdnca-Tenant-Id"
	ingestSiteHeader                    = "Cdnca-Site-Id"
	ingestConfigHeader                  = "Cdnca-Config-Version-Id"
	ingestInstallHeader                 = "Cdnca-Installation-Id"
	isolationWrappedDEKPrefix           = "isolation_wrapped_dek.v1."
	isolationScanStatePrefix            = "isolation_scan.v1."
	isolationCipherKeySize              = 32
	consumerRecoveryStateKey            = "consumer_recovery.v1"
	isolationEvidenceMaxValueSize int32 = 2162688
)

var ErrNoIngestMessages = errors.New("no analytics ingest messages available")

type JetStreamConfig struct {
	Stream               string
	Durable              string
	IsolationStream      string
	AckWait              time.Duration
	FetchTimeout         time.Duration
	OperationTimeout     time.Duration
	NakBaseDelay         time.Duration
	NakMaxDelay          time.Duration
	MaxDeliver           int
	MaxAckPending        int
	MaxWaiting           int
	FetchBatch           int
	StreamMaxAge         time.Duration
	StreamMaxBytes       int64
	StreamMaxMessages    int64
	IsolationMaxAge      time.Duration
	IsolationMaxBytes    int64
	DuplicateWindow      time.Duration
	Replicas             int
	IsolationKeyProvider IsolationKeyProvider
}

type IsolationKeyProvider interface {
	ActiveKeyID(context.Context) (string, error)
	WrapDEK(context.Context, string, []byte) ([]byte, error)
	UnwrapDEK(context.Context, string, []byte) ([]byte, error)
}

type aesGCMIsolationKeyProvider struct {
	mu          sync.RWMutex
	keyID       string
	wrappingKey []byte
	closed      bool
}

func NewAESGCMIsolationKeyProvider(keyID string, wrappingKey []byte) (IsolationKeyProvider, error) {
	if !validIsolationWrappingKeyID(keyID) || len(wrappingKey) != isolationCipherKeySize {
		return nil, ErrInvalidConfiguration
	}
	return &aesGCMIsolationKeyProvider{
		keyID: keyID, wrappingKey: append([]byte(nil), wrappingKey...),
	}, nil
}

func (provider *aesGCMIsolationKeyProvider) ActiveKeyID(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	if provider.closed {
		return "", ErrInvalidConfiguration
	}
	return provider.keyID, nil
}

func (provider *aesGCMIsolationKeyProvider) WrapDEK(ctx context.Context, keyID string, dek []byte) ([]byte, error) {
	if ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	if provider.closed || keyID != provider.keyID || len(dek) != isolationCipherKeySize {
		return nil, ErrInvalidInput
	}
	block, err := aes.NewCipher(provider.wrappingKey)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	wrapped := make([]byte, 1+aead.NonceSize(), 1+aead.NonceSize()+len(dek)+aead.Overhead())
	wrapped[0] = 1
	if _, err := rand.Read(wrapped[1:]); err != nil {
		clear(wrapped)
		return nil, fmt.Errorf("wrap analytics isolation data key")
	}
	wrapped = aead.Seal(wrapped, wrapped[1:], dek, isolationWrappingKeyAAD(keyID))
	if err := ctx.Err(); err != nil {
		clear(wrapped)
		return nil, err
	}
	return wrapped, nil
}

func (provider *aesGCMIsolationKeyProvider) UnwrapDEK(ctx context.Context, keyID string, wrapped []byte) ([]byte, error) {
	if ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	if provider.closed || keyID != provider.keyID {
		return nil, ErrInvalidInput
	}
	block, err := aes.NewCipher(provider.wrappingKey)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(wrapped) != 1+aead.NonceSize()+isolationCipherKeySize+aead.Overhead() || wrapped[0] != 1 {
		return nil, ErrInvalidInput
	}
	plaintext, err := aead.Open(nil, wrapped[1:1+aead.NonceSize()], wrapped[1+aead.NonceSize():], isolationWrappingKeyAAD(keyID))
	if err != nil || len(plaintext) != isolationCipherKeySize {
		clear(plaintext)
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		clear(plaintext)
		return nil, err
	}
	return plaintext, nil
}

func (provider *aesGCMIsolationKeyProvider) Close() error {
	if provider == nil {
		return nil
	}
	provider.mu.Lock()
	clear(provider.wrappingKey)
	provider.closed = true
	provider.mu.Unlock()
	return nil
}

func validIsolationWrappingKeyID(keyID string) bool {
	return keyID != "" && len(keyID) <= 128 && utf8.ValidString(keyID) &&
		strings.TrimSpace(keyID) == keyID && strings.IndexFunc(keyID, unicode.IsControl) < 0
}

func isolationWrappingKeyAAD(keyID string) []byte {
	return []byte("cdnca.analytics.isolation.dek-wrap.v1\x00" + keyID)
}

func DefaultJetStreamConfig() JetStreamConfig {
	return JetStreamConfig{
		Stream: DefaultIngestStream, Durable: DefaultIngestDurable, IsolationStream: DefaultIsolationStream,
		AckWait: 2 * time.Minute, FetchTimeout: 2 * time.Second, OperationTimeout: 10 * time.Second,
		NakBaseDelay: time.Second, NakMaxDelay: 2 * time.Minute,
		MaxDeliver: 8, MaxAckPending: 256, MaxWaiting: 16, FetchBatch: 32,
		StreamMaxAge: 0, StreamMaxBytes: 10 << 30, StreamMaxMessages: 10_000_000,
		IsolationMaxAge: 30 * 24 * time.Hour, IsolationMaxBytes: 1 << 30,
		DuplicateWindow: 10 * time.Minute, Replicas: 1,
	}
}

type IngestDelivery interface {
	Subject() string
	Data() []byte
	MessageID() string
	Attempts() uint64
	StreamSequence() uint64
	Ack(context.Context) error
	Nak(context.Context, time.Duration) error
	Term(context.Context) error
}

type NATSIngestConsumer struct {
	mu              sync.Mutex
	fetchMu         sync.Mutex
	leaseMu         sync.Mutex
	jetstream       nats.JetStreamContext
	subscription    *nats.Subscription
	config          JetStreamConfig
	stateStore      nats.KeyValue
	leaseStore      nats.KeyValue
	evidenceStore   nats.KeyValue
	streamCreated   time.Time
	consumerCreated time.Time
	leaseRevision   uint64
	ownerID         string
	leaseStop       chan struct{}
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	recoverySinks   map[*NATSIsolationSink]struct{}
	recoveryWG      sync.WaitGroup
	closeDone       chan struct{}
	closeErr        error
	closed          bool
}

type natsIngestDelivery struct {
	message        *nats.Msg
	attempts       uint64
	streamSequence uint64
	consumer       *NATSIngestConsumer
}

type ingestAuthority struct {
	nodeID         string
	tenantID       string
	siteID         string
	configVersion  string
	installationID string
}

type IsolationRecord struct {
	SchemaVersion    uint16         `json:"schema_version"`
	ReasonCode       string         `json:"reason_code"`
	MessageID        string         `json:"message_id,omitempty"`
	Subject          string         `json:"subject"`
	PayloadSHA256    string         `json:"payload_sha256"`
	PayloadBytes     int            `json:"payload_bytes"`
	Attempts         uint64         `json:"attempts"`
	StreamSequence   uint64         `json:"stream_sequence"`
	IsolatedAt       time.Time      `json:"isolated_at"`
	WireNonce        string         `json:"wire_nonce,omitempty"`
	WireCiphertext   string         `json:"wire_ciphertext,omitempty"`
	WireSHA256       string         `json:"wire_sha256,omitempty"`
	WireKeyID        string         `json:"wire_key_id,omitempty"`
	WireEvidenceOnly bool           `json:"wire_evidence_only,omitempty"`
	Wire             *IsolationWire `json:"-"`
}

type IsolationWire struct {
	Subject string            `json:"subject"`
	Headers []IsolationHeader `json:"headers"`
	Payload []byte            `json:"payload"`
}

type IsolationHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type IsolationSink interface {
	Record(context.Context, IsolationRecord) error
}

type NATSIsolationSink struct {
	jetstream        nats.JetStreamContext
	stream           string
	streamCreated    time.Time
	expectedStream   nats.StreamConfig
	operationTimeout time.Duration
	scanLimit        uint64
	stateStore       nats.KeyValue
	evidenceStore    nats.KeyValue
	keyProvider      IsolationKeyProvider
	publishMessage   func(*nats.Msg, ...nats.PubOpt) (*nats.PubAck, error)
	recoveryMu       sync.Mutex
	recovering       map[string]*isolationRecoveryTask
	recoveryQueue    []*isolationRecoveryTask
	recoveryWorkers  int
	recoveryWake     chan struct{}
	recoveryCond     *sync.Cond
}

type isolationRecoveryTask struct {
	key      string
	delivery *natsIngestDelivery
	intent   isolationPublishIntent
	state    *parkedDeliveryState
	attempts uint64
	readyAt  time.Time
	active   bool
}

type parkedDeliveryPhase string

const (
	parkedPhaseDelivery          parkedDeliveryPhase = "delivery"
	parkedPhaseEvidencePrepared  parkedDeliveryPhase = "evidence_prepared"
	parkedPhaseEvidenceConfirmed parkedDeliveryPhase = "evidence_confirmed"
	parkedPhaseAckPending        parkedDeliveryPhase = "ack_pending"
	parkedPhaseTermPending       parkedDeliveryPhase = "term_pending"
	parkedPhaseSettled           parkedDeliveryPhase = "settled"
)

type isolationPublishIntent struct {
	Subject        string
	Stream         string
	MessageID      string
	Payload        []byte
	PayloadSHA256  [sha256.Size]byte
	ScanStart      uint64
	ScanLast       uint64
	StreamCreated  time.Time
	delivery       *natsIngestDelivery
	ReconcileFirst bool
}

type isolationEvidenceBlobMetadata struct {
	SchemaVersion        uint16            `json:"schema_version"`
	SourceStreamCreated  string            `json:"source_stream_created"`
	SourceStreamSequence uint64            `json:"source_stream_sequence"`
	Subject              string            `json:"subject"`
	Headers              []IsolationHeader `json:"headers"`
	PayloadBytes         int               `json:"payload_bytes"`
	PayloadSHA256        string            `json:"payload_sha256"`
}

const (
	isolationEvidenceScanBatch          uint64 = 64
	isolationEvidenceRecoveryPause             = time.Millisecond
	isolationEvidenceRecoveryWorkers           = 2
	isolationEvidenceRecoveryMinBackoff        = 5 * time.Millisecond
	isolationEvidenceRecoveryMaxBackoff        = 250 * time.Millisecond
)

var errIsolationEvidenceScanPending = errors.New("analytics isolation reconciliation pending")

// errIsolationEvidenceDedupeHidden：同 MsgId 重发被 JetStream 去重窗口吞掉，PubAck duplicate 指向已删除的序号。
// 证据 MsgId 绑定在不可变意图里不能换，只能等窗口过期再发，恢复须按退避重试而不是按扫描暂停空转。
var errIsolationEvidenceDedupeHidden = errors.New("analytics isolation evidence hidden by publish dedupe window")

var errIsolationStreamEpochChanged = errors.New("analytics isolation stream epoch changed")

func EnsureIngestJetStream(ctx context.Context, connection *nats.Conn, config JetStreamConfig) error {
	if err := validateJetStreamConfig(config); err != nil || connection == nil || connection.IsClosed() {
		return ErrInvalidConfiguration
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return fmt.Errorf("create analytics JetStream context: %w", err)
	}
	if err := ensureStream(ctx, jetstream, expectedIngestStream(config), config.OperationTimeout); err != nil {
		return err
	}
	if err := ensureStream(ctx, jetstream, expectedIsolationStream(config), config.OperationTimeout); err != nil {
		return err
	}
	if err := ensureConsumer(ctx, jetstream, config); err != nil {
		return err
	}
	if _, _, err = ensureCoordinationStores(jetstream, config); err != nil {
		return err
	}
	return ensureEvidenceStore(jetstream, config)
}

func NewNATSIngestConsumer(connection *nats.Conn, config JetStreamConfig) (*NATSIngestConsumer, error) {
	if err := validateJetStreamConfig(config); err != nil || connection == nil || connection.IsClosed() {
		return nil, ErrInvalidConfiguration
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create analytics JetStream context: %w", err)
	}
	streamInfo, err := exactStreamInfo(
		context.Background(), jetstream, expectedIngestStream(config), config.OperationTimeout,
	)
	if err != nil {
		return nil, err
	}
	if _, err := exactStreamInfo(
		context.Background(), jetstream, expectedIsolationStream(config), config.OperationTimeout,
	); err != nil {
		return nil, err
	}
	stateStore, leaseStore, err := ensureCoordinationStores(jetstream, config)
	if err != nil {
		return nil, err
	}
	evidenceStore, err := openEvidenceStore(jetstream, config)
	if err != nil {
		return nil, err
	}
	if err := requireEpoch(stateStore, "stream_created", streamInfo.Created); err != nil {
		return nil, fmt.Errorf("analytics ingest stream epoch: %w", err)
	}
	recovery, _, recoveryErr := loadConsumerRecovery(stateStore)
	if recoveryErr != nil && !errors.Is(recoveryErr, nats.ErrKeyNotFound) {
		return nil, fmt.Errorf("read analytics consumer recovery: %w", recoveryErr)
	}
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	info, infoErr := jetstream.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	cancel()
	if infoErr != nil && (!errors.Is(infoErr, nats.ErrConsumerNotFound) || recovery == nil) {
		return nil, fmt.Errorf("analytics ingest durable consumer configuration does not match")
	}
	if infoErr == nil && !sameIngestConsumer(info, expectedConsumer(config)) {
		return nil, fmt.Errorf("analytics ingest durable consumer configuration does not match")
	}
	if recovery != nil {
		if err := validateConsumerRecovery(*recovery, streamInfo.Created, info); err != nil {
			return nil, fmt.Errorf("analytics ingest consumer recovery: %w", err)
		}
	} else if err := requireEpoch(stateStore, "consumer_created", info.Created); err != nil {
		return nil, fmt.Errorf("analytics ingest consumer epoch: %w", err)
	}
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	consumer := &NATSIngestConsumer{
		jetstream: jetstream, config: config, stateStore: stateStore, leaseStore: leaseStore,
		evidenceStore: evidenceStore,
		streamCreated: streamInfo.Created, ownerID: uuid.NewString(),
		lifecycleCtx: lifecycleCtx, lifecycleCancel: lifecycleCancel,
		closeDone: make(chan struct{}),
	}
	if info != nil {
		consumer.consumerCreated = info.Created
		if err := consumer.bindSubscription(); err != nil {
			lifecycleCancel()
			return nil, err
		}
	}
	return consumer, nil
}

func NewNATSIsolationSink(connection *nats.Conn, config JetStreamConfig) (*NATSIsolationSink, error) {
	if err := validateJetStreamConfig(config); err != nil || connection == nil || connection.IsClosed() ||
		config.IsolationKeyProvider == nil {
		return nil, ErrInvalidConfiguration
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create isolation JetStream context: %w", err)
	}
	expectedStream := expectedIsolationStream(config)
	streamInfo, err := exactStreamInfo(context.Background(), jetstream, expectedStream, config.OperationTimeout)
	if err != nil {
		return nil, err
	}
	stateStore, _, err := ensureCoordinationStores(jetstream, config)
	if err != nil {
		return nil, err
	}
	evidenceStore, err := openEvidenceStore(jetstream, config)
	if err != nil {
		return nil, err
	}
	sink := &NATSIsolationSink{
		jetstream: jetstream, stream: config.IsolationStream, streamCreated: streamInfo.Created,
		expectedStream:   *expectedStream,
		operationTimeout: config.OperationTimeout, scanLimit: isolationEvidenceScanBatch, stateStore: stateStore,
		evidenceStore: evidenceStore,
		keyProvider:   config.IsolationKeyProvider, recovering: make(map[string]*isolationRecoveryTask),
		recoveryWake: make(chan struct{}, isolationEvidenceRecoveryWorkers),
	}
	sink.recoveryCond = sync.NewCond(&sink.recoveryMu)
	return sink, nil
}

func (consumer *NATSIngestConsumer) Fetch(ctx context.Context) ([]IngestDelivery, error) {
	if consumer == nil || ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	consumer.fetchMu.Lock()
	defer consumer.fetchMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	consumer.mu.Lock()
	if consumer.closed {
		consumer.mu.Unlock()
		return nil, ErrInvalidConfiguration
	}
	consumer.mu.Unlock()
	operationCtx, cancelOperation := consumer.lifecycleContext(ctx)
	defer cancelOperation()
	acquired, err := consumer.acquireOrRenewLease()
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, ErrNoIngestMessages
	}
	if err := consumer.recoverParked(operationCtx); err != nil {
		return nil, err
	}
	consumer.mu.Lock()
	subscription := consumer.subscription
	consumer.mu.Unlock()
	if subscription == nil {
		return nil, ErrInvalidConfiguration
	}
	fetchCtx, cancel := context.WithTimeout(operationCtx, consumer.config.FetchTimeout)
	messages, err := subscription.Fetch(consumer.config.FetchBatch, nats.Context(fetchCtx))
	cancel()
	if len(messages) == 0 && err != nil {
		if operationCtx.Err() != nil {
			return nil, operationCtx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
			return nil, ErrNoIngestMessages
		}
		return nil, fmt.Errorf("fetch analytics ingest batch: %w", err)
	}
	if len(messages) == 0 {
		return nil, ErrNoIngestMessages
	}
	deliveries := make([]IngestDelivery, 0, len(messages))
	for _, message := range messages {
		metadata, metadataErr := message.Metadata()
		if metadataErr != nil {
			return nil, fmt.Errorf("read analytics ingest delivery metadata: %w", metadataErr)
		}
		if err := consumer.markParkedLocked(operationCtx, metadata.Sequence.Stream,
			metadata.NumDelivered >= uint64(consumer.config.MaxDeliver)); err != nil {
			return nil, fmt.Errorf("persist delivery recovery state before delivery: %w", err)
		}
		deliveries = append(deliveries, &natsIngestDelivery{
			message: message, attempts: metadata.NumDelivered, streamSequence: metadata.Sequence.Stream, consumer: consumer,
		})
	}
	return deliveries, nil
}

func (consumer *NATSIngestConsumer) HistorySnapshot(
	ctx context.Context,
	expected IngestHistoryGenerationV1,
) (IngestBrokerHistorySnapshotV1, error) {
	if consumer == nil || ctx == nil || consumer.jetstream == nil || ValidateIngestHistoryGenerationV1(expected) != nil ||
		expected.NATSDomain != "" || expected.StreamName != consumer.config.Stream || expected.DurableName != consumer.config.Durable {
		return IngestBrokerHistorySnapshotV1{}, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return IngestBrokerHistorySnapshotV1{}, err
	}
	operationCtx, cancel := context.WithTimeout(ctx, consumer.config.OperationTimeout)
	defer cancel()
	streamInfo, err := consumer.jetstream.StreamInfo(consumer.config.Stream, nats.Context(operationCtx))
	if err != nil || streamInfo == nil {
		return IngestBrokerHistorySnapshotV1{}, fmt.Errorf("read analytics ingest stream history: %w", err)
	}
	consumerInfo, err := consumer.jetstream.ConsumerInfo(consumer.config.Stream, consumer.config.Durable, nats.Context(operationCtx))
	if err != nil || consumerInfo == nil {
		return IngestBrokerHistorySnapshotV1{}, fmt.Errorf("read analytics ingest consumer history: %w", err)
	}
	streamCreated, consumerCreated := streamInfo.Created.UTC(), consumerInfo.Created.UTC()
	if streamCreated.IsZero() || consumerCreated.IsZero() || streamCreated.UnixNano() <= 0 || consumerCreated.UnixNano() <= 0 ||
		uint64(streamCreated.UnixNano()) != expected.StreamCreatedUnixNano ||
		uint64(consumerCreated.UnixNano()) != expected.ConsumerCreatedUnixNano ||
		!streamCreated.Equal(consumer.streamCreated.UTC()) || !consumerCreated.Equal(consumer.consumerCreated.UTC()) {
		return IngestBrokerHistorySnapshotV1{}, ErrIngestHistoryGenerationChanged
	}
	return IngestBrokerHistorySnapshotV1{
		Generation: expected, ConsumerAckFloor: consumerInfo.AckFloor.Consumer, StreamAckFloor: consumerInfo.AckFloor.Stream,
	}, nil
}

func (consumer *NATSIngestConsumer) Close() error {
	if consumer == nil {
		return nil
	}
	consumer.mu.Lock()
	if consumer.closed {
		done := consumer.closeDone
		consumer.mu.Unlock()
		if done != nil {
			<-done
		}
		consumer.mu.Lock()
		err := consumer.closeErr
		consumer.mu.Unlock()
		return err
	}
	consumer.closed = true
	if consumer.lifecycleCancel != nil {
		consumer.lifecycleCancel()
	}
	subscription := consumer.subscription
	consumer.subscription = nil
	sinks := make([]*NATSIsolationSink, 0, len(consumer.recoverySinks))
	for sink := range consumer.recoverySinks {
		sinks = append(sinks, sink)
	}
	consumer.mu.Unlock()
	for _, sink := range sinks {
		sink.stopTerminalEvidenceRecovery(consumer)
	}
	consumer.recoveryWG.Wait()
	for _, sink := range sinks {
		sink.waitTerminalEvidenceRecoveryStopped(consumer)
	}
	consumer.fetchMu.Lock()
	var errs []error
	if subscription != nil {
		errs = append(errs, subscription.Unsubscribe())
	}
	consumer.leaseMu.Lock()
	if consumer.leaseRevision != 0 {
		errs = append(errs, consumer.leaseStore.Delete("active", nats.LastRevision(consumer.leaseRevision)))
		consumer.leaseRevision = 0
	}
	if consumer.leaseStop != nil {
		close(consumer.leaseStop)
		consumer.leaseStop = nil
	}
	consumer.leaseMu.Unlock()
	consumer.fetchMu.Unlock()
	err := errors.Join(errs...)
	consumer.mu.Lock()
	consumer.closeErr = err
	if consumer.closeDone != nil {
		close(consumer.closeDone)
		consumer.closeDone = nil
	}
	consumer.mu.Unlock()
	return err
}

func (consumer *NATSIngestConsumer) lifecycleContext(caller context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(caller)
	if consumer.lifecycleCtx == nil {
		return ctx, cancel
	}
	stop := context.AfterFunc(consumer.lifecycleCtx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

func coordinationBucketNames(config JetStreamConfig) (string, string) {
	digest := sha256Sum([]byte(config.Stream + "\x00" + config.Durable))
	suffix := fmt.Sprintf("%x", digest[:8])
	return "AISTATE_" + suffix, "AILEASE_" + suffix
}

func isolationEvidenceBucketName(config JetStreamConfig) string {
	digest := sha256Sum([]byte(config.Stream + "\x00" + config.Durable))
	return "AIEVIDENCE_" + hex.EncodeToString(digest[:8])
}

func ensureEvidenceStore(jetstream nats.JetStreamContext, config JetStreamConfig) error {
	_, err := openEvidenceStore(jetstream, config)
	return err
}

func openEvidenceStore(jetstream nats.JetStreamContext, config JetStreamConfig) (nats.KeyValue, error) {
	if jetstream == nil {
		return nil, ErrInvalidConfiguration
	}
	bucket := isolationEvidenceBucketName(config)
	store, err := jetstream.KeyValue(bucket)
	if err != nil {
		return nil, fmt.Errorf("open analytics evidence bucket %s: %w", bucket, err)
	}
	info, err := jetstream.StreamInfo("KV_" + bucket)
	if err != nil || !sameEvidenceStore(info, config) {
		return nil, fmt.Errorf("analytics evidence bucket %s configuration does not match: %w", bucket, err)
	}
	return store, nil
}

func sameEvidenceStore(info *nats.StreamInfo, config JetStreamConfig) bool {
	if info == nil {
		return false
	}
	wanted := expectedEvidenceStore(config)
	actual := info.Config
	actual.Description, wanted.Description = "", ""
	actual.Metadata, wanted.Metadata = nil, nil
	actual.Template, wanted.Template = "", ""
	return reflect.DeepEqual(actual, wanted)
}

func expectedEvidenceStore(config JetStreamConfig) nats.StreamConfig {
	bucket := isolationEvidenceBucketName(config)
	return nats.StreamConfig{
		Name: "KV_" + bucket, Subjects: []string{"$KV." + bucket + ".>"}, Retention: nats.LimitsPolicy,
		MaxConsumers: -1, MaxMsgs: -1, MaxBytes: config.IsolationMaxBytes, Discard: nats.DiscardNew,
		MaxAge: 0, MaxMsgsPerSubject: 1, MaxMsgSize: isolationEvidenceMaxValueSize,
		Storage: nats.FileStorage, Replicas: config.Replicas, Duplicates: 2 * time.Minute,
		DenyDelete: true, AllowRollup: true, AllowDirect: true,
	}
}

func ensureCoordinationStores(jetstream nats.JetStreamContext, config JetStreamConfig) (nats.KeyValue, nats.KeyValue, error) {
	stateName, leaseName := coordinationBucketNames(config)
	state, err := ensureCoordinationStore(jetstream, stateName, 0, config.Replicas)
	if err != nil {
		return nil, nil, err
	}
	lease, err := ensureCoordinationStore(jetstream, leaseName, coordinationLeaseTTL(config), config.Replicas)
	if err != nil {
		return nil, nil, err
	}
	return state, lease, nil
}

func coordinationLeaseTTL(config JetStreamConfig) time.Duration {
	return max(4*config.OperationTimeout, 4*config.FetchTimeout)
}

func ensureCoordinationStore(jetstream nats.JetStreamContext, bucket string, ttl time.Duration, replicas int) (nats.KeyValue, error) {
	store, err := jetstream.KeyValue(bucket)
	if errors.Is(err, nats.ErrBucketNotFound) {
		store, err = jetstream.CreateKeyValue(&nats.KeyValueConfig{
			Bucket: bucket, History: 1, TTL: ttl, MaxBytes: 4 << 20, MaxValueSize: 1024,
			Storage: nats.FileStorage, Replicas: replicas,
		})
		if err != nil {
			store, err = jetstream.KeyValue(bucket)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("ensure analytics coordination bucket %s: %w", bucket, err)
	}
	info, err := jetstream.StreamInfo("KV_" + bucket)
	if err != nil || info.Config.Storage != nats.FileStorage || info.Config.Replicas != replicas || info.Config.MaxAge != ttl {
		return nil, fmt.Errorf("analytics coordination bucket %s configuration does not match", bucket)
	}
	return store, nil
}

func requireEpoch(store nats.KeyValue, key string, created time.Time) error {
	value := []byte(created.UTC().Format(time.RFC3339Nano))
	_, err := store.Create(key, value)
	if err == nil {
		return nil
	}
	entry, getErr := store.Get(key)
	if getErr != nil {
		return errors.Join(err, getErr)
	}
	if string(entry.Value()) != string(value) {
		return fmt.Errorf("changed from %s to %s", entry.Value(), value)
	}
	return nil
}

func (consumer *NATSIngestConsumer) acquireOrRenewLease() (bool, error) {
	consumer.leaseMu.Lock()
	defer consumer.leaseMu.Unlock()
	if consumer.leaseRevision == 0 {
		revision, err := consumer.leaseStore.Create("active", []byte(consumer.ownerID))
		if errors.Is(err, nats.ErrKeyExists) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("acquire analytics ingest lease: %w", err)
		}
		consumer.leaseRevision = revision
		consumer.leaseStop = make(chan struct{})
		go consumer.renewLease(consumer.leaseStop)
		return true, nil
	}
	revision, err := consumer.leaseStore.Update("active", []byte(consumer.ownerID), consumer.leaseRevision)
	if errors.Is(err, nats.ErrKeyNotFound) || errors.Is(err, nats.ErrKeyExists) {
		consumer.leaseRevision = 0
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("renew analytics ingest lease: %w", err)
	}
	consumer.leaseRevision = revision
	return true, nil
}

func (consumer *NATSIngestConsumer) renewLease(stop <-chan struct{}) {
	interval := coordinationLeaseTTL(consumer.config) / 3
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			consumer.leaseMu.Lock()
			if consumer.leaseRevision == 0 {
				consumer.leaseMu.Unlock()
				return
			}
			revision, err := consumer.leaseStore.Update("active", []byte(consumer.ownerID), consumer.leaseRevision)
			if err != nil {
				consumer.leaseRevision = 0
				consumer.leaseMu.Unlock()
				return
			}
			consumer.leaseRevision = revision
			consumer.leaseMu.Unlock()
		}
	}
}

func (consumer *NATSIngestConsumer) withLeaseFence(action func(context.Context) error) error {
	return consumer.withLeaseFenceContext(context.Background(), action)
}

func (consumer *NATSIngestConsumer) withLeaseFenceContext(
	caller context.Context,
	action func(context.Context) error,
) error {
	if consumer == nil || consumer.leaseStore == nil {
		return fmt.Errorf("analytics ingest lease is unavailable")
	}
	if caller == nil {
		return ErrInvalidInput
	}
	actionCtx, cancel := context.WithTimeout(caller, coordinationLeaseTTL(consumer.config)/2)
	if consumer.lifecycleCtx != nil {
		stop := context.AfterFunc(consumer.lifecycleCtx, cancel)
		defer stop()
	}
	defer cancel()
	consumer.leaseMu.Lock()
	defer consumer.leaseMu.Unlock()
	if consumer.leaseRevision == 0 {
		return fmt.Errorf("analytics ingest lease was lost")
	}
	revision, err := consumer.leaseStore.Update("active", []byte(consumer.ownerID), consumer.leaseRevision)
	if err != nil {
		consumer.leaseRevision = 0
		return fmt.Errorf("analytics ingest lease was lost: %w", err)
	}
	consumer.leaseRevision = revision
	if err := actionCtx.Err(); err != nil {
		return fmt.Errorf("analytics ingest lease action expired: %w", err)
	}
	if action == nil {
		return nil
	}
	return action(actionCtx)
}

func (consumer *NATSIngestConsumer) markParked(sequence uint64) error {
	if consumer == nil || consumer.stateStore == nil || sequence == 0 {
		return ErrInvalidConfiguration
	}
	return consumer.markParkedLocked(context.Background(), sequence, true)
}

type parkedDeliveryState struct {
	StreamCreated         string              `json:"stream_created"`
	OwnerID               string              `json:"owner_id"`
	Terminal              bool                `json:"terminal"`
	Phase                 parkedDeliveryPhase `json:"phase,omitempty"`
	MessageID             string              `json:"message_id,omitempty"`
	ReasonCode            string              `json:"reason_code,omitempty"`
	PayloadSHA256         string              `json:"payload_sha256,omitempty"`
	EvidenceMessageID     string              `json:"evidence_message_id,omitempty"`
	EvidenceConfirmed     bool                `json:"evidence_confirmed,omitempty"`
	EvidenceSubject       string              `json:"es,omitempty"`
	EvidencePayloadSHA256 string              `json:"ep,omitempty"`
	EvidenceBlobSHA256    string              `json:"ez,omitempty"`
	EvidenceWireSHA256    string              `json:"ew,omitempty"`
	EvidenceKeySHA256     string              `json:"ek,omitempty"`
	EvidenceNonce         string              `json:"en,omitempty"`
	EvidenceIsolatedAt    string              `json:"et,omitempty"`
	EvidenceAttempts      uint64              `json:"ea,omitempty"`
	EvidenceGeneration    uint64              `json:"eg,omitempty"`
	EvidenceStreamCreated string              `json:"ec,omitempty"`
	EvidenceScanStart     uint64              `json:"eb,omitempty"`
	EvidenceScanLast      uint64              `json:"el,omitempty"`
	EvidenceSequence      uint64              `json:"eq,omitempty"`
	EvidenceOnly          bool                `json:"eo,omitempty"`
	TermSent              bool                `json:"ts,omitempty"`
}

func (consumer *NATSIngestConsumer) markParkedLocked(ctx context.Context, sequence uint64, terminal bool) error {
	return consumer.withLeaseFenceContext(ctx, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return consumer.persistParkedLocked(sequence, terminal)
	})
}

func (consumer *NATSIngestConsumer) persistParkedLocked(sequence uint64, terminal bool) error {
	key := fmt.Sprintf("parked.%020d", sequence)
	state := parkedDeliveryState{
		StreamCreated: consumer.streamCreated.UTC().Format(time.RFC3339Nano),
		OwnerID:       consumer.ownerID, Terminal: terminal, Phase: parkedPhaseDelivery,
	}
	value, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, createErr := consumer.stateStore.Create(key, value)
	if errors.Is(createErr, nats.ErrKeyExists) {
		entry, getErr := consumer.stateStore.Get(key)
		if getErr != nil {
			return errors.Join(createErr, getErr)
		}
		existing, decodeErr := decodeParkedDeliveryState(entry.Value(), sequence)
		if decodeErr != nil || existing.StreamCreated != state.StreamCreated {
			return fmt.Errorf("parked delivery state does not match stream epoch")
		}
		if existing.OwnerID == state.OwnerID && (existing.Terminal || !terminal) {
			return nil
		}
		existing.OwnerID = state.OwnerID
		existing.Terminal = existing.Terminal || terminal
		value, err = json.Marshal(existing)
		if err != nil {
			return err
		}
		_, updateErr := consumer.stateStore.Update(key, value, entry.Revision())
		return updateErr
	}
	return createErr
}

func decodeParkedDeliveryState(value []byte, sequence uint64) (parkedDeliveryState, error) {
	var state parkedDeliveryState
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil {
		return state, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return state, ErrInvalidInput
	}
	if state.StreamCreated == "" || state.OwnerID == "" {
		return state, ErrInvalidInput
	}
	if state.Phase == "" {
		if state.EvidenceConfirmed {
			state.Phase = parkedPhaseEvidenceConfirmed
		} else {
			state.Phase = parkedPhaseDelivery
		}
	}
	validPhase := state.Phase == parkedPhaseDelivery || state.Phase == parkedPhaseEvidencePrepared ||
		state.Phase == parkedPhaseEvidenceConfirmed || state.Phase == parkedPhaseAckPending ||
		state.Phase == parkedPhaseTermPending || state.Phase == parkedPhaseSettled
	if !validPhase {
		return state, ErrInvalidInput
	}
	hasEvidenceIntent := state.EvidenceMessageID != "" || state.EvidenceSubject != "" ||
		state.EvidencePayloadSHA256 != "" || state.EvidenceBlobSHA256 != "" || state.EvidenceWireSHA256 != "" || state.EvidenceKeySHA256 != "" ||
		state.EvidenceNonce != "" || state.EvidenceIsolatedAt != "" || state.EvidenceAttempts != 0 ||
		state.EvidenceGeneration != 0 || state.EvidenceStreamCreated != "" ||
		state.EvidenceScanStart != 0 || state.EvidenceScanLast != 0 ||
		state.EvidenceSequence != 0 || state.EvidenceOnly
	if !hasEvidenceIntent {
		if state.MessageID != "" || state.ReasonCode != "" || state.PayloadSHA256 != "" || state.EvidenceConfirmed || state.TermSent ||
			(state.Phase != parkedPhaseDelivery && state.Phase != parkedPhaseAckPending && state.Phase != parkedPhaseSettled) {
			return state, ErrInvalidInput
		}
		return state, nil
	}
	evidenceSubject := state.EvidenceSubject
	if evidenceSubject == "" {
		evidenceSubject = IsolationSubject
	}
	if !state.Terminal || state.ReasonCode == "" || len(state.ReasonCode) > 128 ||
		strings.TrimSpace(state.ReasonCode) != state.ReasonCode || len(state.PayloadSHA256) != sha256HexLength ||
		evidenceSubject != IsolationSubject || len(state.EvidencePayloadSHA256) != sha256HexLength ||
		len(state.EvidenceBlobSHA256) != sha256HexLength || len(state.EvidenceWireSHA256) != sha256HexLength ||
		len(state.EvidenceKeySHA256) != sha256HexLength ||
		state.EvidenceNonce == "" || state.EvidenceIsolatedAt == "" || state.EvidenceAttempts == 0 ||
		state.EvidenceScanStart == 0 {
		return state, ErrInvalidInput
	}
	if _, err := hex.DecodeString(state.PayloadSHA256); err != nil {
		return state, ErrInvalidInput
	}
	for _, digest := range []string{
		state.EvidencePayloadSHA256, state.EvidenceBlobSHA256, state.EvidenceWireSHA256, state.EvidenceKeySHA256,
	} {
		if _, err := hex.DecodeString(digest); err != nil {
			return state, ErrInvalidInput
		}
	}
	if nonce, err := base64.RawStdEncoding.DecodeString(state.EvidenceNonce); err != nil || len(nonce) != 12 {
		return state, ErrInvalidInput
	}
	if isolatedAt, err := time.Parse(time.RFC3339Nano, state.EvidenceIsolatedAt); err != nil ||
		isolatedAt.Location() != time.UTC {
		return state, ErrInvalidInput
	}
	if state.EvidenceStreamCreated != "" {
		created, err := time.Parse(time.RFC3339Nano, state.EvidenceStreamCreated)
		if err != nil || created.Location() != time.UTC {
			return state, ErrInvalidInput
		}
	}
	if state.EvidenceMessageID == "" || !strings.HasPrefix(state.EvidenceMessageID, "analytics-isolation-v1-") {
		return state, ErrInvalidInput
	}
	confirmedPhase := state.Phase == parkedPhaseEvidenceConfirmed || state.Phase == parkedPhaseTermPending ||
		state.Phase == parkedPhaseSettled
	if state.EvidenceConfirmed != confirmedPhase || (state.EvidenceConfirmed && state.EvidenceSequence == 0) ||
		(!state.EvidenceConfirmed && state.EvidenceSequence != 0) || state.Phase == parkedPhaseAckPending ||
		(state.TermSent && !state.Terminal) {
		return state, ErrInvalidInput
	}
	state.EvidenceSubject = ""
	return state, nil
}

type consumerRecoveryPhase string

const (
	recoveryPrepared        consumerRecoveryPhase = "prepared"
	recoveryDeletePending   consumerRecoveryPhase = "delete_pending"
	recoveryDeleted         consumerRecoveryPhase = "deleted"
	recoveryRecreatePending consumerRecoveryPhase = "recreate_pending"
	recoveryRecreated       consumerRecoveryPhase = "recreated"
	recoveryEpochPending    consumerRecoveryPhase = "epoch_pending"
	recoveryEpochUpdated    consumerRecoveryPhase = "epoch_updated"
	recoveryCleanupPending  consumerRecoveryPhase = "cleanup_pending"
)

type consumerRecoveryState struct {
	SchemaVersion         uint16                `json:"schema_version"`
	Phase                 consumerRecoveryPhase `json:"phase"`
	OwnerID               string                `json:"owner_id"`
	StreamCreated         string                `json:"stream_created"`
	SourceConsumerCreated string                `json:"source_consumer_created"`
	TargetConsumerCreated string                `json:"target_consumer_created,omitempty"`
}

func loadConsumerRecovery(store nats.KeyValue) (*consumerRecoveryState, uint64, error) {
	entry, err := store.Get(consumerRecoveryStateKey)
	if err != nil {
		return nil, 0, err
	}
	var state consumerRecoveryState
	decoder := json.NewDecoder(bytes.NewReader(entry.Value()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil {
		return nil, 0, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, 0, ErrInvalidInput
	}
	return &state, entry.Revision(), nil
}

func validateConsumerRecovery(state consumerRecoveryState, streamCreated time.Time, info *nats.ConsumerInfo) error {
	validPhase := state.Phase == recoveryPrepared || state.Phase == recoveryDeletePending ||
		state.Phase == recoveryDeleted || state.Phase == recoveryRecreatePending ||
		state.Phase == recoveryRecreated || state.Phase == recoveryEpochPending ||
		state.Phase == recoveryEpochUpdated || state.Phase == recoveryCleanupPending
	if state.SchemaVersion != 1 || !validPhase || state.OwnerID == "" ||
		state.StreamCreated != streamCreated.UTC().Format(time.RFC3339Nano) {
		return ErrInvalidInput
	}
	if _, err := time.Parse(time.RFC3339Nano, state.SourceConsumerCreated); err != nil {
		return ErrInvalidInput
	}
	if state.TargetConsumerCreated != "" {
		target, err := time.Parse(time.RFC3339Nano, state.TargetConsumerCreated)
		if err != nil {
			return ErrInvalidInput
		}
		if info != nil && (state.Phase == recoveryRecreated || state.Phase == recoveryEpochPending ||
			state.Phase == recoveryEpochUpdated || state.Phase == recoveryCleanupPending) && !info.Created.Equal(target) {
			return ErrInvalidInput
		}
	}
	return nil
}

func (consumer *NATSIngestConsumer) recoverParked(ctx context.Context) error {
	recovery, revision, err := loadConsumerRecovery(consumer.stateStore)
	if err == nil {
		return consumer.resumeConsumerRecovery(ctx, *recovery, revision)
	}
	if !errors.Is(err, nats.ErrKeyNotFound) {
		return fmt.Errorf("read analytics consumer recovery: %w", err)
	}
	keys, err := consumer.stateStore.Keys(nats.Context(ctx))
	if errors.Is(err, nats.ErrNoKeysFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list analytics parked deliveries: %w", err)
	}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		if strings.HasPrefix(key, "parked.") {
			entry, getErr := consumer.stateStore.Get(key)
			if getErr != nil {
				return fmt.Errorf("read analytics parked delivery %s: %w", key, getErr)
			}
			sequence, parseErr := parseParkedStateKey(key)
			if parseErr != nil {
				return fmt.Errorf("read analytics parked delivery %s: %w", key, parseErr)
			}
			state, decodeErr := decodeParkedDeliveryState(entry.Value(), sequence)
			if decodeErr != nil {
				return fmt.Errorf("read analytics parked delivery %s: %w", key, ErrInvalidInput)
			}
			if state.StreamCreated != consumer.streamCreated.UTC().Format(time.RFC3339Nano) {
				return fmt.Errorf("parked analytics delivery %s has a different stream epoch", key)
			}
			if err := consumer.reconcileParkedState(ctx, sequence); err != nil {
				return fmt.Errorf("claim analytics parked delivery %s: %w", key, err)
			}
		}
	}
	return nil
}

func (consumer *NATSIngestConsumer) reconcileParkedState(ctx context.Context, sequence uint64) error {
	return consumer.withLeaseFenceContext(ctx, func(ctx context.Context) error {
		key := fmt.Sprintf("parked.%020d", sequence)
		entry, err := consumer.stateStore.Get(key)
		if err != nil {
			return err
		}
		state, err := decodeParkedDeliveryState(entry.Value(), sequence)
		if err != nil || state.StreamCreated != consumer.streamCreated.UTC().Format(time.RFC3339Nano) {
			return ErrInvalidInput
		}
		revision := entry.Revision()
		if state.OwnerID != consumer.ownerID {
			state.OwnerID = consumer.ownerID
			value, marshalErr := json.Marshal(state)
			if marshalErr != nil {
				return marshalErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			revision, err = consumer.stateStore.Update(key, value, revision)
			if err != nil {
				return err
			}
		}
		if state.Phase != parkedPhaseAckPending && state.Phase != parkedPhaseTermPending &&
			state.Phase != parkedPhaseSettled {
			return nil
		}
		operationCtx, cancel := context.WithTimeout(ctx, consumer.config.OperationTimeout)
		defer cancel()
		_, err = consumer.jetstream.GetMsg(consumer.config.Stream, sequence, nats.Context(operationCtx))
		if err == nil {
			if state.Phase == parkedPhaseSettled {
				return ErrInvalidInput
			}
			return nil
		}
		if !errors.Is(err, nats.ErrMsgNotFound) {
			return err
		}
		if state.Terminal {
			state, revision, err = consumer.reconcileRetainedTerminalEvidence(
				ctx, sequence, state, revision,
			)
			if err != nil {
				return fmt.Errorf("retain analytics terminal proof: %w", err)
			}
		}
		if state.Phase != parkedPhaseSettled {
			state.Phase = parkedPhaseSettled
			state.TermSent = state.Terminal
			value, marshalErr := json.Marshal(state)
			if marshalErr != nil {
				return marshalErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			revision, err = consumer.stateStore.Update(key, value, revision)
			if err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if state.Terminal {
			return nil
		}
		return consumer.stateStore.Delete(key, nats.LastRevision(revision))
	})
}

func (consumer *NATSIngestConsumer) reconcileRetainedTerminalEvidence(
	ctx context.Context,
	sequence uint64,
	state parkedDeliveryState,
	revision uint64,
) (parkedDeliveryState, uint64, error) {
	if !state.Terminal || state.EvidenceBlobSHA256 == "" {
		return state, revision, ErrInvalidInput
	}
	delivery := &natsIngestDelivery{streamSequence: sequence, consumer: consumer}
	if state.EvidenceConfirmed {
		if err := delivery.validateTerminalEvidenceCurrent(ctx, state); err == nil {
			return state, revision, nil
		} else if !retryableIsolationRecoveryError(err) {
			return state, revision, err
		}
	}
	intent, err := loadIsolationEvidenceBlob(
		consumer.evidenceStore, consumer.streamCreated, sequence, consumer.config.IsolationStream,
		state.EvidenceBlobSHA256,
	)
	if err != nil {
		return state, revision, fmt.Errorf("load retained evidence blob: %w", err)
	}
	defer clear(intent.Payload)
	info, err := exactStreamInfo(ctx, consumer.jetstream, expectedIsolationStream(consumer.config), consumer.config.OperationTimeout)
	if err != nil || info.State.LastSeq == ^uint64(0) {
		return state, revision, fmt.Errorf("read retained evidence stream: %w", errors.Join(errIsolationStreamEpochChanged, err))
	}
	intent.StreamCreated = info.Created
	intent.ScanStart = info.State.FirstSeq
	if intent.ScanStart == 0 {
		intent.ScanStart = info.State.LastSeq + 1
	}
	intent.ScanLast = info.State.LastSeq
	intent.ReconcileFirst = true
	sink := &NATSIsolationSink{
		jetstream: consumer.jetstream, stream: consumer.config.IsolationStream,
		streamCreated: info.Created, expectedStream: *expectedIsolationStream(consumer.config),
		operationTimeout: consumer.config.OperationTimeout, scanLimit: isolationEvidenceScanBatch,
		stateStore: consumer.stateStore, evidenceStore: consumer.evidenceStore,
		keyProvider: consumer.config.IsolationKeyProvider,
	}
	intent, err = sink.resumeIsolationScan(ctx, intent)
	if err != nil {
		return state, revision, fmt.Errorf("resume retained evidence scan: %w", err)
	}
	evidenceSequence, err := sink.publishEvidenceIntent(ctx, intent)
	if err != nil {
		return state, revision, fmt.Errorf("publish retained evidence: %w", err)
	}
	key := fmt.Sprintf("parked.%020d", sequence)
	entry, err := consumer.stateStore.Get(key)
	if err != nil {
		return state, revision, fmt.Errorf("reload retained marker: %w", err)
	}
	current, err := decodeParkedDeliveryState(entry.Value(), sequence)
	if err != nil || current.OwnerID != consumer.ownerID || current.EvidenceBlobSHA256 != state.EvidenceBlobSHA256 ||
		current.EvidenceMessageID != intent.MessageID ||
		current.EvidencePayloadSHA256 != hex.EncodeToString(intent.PayloadSHA256[:]) {
		return state, revision, ErrInvalidInput
	}
	current.Phase = parkedPhaseEvidenceConfirmed
	current.EvidenceConfirmed = true
	current.EvidenceSequence = evidenceSequence
	current.EvidenceStreamCreated = intent.StreamCreated.UTC().Format(time.RFC3339Nano)
	current.EvidenceScanStart = intent.ScanStart
	current.EvidenceScanLast = intent.ScanLast
	value, err := json.Marshal(current)
	if err != nil || len(value) > 1024 {
		return state, revision, ErrInvalidInput
	}
	revision, err = consumer.stateStore.Update(key, value, entry.Revision())
	if err != nil {
		return state, revision, fmt.Errorf("confirm retained evidence marker: %w", err)
	}
	if err := delivery.validateTerminalEvidenceCurrent(ctx, current); err != nil {
		return current, revision, fmt.Errorf("revalidate retained evidence: %w", err)
	}
	return current, revision, nil
}

func (consumer *NATSIngestConsumer) validateParkedEvidence(
	ctx context.Context,
	state parkedDeliveryState,
	sequence uint64,
) error {
	digest, err := decodeSHA256(state.EvidencePayloadSHA256)
	if err != nil || state.EvidenceSequence == 0 {
		return ErrInvalidInput
	}
	intent, err := loadIsolationEvidenceBlob(
		consumer.evidenceStore, consumer.streamCreated, sequence,
		consumer.config.IsolationStream, state.EvidenceBlobSHA256,
	)
	if err != nil || intent.MessageID != state.EvidenceMessageID || intent.PayloadSHA256 != digest {
		clear(intent.Payload)
		return errors.Join(ErrInvalidInput, err)
	}
	defer clear(intent.Payload)
	stored, err := consumer.jetstream.GetMsg(
		consumer.config.IsolationStream, state.EvidenceSequence, nats.Context(ctx),
	)
	if err != nil {
		return err
	}
	return validateStoredIsolationEvidence(intent, stored)
}

func parseParkedStateKey(key string) (uint64, error) {
	var sequence uint64
	if _, err := fmt.Sscanf(key, "parked.%020d", &sequence); err != nil || sequence == 0 ||
		key != fmt.Sprintf("parked.%020d", sequence) {
		return 0, ErrInvalidInput
	}
	return sequence, nil
}

func (consumer *NATSIngestConsumer) resumeConsumerRecovery(
	ctx context.Context,
	state consumerRecoveryState,
	revision uint64,
) error {
	if err := validateConsumerRecovery(state, consumer.streamCreated, nil); err != nil {
		return err
	}
	if state.OwnerID != consumer.ownerID {
		state.OwnerID = consumer.ownerID
		var err error
		state, revision, err = consumer.checkpointConsumerRecovery(ctx, state, revision)
		if err != nil {
			return fmt.Errorf("claim analytics consumer recovery: %w", err)
		}
	}
	info, err := consumer.recreateConsumer(ctx)
	if err != nil {
		return err
	}
	consumer.consumerCreated = info.Created
	if err := consumer.withLeaseFenceContext(ctx, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return setEpoch(consumer.stateStore, "consumer_created", info.Created)
	}); err != nil {
		return fmt.Errorf("record analytics consumer epoch: %w", err)
	}
	if err := consumer.withLeaseFenceContext(ctx, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return consumer.bindSubscription()
	}); err != nil {
		return err
	}
	return consumer.clearParkedRecoveryState(ctx, revision)
}

func (consumer *NATSIngestConsumer) checkpointConsumerRecovery(
	ctx context.Context,
	state consumerRecoveryState,
	revision uint64,
) (consumerRecoveryState, uint64, error) {
	value, err := json.Marshal(state)
	if err != nil {
		return state, revision, err
	}
	var next uint64
	err = consumer.withLeaseFenceContext(ctx, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var updateErr error
		next, updateErr = consumer.stateStore.Update(consumerRecoveryStateKey, value, revision)
		return updateErr
	})
	return state, next, err
}

func (consumer *NATSIngestConsumer) recreateConsumer(ctx context.Context) (*nats.ConsumerInfo, error) {
	retryCtx, cancel := context.WithTimeout(ctx, max(5*time.Second, 4*consumer.config.OperationTimeout))
	defer cancel()
	for {
		var info *nats.ConsumerInfo
		err := consumer.withLeaseFenceContext(retryCtx, func(fenceCtx context.Context) error {
			operationCtx, cancel := context.WithTimeout(fenceCtx, consumer.config.OperationTimeout)
			defer cancel()
			current, currentErr := consumer.jetstream.ConsumerInfo(
				consumer.config.Stream, consumer.config.Durable, nats.Context(operationCtx),
			)
			if currentErr == nil {
				if !sameIngestConsumer(current, expectedConsumer(consumer.config)) {
					return ErrInvalidConfiguration
				}
				info = current
				return nil
			}
			if !errors.Is(currentErr, nats.ErrConsumerNotFound) {
				return currentErr
			}
			created, createErr := consumer.jetstream.AddConsumer(
				consumer.config.Stream, expectedConsumer(consumer.config), nats.Context(operationCtx),
			)
			info = created
			return createErr
		})
		if err == nil && info != nil {
			return info, nil
		}
		if retryCtx.Err() != nil {
			return nil, fmt.Errorf("recreate parked analytics consumer: %w", errors.Join(err, retryCtx.Err()))
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-retryCtx.Done():
			timer.Stop()
			return nil, fmt.Errorf("recreate parked analytics consumer: %w", errors.Join(err, retryCtx.Err()))
		case <-timer.C:
		}
	}
}

func (consumer *NATSIngestConsumer) bindSubscription() error {
	consumer.mu.Lock()
	if consumer.closed {
		consumer.mu.Unlock()
		return ErrInvalidConfiguration
	}
	if consumer.subscription != nil {
		consumer.mu.Unlock()
		return nil
	}
	consumer.mu.Unlock()
	subscription, err := consumer.jetstream.PullSubscribe(
		IngestSubjectPrefix+".*", consumer.config.Durable, nats.Bind(consumer.config.Stream, consumer.config.Durable),
	)
	if err != nil {
		return fmt.Errorf("bind analytics ingest consumer: %w", err)
	}
	consumer.mu.Lock()
	if consumer.closed {
		consumer.mu.Unlock()
		return errors.Join(ErrInvalidConfiguration, unsubscribeBoundSubscription(subscription))
	}
	if consumer.subscription != nil {
		consumer.mu.Unlock()
		return unsubscribeBoundSubscription(subscription)
	}
	consumer.mu.Unlock()
	operationCtx, cancelOperation := consumer.lifecycleContext(context.Background())
	infoCtx, cancelInfo := context.WithTimeout(operationCtx, consumer.config.OperationTimeout)
	info, infoErr := consumer.jetstream.ConsumerInfo(
		consumer.config.Stream, consumer.config.Durable, nats.Context(infoCtx),
	)
	cancelInfo()
	cancelOperation()
	if infoErr != nil || !sameIngestConsumer(info, expectedConsumer(consumer.config)) {
		return errors.Join(
			fmt.Errorf("analytics ingest durable consumer configuration does not match"),
			infoErr,
			unsubscribeBoundSubscription(subscription),
		)
	}
	consumer.mu.Lock()
	if consumer.closed {
		consumer.mu.Unlock()
		return errors.Join(ErrInvalidConfiguration, unsubscribeBoundSubscription(subscription))
	}
	if consumer.subscription != nil {
		consumer.mu.Unlock()
		return unsubscribeBoundSubscription(subscription)
	}
	consumer.subscription = subscription
	consumer.mu.Unlock()
	return nil
}

func unsubscribeBoundSubscription(subscription *nats.Subscription) error {
	if subscription == nil {
		return nil
	}
	if err := subscription.Unsubscribe(); err != nil && !errors.Is(err, nats.ErrBadSubscription) {
		return fmt.Errorf("unsubscribe rejected analytics ingest binding: %w", err)
	}
	return nil
}

func (consumer *NATSIngestConsumer) unbindSubscription() error {
	consumer.mu.Lock()
	subscription := consumer.subscription
	consumer.subscription = nil
	consumer.mu.Unlock()
	if subscription == nil {
		return nil
	}
	if err := subscription.Unsubscribe(); err != nil && !errors.Is(err, nats.ErrBadSubscription) {
		return fmt.Errorf("unbind parked analytics consumer: %w", err)
	}
	return nil
}

func (consumer *NATSIngestConsumer) clearParkedRecoveryState(ctx context.Context, revision uint64) error {
	keys, err := consumer.stateStore.Keys(nats.Context(ctx))
	if errors.Is(err, nats.ErrNoKeysFound) {
		keys = nil
	} else if err != nil {
		return err
	}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !strings.HasPrefix(key, "parked.") {
			continue
		}
		entry, getErr := consumer.stateStore.Get(key)
		if errors.Is(getErr, nats.ErrKeyNotFound) {
			continue
		}
		if getErr != nil {
			return getErr
		}
		if err := consumer.withLeaseFenceContext(ctx, func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			deleteErr := consumer.stateStore.Delete(key, nats.LastRevision(entry.Revision()))
			if errors.Is(deleteErr, nats.ErrKeyNotFound) {
				return nil
			}
			return deleteErr
		}); err != nil {
			return fmt.Errorf("clear analytics parked delivery %s: %w", key, err)
		}
	}
	return consumer.withLeaseFenceContext(ctx, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return consumer.stateStore.Delete(consumerRecoveryStateKey, nats.LastRevision(revision))
	})
}

func setEpoch(store nats.KeyValue, key string, created time.Time) error {
	value := []byte(created.UTC().Format(time.RFC3339Nano))
	entry, err := store.Get(key)
	if err != nil {
		return err
	}
	if bytes.Equal(entry.Value(), value) {
		return nil
	}
	_, err = store.Update(key, value, entry.Revision())
	return err
}

func (delivery *natsIngestDelivery) Subject() string {
	if delivery == nil || delivery.message == nil || !trustedIngestAuthority(delivery.message) {
		return ""
	}
	return delivery.message.Subject
}
func (delivery *natsIngestDelivery) Data() []byte { return delivery.message.Data }
func (delivery *natsIngestDelivery) MessageID() string {
	return delivery.message.Header.Get(nats.MsgIdHdr)
}
func (delivery *natsIngestDelivery) InstallationID() string {
	if delivery == nil || delivery.message == nil || !trustedIngestAuthority(delivery.message) {
		return ""
	}
	installationID, _ := uniqueHeader(delivery.message, ingestInstallHeader)
	return installationID
}
func (delivery *natsIngestDelivery) Attempts() uint64       { return delivery.attempts }
func (delivery *natsIngestDelivery) StreamSequence() uint64 { return delivery.streamSequence }

func (delivery *natsIngestDelivery) IsolationWire() *IsolationWire {
	if delivery == nil || delivery.message == nil || delivery.message.Subject == "" ||
		len(delivery.message.Subject) > 256 || len(delivery.message.Data) > DefaultMaxIngestMessageBytes {
		return nil
	}
	names := make([]string, 0, len(delivery.message.Header))
	for name := range delivery.message.Header {
		known := false
		for _, authorityName := range isolationWireHeaderNames {
			known = known || name == authorityName
		}
		if !known {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	headers := make([]IsolationHeader, 0, len(delivery.message.Header))
	for _, name := range isolationWireHeaderNames {
		for _, value := range delivery.message.Header.Values(name) {
			headers = append(headers, IsolationHeader{Name: name, Value: value})
		}
	}
	for _, name := range names {
		for _, value := range delivery.message.Header.Values(name) {
			headers = append(headers, IsolationHeader{Name: name, Value: value})
		}
	}
	return &IsolationWire{
		Subject: delivery.message.Subject, Headers: headers,
		Payload: append([]byte(nil), delivery.message.Data...),
	}
}

func (delivery *natsIngestDelivery) TerminalEvidenceConfirmed(ctx context.Context) (bool, error) {
	if delivery == nil || delivery.consumer == nil || delivery.message == nil || delivery.streamSequence == 0 {
		return false, ErrInvalidConfiguration
	}
	confirmed := false
	err := delivery.consumer.withLeaseFenceContext(ctx, func(fenceCtx context.Context) error {
		operationCtx, cancel := boundedSettlementContext(ctx, fenceCtx)
		defer cancel()
		entry, err := delivery.consumer.stateStore.Get(fmt.Sprintf("parked.%020d", delivery.streamSequence))
		if errors.Is(err, nats.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := operationCtx.Err(); err != nil {
			return err
		}
		state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
		if err != nil || state.StreamCreated != delivery.consumer.streamCreated.UTC().Format(time.RFC3339Nano) {
			return ErrInvalidInput
		}
		if state.OwnerID != delivery.consumer.ownerID || !state.EvidenceConfirmed {
			return nil
		}
		isolationInfo, err := exactStreamInfo(
			operationCtx, delivery.consumer.jetstream, expectedIsolationStream(delivery.consumer.config),
			delivery.consumer.config.OperationTimeout,
		)
		if err != nil {
			return err
		}
		currentIsolationEpoch := isolationInfo.Created.UTC().Format(time.RFC3339Nano)
		if state.EvidenceStreamCreated != currentIsolationEpoch {
			state.Phase = parkedPhaseEvidencePrepared
			state.EvidenceConfirmed = false
			state.EvidenceSequence = 0
			state.EvidenceStreamCreated = currentIsolationEpoch
			state.EvidenceScanStart = isolationInfo.State.FirstSeq
			if state.EvidenceScanStart == 0 {
				state.EvidenceScanStart = isolationInfo.State.LastSeq + 1
			}
			state.EvidenceScanLast = isolationInfo.State.LastSeq
			value, marshalErr := json.Marshal(state)
			if marshalErr != nil || len(value) > 1024 {
				return ErrInvalidInput
			}
			_, updateErr := delivery.consumer.stateStore.Update(
				fmt.Sprintf("parked.%020d", delivery.streamSequence), value, entry.Revision(),
			)
			return updateErr
		}
		messageID := delivery.MessageID()
		if !validBatchID(messageID) {
			messageID = ""
		}
		digest := sha256Sum(delivery.Data())
		if state.MessageID != messageID || state.PayloadSHA256 != hex.EncodeToString(digest[:]) {
			return ErrInvalidInput
		}
		payloadDigest, err := decodeSHA256(state.EvidencePayloadSHA256)
		if err != nil {
			return err
		}
		intent := isolationPublishIntent{
			Subject: IsolationSubject, Stream: delivery.consumer.config.IsolationStream,
			MessageID:     state.EvidenceMessageID,
			PayloadSHA256: payloadDigest, ScanStart: state.EvidenceScanStart,
		}
		storedIntent, err := loadIsolationEvidenceBlob(
			delivery.consumer.evidenceStore, delivery.consumer.streamCreated, delivery.streamSequence,
			delivery.consumer.config.IsolationStream, state.EvidenceBlobSHA256,
		)
		if err != nil || storedIntent.MessageID != intent.MessageID ||
			storedIntent.PayloadSHA256 != intent.PayloadSHA256 {
			clear(storedIntent.Payload)
			return errors.Join(ErrInvalidInput, err)
		}
		intent.Payload = storedIntent.Payload
		defer clear(intent.Payload)
		stored, err := delivery.consumer.jetstream.GetMsg(
			delivery.consumer.config.IsolationStream, state.EvidenceSequence, nats.Context(operationCtx),
		)
		if errors.Is(err, nats.ErrMsgNotFound) {
			info, infoErr := exactStreamInfo(
				operationCtx, delivery.consumer.jetstream, expectedIsolationStream(delivery.consumer.config),
				delivery.consumer.config.OperationTimeout,
			)
			if infoErr != nil || !info.Created.Equal(isolationInfo.Created) || info.State.LastSeq == ^uint64(0) {
				return ErrInvalidInput
			}
			state.Phase = parkedPhaseEvidencePrepared
			state.EvidenceConfirmed = false
			state.EvidenceSequence = 0
			state.EvidenceStreamCreated = currentIsolationEpoch
			state.EvidenceScanStart = info.State.FirstSeq
			if state.EvidenceScanStart == 0 {
				state.EvidenceScanStart = info.State.LastSeq + 1
			}
			state.EvidenceScanLast = info.State.LastSeq
			value, marshalErr := json.Marshal(state)
			if marshalErr != nil || len(value) > 1024 {
				return ErrInvalidInput
			}
			if err := operationCtx.Err(); err != nil {
				return err
			}
			_, updateErr := delivery.consumer.stateStore.Update(
				fmt.Sprintf("parked.%020d", delivery.streamSequence), value, entry.Revision(),
			)
			return updateErr
		}
		latest, latestErr := exactStreamInfo(
			operationCtx, delivery.consumer.jetstream, expectedIsolationStream(delivery.consumer.config),
			delivery.consumer.config.OperationTimeout,
		)
		if err != nil || latestErr != nil || !latest.Created.Equal(isolationInfo.Created) ||
			validateStoredIsolationEvidence(intent, stored) != nil {
			return ErrInvalidInput
		}
		confirmed = true
		return nil
	})
	return confirmed, err
}

func (delivery *natsIngestDelivery) ConfirmTerminalEvidence(ctx context.Context, record IsolationRecord) error {
	if delivery == nil || delivery.consumer == nil || delivery.message == nil ||
		record.StreamSequence != delivery.streamSequence || record.ReasonCode == "" {
		return ErrInvalidInput
	}
	messageID := delivery.MessageID()
	if !validBatchID(messageID) {
		messageID = ""
	}
	digest := sha256Sum(delivery.Data())
	payloadSHA256 := hex.EncodeToString(digest[:])
	if record.MessageID != messageID || record.PayloadSHA256 != payloadSHA256 {
		return ErrInvalidInput
	}
	return delivery.consumer.withLeaseFenceContext(ctx, func(fenceCtx context.Context) error {
		operationCtx, cancel := boundedSettlementContext(ctx, fenceCtx)
		defer cancel()
		key := fmt.Sprintf("parked.%020d", delivery.streamSequence)
		entry, err := delivery.consumer.stateStore.Get(key)
		if err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
			return err
		}
		if entry == nil {
			return ErrInvalidInput
		}
		state, decodeErr := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
		if decodeErr != nil || state.StreamCreated != delivery.consumer.streamCreated.UTC().Format(time.RFC3339Nano) ||
			state.OwnerID != delivery.consumer.ownerID || !state.EvidenceConfirmed || state.MessageID != messageID ||
			state.ReasonCode != record.ReasonCode || state.PayloadSHA256 != payloadSHA256 {
			return ErrInvalidInput
		}
		return operationCtx.Err()
	})
}

func (delivery *natsIngestDelivery) Ack(ctx context.Context) error {
	return delivery.settle(ctx, parkedPhaseAckPending, func(operationCtx context.Context) error {
		if err := delivery.message.AckSync(nats.Context(operationCtx)); err != nil {
			return fmt.Errorf("ack analytics ingest message: %w", err)
		}
		return nil
	})
}

func (delivery *natsIngestDelivery) Nak(ctx context.Context, delay time.Duration) error {
	return delivery.consumer.withLeaseFenceContext(ctx, func(fenceCtx context.Context) error {
		operationCtx, cancel := boundedSettlementContext(ctx, fenceCtx)
		defer cancel()
		if delivery.attempts >= uint64(delivery.consumer.config.MaxDeliver) {
			if err := operationCtx.Err(); err != nil {
				return err
			}
			if err := delivery.consumer.persistParkedLocked(delivery.streamSequence, true); err != nil {
				return fmt.Errorf("persist max-delivery replay state: %w", err)
			}
		}
		if err := delivery.message.NakWithDelay(delay, nats.Context(operationCtx)); err != nil {
			return fmt.Errorf("nak analytics ingest message: %w", err)
		}
		return nil
	})
}

func (delivery *natsIngestDelivery) Term(ctx context.Context) error {
	return delivery.settle(ctx, parkedPhaseTermPending, func(operationCtx context.Context) error {
		if err := delivery.message.Term(nats.Context(operationCtx)); err != nil {
			return fmt.Errorf("terminate analytics ingest message: %w", err)
		}
		return nil
	})
}

func (delivery *natsIngestDelivery) settle(
	ctx context.Context,
	pending parkedDeliveryPhase,
	settleMessage func(context.Context) error,
) error {
	var recoveryState *parkedDeliveryState
	err := delivery.consumer.withLeaseFenceContext(ctx, func(fenceCtx context.Context) error {
		operationCtx, cancel := boundedSettlementContext(ctx, fenceCtx)
		defer cancel()
		key := fmt.Sprintf("parked.%020d", delivery.streamSequence)
		entry, err := delivery.consumer.stateStore.Get(key)
		if err != nil {
			return err
		}
		state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
		if err != nil || state.OwnerID != delivery.consumer.ownerID ||
			(pending == parkedPhaseTermPending && !state.EvidenceConfirmed) {
			return ErrInvalidInput
		}
		state.Phase = pending
		value, err := json.Marshal(state)
		if err != nil {
			return err
		}
		if err := operationCtx.Err(); err != nil {
			return err
		}
		revision, err := delivery.consumer.stateStore.Update(key, value, entry.Revision())
		if err != nil {
			return err
		}
		if pending == parkedPhaseTermPending {
			if err := delivery.validateTerminalEvidenceCurrent(operationCtx, state); err != nil {
				return err
			}
		}
		if pending != parkedPhaseTermPending || !state.TermSent {
			if err := settleMessage(operationCtx); err != nil {
				return err
			}
			if pending == parkedPhaseTermPending {
				state.TermSent = true
				value, err = json.Marshal(state)
				if err != nil || len(value) > 1024 {
					return ErrInvalidInput
				}
				if err := operationCtx.Err(); err != nil {
					return err
				}
				revision, err = delivery.consumer.stateStore.Update(key, value, revision)
				if err != nil {
					return err
				}
			}
		}
		if pending == parkedPhaseTermPending {
			if err := delivery.validateTerminalEvidenceCurrent(operationCtx, state); err != nil {
				retained := state
				recoveryState = &retained
				return err
			}
		}
		state.Phase = parkedPhaseSettled
		value, err = json.Marshal(state)
		if err != nil {
			return err
		}
		if err := operationCtx.Err(); err != nil {
			return err
		}
		revision, err = delivery.consumer.stateStore.Update(key, value, revision)
		if err != nil {
			return err
		}
		if pending == parkedPhaseTermPending {
			if err := delivery.validateTerminalEvidenceCurrent(operationCtx, state); err != nil {
				retained := state
				recoveryState = &retained
				return err
			}
		}
		if err := operationCtx.Err(); err != nil {
			return err
		}
		if pending == parkedPhaseTermPending {
			return nil
		}
		return delivery.consumer.stateStore.Delete(key, nats.LastRevision(revision))
	})
	if recoveryState != nil {
		delivery.consumer.resumeTerminalEvidenceRecovery(delivery, *recoveryState)
	}
	return err
}

func (consumer *NATSIngestConsumer) resumeTerminalEvidenceRecovery(
	delivery *natsIngestDelivery,
	state parkedDeliveryState,
) {
	consumer.mu.Lock()
	sinks := make([]*NATSIsolationSink, 0, len(consumer.recoverySinks))
	for sink := range consumer.recoverySinks {
		sinks = append(sinks, sink)
	}
	consumer.mu.Unlock()
	for _, sink := range sinks {
		sink.startTerminalEvidenceStateRecovery(delivery, state)
	}
}

func (delivery *natsIngestDelivery) validateTerminalEvidenceCurrent(
	ctx context.Context,
	state parkedDeliveryState,
) error {
	if delivery == nil || delivery.consumer == nil || !state.EvidenceConfirmed || state.EvidenceSequence == 0 {
		return ErrInvalidInput
	}
	created, err := time.Parse(time.RFC3339Nano, state.EvidenceStreamCreated)
	if err != nil {
		return ErrInvalidInput
	}
	info, err := exactStreamInfo(
		ctx, delivery.consumer.jetstream, expectedIsolationStream(delivery.consumer.config),
		delivery.consumer.config.OperationTimeout,
	)
	if err != nil {
		return err
	}
	if !info.Created.Equal(created) {
		return errIsolationStreamEpochChanged
	}
	digest, err := decodeSHA256(state.EvidencePayloadSHA256)
	if err != nil {
		return err
	}
	intent, err := loadIsolationEvidenceBlob(
		delivery.consumer.evidenceStore, delivery.consumer.streamCreated, delivery.streamSequence,
		delivery.consumer.config.IsolationStream, state.EvidenceBlobSHA256,
	)
	if err != nil || intent.MessageID != state.EvidenceMessageID || intent.PayloadSHA256 != digest {
		clear(intent.Payload)
		return errors.Join(ErrInvalidInput, err)
	}
	defer clear(intent.Payload)
	stored, err := delivery.consumer.jetstream.GetMsg(
		delivery.consumer.config.IsolationStream, state.EvidenceSequence, nats.Context(ctx),
	)
	if err != nil {
		if errors.Is(err, nats.ErrMsgNotFound) {
			return errors.Join(errIsolationEvidenceScanPending, err)
		}
		return err
	}
	latest, err := exactStreamInfo(
		ctx, delivery.consumer.jetstream, expectedIsolationStream(delivery.consumer.config),
		delivery.consumer.config.OperationTimeout,
	)
	if err != nil {
		return err
	}
	if !latest.Created.Equal(created) {
		return errIsolationStreamEpochChanged
	}
	return validateStoredIsolationEvidence(intent, stored)
}

func boundedSettlementContext(caller, fence context.Context) (context.Context, context.CancelFunc) {
	if caller == nil {
		caller = context.Background()
	}
	ctx, cancel := context.WithCancel(caller)
	stop := context.AfterFunc(fence, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

func trustedIngestAuthority(message *nats.Msg) bool {
	if message == nil || len(message.Header) != 6 {
		return false
	}
	messageID, ok := uniqueHeader(message, nats.MsgIdHdr)
	if !ok || !validBatchID(messageID) {
		return false
	}
	authority := ingestAuthority{}
	if authority.nodeID, ok = uniqueHeader(message, ingestNodeHeader); !ok ||
		!validUUID(authority.nodeID) || strings.ToLower(authority.nodeID) != authority.nodeID {
		return false
	}
	if authority.tenantID, ok = uniqueHeader(message, ingestTenantHeader); !ok ||
		!validUUID(authority.tenantID) || strings.ToLower(authority.tenantID) != authority.tenantID {
		return false
	}
	if authority.siteID, ok = uniqueHeader(message, ingestSiteHeader); !ok ||
		!validUUID(authority.siteID) || strings.ToLower(authority.siteID) != authority.siteID {
		return false
	}
	if authority.configVersion, ok = uniqueHeader(message, ingestConfigHeader); !ok ||
		!validUUID(authority.configVersion) || nilUUID(authority.configVersion) ||
		strings.ToLower(authority.configVersion) != authority.configVersion {
		return false
	}
	if authority.installationID, ok = uniqueHeader(message, ingestInstallHeader); !ok || !validBatchID(authority.installationID) {
		return false
	}
	subject, err := IngestSubject(authority.nodeID)
	return err == nil && message.Subject == subject && payloadMatchesAuthority(message.Data, authority)
}

func uniqueHeader(message *nats.Msg, name string) (string, bool) {
	values := message.Header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != "" && strings.TrimSpace(returnValue) == returnValue
}

func payloadMatchesAuthority(payload []byte, authority ingestAuthority) bool {
	var probe struct {
		SchemaVersion uint16 `json:"schema_version"`
		Type          string `json:"type"`
	}
	if json.Unmarshal(payload, &probe) != nil {
		return true
	}
	v2 := probe.SchemaVersion == IngestSchemaVersionV2 &&
		(probe.Type == AccessEnvelopeTypeV2 || probe.Type == SecurityEnvelopeTypeV2)
	v1 := probe.SchemaVersion == IngestSchemaVersion &&
		(probe.Type == AccessEnvelopeType || probe.Type == SecurityEnvelopeType)
	window := probe.SchemaVersion == IngestSchemaVersion &&
		(probe.Type == AccessWindowEnvelopeType || probe.Type == SubscriptionMinuteEnvelopeType)
	if !v1 && !v2 && !window {
		return true
	}
	bound := v2 || window
	var envelope struct {
		TenantID       string `json:"tenant_id"`
		NodeID         string `json:"node_id"`
		InstallationID string `json:"installation_id"`
		Events         []struct {
			TenantID       string `json:"tenant_id"`
			NodeID         string `json:"node_id"`
			SiteID         string `json:"site_id"`
			ConfigVersion  string `json:"config_version_id"`
			InstallationID string `json:"installation_id"`
		} `json:"events"`
	}
	if json.Unmarshal(payload, &envelope) != nil || !sameAuthority(authority, envelope.TenantID, envelope.NodeID) ||
		(bound && envelope.InstallationID != authority.installationID) || (!bound && envelope.InstallationID != "") {
		return false
	}
	for _, event := range envelope.Events {
		if !sameEventAuthority(authority, event.TenantID, event.NodeID, event.SiteID, event.ConfigVersion) ||
			(bound && event.InstallationID != authority.installationID) || (!bound && event.InstallationID != "") {
			return false
		}
	}
	return true
}

func sameAuthority(authority ingestAuthority, tenantID, nodeID string) bool {
	return authority.tenantID == tenantID && authority.nodeID == nodeID
}

func sameEventAuthority(authority ingestAuthority, tenantID, nodeID, siteID, configVersion string) bool {
	return sameAuthority(authority, tenantID, nodeID) && authority.siteID == siteID &&
		authority.configVersion == configVersion
}

func (sink *NATSIsolationSink) Record(ctx context.Context, record IsolationRecord) error {
	intent, _, err := sink.buildIsolationIntent(ctx, record, "", nil)
	if err != nil {
		return err
	}
	info, err := sink.isolationStreamInfo(ctx)
	if err != nil || info.State.LastSeq == ^uint64(0) {
		return fmt.Errorf("read analytics isolation stream state")
	}
	intent.StreamCreated = info.Created
	intent.ScanStart = info.State.FirstSeq
	if intent.ScanStart == 0 {
		intent.ScanStart = info.State.LastSeq + 1
	}
	intent.ScanLast = info.State.LastSeq
	intent, err = sink.resumeIsolationScan(ctx, intent)
	if err != nil {
		return err
	}
	_, err = sink.publishEvidenceIntent(ctx, intent)
	return err
}

func (sink *NATSIsolationSink) RecordTerminal(
	ctx context.Context,
	delivery IngestDelivery,
	record IsolationRecord,
) error {
	natsDelivery, ok := delivery.(*natsIngestDelivery)
	if !ok {
		return ErrInvalidInput
	}
	intent, err := sink.prepareTerminalEvidence(ctx, natsDelivery, record)
	if err != nil {
		return err
	}
	sequence, err := sink.publishEvidenceIntent(ctx, intent)
	if err != nil {
		if retryableIsolationRecoveryError(err) {
			sink.startTerminalEvidenceRecovery(natsDelivery, intent)
		}
		return err
	}
	confirmedIntent, err := sink.reloadTerminalIsolationIntent(intent)
	if err != nil {
		if retryableIsolationRecoveryError(err) {
			sink.startTerminalEvidenceRecovery(natsDelivery, intent)
		}
		return err
	}
	if err := sink.confirmTerminalEvidence(ctx, natsDelivery, confirmedIntent, sequence); err != nil {
		if retryableIsolationRecoveryError(err) {
			sink.startTerminalEvidenceRecovery(natsDelivery, intent)
		}
		return err
	}
	return nil
}

func (sink *NATSIsolationSink) startTerminalEvidenceRecovery(
	delivery *natsIngestDelivery,
	intent isolationPublishIntent,
) {
	if sink == nil || delivery == nil || delivery.consumer == nil || delivery.consumer.lifecycleCtx == nil {
		return
	}
	key := fmt.Sprintf("%020d:%s", delivery.streamSequence, intent.MessageID)
	sink.enqueueTerminalEvidenceRecovery(&isolationRecoveryTask{key: key, delivery: delivery, intent: intent})
}

func (sink *NATSIsolationSink) startTerminalEvidenceStateRecovery(
	delivery *natsIngestDelivery,
	state parkedDeliveryState,
) {
	if sink == nil || delivery == nil || delivery.consumer == nil || delivery.consumer.lifecycleCtx == nil ||
		state.EvidenceMessageID == "" {
		return
	}
	retained := state
	key := fmt.Sprintf("%020d:%s", delivery.streamSequence, state.EvidenceMessageID)
	sink.enqueueTerminalEvidenceRecovery(&isolationRecoveryTask{key: key, delivery: delivery, state: &retained})
}

func (sink *NATSIsolationSink) enqueueTerminalEvidenceRecovery(task *isolationRecoveryTask) {
	if sink == nil || task == nil || task.key == "" || task.delivery == nil || task.delivery.consumer == nil {
		return
	}
	sink.recoveryMu.Lock()
	if _, exists := sink.recovering[task.key]; exists {
		sink.recoveryMu.Unlock()
		return
	}
	if !task.delivery.consumer.beginTerminalEvidenceRecovery(sink) {
		sink.recoveryMu.Unlock()
		return
	}
	sink.recovering[task.key] = task
	sink.recoveryQueue = append(sink.recoveryQueue, task)
	for sink.recoveryWorkers < isolationEvidenceRecoveryWorkers && sink.recoveryWorkers < len(sink.recoveryQueue) {
		sink.recoveryWorkers++
		go sink.runTerminalEvidenceRecoveryWorker()
	}
	sink.wakeTerminalEvidenceRecoveryLocked()
	sink.recoveryCond.Broadcast()
	sink.recoveryMu.Unlock()
}

func (consumer *NATSIngestConsumer) attachIsolationSink(sink *NATSIsolationSink) bool {
	if consumer == nil || sink == nil {
		return false
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if consumer.closed {
		return false
	}
	if consumer.recoverySinks == nil {
		consumer.recoverySinks = make(map[*NATSIsolationSink]struct{})
	}
	consumer.recoverySinks[sink] = struct{}{}
	return true
}

func (consumer *NATSIngestConsumer) beginTerminalEvidenceRecovery(sink *NATSIsolationSink) bool {
	if !consumer.attachIsolationSink(sink) {
		return false
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if consumer.closed {
		return false
	}
	consumer.recoveryWG.Add(1)
	return true
}

func (sink *NATSIsolationSink) runTerminalEvidenceRecoveryWorker() {
	for {
		task, wait, ok := sink.nextTerminalEvidenceRecoveryTask()
		if !ok {
			return
		}
		if task == nil {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-sink.recoveryWake:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
			continue
		}
		ctx := task.delivery.consumer.lifecycleCtx
		if ctx.Err() != nil {
			sink.finishTerminalEvidenceRecovery(task)
			continue
		}
		current := task.intent
		markerMissing := false
		var err error
		if task.state != nil {
			state := *task.state
			record := isolationRecord(task.delivery, state.ReasonCode, time.Now().UTC())
			record.WireEvidenceOnly = state.EvidenceOnly
			current, err = sink.rebuildIsolationIntent(ctx, task.delivery, record, state)
			if err != nil {
				err = fmt.Errorf("rebuild terminal evidence intent: %w", err)
			} else {
				task.intent = current
				task.state = nil
			}
		} else {
			current, err = sink.reloadTerminalIsolationIntent(task.intent)
			if err != nil {
				markerMissing = errors.Is(err, nats.ErrKeyNotFound) || errors.Is(err, nats.ErrKeyDeleted)
				err = fmt.Errorf("reload terminal evidence intent: %w", err)
			}
		}
		if markerMissing {
			sink.finishTerminalEvidenceRecovery(task)
			continue
		}
		confirmed := false
		if err == nil {
			confirmed, err = task.delivery.TerminalEvidenceConfirmed(ctx)
			if err != nil {
				err = fmt.Errorf("revalidate terminal evidence: %w", err)
			}
		}
		if err == nil && !confirmed {
			current, err = sink.reloadTerminalIsolationIntent(current)
			if err != nil {
				err = fmt.Errorf("reload revalidated terminal evidence intent: %w", err)
			}
		}
		if err == nil && !confirmed {
			var sequence uint64
			sequence, err = sink.publishEvidenceIntent(ctx, current)
			if err != nil {
				err = fmt.Errorf("publish terminal evidence: %w", err)
			}
			if err == nil {
				current, err = sink.reloadTerminalIsolationIntent(current)
				if err != nil {
					err = fmt.Errorf("reload published terminal evidence intent: %w", err)
				}
			}
			if err == nil {
				err = sink.confirmTerminalEvidence(ctx, task.delivery, current, sequence)
				if err != nil {
					err = fmt.Errorf("confirm terminal evidence: %w", err)
				}
			}
		}
		if err == nil {
			err = task.delivery.Term(ctx)
			if err != nil {
				err = fmt.Errorf("settle terminal evidence recovery: %w", err)
			}
		}
		if errors.Is(err, nats.ErrKeyNotFound) || errors.Is(err, nats.ErrKeyDeleted) {
			sink.finishTerminalEvidenceRecovery(task)
			continue
		}
		if err == nil {
			sink.finishTerminalEvidenceRecovery(task)
			continue
		}
		if ctx.Err() != nil {
			sink.finishTerminalEvidenceRecovery(task)
			continue
		}
		if !retryableIsolationRecoveryError(err) {
			slog.Error("analytics terminal evidence recovery stopped",
				"stream_sequence", task.delivery.streamSequence, "error", err)
			sink.finishTerminalEvidenceRecovery(task)
			continue
		}
		task.attempts++
		delay := isolationEvidenceRecoveryDelay(err, task.attempts)
		task.readyAt = time.Now().Add(delay)
		sink.requeueTerminalEvidenceRecovery(task)
	}
}

func (sink *NATSIsolationSink) nextTerminalEvidenceRecoveryTask() (*isolationRecoveryTask, time.Duration, bool) {
	sink.recoveryMu.Lock()
	defer sink.recoveryMu.Unlock()
	for {
		if len(sink.recoveryQueue) == 0 {
			sink.recoveryWorkers--
			sink.recoveryCond.Broadcast()
			return nil, 0, false
		}
		now := time.Now()
		ready := -1
		var wait time.Duration
		for index := 0; index < len(sink.recoveryQueue); {
			task := sink.recoveryQueue[index]
			if task.delivery.consumer.lifecycleCtx.Err() != nil {
				delete(sink.recovering, task.key)
				sink.recoveryQueue = slices.Delete(sink.recoveryQueue, index, index+1)
				task.delivery.consumer.recoveryWG.Done()
				sink.recoveryCond.Broadcast()
				continue
			}
			if !task.readyAt.After(now) {
				ready = index
				break
			}
			remaining := task.readyAt.Sub(now)
			if wait == 0 || remaining < wait {
				wait = remaining
			}
			index++
		}
		if ready >= 0 {
			task := sink.recoveryQueue[ready]
			sink.recoveryQueue = slices.Delete(sink.recoveryQueue, ready, ready+1)
			task.active = true
			return task, 0, true
		}
		if len(sink.recoveryQueue) != 0 {
			return nil, wait, true
		}
	}
}

func (sink *NATSIsolationSink) requeueTerminalEvidenceRecovery(task *isolationRecoveryTask) {
	sink.recoveryMu.Lock()
	if sink.recovering[task.key] != task || task.delivery.consumer.lifecycleCtx.Err() != nil {
		if sink.recovering[task.key] == task {
			delete(sink.recovering, task.key)
			sink.recoveryCond.Broadcast()
			sink.recoveryMu.Unlock()
			task.delivery.consumer.recoveryWG.Done()
			return
		}
		sink.recoveryMu.Unlock()
		return
	}
	task.active = false
	sink.recoveryQueue = append(sink.recoveryQueue, task)
	sink.wakeTerminalEvidenceRecoveryLocked()
	sink.recoveryCond.Broadcast()
	sink.recoveryMu.Unlock()
}

func (sink *NATSIsolationSink) finishTerminalEvidenceRecovery(task *isolationRecoveryTask) {
	sink.recoveryMu.Lock()
	finished := false
	if sink.recovering[task.key] == task {
		delete(sink.recovering, task.key)
		finished = true
	}
	sink.recoveryCond.Broadcast()
	sink.recoveryMu.Unlock()
	if finished {
		task.delivery.consumer.recoveryWG.Done()
	}
}

func (sink *NATSIsolationSink) wakeTerminalEvidenceRecoveryLocked() {
	select {
	case sink.recoveryWake <- struct{}{}:
	default:
	}
}

func (sink *NATSIsolationSink) stopTerminalEvidenceRecovery(consumer *NATSIngestConsumer) {
	if sink == nil || consumer == nil {
		return
	}
	sink.recoveryMu.Lock()
	finished := make([]*isolationRecoveryTask, 0)
	for key, task := range sink.recovering {
		if task.delivery.consumer == consumer && !task.active {
			delete(sink.recovering, key)
			finished = append(finished, task)
		}
	}
	sink.recoveryQueue = slices.DeleteFunc(sink.recoveryQueue, func(task *isolationRecoveryTask) bool {
		return task.delivery.consumer == consumer && !task.active
	})
	for range sink.recoveryWorkers {
		sink.wakeTerminalEvidenceRecoveryLocked()
	}
	sink.recoveryCond.Broadcast()
	sink.recoveryMu.Unlock()
	for _, task := range finished {
		task.delivery.consumer.recoveryWG.Done()
	}
}

func (sink *NATSIsolationSink) waitTerminalEvidenceRecoveryStopped(consumer *NATSIngestConsumer) {
	if sink == nil || consumer == nil {
		return
	}
	sink.recoveryMu.Lock()
	defer sink.recoveryMu.Unlock()
	for {
		consumerActive := false
		for _, task := range sink.recovering {
			consumerActive = consumerActive || task.delivery.consumer == consumer
		}
		if consumerActive {
			sink.recoveryCond.Wait()
			continue
		}
		if len(sink.recovering) != 0 || sink.recoveryWorkers == 0 {
			return
		}
		sink.recoveryCond.Wait()
	}
}

func retryableIsolationRecoveryError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, errIsolationEvidenceScanPending) || errors.Is(err, errIsolationStreamEpochChanged) ||
		errors.Is(err, nats.ErrKeyExists) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, nats.ErrTimeout) || errors.Is(err, nats.ErrNoResponders) ||
		errors.Is(err, nats.ErrDisconnected) || errors.Is(err, nats.ErrConnectionClosed) ||
		errors.Is(err, nats.ErrStreamNotFound)
}

func isolationEvidenceRecoveryDelay(err error, attempts uint64) time.Duration {
	if !errors.Is(err, errIsolationEvidenceDedupeHidden) &&
		(errors.Is(err, errIsolationEvidenceScanPending) || errors.Is(err, errIsolationStreamEpochChanged)) {
		return isolationEvidenceRecoveryPause
	}
	delay := isolationEvidenceRecoveryMinBackoff
	for attempt := uint64(1); attempt < attempts && delay < isolationEvidenceRecoveryMaxBackoff; attempt++ {
		delay = min(2*delay, isolationEvidenceRecoveryMaxBackoff)
	}
	return delay
}

func (sink *NATSIsolationSink) reloadTerminalIsolationIntent(
	intent isolationPublishIntent,
) (isolationPublishIntent, error) {
	delivery := intent.delivery
	if delivery == nil || delivery.consumer == nil {
		return intent, ErrInvalidInput
	}
	entry, err := delivery.consumer.stateStore.Get(fmt.Sprintf("parked.%020d", delivery.streamSequence))
	if err != nil {
		return intent, err
	}
	state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
	if err != nil || state.OwnerID != delivery.consumer.ownerID ||
		state.EvidencePayloadSHA256 != hex.EncodeToString(intent.PayloadSHA256[:]) {
		return intent, ErrInvalidInput
	}
	storedIntent, err := loadIsolationEvidenceBlob(
		sink.evidenceStore, delivery.consumer.streamCreated, delivery.streamSequence, sink.stream,
		state.EvidenceBlobSHA256,
	)
	if err != nil || storedIntent.MessageID != state.EvidenceMessageID ||
		storedIntent.PayloadSHA256 != intent.PayloadSHA256 || !bytes.Equal(storedIntent.Payload, intent.Payload) {
		clear(storedIntent.Payload)
		return intent, errors.Join(ErrInvalidInput, err)
	}
	intent.Payload = storedIntent.Payload
	intent.MessageID = state.EvidenceMessageID
	intent.ScanStart = state.EvidenceScanStart
	intent.ScanLast = state.EvidenceScanLast
	intent.StreamCreated = time.Time{}
	if state.EvidenceStreamCreated != "" {
		intent.StreamCreated, err = time.Parse(time.RFC3339Nano, state.EvidenceStreamCreated)
		if err != nil {
			return intent, ErrInvalidInput
		}
	}
	return intent, nil
}

var isolationEvidenceBlobMagic = [...]byte{'A', 'I', 'E', 'V', 1}

func isolationEvidenceBlobKey(sourceCreated time.Time, sourceSequence uint64) string {
	digest := sha256Sum([]byte(sourceCreated.UTC().Format(time.RFC3339Nano) + "\x00" +
		fmt.Sprintf("%020d", sourceSequence)))
	return "terminal_intent.v1." + hex.EncodeToString(digest[:])
}

func encodeIsolationEvidenceBlob(
	intent isolationPublishIntent,
	sourceCreated time.Time,
	sourceSequence uint64,
) ([]byte, error) {
	if sourceCreated.IsZero() || sourceSequence == 0 || intent.Subject != IsolationSubject ||
		intent.MessageID == "" || len(intent.Payload) == 0 {
		return nil, ErrInvalidInput
	}
	digest := sha256Sum(intent.Payload)
	if digest != intent.PayloadSHA256 {
		return nil, ErrInvalidInput
	}
	metadata, err := json.Marshal(isolationEvidenceBlobMetadata{
		SchemaVersion: 1, SourceStreamCreated: sourceCreated.UTC().Format(time.RFC3339Nano),
		SourceStreamSequence: sourceSequence, Subject: intent.Subject,
		Headers:      []IsolationHeader{{Name: nats.MsgIdHdr, Value: intent.MessageID}},
		PayloadBytes: len(intent.Payload), PayloadSHA256: hex.EncodeToString(digest[:]),
	})
	if err != nil || len(metadata) > int(^uint32(0)) {
		clear(metadata)
		return nil, ErrInvalidInput
	}
	headerBytes := len(isolationEvidenceBlobMagic) + 4
	if len(intent.Payload) > int(isolationEvidenceMaxValueSize)-headerBytes-len(metadata) {
		clear(metadata)
		return nil, ErrInvalidInput
	}
	encoded := make([]byte, headerBytes+len(metadata)+len(intent.Payload))
	copy(encoded, isolationEvidenceBlobMagic[:])
	binary.BigEndian.PutUint32(encoded[len(isolationEvidenceBlobMagic):headerBytes], uint32(len(metadata)))
	copy(encoded[headerBytes:], metadata)
	copy(encoded[headerBytes+len(metadata):], intent.Payload)
	clear(metadata)
	return encoded, nil
}

func decodeIsolationEvidenceBlob(
	encoded []byte,
	sourceCreated time.Time,
	sourceSequence uint64,
	isolationStream string,
) (isolationPublishIntent, error) {
	var intent isolationPublishIntent
	headerBytes := len(isolationEvidenceBlobMagic) + 4
	if sourceCreated.IsZero() || sourceSequence == 0 || !validNATSName(isolationStream) ||
		len(encoded) < headerBytes || len(encoded) > int(isolationEvidenceMaxValueSize) ||
		!bytes.Equal(encoded[:len(isolationEvidenceBlobMagic)], isolationEvidenceBlobMagic[:]) {
		return intent, ErrInvalidInput
	}
	metadataBytes := int(binary.BigEndian.Uint32(encoded[len(isolationEvidenceBlobMagic):headerBytes]))
	if metadataBytes <= 0 || metadataBytes > len(encoded)-headerBytes {
		return intent, ErrInvalidInput
	}
	var metadata isolationEvidenceBlobMetadata
	decoder := json.NewDecoder(bytes.NewReader(encoded[headerBytes : headerBytes+metadataBytes]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&metadata) != nil {
		return intent, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return intent, ErrInvalidInput
	}
	payload := encoded[headerBytes+metadataBytes:]
	wantCreated := sourceCreated.UTC().Format(time.RFC3339Nano)
	if metadata.SchemaVersion != 1 || metadata.SourceStreamCreated != wantCreated ||
		metadata.SourceStreamSequence != sourceSequence || metadata.Subject != IsolationSubject ||
		len(metadata.Headers) != 1 || metadata.Headers[0].Name != nats.MsgIdHdr ||
		!validBatchID(metadata.Headers[0].Value) && !strings.HasPrefix(metadata.Headers[0].Value, "analytics-isolation-v1-") ||
		metadata.PayloadBytes != len(payload) || metadata.PayloadBytes <= 0 ||
		len(metadata.PayloadSHA256) != sha256HexLength {
		return intent, ErrInvalidInput
	}
	digest := sha256Sum(payload)
	if hex.EncodeToString(digest[:]) != metadata.PayloadSHA256 {
		return intent, ErrInvalidInput
	}
	intent = isolationPublishIntent{
		Subject: metadata.Subject, Stream: isolationStream, MessageID: metadata.Headers[0].Value,
		Payload: append([]byte(nil), payload...), PayloadSHA256: digest,
	}
	return intent, nil
}

func persistIsolationEvidenceBlob(
	ctx context.Context,
	store nats.KeyValue,
	intent isolationPublishIntent,
	sourceCreated time.Time,
	sourceSequence uint64,
) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if ctx == nil || store == nil {
		return zero, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	encoded, err := encodeIsolationEvidenceBlob(intent, sourceCreated, sourceSequence)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	key := isolationEvidenceBlobKey(sourceCreated, sourceSequence)
	_, createErr := store.Create(key, encoded)
	if createErr != nil && !errors.Is(createErr, nats.ErrKeyExists) {
		return zero, fmt.Errorf("persist analytics terminal evidence blob: %w", createErr)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	entry, err := store.Get(key)
	if err != nil || entry == nil || !bytes.Equal(entry.Value(), encoded) {
		return zero, errors.Join(ErrInvalidInput, createErr, err)
	}
	return sha256Sum(encoded), nil
}

func loadIsolationEvidenceBlob(
	store nats.KeyValue,
	sourceCreated time.Time,
	sourceSequence uint64,
	isolationStream string,
	wantDigest string,
) (isolationPublishIntent, error) {
	if store == nil {
		return isolationPublishIntent{}, ErrInvalidConfiguration
	}
	entry, err := store.Get(isolationEvidenceBlobKey(sourceCreated, sourceSequence))
	if err != nil {
		return isolationPublishIntent{}, err
	}
	if wantDigest != "" {
		digest := sha256Sum(entry.Value())
		if hex.EncodeToString(digest[:]) != wantDigest {
			return isolationPublishIntent{}, ErrInvalidInput
		}
	}
	return decodeIsolationEvidenceBlob(entry.Value(), sourceCreated, sourceSequence, isolationStream)
}

func decodeIsolationEvidenceRecord(payload []byte) (IsolationRecord, error) {
	var record IsolationRecord
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil {
		return record, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return record, ErrInvalidInput
	}
	return record, nil
}

func (sink *NATSIsolationSink) prepareTerminalEvidence(
	ctx context.Context,
	delivery *natsIngestDelivery,
	record IsolationRecord,
) (isolationPublishIntent, error) {
	if sink == nil || delivery == nil || delivery.consumer == nil || record.StreamSequence != delivery.streamSequence {
		return isolationPublishIntent{}, ErrInvalidInput
	}
	if !delivery.consumer.attachIsolationSink(sink) {
		return isolationPublishIntent{}, ErrInvalidConfiguration
	}
	var existing parkedDeliveryState
	hasPrepared := false
	err := delivery.consumer.withLeaseFenceContext(ctx, func(fenceCtx context.Context) error {
		operationCtx, cancel := boundedSettlementContext(ctx, fenceCtx)
		defer cancel()
		entry, err := delivery.consumer.stateStore.Get(fmt.Sprintf("parked.%020d", delivery.streamSequence))
		if err != nil {
			return err
		}
		state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
		if err != nil || state.OwnerID != delivery.consumer.ownerID {
			return ErrInvalidInput
		}
		if state.Phase != parkedPhaseDelivery {
			existing = state
			hasPrepared = true
		}
		return operationCtx.Err()
	})
	if err != nil {
		return isolationPublishIntent{}, err
	}
	if hasPrepared {
		intent, rebuildErr := sink.rebuildIsolationIntent(ctx, delivery, record, existing)
		intent.ReconcileFirst = true
		return intent, rebuildErr
	}
	intent, loadErr := loadIsolationEvidenceBlob(
		sink.evidenceStore, delivery.consumer.streamCreated, delivery.streamSequence, sink.stream, "",
	)
	var encodedRecord IsolationRecord
	var wireDigest [sha256.Size]byte
	if loadErr == nil {
		encodedRecord, err = decodeIsolationEvidenceRecord(intent.Payload)
		if err != nil || !sameIsolationEvidenceRecord(encodedRecord, record) {
			clear(intent.Payload)
			return isolationPublishIntent{}, ErrInvalidInput
		}
		wireDigest, err = decodeSHA256(encodedRecord.WireSHA256)
		if err != nil {
			clear(intent.Payload)
			return isolationPublishIntent{}, ErrInvalidInput
		}
		if err := sink.validateExistingIsolationEvidenceWire(ctx, intent, encodedRecord, record.Wire, wireDigest); err != nil {
			clear(intent.Payload)
			return isolationPublishIntent{}, err
		}
	} else if errors.Is(loadErr, nats.ErrKeyNotFound) || errors.Is(loadErr, nats.ErrKeyDeleted) {
		intent, wireDigest, err = sink.buildIsolationIntent(ctx, record, "", nil)
		if err != nil {
			return isolationPublishIntent{}, err
		}
		encodedRecord, err = decodeIsolationEvidenceRecord(intent.Payload)
		if err != nil {
			clear(intent.Payload)
			return isolationPublishIntent{}, ErrInvalidInput
		}
	} else {
		return isolationPublishIntent{}, loadErr
	}
	blobDigest, err := persistIsolationEvidenceBlob(
		ctx, sink.evidenceStore, intent, delivery.consumer.streamCreated, delivery.streamSequence,
	)
	if err != nil {
		clear(intent.Payload)
		return isolationPublishIntent{}, err
	}
	info, err := sink.isolationStreamInfo(ctx)
	if err != nil || info.State.LastSeq == ^uint64(0) {
		clear(intent.Payload)
		return isolationPublishIntent{}, fmt.Errorf("read analytics isolation stream state")
	}
	intent.StreamCreated = info.Created
	intent.ScanStart = info.State.FirstSeq
	if intent.ScanStart == 0 {
		intent.ScanStart = info.State.LastSeq + 1
	}
	intent.ScanLast = info.State.LastSeq
	intent.delivery = delivery
	keyDigest := sha256Sum([]byte(encodedRecord.WireKeyID))
	state := parkedDeliveryState{
		StreamCreated: delivery.consumer.streamCreated.UTC().Format(time.RFC3339Nano),
		OwnerID:       delivery.consumer.ownerID, Terminal: true, Phase: parkedPhaseEvidencePrepared,
		MessageID: encodedRecord.MessageID, ReasonCode: encodedRecord.ReasonCode, PayloadSHA256: encodedRecord.PayloadSHA256,
		EvidenceMessageID:     intent.MessageID,
		EvidencePayloadSHA256: hex.EncodeToString(intent.PayloadSHA256[:]),
		EvidenceBlobSHA256:    hex.EncodeToString(blobDigest[:]),
		EvidenceWireSHA256:    hex.EncodeToString(wireDigest[:]), EvidenceKeySHA256: hex.EncodeToString(keyDigest[:]),
		EvidenceNonce: encodedRecord.WireNonce, EvidenceIsolatedAt: encodedRecord.IsolatedAt.UTC().Format(time.RFC3339Nano),
		EvidenceAttempts: encodedRecord.Attempts, EvidenceScanStart: intent.ScanStart,
		EvidenceScanLast:      intent.ScanLast,
		EvidenceStreamCreated: info.Created.UTC().Format(time.RFC3339Nano), EvidenceOnly: record.WireEvidenceOnly,
	}
	err = delivery.consumer.withLeaseFenceContext(ctx, func(fenceCtx context.Context) error {
		operationCtx, cancel := boundedSettlementContext(ctx, fenceCtx)
		defer cancel()
		key := fmt.Sprintf("parked.%020d", delivery.streamSequence)
		entry, err := delivery.consumer.stateStore.Get(key)
		if err != nil {
			return err
		}
		current, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
		if err != nil || current.OwnerID != delivery.consumer.ownerID || current.Phase != parkedPhaseDelivery {
			return ErrInvalidInput
		}
		value, err := json.Marshal(state)
		if err != nil || len(value) > 1024 {
			return ErrInvalidInput
		}
		if err := operationCtx.Err(); err != nil {
			return err
		}
		_, err = delivery.consumer.stateStore.Update(key, value, entry.Revision())
		return err
	})
	if err != nil {
		return isolationPublishIntent{}, err
	}
	return intent, nil
}

func (sink *NATSIsolationSink) validateExistingIsolationEvidenceWire(
	ctx context.Context,
	stored isolationPublishIntent,
	record IsolationRecord,
	wire *IsolationWire,
	wireDigest [sha256.Size]byte,
) error {
	if wire == nil {
		return ErrInvalidInput
	}
	nonce, err := base64.RawStdEncoding.DecodeString(record.WireNonce)
	if err != nil {
		return ErrInvalidInput
	}
	defer clear(nonce)
	record.WireNonce = ""
	record.WireCiphertext = ""
	record.WireSHA256 = ""
	record.Wire = wire
	rebuilt, rebuiltWireDigest, err := sink.buildIsolationIntent(ctx, record, record.WireKeyID, nonce)
	if err != nil {
		return err
	}
	defer clear(rebuilt.Payload)
	if rebuilt.Subject != stored.Subject || rebuilt.MessageID != stored.MessageID ||
		rebuilt.PayloadSHA256 != stored.PayloadSHA256 || rebuiltWireDigest != wireDigest ||
		!bytes.Equal(rebuilt.Payload, stored.Payload) {
		return ErrInvalidInput
	}
	return nil
}

func (sink *NATSIsolationSink) buildIsolationIntent(
	ctx context.Context,
	record IsolationRecord,
	keyID string,
	nonce []byte,
) (isolationPublishIntent, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if sink == nil || record.SchemaVersion != IngestSchemaVersion || record.ReasonCode == "" ||
		record.Subject == "" || len(record.PayloadSHA256) != sha256HexLength || record.PayloadBytes < 0 ||
		sink.stateStore == nil || sink.keyProvider == nil ||
		(record.WireEvidenceOnly && !validIsolationEvidenceWire(record.Wire, record)) ||
		(!record.WireEvidenceOnly && !validIsolationWire(record.Wire, record)) {
		return isolationPublishIntent{}, zero, ErrInvalidInput
	}
	wire, err := json.Marshal(record.Wire)
	if err != nil || len(wire) > 2*DefaultMaxIngestMessageBytes {
		return isolationPublishIntent{}, zero, ErrInvalidInput
	}
	defer clear(wire)
	keyCtx, keyCancel := context.WithTimeout(ctx, sink.operationTimeout)
	var dek []byte
	if keyID == "" {
		keyID, err = sink.keyProvider.ActiveKeyID(keyCtx)
		if err == nil && validIsolationKeyID(keyID) {
			dek, err = sink.loadOrCreateIsolationDEK(keyCtx, keyID)
		}
	} else {
		dek, err = sink.loadIsolationDEK(keyCtx, keyID)
	}
	keyCancel()
	if err != nil {
		return isolationPublishIntent{}, zero, err
	}
	if !validIsolationKeyID(keyID) {
		clear(dek)
		return isolationPublishIntent{}, zero, ErrInvalidConfiguration
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return isolationPublishIntent{}, zero, ErrInvalidConfiguration
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return isolationPublishIntent{}, zero, ErrInvalidConfiguration
	}
	wireDigest := sha256Sum(wire)
	record.WireKeyID = keyID
	if len(nonce) == 0 {
		mac := hmac.New(sha256.New, dek)
		_, _ = mac.Write(isolationAssociatedData(record))
		_, _ = mac.Write(wire)
		nonce = append([]byte(nil), mac.Sum(nil)[:aead.NonceSize()]...)
	}
	if len(nonce) != aead.NonceSize() {
		return isolationPublishIntent{}, zero, ErrInvalidInput
	}
	record.WireNonce = base64.RawStdEncoding.EncodeToString(nonce)
	record.WireCiphertext = base64.RawStdEncoding.EncodeToString(
		aead.Seal(nil, nonce, wire, isolationAssociatedData(record)),
	)
	record.WireSHA256 = hex.EncodeToString(wireDigest[:])
	record.Wire = nil
	payload, err := json.Marshal(record)
	if err != nil {
		return isolationPublishIntent{}, zero, ErrInvalidInput
	}
	payloadDigest := sha256Sum(payload)
	return isolationPublishIntent{
		Subject: IsolationSubject, MessageID: isolationMessageID(record), Payload: payload,
		Stream: sink.stream, PayloadSHA256: payloadDigest,
	}, wireDigest, nil
}

func (sink *NATSIsolationSink) rebuildIsolationIntent(
	ctx context.Context,
	delivery *natsIngestDelivery,
	record IsolationRecord,
	state parkedDeliveryState,
) (isolationPublishIntent, error) {
	if state.MessageID != record.MessageID || state.ReasonCode != record.ReasonCode ||
		state.PayloadSHA256 != record.PayloadSHA256 || state.EvidenceOnly != record.WireEvidenceOnly {
		return isolationPublishIntent{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return isolationPublishIntent{}, err
	}
	intent, err := loadIsolationEvidenceBlob(
		sink.evidenceStore, delivery.consumer.streamCreated, delivery.streamSequence, sink.stream,
		state.EvidenceBlobSHA256,
	)
	if err != nil {
		return isolationPublishIntent{}, err
	}
	encodedRecord, err := decodeIsolationEvidenceRecord(intent.Payload)
	if err != nil || !sameIsolationEvidenceRecord(encodedRecord, record) ||
		encodedRecord.WireSHA256 != state.EvidenceWireSHA256 ||
		intent.Subject != IsolationSubject || intent.MessageID != state.EvidenceMessageID ||
		hex.EncodeToString(intent.PayloadSHA256[:]) != state.EvidencePayloadSHA256 {
		clear(intent.Payload)
		return isolationPublishIntent{}, ErrInvalidInput
	}
	intent.ScanStart = state.EvidenceScanStart
	intent.ScanLast = state.EvidenceScanLast
	if state.EvidenceStreamCreated != "" {
		intent.StreamCreated, err = time.Parse(time.RFC3339Nano, state.EvidenceStreamCreated)
		if err != nil {
			return isolationPublishIntent{}, ErrInvalidInput
		}
	}
	intent.delivery = delivery
	return intent, nil
}

func sameIsolationEvidenceRecord(encoded, source IsolationRecord) bool {
	return encoded.SchemaVersion == source.SchemaVersion && encoded.ReasonCode == source.ReasonCode &&
		encoded.MessageID == source.MessageID && encoded.Subject == source.Subject &&
		encoded.PayloadSHA256 == source.PayloadSHA256 && encoded.PayloadBytes == source.PayloadBytes &&
		encoded.StreamSequence == source.StreamSequence && encoded.WireEvidenceOnly == source.WireEvidenceOnly
}

func (sink *NATSIsolationSink) publishEvidenceIntent(ctx context.Context, intent isolationPublishIntent) (uint64, error) {
	if sink == nil || intent.Subject != IsolationSubject || intent.MessageID == "" || intent.ScanStart == 0 ||
		len(intent.Payload) == 0 || sha256Sum(intent.Payload) != intent.PayloadSHA256 {
		return 0, ErrInvalidInput
	}
	var err error
	intent, err = sink.ensureIsolationIntentEpoch(ctx, intent)
	if err != nil {
		return 0, err
	}
	remainingReads := isolationEvidenceScanBatch
	search, err := sink.findIsolationEvidence(ctx, intent, remainingReads)
	if err != nil {
		return 0, err
	}
	remainingReads -= search.Reads
	if search.Found {
		if err := sink.completeIsolationScan(ctx, intent); err != nil {
			return 0, err
		}
		return search.Sequence, nil
	}
	if err := sink.checkpointIsolationScan(ctx, intent, search.Next, search.Last); err != nil {
		return 0, err
	}
	if !search.Complete {
		return 0, errIsolationEvidenceScanPending
	}
	if err := sink.requireIsolationIntentEpoch(ctx, intent); err != nil {
		return 0, err
	}
	message := nats.NewMsg(intent.Subject)
	message.Data = append([]byte(nil), intent.Payload...)
	message.Header.Set(nats.MsgIdHdr, intent.MessageID)
	publishCtx, publishCancel := context.WithTimeout(ctx, sink.operationTimeout)
	defer publishCancel()
	publish := sink.publishMessage
	if publish == nil {
		publish = sink.jetstream.PublishMsg
	}
	acknowledgement, publishErr := publish(
		message, nats.Context(publishCtx), nats.ExpectStream(sink.stream), nats.ExpectLastSequence(search.Last),
	)
	if publishErr == nil && acknowledgement != nil && acknowledgement.Stream == sink.stream && acknowledgement.Sequence > 0 {
		if err := sink.requireIsolationIntentEpoch(ctx, intent); err != nil {
			return 0, err
		}
		if remainingReads == 0 {
			if err := sink.checkpointIsolationScan(
				ctx, intent, acknowledgement.Sequence, acknowledgement.Sequence,
			); err != nil {
				return 0, err
			}
			return 0, errIsolationEvidenceScanPending
		}
		stored, err := sink.jetstream.GetMsg(sink.stream, acknowledgement.Sequence, nats.Context(publishCtx))
		remainingReads--
		if err == nil {
			if err := validateStoredIsolationEvidence(intent, stored); err != nil {
				return 0, ErrInvalidInput
			}
			if err := sink.completeIsolationScan(ctx, intent); err != nil {
				return 0, err
			}
			return acknowledgement.Sequence, nil
		}
		if acknowledgement.Duplicate && errors.Is(err, nats.ErrMsgNotFound) {
			err = errors.Join(errIsolationEvidenceDedupeHidden, err)
		}
		publishErr = err
	}
	info, infoErr := sink.isolationStreamInfo(ctx)
	if infoErr != nil {
		return 0, infoErr
	}
	if !info.Created.Equal(intent.StreamCreated) {
		return 0, errIsolationStreamEpochChanged
	}
	reconcile := intent
	reconcile.ScanStart = max(search.Last+1, info.State.FirstSeq)
	if reconcile.ScanStart == 0 {
		reconcile.ScanStart = info.State.LastSeq + 1
	}
	reconcile.ScanLast = info.State.LastSeq
	if remainingReads == 0 {
		if err := sink.checkpointIsolationScan(ctx, intent, reconcile.ScanStart, reconcile.ScanLast); err != nil {
			return 0, err
		}
		return 0, errors.Join(errIsolationEvidenceScanPending, publishErr)
	}
	reconciled, reconcileErr := sink.findIsolationEvidence(ctx, reconcile, remainingReads)
	if reconcileErr != nil {
		return 0, reconcileErr
	}
	if reconciled.Found {
		if err := sink.completeIsolationScan(ctx, intent); err != nil {
			return 0, err
		}
		return reconciled.Sequence, nil
	}
	if err := sink.checkpointIsolationScan(ctx, intent, reconciled.Next, reconciled.Last); err != nil {
		return 0, err
	}
	if !reconciled.Complete {
		return 0, errIsolationEvidenceScanPending
	}
	return 0, errors.Join(errIsolationEvidenceScanPending, publishErr)
}

type isolationEvidenceSearch struct {
	Sequence uint64
	Next     uint64
	Last     uint64
	Reads    uint64
	Found    bool
	Complete bool
}

type isolationScanState struct {
	SchemaVersion uint16 `json:"schema_version"`
	StreamCreated string `json:"stream_created"`
	MessageID     string `json:"message_id"`
	PayloadSHA256 string `json:"payload_sha256"`
	Next          uint64 `json:"next"`
	Last          uint64 `json:"last"`
}

func (sink *NATSIsolationSink) resumeIsolationScan(
	ctx context.Context,
	intent isolationPublishIntent,
) (isolationPublishIntent, error) {
	return sink.resetStandaloneIsolationScan(ctx, intent)
}

func (sink *NATSIsolationSink) resetStandaloneIsolationScan(
	ctx context.Context,
	intent isolationPublishIntent,
) (isolationPublishIntent, error) {
	key := isolationScanStateKey(intent)
	for {
		info, err := sink.isolationStreamInfo(ctx)
		if err != nil || info.State.LastSeq == ^uint64(0) {
			return intent, errors.Join(errIsolationStreamEpochChanged, err)
		}
		intent.StreamCreated = info.Created
		state := isolationScanState{
			SchemaVersion: 1, StreamCreated: info.Created.UTC().Format(time.RFC3339Nano),
			MessageID: intent.MessageID, PayloadSHA256: hex.EncodeToString(intent.PayloadSHA256[:]),
			Next: info.State.FirstSeq, Last: info.State.LastSeq,
		}
		if state.Next == 0 {
			state.Next = state.Last + 1
		}
		entry, getErr := sink.stateStore.Get(key)
		if errors.Is(getErr, nats.ErrKeyNotFound) {
			value, marshalErr := json.Marshal(state)
			if marshalErr != nil {
				return intent, marshalErr
			}
			if _, createErr := sink.stateStore.Create(key, value); createErr == nil {
				intent.ScanStart, intent.ScanLast = state.Next, state.Last
				return intent, nil
			} else if errors.Is(createErr, nats.ErrKeyExists) {
				continue
			} else {
				return intent, createErr
			}
		}
		if getErr != nil {
			return intent, getErr
		}
		existing, decodeErr := decodeIsolationScanState(entry.Value(), intent)
		if decodeErr != nil {
			return intent, decodeErr
		}
		if existing.StreamCreated == state.StreamCreated {
			intent.ScanStart, intent.ScanLast = existing.Next, existing.Last
			return intent, nil
		}
		value, marshalErr := json.Marshal(state)
		if marshalErr != nil {
			return intent, marshalErr
		}
		if err := ctx.Err(); err != nil {
			return intent, err
		}
		if _, updateErr := sink.stateStore.Update(key, value, entry.Revision()); updateErr == nil {
			intent.ScanStart, intent.ScanLast = state.Next, state.Last
			return intent, nil
		} else if errors.Is(updateErr, nats.ErrKeyExists) || errors.Is(updateErr, nats.ErrKeyNotFound) {
			continue
		} else {
			return intent, updateErr
		}
	}
}

func (sink *NATSIsolationSink) resetTerminalIsolationScan(
	ctx context.Context,
	intent isolationPublishIntent,
) (isolationPublishIntent, error) {
	delivery := intent.delivery
	if delivery == nil || delivery.consumer == nil {
		return intent, ErrInvalidInput
	}
	updated := intent
	err := delivery.consumer.withLeaseFenceContext(ctx, func(fenceCtx context.Context) error {
		info, err := sink.isolationStreamInfo(fenceCtx)
		if err != nil || info.State.LastSeq == ^uint64(0) {
			return errors.Join(errIsolationStreamEpochChanged, err)
		}
		entry, err := delivery.consumer.stateStore.Get(fmt.Sprintf("parked.%020d", delivery.streamSequence))
		if err != nil {
			return err
		}
		state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
		if err != nil || state.OwnerID != delivery.consumer.ownerID ||
			state.EvidenceMessageID != intent.MessageID ||
			state.EvidencePayloadSHA256 != hex.EncodeToString(intent.PayloadSHA256[:]) {
			return ErrInvalidInput
		}
		created := info.Created.UTC().Format(time.RFC3339Nano)
		if state.EvidenceStreamCreated != created {
			state.Phase = parkedPhaseEvidencePrepared
			state.EvidenceConfirmed = false
			state.EvidenceSequence = 0
			state.EvidenceStreamCreated = created
			state.EvidenceScanStart = info.State.FirstSeq
			if state.EvidenceScanStart == 0 {
				state.EvidenceScanStart = info.State.LastSeq + 1
			}
			state.EvidenceScanLast = info.State.LastSeq
			value, marshalErr := json.Marshal(state)
			if marshalErr != nil || len(value) > 1024 {
				return ErrInvalidInput
			}
			epochIntent := intent
			epochIntent.StreamCreated = info.Created
			if err := sink.requireIsolationIntentEpoch(fenceCtx, epochIntent); err != nil {
				return err
			}
			if _, err := delivery.consumer.stateStore.Update(
				fmt.Sprintf("parked.%020d", delivery.streamSequence), value, entry.Revision(),
			); err != nil {
				if errors.Is(err, nats.ErrKeyExists) {
					return errIsolationEvidenceScanPending
				}
				return err
			}
		}
		updated.StreamCreated = info.Created
		updated.ScanStart = state.EvidenceScanStart
		updated.ScanLast = state.EvidenceScanLast
		return nil
	})
	return updated, err
}

func (sink *NATSIsolationSink) ensureIsolationIntentEpoch(
	ctx context.Context,
	intent isolationPublishIntent,
) (isolationPublishIntent, error) {
	info, err := sink.isolationStreamInfo(ctx)
	if err != nil {
		return intent, err
	}
	if !intent.StreamCreated.IsZero() && info.Created.Equal(intent.StreamCreated) {
		return intent, nil
	}
	if intent.delivery == nil {
		return sink.resetStandaloneIsolationScan(ctx, intent)
	}
	return sink.resetTerminalIsolationScan(ctx, intent)
}

func (sink *NATSIsolationSink) requireIsolationIntentEpoch(
	ctx context.Context,
	intent isolationPublishIntent,
) error {
	info, err := sink.isolationStreamInfo(ctx)
	if err != nil {
		return err
	}
	if intent.StreamCreated.IsZero() || !info.Created.Equal(intent.StreamCreated) {
		return errIsolationStreamEpochChanged
	}
	return nil
}

func (sink *NATSIsolationSink) checkpointStandaloneIsolationScan(
	ctx context.Context,
	intent isolationPublishIntent,
	next uint64,
	last uint64,
) error {
	key := isolationScanStateKey(intent)
	for {
		entry, err := sink.stateStore.Get(key)
		if err != nil {
			return err
		}
		state, err := decodeIsolationScanState(entry.Value(), intent)
		if err != nil {
			return err
		}
		if state.StreamCreated != intent.StreamCreated.UTC().Format(time.RFC3339Nano) {
			return errIsolationStreamEpochChanged
		}
		if err := sink.requireIsolationIntentEpoch(ctx, intent); err != nil {
			return err
		}
		if state.Last > last || state.Last == last && state.Next >= next {
			return nil
		}
		state.Next = max(state.Next, next)
		state.Last = max(state.Last, last)
		value, err := json.Marshal(state)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err = sink.stateStore.Update(key, value, entry.Revision()); err == nil {
			return nil
		} else if errors.Is(err, nats.ErrKeyExists) {
			continue
		} else {
			return err
		}
	}
}

func (sink *NATSIsolationSink) completeIsolationScan(ctx context.Context, intent isolationPublishIntent) error {
	if intent.delivery != nil {
		return nil
	}
	key := isolationScanStateKey(intent)
	for {
		entry, err := sink.stateStore.Get(key)
		if errors.Is(err, nats.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		state, err := decodeIsolationScanState(entry.Value(), intent)
		if err != nil {
			return err
		}
		if state.StreamCreated != intent.StreamCreated.UTC().Format(time.RFC3339Nano) {
			return errIsolationStreamEpochChanged
		}
		if err := sink.requireIsolationIntentEpoch(ctx, intent); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		err = sink.stateStore.Delete(key, nats.LastRevision(entry.Revision()))
		if err == nil || errors.Is(err, nats.ErrKeyNotFound) {
			return nil
		}
		if !errors.Is(err, nats.ErrKeyExists) {
			return err
		}
	}
}

func isolationScanStateKey(intent isolationPublishIntent) string {
	digest := sha256Sum([]byte(intent.MessageID + "\x00" + hex.EncodeToString(intent.PayloadSHA256[:])))
	return isolationScanStatePrefix + hex.EncodeToString(digest[:])
}

func decodeIsolationScanState(
	value []byte,
	intent isolationPublishIntent,
) (isolationScanState, error) {
	var state isolationScanState
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil {
		return state, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return state, ErrInvalidInput
	}
	if state.SchemaVersion != 1 || state.StreamCreated == "" || state.MessageID != intent.MessageID ||
		state.PayloadSHA256 != hex.EncodeToString(intent.PayloadSHA256[:]) ||
		state.Next == 0 {
		return state, ErrInvalidInput
	}
	created, err := time.Parse(time.RFC3339Nano, state.StreamCreated)
	if err != nil || created.Location() != time.UTC {
		return state, ErrInvalidInput
	}
	return state, nil
}

func (sink *NATSIsolationSink) findIsolationEvidence(
	ctx context.Context,
	intent isolationPublishIntent,
	maxReads uint64,
) (isolationEvidenceSearch, error) {
	result := isolationEvidenceSearch{Next: intent.ScanStart, Last: intent.ScanLast}
	operationCtx, cancel := context.WithTimeout(ctx, sink.operationTimeout)
	defer cancel()
	info, err := sink.jetstream.StreamInfo(
		sink.stream, &nats.StreamInfoRequest{DeletedDetails: true}, nats.Context(operationCtx),
	)
	if err != nil {
		return result, err
	}
	if !sameStream(info, &sink.expectedStream) {
		return result, fmt.Errorf("analytics stream %s configuration does not match", sink.stream)
	}
	if intent.StreamCreated.IsZero() || !info.Created.Equal(intent.StreamCreated) {
		return result, errIsolationStreamEpochChanged
	}
	result.Last = min(result.Last, info.State.LastSeq)
	result.Next = max(result.Next, info.State.FirstSeq)
	if result.Next == 0 {
		result.Next = result.Last + 1
	}
	if result.Next > result.Last {
		result.Complete = true
		return result, nil
	}
	limit := sink.scanLimit
	if limit == 0 || limit > isolationEvidenceScanBatch {
		limit = isolationEvidenceScanBatch
	}
	limit = min(limit, maxReads)
	checked := uint64(0)
	for result.Next <= result.Last && checked < limit {
		sequence := result.Next
		result.Next++
		checked++
		result.Reads++
		stored, getErr := sink.jetstream.GetMsg(sink.stream, sequence, nats.Context(operationCtx))
		if errors.Is(getErr, nats.ErrMsgNotFound) {
			if sequence < info.State.FirstSeq || slices.Contains(info.State.Deleted, sequence) {
				continue
			}
			return result, getErr
		}
		if getErr != nil {
			return result, getErr
		}
		if stored.Header.Get(nats.MsgIdHdr) != intent.MessageID {
			continue
		}
		if err := validateStoredIsolationEvidence(intent, stored); err != nil {
			return result, err
		}
		result.Sequence = stored.Sequence
		result.Found = true
		result.Complete = true
		return result, nil
	}
	result.Complete = result.Next > result.Last
	return result, nil
}

func (sink *NATSIsolationSink) checkpointIsolationScan(
	ctx context.Context,
	intent isolationPublishIntent,
	next uint64,
	last uint64,
) error {
	if intent.delivery == nil {
		return sink.checkpointStandaloneIsolationScan(ctx, intent, next, last)
	}
	delivery := intent.delivery
	return delivery.consumer.withLeaseFenceContext(ctx, func(fenceCtx context.Context) error {
		operationCtx, cancel := boundedSettlementContext(ctx, fenceCtx)
		defer cancel()
		key := fmt.Sprintf("parked.%020d", delivery.streamSequence)
		entry, err := delivery.consumer.stateStore.Get(key)
		if err != nil {
			return err
		}
		state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
		if err != nil || state.OwnerID != delivery.consumer.ownerID ||
			state.EvidenceMessageID != intent.MessageID ||
			state.EvidencePayloadSHA256 != hex.EncodeToString(intent.PayloadSHA256[:]) ||
			state.EvidenceStreamCreated != intent.StreamCreated.UTC().Format(time.RFC3339Nano) {
			return ErrInvalidInput
		}
		if state.EvidenceScanLast > last || state.EvidenceScanLast == last && state.EvidenceScanStart >= next {
			return nil
		}
		state.EvidenceScanStart = max(state.EvidenceScanStart, next)
		state.EvidenceScanLast = max(state.EvidenceScanLast, last)
		value, err := json.Marshal(state)
		if err != nil || len(value) > 1024 {
			return ErrInvalidInput
		}
		if err := operationCtx.Err(); err != nil {
			return err
		}
		if err := sink.requireIsolationIntentEpoch(operationCtx, intent); err != nil {
			return err
		}
		_, err = delivery.consumer.stateStore.Update(key, value, entry.Revision())
		if errors.Is(err, nats.ErrKeyExists) {
			return errIsolationEvidenceScanPending
		}
		return err
	})
}

func validateStoredIsolationEvidence(intent isolationPublishIntent, stored *nats.RawStreamMsg) error {
	if stored == nil || stored.Sequence == 0 || stored.Subject != intent.Subject ||
		len(stored.Header.Values(nats.MsgIdHdr)) != 1 || stored.Header.Get(nats.MsgIdHdr) != intent.MessageID {
		return ErrInvalidInput
	}
	if intent.Stream == "" {
		if len(stored.Header) != 1 {
			return ErrInvalidInput
		}
	} else {
		expectedLast, err := strconv.ParseUint(stored.Header.Get(nats.ExpectedLastSeqHdr), 10, 64)
		if len(stored.Header) != 3 || len(stored.Header.Values(nats.ExpectedStreamHdr)) != 1 ||
			stored.Header.Get(nats.ExpectedStreamHdr) != intent.Stream ||
			len(stored.Header.Values(nats.ExpectedLastSeqHdr)) != 1 || err != nil ||
			expectedLast >= stored.Sequence {
			return ErrInvalidInput
		}
	}
	digest := sha256Sum(stored.Data)
	if digest != intent.PayloadSHA256 || (len(intent.Payload) != 0 && !bytes.Equal(stored.Data, intent.Payload)) {
		return ErrInvalidInput
	}
	return nil
}

func (sink *NATSIsolationSink) confirmTerminalEvidence(
	ctx context.Context,
	delivery *natsIngestDelivery,
	intent isolationPublishIntent,
	sequence uint64,
) error {
	resetEpoch := false
	err := delivery.consumer.withLeaseFenceContext(ctx, func(fenceCtx context.Context) error {
		operationCtx, cancel := boundedSettlementContext(ctx, fenceCtx)
		defer cancel()
		key := fmt.Sprintf("parked.%020d", delivery.streamSequence)
		entry, err := delivery.consumer.stateStore.Get(key)
		if err != nil {
			return err
		}
		state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
		if err != nil || state.OwnerID != delivery.consumer.ownerID || state.EvidenceMessageID != intent.MessageID ||
			state.EvidencePayloadSHA256 != hex.EncodeToString(intent.PayloadSHA256[:]) ||
			state.EvidenceStreamCreated != intent.StreamCreated.UTC().Format(time.RFC3339Nano) {
			return ErrInvalidInput
		}
		if err := sink.requireIsolationIntentEpoch(operationCtx, intent); err != nil {
			return err
		}
		if state.EvidenceConfirmed {
			if state.EvidenceSequence != sequence {
				return ErrInvalidInput
			}
			if err := delivery.validateTerminalEvidenceCurrent(operationCtx, state); err != nil {
				resetEpoch = errors.Is(err, errIsolationStreamEpochChanged)
				return err
			}
			return nil
		}
		if state.Phase != parkedPhaseEvidencePrepared || sequence == 0 {
			return ErrInvalidInput
		}
		state.Phase = parkedPhaseEvidenceConfirmed
		state.EvidenceConfirmed = true
		state.EvidenceSequence = sequence
		value, err := json.Marshal(state)
		if err != nil || len(value) > 1024 {
			return ErrInvalidInput
		}
		if err := operationCtx.Err(); err != nil {
			return err
		}
		if _, err = delivery.consumer.stateStore.Update(key, value, entry.Revision()); err != nil {
			return err
		}
		if err := delivery.validateTerminalEvidenceCurrent(operationCtx, state); err != nil {
			resetEpoch = errors.Is(err, errIsolationStreamEpochChanged)
			return err
		}
		return nil
	})
	if resetEpoch {
		_, resetErr := sink.resetTerminalIsolationScan(ctx, intent)
		return errors.Join(err, resetErr)
	}
	return err
}

func (sink *NATSIsolationSink) Replay(payload []byte) (*nats.Msg, error) {
	if sink == nil || sink.stateStore == nil || sink.keyProvider == nil || len(payload) == 0 ||
		len(payload) > 2*DefaultMaxIngestMessageBytes {
		return nil, ErrInvalidInput
	}
	var record IsolationRecord
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil {
		return nil, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidInput
	}
	if record.SchemaVersion != IngestSchemaVersion || record.ReasonCode == "" || record.Subject == "" ||
		len(record.PayloadSHA256) != sha256HexLength || record.PayloadBytes < 0 ||
		len(record.WireSHA256) != sha256HexLength || record.WireNonce == "" || record.WireCiphertext == "" ||
		!validIsolationKeyID(record.WireKeyID) {
		return nil, ErrInvalidInput
	}
	nonce, nonceErr := base64.RawStdEncoding.DecodeString(record.WireNonce)
	ciphertext, ciphertextErr := base64.RawStdEncoding.DecodeString(record.WireCiphertext)
	operationCtx, cancel := context.WithTimeout(context.Background(), sink.operationTimeout)
	defer cancel()
	dek, dekErr := sink.loadIsolationDEK(operationCtx, record.WireKeyID)
	if dekErr != nil {
		return nil, ErrInvalidInput
	}
	defer clear(dek)
	block, blockErr := aes.NewCipher(dek)
	if nonceErr != nil || ciphertextErr != nil || blockErr != nil {
		return nil, ErrInvalidInput
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, ErrInvalidInput
	}
	wirePayload, err := aead.Open(nil, nonce, ciphertext, isolationAssociatedData(record))
	if err != nil {
		return nil, ErrInvalidInput
	}
	defer clear(wirePayload)
	digest := sha256Sum(wirePayload)
	if hex.EncodeToString(digest[:]) != record.WireSHA256 {
		return nil, ErrInvalidInput
	}
	var wire IsolationWire
	wireDecoder := json.NewDecoder(bytes.NewReader(wirePayload))
	wireDecoder.DisallowUnknownFields()
	if wireDecoder.Decode(&wire) != nil || !validIsolationWire(&wire, record) {
		return nil, ErrInvalidInput
	}
	message := nats.NewMsg(wire.Subject)
	message.Data = append([]byte(nil), wire.Payload...)
	for _, header := range wire.Headers {
		message.Header.Set(header.Name, header.Value)
	}
	if !trustedIngestAuthority(message) {
		return nil, ErrInvalidInput
	}
	return message, nil
}

const sha256HexLength = 64

func isolationMessageID(record IsolationRecord) string {
	record.Wire = nil
	encoded, _ := json.Marshal(record)
	digest := sha256Sum(append([]byte(IsolationSubject+"\x00"), encoded...))
	return "analytics-isolation-v1-" + hex.EncodeToString(digest[:])
}

func isolationRetentionMessageID(payloadDigest [sha256.Size]byte, generation uint64) string {
	encoded := IsolationSubject + "\x00retention\x00" + hex.EncodeToString(payloadDigest[:]) +
		"\x00" + strconv.FormatUint(generation, 10)
	digest := sha256Sum([]byte(encoded))
	return "analytics-isolation-v1-" + hex.EncodeToString(digest[:])
}

func decodeSHA256(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		return digest, ErrInvalidInput
	}
	copy(digest[:], decoded)
	return digest, nil
}

var isolationWireHeaderNames = [...]string{
	nats.MsgIdHdr, ingestNodeHeader, ingestTenantHeader, ingestSiteHeader, ingestConfigHeader, ingestInstallHeader,
}

type isolationWireProvider interface {
	IsolationWire() *IsolationWire
}

func validIsolationWire(wire *IsolationWire, record IsolationRecord) bool {
	if !validIsolationEvidenceWire(wire, record) || len(wire.Headers) != len(isolationWireHeaderNames) {
		return false
	}
	for index, name := range isolationWireHeaderNames {
		if wire.Headers[index].Name != name || wire.Headers[index].Value == "" ||
			strings.TrimSpace(wire.Headers[index].Value) != wire.Headers[index].Value {
			return false
		}
	}
	if wire.Headers[0].Value != record.MessageID {
		return false
	}
	message := nats.NewMsg(wire.Subject)
	message.Data = wire.Payload
	for _, header := range wire.Headers {
		message.Header.Set(header.Name, header.Value)
	}
	return trustedIngestAuthority(message)
}

func validIsolationEvidenceWire(wire *IsolationWire, record IsolationRecord) bool {
	if wire == nil || wire.Subject == "" || len(wire.Subject) > 256 || wire.Subject != record.Subject ||
		len(wire.Payload) != record.PayloadBytes || len(wire.Payload) > DefaultMaxIngestMessageBytes ||
		len(wire.Headers) > 64 {
		return false
	}
	digest := sha256Sum(wire.Payload)
	if hex.EncodeToString(digest[:]) != record.PayloadSHA256 {
		return false
	}
	totalHeaderBytes := 0
	for _, header := range wire.Headers {
		if header.Name == "" || len(header.Name) > 128 || len(header.Value) > 8<<10 {
			return false
		}
		totalHeaderBytes += len(header.Name) + len(header.Value)
	}
	return totalHeaderBytes <= 64<<10
}

func isolationAssociatedData(record IsolationRecord) []byte {
	return []byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%s\x00%s\x00%t",
		record.SchemaVersion, record.ReasonCode, record.MessageID, record.Subject, record.PayloadSHA256,
		record.PayloadBytes, record.Attempts, record.StreamSequence, record.IsolatedAt.UTC().Format(time.RFC3339Nano),
		record.WireKeyID, record.WireEvidenceOnly))
}

type wrappedIsolationDEK struct {
	SchemaVersion uint16 `json:"schema_version"`
	KeyID         string `json:"key_id"`
	WrappedDEK    string `json:"wrapped_dek"`
}

func (sink *NATSIsolationSink) loadOrCreateIsolationDEK(ctx context.Context, keyID string) ([]byte, error) {
	dek, err := sink.loadIsolationDEK(ctx, keyID)
	if err == nil {
		return dek, nil
	}
	if !errors.Is(err, nats.ErrKeyNotFound) {
		return nil, err
	}
	dek = make([]byte, isolationCipherKeySize)
	if _, err := rand.Read(dek); err != nil {
		clear(dek)
		return nil, fmt.Errorf("create analytics isolation data key")
	}
	wrapped, err := sink.keyProvider.WrapDEK(ctx, keyID, dek)
	if err != nil || len(wrapped) == 0 {
		clear(dek)
		clear(wrapped)
		return nil, fmt.Errorf("wrap analytics isolation data key")
	}
	state := wrappedIsolationDEK{
		SchemaVersion: 1, KeyID: keyID,
		WrappedDEK: base64.RawStdEncoding.EncodeToString(wrapped),
	}
	clear(wrapped)
	value, err := json.Marshal(state)
	if err != nil {
		clear(dek)
		return nil, ErrInvalidConfiguration
	}
	_, err = sink.stateStore.Create(isolationWrappedDEKKey(keyID), value)
	clear(value)
	if err == nil {
		return dek, nil
	}
	clear(dek)
	if !errors.Is(err, nats.ErrKeyExists) {
		return nil, fmt.Errorf("persist wrapped analytics isolation data key")
	}
	return sink.loadIsolationDEK(ctx, keyID)
}

func (sink *NATSIsolationSink) loadIsolationDEK(ctx context.Context, keyID string) ([]byte, error) {
	entry, err := sink.stateStore.Get(isolationWrappedDEKKey(keyID))
	if err != nil {
		return nil, err
	}
	var state wrappedIsolationDEK
	decoder := json.NewDecoder(bytes.NewReader(entry.Value()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil {
		return nil, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || state.SchemaVersion != 1 || state.KeyID != keyID {
		return nil, ErrInvalidInput
	}
	wrapped, err := base64.RawStdEncoding.DecodeString(state.WrappedDEK)
	if err != nil || len(wrapped) == 0 {
		return nil, ErrInvalidInput
	}
	dek, err := sink.keyProvider.UnwrapDEK(ctx, keyID, wrapped)
	clear(wrapped)
	if err != nil || len(dek) != isolationCipherKeySize {
		clear(dek)
		if retryableIsolationRecoveryError(err) {
			return nil, err
		}
		return nil, ErrInvalidInput
	}
	return dek, nil
}

func (sink *NATSIsolationSink) isolationKeyIDByDigest(digest string) (string, error) {
	if len(digest) != sha256HexLength {
		return "", ErrInvalidInput
	}
	entry, err := sink.stateStore.Get(isolationWrappedDEKPrefix + digest)
	if err != nil {
		return "", err
	}
	var state wrappedIsolationDEK
	decoder := json.NewDecoder(bytes.NewReader(entry.Value()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || !validIsolationKeyID(state.KeyID) || isolationWrappedDEKKey(state.KeyID) != isolationWrappedDEKPrefix+digest {
		return "", ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", ErrInvalidInput
	}
	return state.KeyID, nil
}

func isolationWrappedDEKKey(keyID string) string {
	digest := sha256Sum([]byte(keyID))
	return isolationWrappedDEKPrefix + hex.EncodeToString(digest[:])
}

func validIsolationKeyID(keyID string) bool {
	return keyID != "" && len(keyID) <= 256 && strings.TrimSpace(keyID) == keyID
}

func (sink *NATSIsolationSink) isolationStreamInfo(ctx context.Context) (*nats.StreamInfo, error) {
	if sink == nil {
		return nil, ErrInvalidConfiguration
	}
	return exactStreamInfo(ctx, sink.jetstream, &sink.expectedStream, sink.operationTimeout)
}

func exactStreamInfo(
	ctx context.Context,
	jetstream nats.JetStreamContext,
	expected *nats.StreamConfig,
	operationTimeout time.Duration,
) (*nats.StreamInfo, error) {
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	info, err := jetstream.StreamInfo(expected.Name, nats.Context(operationCtx))
	if err != nil {
		return nil, fmt.Errorf("read analytics stream %s configuration: %w", expected.Name, err)
	}
	if !sameStream(info, expected) {
		return nil, fmt.Errorf("analytics stream %s configuration does not match", expected.Name)
	}
	return info, nil
}

func ensureStream(
	ctx context.Context,
	jetstream nats.JetStreamContext,
	expected *nats.StreamConfig,
	operationTimeout time.Duration,
) error {
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	info, err := jetstream.StreamInfo(expected.Name, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrStreamNotFound) {
		operationCtx, cancel = context.WithTimeout(ctx, operationTimeout)
		info, err = jetstream.AddStream(expected, nats.Context(operationCtx))
		cancel()
		if err != nil {
			operationCtx, cancel = context.WithTimeout(ctx, operationTimeout)
			info, err = jetstream.StreamInfo(expected.Name, nats.Context(operationCtx))
			cancel()
		}
	}
	if err != nil {
		return fmt.Errorf("ensure analytics stream %s: %w", expected.Name, err)
	}
	if !sameStream(info, expected) {
		return fmt.Errorf("analytics stream %s configuration does not match", expected.Name)
	}
	return nil
}

func ensureConsumer(ctx context.Context, jetstream nats.JetStreamContext, config JetStreamConfig) error {
	expected := expectedConsumer(config)
	operationCtx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
	info, err := jetstream.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrConsumerNotFound) {
		operationCtx, cancel = context.WithTimeout(ctx, config.OperationTimeout)
		info, err = jetstream.AddConsumer(config.Stream, expected, nats.Context(operationCtx))
		cancel()
		if err != nil {
			operationCtx, cancel = context.WithTimeout(ctx, config.OperationTimeout)
			info, err = jetstream.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
			cancel()
		}
	}
	if err != nil {
		return fmt.Errorf("ensure analytics ingest consumer: %w", err)
	}
	if !sameIngestConsumer(info, expected) {
		return fmt.Errorf("analytics ingest consumer configuration does not match")
	}
	return nil
}

func expectedIngestStream(config JetStreamConfig) *nats.StreamConfig {
	return &nats.StreamConfig{
		Name: config.Stream, Subjects: []string{IngestSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy,
		MaxConsumers: 1, MaxMsgs: config.StreamMaxMessages, MaxBytes: config.StreamMaxBytes,
		Discard: nats.DiscardNew, MaxAge: config.StreamMaxAge, MaxMsgsPerSubject: -1,
		MaxMsgSize: DefaultMaxIngestMessageBytes,
		Storage:    nats.FileStorage, Replicas: config.Replicas, Duplicates: config.DuplicateWindow,
	}
}

func expectedIsolationStream(config JetStreamConfig) *nats.StreamConfig {
	return &nats.StreamConfig{
		Name: config.IsolationStream, Subjects: []string{IsolationSubject}, Retention: nats.LimitsPolicy,
		MaxConsumers: -1, MaxMsgs: config.StreamMaxMessages, MaxBytes: config.IsolationMaxBytes,
		Discard: nats.DiscardNew, MaxAge: config.IsolationMaxAge, MaxMsgsPerSubject: -1,
		MaxMsgSize: 2 * DefaultMaxIngestMessageBytes,
		Storage:    nats.FileStorage, Replicas: config.Replicas, Duplicates: config.DuplicateWindow,
	}
}

func expectedConsumer(config JetStreamConfig) *nats.ConsumerConfig {
	return &nats.ConsumerConfig{
		Durable: config.Durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		AckWait: config.AckWait, MaxDeliver: -1, FilterSubject: IngestSubjectPrefix + ".*",
		ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: config.MaxAckPending, MaxWaiting: config.MaxWaiting,
		MaxRequestBatch: config.FetchBatch, MaxRequestExpires: config.FetchTimeout,
		MaxRequestMaxBytes: config.FetchBatch * DefaultMaxIngestMessageBytes,
	}
}

func sameStream(info *nats.StreamInfo, expected *nats.StreamConfig) bool {
	if info == nil || expected == nil {
		return false
	}
	actual := info.Config
	wanted := *expected
	actual.Description, wanted.Description = "", ""
	actual.Metadata, wanted.Metadata = nil, nil
	actual.Template, wanted.Template = "", ""
	return reflect.DeepEqual(actual, wanted)
}

func sameIngestConsumer(info *nats.ConsumerInfo, expected *nats.ConsumerConfig) bool {
	if info == nil || expected == nil {
		return false
	}
	actual := info.Config
	wanted := *expected
	actual.Name, wanted.Name = "", ""
	actual.Description, wanted.Description = "", ""
	actual.Metadata, wanted.Metadata = nil, nil
	return reflect.DeepEqual(actual, wanted)
}

func validateJetStreamConfig(config JetStreamConfig) error {
	if !validNATSName(config.Stream) || !validNATSName(config.Durable) || !validNATSName(config.IsolationStream) ||
		config.Stream == config.IsolationStream || config.AckWait <= 3*config.OperationTimeout ||
		config.FetchTimeout <= 0 || config.FetchTimeout > config.AckWait || config.OperationTimeout <= 0 ||
		config.NakBaseDelay <= 0 || config.NakMaxDelay < config.NakBaseDelay || config.MaxDeliver < 2 ||
		config.FetchBatch <= 0 || config.FetchBatch > 256 || config.MaxAckPending < config.FetchBatch ||
		config.MaxWaiting <= 0 || config.StreamMaxAge != 0 || config.StreamMaxBytes < DefaultMaxIngestMessageBytes ||
		config.StreamMaxMessages <= 0 || config.IsolationMaxAge <= 0 || config.IsolationMaxBytes < DefaultMaxIngestMessageBytes ||
		config.DuplicateWindow <= 0 || config.Replicas < 1 || config.Replicas > 5 {
		return ErrInvalidConfiguration
	}
	return nil
}

func ValidateJetStreamConfig(config JetStreamConfig) error {
	return validateJetStreamConfig(config)
}

func validNATSName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func sha256Sum(payload []byte) [32]byte {
	return sha256.Sum256(payload)
}
