package l4analytics

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

const (
	L4IngestStream       = "L4_SESSIONS_INGEST_V1"
	L4IngestSubject      = "cdnca.l4.sessions.v1.*.*.*"
	L4IngestDurable      = "control_api_l4_sessions_v1"
	L4IngestMaxPayload   = 1 << 20
	L4IngestRetentionAge = 30 * 24 * time.Hour
	clickHouseDateTime64 = "2006-01-02 15:04:05.000"
)

// FactWriter writes one decoded L4 envelope: its session facts (and session
// logs) or its in-progress usage checkpoints (L4-USAGE-01).
type FactWriter interface {
	WriteEnvelope(context.Context, *agentv1.L4SessionEnvelopeV1) error
}

type NATSIngestConfig struct {
	Stream           string
	Subject          string
	Durable          string
	OperationTimeout time.Duration
}

func DefaultNATSIngestConfig() NATSIngestConfig {
	return NATSIngestConfig{Stream: L4IngestStream, Subject: L4IngestSubject, Durable: L4IngestDurable, OperationTimeout: 5 * time.Second}
}

type NATSIngestor struct {
	sub    *nats.Subscription
	writer FactWriter
	config NATSIngestConfig
}

func EnsureL4JetStream(ctx context.Context, connection *nats.Conn, config NATSIngestConfig) error {
	if ctx == nil || connection == nil || connection.IsClosed() || config.Stream == "" || config.Subject == "" || config.Durable == "" || config.OperationTimeout <= 0 {
		return ErrInvalidConfig
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return ErrDependencyUnavailable
	}
	stream, err := js.StreamInfo(config.Stream, nats.Context(ctx))
	if err != nil {
		stream, err = js.AddStream(&nats.StreamConfig{Name: config.Stream, Subjects: []string{config.Subject}, Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 5_000_000, MaxBytes: 5 << 30, Discard: nats.DiscardNew, MaxAge: L4IngestRetentionAge, MaxMsgSize: L4IngestMaxPayload, Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute}, nats.Context(ctx))
	}
	if err != nil || stream == nil || stream.Config.Name != config.Stream || len(stream.Config.Subjects) != 1 || stream.Config.Subjects[0] != config.Subject || stream.Config.Retention != nats.WorkQueuePolicy || stream.Config.Storage != nats.FileStorage || stream.Config.MaxConsumers != 1 || stream.Config.MaxMsgs != 5_000_000 || stream.Config.MaxBytes != 5<<30 || stream.Config.MaxAge != L4IngestRetentionAge || stream.Config.MaxMsgSize != L4IngestMaxPayload || stream.Config.Duplicates != 10*time.Minute {
		return ErrDependencyUnavailable
	}
	consumer, err := js.ConsumerInfo(config.Stream, config.Durable, nats.Context(ctx))
	if err != nil {
		consumer, err = js.AddConsumer(config.Stream, &nats.ConsumerConfig{Durable: config.Durable, AckPolicy: nats.AckExplicitPolicy, FilterSubject: config.Subject, MaxAckPending: 1000, AckWait: config.OperationTimeout, MaxRequestExpires: config.OperationTimeout}, nats.Context(ctx))
	}
	if err != nil || consumer == nil || consumer.Config.Durable != config.Durable || consumer.Config.FilterSubject != config.Subject || consumer.Config.AckPolicy != nats.AckExplicitPolicy || consumer.Config.AckWait != config.OperationTimeout || consumer.Config.MaxAckPending != 1000 || consumer.Config.MaxRequestExpires < config.OperationTimeout {
		return ErrDependencyUnavailable
	}
	return nil
}

func NewNATSIngestor(connection *nats.Conn, writer FactWriter, config NATSIngestConfig) (*NATSIngestor, error) {
	if connection == nil || connection.IsClosed() || writer == nil || config.Stream == "" || config.Subject == "" || config.Durable == "" || config.OperationTimeout <= 0 {
		return nil, ErrInvalidConfig
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, ErrDependencyUnavailable
	}
	sub, err := js.PullSubscribe(config.Subject, config.Durable, nats.BindStream(config.Stream))
	if err != nil {
		return nil, ErrDependencyUnavailable
	}
	return &NATSIngestor{sub: sub, writer: writer, config: config}, nil
}

func (ingestor *NATSIngestor) Run(ctx context.Context) error {
	if ingestor == nil || ingestor.sub == nil || ingestor.writer == nil || ctx == nil {
		return ErrInvalidConfig
	}
	for {
		fetchCtx, cancel := context.WithTimeout(ctx, ingestor.config.OperationTimeout)
		messages, err := ingestor.sub.Fetch(32, nats.Context(fetchCtx))
		cancel()
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("fetch L4 analytics batch: %w (%v)", ErrDependencyUnavailable, err)
		}
		for _, message := range messages {
			envelope, err := decodeL4Envelope(message)
			if err != nil {
				_ = message.Term()
				continue
			}
			if err := ingestor.writer.WriteEnvelope(ctx, envelope); err != nil {
				_ = message.Nak()
				return fmt.Errorf("write L4 analytics facts: %w", err)
			}
			if err := message.Ack(); err != nil {
				return fmt.Errorf("acknowledge L4 analytics batch: %w", ErrDependencyUnavailable)
			}
		}
	}
}

func (ingestor *NATSIngestor) Close() error {
	if ingestor == nil || ingestor.sub == nil {
		return nil
	}
	return ingestor.sub.Unsubscribe()
}

func decodeL4Envelope(message *nats.Msg) (*agentv1.L4SessionEnvelopeV1, error) {
	if message == nil || !strings.HasPrefix(message.Subject, "cdnca.l4.sessions.v1.") || len(message.Data) == 0 || len(message.Data) > L4IngestMaxPayload {
		return nil, ErrInvalidRequest
	}
	subjectParts := strings.Split(message.Subject, ".")
	if len(subjectParts) != 7 || !canonicalUUID(subjectParts[4]) || !canonicalUUID(subjectParts[5]) || !canonicalUUID(subjectParts[6]) {
		return nil, ErrInvalidRequest
	}
	var envelope agentv1.L4SessionEnvelopeV1
	if proto.Unmarshal(message.Data, &envelope) != nil || len(envelope.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrInvalidRequest
	}
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&envelope)
	if err != nil || !bytes.Equal(canonical, message.Data) || envelope.GetNodeId() != subjectParts[6] || envelope.GetTenantId() != subjectParts[4] || envelope.GetSiteId() != subjectParts[5] {
		return nil, ErrInvalidRequest
	}
	if err := validL4EnvelopeContents(&envelope); err != nil {
		return nil, err
	}
	return &envelope, nil
}

// validL4EnvelopeContents: one envelope carries session events or usage
// checkpoints (L4-USAGE-01), each of the envelope's tenant, node, site and
// configuration with valid times.
func validL4EnvelopeContents(envelope *agentv1.L4SessionEnvelopeV1) error {
	if envelope.GetSchemaVersion() != 1 || envelope.GetMessageId() == "" || envelope.GetSourceWatermark() == 0 ||
		(len(envelope.GetEvents()) == 0) == (len(envelope.GetCheckpoints()) == 0) ||
		!canonicalUUID(envelope.GetConfigVersionId()) || envelope.GetProducedAt() == nil || envelope.GetFinalizedThrough() == nil ||
		envelope.GetProducedAt().CheckValid() != nil || envelope.GetFinalizedThrough().CheckValid() != nil ||
		envelope.GetFinalizedThrough().AsTime().After(envelope.GetProducedAt().AsTime()) {
		return ErrInvalidRequest
	}
	for _, event := range envelope.GetEvents() {
		if event == nil || event.GetEvent() == nil || event.GetStartedAt() == nil || event.GetFinalizedAt() == nil ||
			event.GetTenantId() != envelope.GetTenantId() || event.GetNodeId() != envelope.GetNodeId() || event.GetSiteId() != envelope.GetSiteId() ||
			event.GetConfigVersionId() != envelope.GetConfigVersionId() || event.GetStartedAt().CheckValid() != nil || event.GetFinalizedAt().CheckValid() != nil {
			return ErrInvalidRequest
		}
	}
	for _, checkpoint := range envelope.GetCheckpoints() {
		if checkpoint == nil || checkpoint.GetEvent() == nil || checkpoint.GetStartedAt() == nil || checkpoint.GetCheckpointAt() == nil ||
			checkpoint.GetTenantId() != envelope.GetTenantId() || checkpoint.GetNodeId() != envelope.GetNodeId() ||
			checkpoint.GetSiteId() != envelope.GetSiteId() || checkpoint.GetConfigVersionId() != envelope.GetConfigVersionId() ||
			checkpoint.GetStartedAt().CheckValid() != nil || checkpoint.GetCheckpointAt().CheckValid() != nil || checkpoint.GetSequence() == 0 {
			return ErrInvalidRequest
		}
	}
	return nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

type ClickHouseFactWriter struct {
	source *ClickHouseSource
	// sessionLogs: l4_session_logs_v1 exists (NewClickHouseFactWriterWithSessionLogs).
	sessionLogs bool
}

func NewClickHouseFactWriter(source *ClickHouseSource) (*ClickHouseFactWriter, error) {
	if source == nil {
		return nil, ErrInvalidConfig
	}
	return &ClickHouseFactWriter{source: source}, nil
}

type l4FactInsertRow struct {
	TenantID    string `json:"tenant_id"`
	NodeID      string `json:"node_id"`
	SiteID      string `json:"site_id"`
	StreamID    string `json:"stream_id"`
	ListenerID  string `json:"listener_id"`
	SessionID   string `json:"session_id"`
	StartedAt   string `json:"started_at"`
	FinalizedAt string `json:"finalized_at"`
	BytesUp     uint64 `json:"bytes_up"`
	BytesDown   uint64 `json:"bytes_down"`
	// CheckpointedBytesUp/Down (CH 029, L4-USAGE-01): the bytes the session's
	// in-progress checkpoints billed; the fact bills the rest.
	CheckpointedBytesUp   uint64 `json:"checkpointed_bytes_up"`
	CheckpointedBytesDown uint64 `json:"checkpointed_bytes_down"`
	StatusCode            uint32 `json:"status_code"`
	ErrorCode             string `json:"error_code"`
	ConfigVersionID       string `json:"config_version_id"`
	ConfigRevision        uint64 `json:"config_revision"`
	Protocol              string `json:"protocol"`
	ListenPort            uint32 `json:"listen_port"`
	EventID               string `json:"event_id"`
	Traceparent           string `json:"traceparent"`
	TaskID                string `json:"task_id"`
	SourceWatermark       uint64 `json:"source_watermark"`
	EvidenceSHA256        string `json:"evidence_sha256"`
	CanonicalEventSHA256  string `json:"canonical_event_sha256"`
	// PackageSubscriptionID (CH 027): the forward's package when the session
	// ran; the nil UUID for a forward without a package.
	PackageSubscriptionID string `json:"package_subscription_id"`
}

func (writer *ClickHouseFactWriter) Write(ctx context.Context, events []*agentv1.L4SessionEventV1, watermark uint64) error {
	if writer == nil || writer.source == nil || len(events) == 0 || watermark == 0 {
		return ErrInvalidRequest
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, event := range events {
		if event == nil || event.GetEvent() == nil || event.GetStartedAt() == nil || event.GetFinalizedAt() == nil {
			return ErrInvalidRequest
		}
		row := l4FactInsertRow{TenantID: event.GetTenantId(), NodeID: event.GetNodeId(), SiteID: event.GetSiteId(), StreamID: event.GetStreamId(), ListenerID: event.GetListenerId(), SessionID: event.GetSessionId(), StartedAt: event.GetStartedAt().AsTime().UTC().Format(clickHouseDateTime64), FinalizedAt: event.GetFinalizedAt().AsTime().UTC().Format(clickHouseDateTime64), BytesUp: event.GetBytesUp(), BytesDown: event.GetBytesDown(), StatusCode: event.GetStatusCode(), ErrorCode: event.GetErrorCode(), ConfigVersionID: event.GetConfigVersionId(), ConfigRevision: event.GetConfigRevision(), Protocol: event.GetProtocol(), ListenPort: event.GetListenPort(), EventID: event.GetEvent().GetEventId(), Traceparent: event.GetEvent().GetTraceparent(), SourceWatermark: watermark, EvidenceSHA256: hex.EncodeToString(event.GetEvidenceSha256()), CanonicalEventSHA256: hex.EncodeToString(event.GetCanonicalEventSha256())}
		row.TaskID = event.GetEvent().GetTaskId()
		row.CheckpointedBytesUp, row.CheckpointedBytesDown = event.GetCheckpointedBytesUp(), event.GetCheckpointedBytesDown()
		row.PackageSubscriptionID = event.GetPackageSubscriptionId()
		if row.PackageSubscriptionID == "" {
			row.PackageSubscriptionID = "00000000-0000-0000-0000-000000000000"
		}
		if err := encoder.Encode(row); err != nil {
			return ErrInvalidRequest
		}
	}
	if err := writer.source.insertRows(ctx, "l4_session_facts_v1", body.Bytes()); err != nil {
		return err
	}
	// Facts first: a redelivery after a failed log insert replaces them.
	return writer.writeSessionLogs(ctx, events, watermark)
}

// WriteEnvelope writes an envelope's session facts or usage checkpoints.
func (writer *ClickHouseFactWriter) WriteEnvelope(ctx context.Context, envelope *agentv1.L4SessionEnvelopeV1) error {
	if envelope == nil || (len(envelope.GetEvents()) == 0) == (len(envelope.GetCheckpoints()) == 0) {
		return ErrInvalidRequest
	}
	if len(envelope.GetCheckpoints()) != 0 {
		return writer.writeCheckpoints(ctx, envelope.GetCheckpoints(), envelope.GetSourceWatermark())
	}
	return writer.Write(ctx, envelope.GetEvents(), envelope.GetSourceWatermark())
}

// usageCheckpointTable (CH 029): ReplacingMergeTree by (tenant, node,
// listener, session, started, sequence), billed at checkpoint_at.
const usageCheckpointTable = "l4_usage_checkpoints_v1"

type l4CheckpointInsertRow struct {
	TenantID              string `json:"tenant_id"`
	NodeID                string `json:"node_id"`
	SiteID                string `json:"site_id"`
	StreamID              string `json:"stream_id"`
	PackageSubscriptionID string `json:"package_subscription_id"`
	ListenerID            string `json:"listener_id"`
	SessionID             string `json:"session_id"`
	StartedAt             string `json:"started_at"`
	CheckpointAt          string `json:"checkpoint_at"`
	Sequence              uint32 `json:"sequence"`
	BytesUp               uint64 `json:"bytes_up"`
	BytesDown             uint64 `json:"bytes_down"`
	ConfigVersionID       string `json:"config_version_id"`
	ConfigRevision        uint64 `json:"config_revision"`
	Protocol              string `json:"protocol"`
	ListenPort            uint32 `json:"listen_port"`
	EventID               string `json:"event_id"`
	SourceWatermark       uint64 `json:"source_watermark"`
}

func (writer *ClickHouseFactWriter) writeCheckpoints(ctx context.Context, checkpoints []*agentv1.L4UsageCheckpointV1, watermark uint64) error {
	if writer == nil || writer.source == nil || watermark == 0 {
		return ErrInvalidRequest
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, checkpoint := range checkpoints {
		if checkpoint == nil || checkpoint.GetEvent() == nil || checkpoint.GetStartedAt() == nil || checkpoint.GetCheckpointAt() == nil {
			return ErrInvalidRequest
		}
		row := l4CheckpointInsertRow{TenantID: checkpoint.GetTenantId(), NodeID: checkpoint.GetNodeId(), SiteID: checkpoint.GetSiteId(),
			StreamID: checkpoint.GetStreamId(), PackageSubscriptionID: checkpoint.GetPackageSubscriptionId(),
			ListenerID: checkpoint.GetListenerId(), SessionID: checkpoint.GetSessionId(),
			StartedAt:    checkpoint.GetStartedAt().AsTime().UTC().Format(clickHouseDateTime64),
			CheckpointAt: checkpoint.GetCheckpointAt().AsTime().UTC().Format(clickHouseDateTime64), Sequence: checkpoint.GetSequence(),
			BytesUp: checkpoint.GetBytesUp(), BytesDown: checkpoint.GetBytesDown(), ConfigVersionID: checkpoint.GetConfigVersionId(),
			ConfigRevision: checkpoint.GetConfigRevision(), Protocol: checkpoint.GetProtocol(), ListenPort: checkpoint.GetListenPort(),
			EventID: checkpoint.GetEvent().GetEventId(), SourceWatermark: watermark}
		if row.PackageSubscriptionID == "" {
			row.PackageSubscriptionID = "00000000-0000-0000-0000-000000000000"
		}
		if err := encoder.Encode(row); err != nil {
			return ErrInvalidRequest
		}
	}
	return writer.source.insertRows(ctx, usageCheckpointTable, body.Bytes())
}

func (source *ClickHouseSource) insertRows(ctx context.Context, table string, body []byte) error {
	operationCtx, cancel := context.WithTimeout(ctx, source.timeout)
	defer cancel()
	endpoint := *source.endpoint
	values := endpoint.Query()
	values.Set("database", source.database)
	values.Set("query", "INSERT INTO "+table+" FORMAT JSONEachRow")
	endpoint.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(operationCtx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return ErrDependencyUnavailable
	}
	request.Header.Set("Content-Type", "application/x-ndjson")
	if source.username != "" {
		request.SetBasicAuth(source.username, source.password)
	}
	response, err := source.httpClient.Do(request)
	if err != nil {
		return ErrDependencyUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return ErrDependencyUnavailable
	}
	return nil
}

var _ FactWriter = (*ClickHouseFactWriter)(nil)
