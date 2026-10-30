package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

const (
	telemetryNodeHeader               = "Cdnca-Node-Id"
	telemetryTenantHeader             = "Cdnca-Tenant-Id"
	telemetrySiteHeader               = "Cdnca-Site-Id"
	telemetryConfigHeader             = "Cdnca-Config-Version-Id"
	telemetryInstallationHeader       = "Cdnca-Installation-Id"
	connectionsBatchHeader            = "Cdnca-Connections-Batch-Id"
	connectionsSchemaHeader           = "Cdnca-Connections-Schema-Version"
	connectionsReceiptHeader          = "Cdnca-Connections-Receipt-Id"
	connectionsSubscriptionHeader     = "Cdnca-Connections-Subscription-Id"
	connectionsPayloadDigestHeader    = "Cdnca-Connections-Payload-SHA256"
	connectionsCanonicalDigestHeader  = "Cdnca-Connections-Canonical-SHA256"
	connectionsEvidenceDigestHeader   = "Cdnca-Connections-Evidence-SHA256"
	connectionsWatermarkHeader        = "Cdnca-Connections-Source-Watermark"
	connectionsFinalizedThroughHeader = "Cdnca-Connections-Finalized-Through"
	connectionsDomainHeader           = "Cdnca-Connections-Domain"
	connectionsListenPortHeader       = "Cdnca-Connections-Listen-Port"
)

type TelemetryPublication struct {
	Kind            agentv1.TelemetryKind
	NodeID          string
	TenantID        string
	SiteID          string
	ConfigVersionID string
	InstallationID  string
	BatchID         string
	MessageID       string
	Domain          string
	ListenPort      uint32
	Payload         []byte
}

type TelemetryPublishResult struct {
	Stream    string
	Sequence  uint64
	Duplicate bool
}

type TelemetryPublisher interface {
	Publish(context.Context, TelemetryPublication) (TelemetryPublishResult, error)
	Check(context.Context) error
}

type NATSTelemetryPublisherConfig struct {
	Stream               string
	CCCoordinationStream string
	ConnectionsStream    string
	L4Stream             string
	OperationTimeout     time.Duration
}

func DefaultNATSTelemetryPublisherConfig() NATSTelemetryPublisherConfig {
	return NATSTelemetryPublisherConfig{
		Stream: TelemetryIngestStream, CCCoordinationStream: CCCoordinationStream,
		ConnectionsStream: ConnectionsTelemetryIngestStream,
		L4Stream:          L4TelemetryIngestStream,
		OperationTimeout:  5 * time.Second,
	}
}

func (c NATSTelemetryPublisherConfig) validate() error {
	if !validNATSName(c.Stream) || !validNATSName(c.CCCoordinationStream) || !validNATSName(c.ConnectionsStream) || !validNATSName(c.L4Stream) ||
		c.Stream == c.CCCoordinationStream || c.Stream == c.ConnectionsStream ||
		c.Stream == c.L4Stream || c.CCCoordinationStream == c.ConnectionsStream ||
		c.CCCoordinationStream == c.L4Stream || c.ConnectionsStream == c.L4Stream || c.OperationTimeout <= 0 {
		return fmt.Errorf("telemetry JetStream configuration is invalid")
	}
	return nil
}

type telemetryJetStream interface {
	PublishMsg(*nats.Msg, ...nats.PubOpt) (*nats.PubAck, error)
	StreamInfo(string, ...nats.JSOpt) (*nats.StreamInfo, error)
}

type NATSTelemetryPublisher struct {
	js            telemetryJetStream
	cccoordJS     telemetryJetStream
	connectionsJS telemetryJetStream
	l4JS          telemetryJetStream
	config        NATSTelemetryPublisherConfig
}

func NewNATSTelemetryPublisher(connection *nats.Conn, config NATSTelemetryPublisherConfig) (*NATSTelemetryPublisher, error) {
	if connection == nil || connection.IsClosed() {
		return nil, fmt.Errorf("an active NATS connection is required")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create telemetry JetStream context: %w", err)
	}
	return &NATSTelemetryPublisher{js: js, cccoordJS: js, connectionsJS: js, l4JS: js, config: config}, nil
}

func (p *NATSTelemetryPublisher) Publish(ctx context.Context, publication TelemetryPublication) (TelemetryPublishResult, error) {
	if publication.Kind == agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1 {
		return p.publishL4(ctx, publication)
	}
	if p == nil || p.js == nil || ctx == nil || !canonicalUUID(publication.NodeID) ||
		!canonicalUUID(publication.TenantID) || !canonicalUUID(publication.SiteID) ||
		!canonicalUUID(publication.ConfigVersionID) || !validTelemetryID(publication.InstallationID) ||
		!validTelemetryID(publication.MessageID) || len(publication.Payload) == 0 {
		return TelemetryPublishResult{}, fmt.Errorf("telemetry publication is invalid")
	}
	message := nats.NewMsg(TelemetryIngestSubjectPrefix + "." + publication.NodeID)
	message.Data = publication.Payload
	message.Header.Set(nats.MsgIdHdr, publication.MessageID)
	message.Header.Set(telemetryNodeHeader, publication.NodeID)
	message.Header.Set(telemetryTenantHeader, publication.TenantID)
	message.Header.Set(telemetrySiteHeader, publication.SiteID)
	message.Header.Set(telemetryConfigHeader, publication.ConfigVersionID)
	message.Header.Set(telemetryInstallationHeader, publication.InstallationID)
	operationCtx, cancel := context.WithTimeout(ctx, p.config.OperationTimeout)
	defer cancel()
	ack, err := p.js.PublishMsg(message, nats.Context(operationCtx))
	if err != nil {
		return TelemetryPublishResult{}, fmt.Errorf("publish telemetry record")
	}
	if ack == nil || ack.Stream != p.config.Stream || ack.Sequence == 0 {
		return TelemetryPublishResult{}, fmt.Errorf("telemetry JetStream acknowledgement is invalid")
	}
	coordination, publishCoordination, err := buildCCCoordinationMessage(publication, time.Now().UTC())
	if err != nil {
		return TelemetryPublishResult{}, err
	}
	if publishCoordination {
		if p.cccoordJS == nil {
			return TelemetryPublishResult{}, fmt.Errorf("CC coordination publisher is unavailable")
		}
		coordinationAck, publishErr := p.cccoordJS.PublishMsg(coordination, nats.Context(operationCtx))
		if publishErr != nil {
			return TelemetryPublishResult{}, fmt.Errorf("publish CC coordination record")
		}
		if coordinationAck == nil || coordinationAck.Stream != p.config.CCCoordinationStream || coordinationAck.Sequence == 0 {
			return TelemetryPublishResult{}, fmt.Errorf("CC coordination JetStream acknowledgement is invalid")
		}
	}
	return TelemetryPublishResult{Stream: ack.Stream, Sequence: ack.Sequence, Duplicate: ack.Duplicate}, nil
}

func (p *NATSTelemetryPublisher) publishL4(ctx context.Context, publication TelemetryPublication) (TelemetryPublishResult, error) {
	if p == nil || p.l4JS == nil || ctx == nil || !canonicalUUID(publication.NodeID) ||
		!canonicalUUID(publication.TenantID) || !canonicalUUID(publication.SiteID) ||
		!canonicalUUID(publication.ConfigVersionID) || !validTelemetryID(publication.InstallationID) ||
		!validTelemetryID(publication.MessageID) || publication.BatchID != "" ||
		len(publication.Payload) == 0 || len(publication.Payload) > L4TelemetryMaxPayloadBytes {
		return TelemetryPublishResult{}, fmt.Errorf("L4 telemetry publication is invalid")
	}
	var envelope agentv1.L4SessionEnvelopeV1
	if err := proto.Unmarshal(publication.Payload, &envelope); err != nil || cacheControlMessageHasUnknown(envelope.ProtoReflect()) {
		return TelemetryPublishResult{}, fmt.Errorf("L4 telemetry publication is invalid")
	}
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&envelope)
	if err != nil || !bytes.Equal(canonical, publication.Payload) || envelope.GetMessageId() != publication.MessageID ||
		envelope.GetNodeId() != publication.NodeID || envelope.GetTenantId() != publication.TenantID ||
		envelope.GetSiteId() != publication.SiteID || envelope.GetConfigVersionId() != publication.ConfigVersionID {
		return TelemetryPublishResult{}, fmt.Errorf("L4 telemetry publication is not canonical")
	}
	message := nats.NewMsg(L4TelemetrySubjectPrefix + "." + publication.TenantID + "." + publication.SiteID + "." + publication.NodeID)
	message.Data = append([]byte(nil), publication.Payload...)
	message.Header.Set(nats.MsgIdHdr, publication.MessageID)
	message.Header.Set(telemetryNodeHeader, publication.NodeID)
	message.Header.Set(telemetryTenantHeader, publication.TenantID)
	message.Header.Set(telemetrySiteHeader, publication.SiteID)
	message.Header.Set(telemetryConfigHeader, publication.ConfigVersionID)
	message.Header.Set(telemetryInstallationHeader, publication.InstallationID)
	operationCtx, cancel := context.WithTimeout(ctx, p.config.OperationTimeout)
	defer cancel()
	ack, err := p.l4JS.PublishMsg(message, nats.Context(operationCtx))
	if err != nil {
		return TelemetryPublishResult{}, fmt.Errorf("publish L4 telemetry record")
	}
	if ack == nil || ack.Stream != p.config.L4Stream || ack.Sequence == 0 {
		return TelemetryPublishResult{}, fmt.Errorf("L4 telemetry JetStream acknowledgement is invalid")
	}
	return TelemetryPublishResult{Stream: ack.Stream, Sequence: ack.Sequence, Duplicate: ack.Duplicate}, nil
}

type ccCoordinationEnvelopeV1 struct {
	SchemaVersion   uint16                  `json:"schema_version"`
	Type            string                  `json:"type"`
	MessageID       string                  `json:"message_id"`
	ProducedAt      time.Time               `json:"produced_at"`
	TenantID        string                  `json:"tenant_id"`
	SiteID          string                  `json:"site_id"`
	NodeID          string                  `json:"node_id"`
	ConfigVersionID string                  `json:"config_version_id"`
	Events          []ccCoordinationEventV1 `json:"events"`
}

type ccCoordinationEventV1 struct {
	EventID      string    `json:"event_id"`
	OccurredAt   time.Time `json:"occurred_at"`
	RuleID       string    `json:"rule_id"`
	ClientIP     string    `json:"client_ip"`
	Host         string    `json:"host"`
	Path         string    `json:"path"`
	Method       string    `json:"method"`
	ListenPort   uint16    `json:"listen_port"`
	Protocol     string    `json:"protocol"`
	RequestClass string    `json:"request_class"`
	Action       string    `json:"action"`
	StatusCode   uint16    `json:"status_code"`
}

func buildCCCoordinationMessage(publication TelemetryPublication, now time.Time) (*nats.Msg, bool, error) {
	if !canonicalUUID(publication.NodeID) || !canonicalUUID(publication.TenantID) ||
		!canonicalUUID(publication.SiteID) || !canonicalUUID(publication.ConfigVersionID) ||
		!validTelemetryID(publication.InstallationID) || !validTelemetryID(publication.MessageID) ||
		len(publication.Payload) == 0 || now.IsZero() || validateTelemetryUniqueJSONKeys(publication.Payload) != nil {
		return nil, false, fmt.Errorf("CC coordination publication is invalid")
	}
	var kind struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(publication.Payload, &kind); err != nil {
		return nil, false, fmt.Errorf("decode telemetry publication kind")
	}
	if kind.Type != "security.v1" {
		return nil, false, nil
	}
	var source telemetrySecurityEnvelope
	if err := decodeStrictTelemetryJSON(publication.Payload, &source); err != nil ||
		source.SchemaVersion != telemetrySchemaVersion || source.Type != "security.v1" ||
		source.MessageID != publication.MessageID || source.TenantID != publication.TenantID ||
		source.NodeID != publication.NodeID || source.ProducedAt.IsZero() {
		return nil, false, fmt.Errorf("CC coordination security envelope is invalid")
	}
	events := make([]ccCoordinationEventV1, 0, len(source.Events))
	for _, event := range source.Events {
		if event.EventType != "cc" {
			continue
		}
		address, err := netip.ParseAddr(event.ClientIP)
		if err != nil || event.TenantID != publication.TenantID || event.SiteID != publication.SiteID ||
			event.NodeID != publication.NodeID || event.ConfigVersion != publication.ConfigVersionID ||
			!canonicalUUID(event.RuleID) || !validTelemetryID(event.EventID) || event.OccurredAt.IsZero() ||
			!telemetryRequired(event.Host, 253) || !telemetryRequired(event.Path, 4096) ||
			!telemetryRequired(event.Method, 32) || event.ListenPort == 0 ||
			(event.Protocol != "http" && event.Protocol != "https") || !validTelemetryRequestClass(event.RequestClass) ||
			!telemetryRequired(event.Action, 64) || event.StatusCode == 0 {
			return nil, false, fmt.Errorf("CC coordination event is invalid")
		}
		if event.RequestClass != "standard" {
			continue
		}
		events = append(events, ccCoordinationEventV1{
			EventID: event.EventID, OccurredAt: event.OccurredAt.UTC(), RuleID: event.RuleID,
			ClientIP: address.Unmap().String(), Host: event.Host, Path: event.Path, Method: event.Method,
			ListenPort: event.ListenPort, Protocol: event.Protocol, RequestClass: event.RequestClass,
			Action: event.Action, StatusCode: event.StatusCode,
		})
	}
	if len(events) == 0 {
		return nil, false, nil
	}
	envelope := ccCoordinationEnvelopeV1{
		SchemaVersion: 1, Type: "security.cccoord.v1", MessageID: publication.MessageID,
		ProducedAt: source.ProducedAt.UTC(), TenantID: publication.TenantID, SiteID: publication.SiteID,
		NodeID: publication.NodeID, ConfigVersionID: publication.ConfigVersionID, Events: events,
	}
	payload, err := json.Marshal(envelope)
	if err != nil || len(payload) == 0 || len(payload) > 1<<20 {
		return nil, false, fmt.Errorf("encode CC coordination envelope")
	}
	message := nats.NewMsg(CCCoordinationSubjectPrefix + "." + publication.TenantID + "." + publication.SiteID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, publication.MessageID)
	message.Header.Set(telemetryNodeHeader, publication.NodeID)
	message.Header.Set(telemetryTenantHeader, publication.TenantID)
	message.Header.Set(telemetrySiteHeader, publication.SiteID)
	message.Header.Set(telemetryConfigHeader, publication.ConfigVersionID)
	message.Header.Set(telemetryInstallationHeader, publication.InstallationID)
	return message, true, nil
}

func (p *NATSTelemetryPublisher) PublishConnections(ctx context.Context, publication TelemetryPublication) (TelemetryPublishResult, error) {
	if p == nil || p.connectionsJS == nil || ctx == nil {
		return TelemetryPublishResult{}, fmt.Errorf("connections telemetry publisher is unavailable")
	}
	envelope, payload, err := decodeConnectionsTelemetryPublication(publication)
	if err != nil {
		return TelemetryPublishResult{}, err
	}
	payloadDigest := sha256.Sum256(payload)
	receiptID := publication.MessageID
	subject := ConnectionsTelemetrySubjectPrefix + "." + envelope.GetInstallationId() + "." + receiptID
	message := nats.NewMsg(subject)
	message.Data = append([]byte(nil), payload...)
	message.Header.Set(nats.MsgIdHdr, receiptID+":"+hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(connectionsBatchHeader, publication.BatchID)
	message.Header.Set(connectionsSchemaHeader, strconv.FormatUint(uint64(envelope.GetSchemaVersion()), 10))
	message.Header.Set(connectionsReceiptHeader, receiptID)
	message.Header.Set(telemetryTenantHeader, envelope.GetTenantId())
	message.Header.Set(telemetryNodeHeader, envelope.GetNodeId())
	message.Header.Set(telemetryInstallationHeader, envelope.GetInstallationId())
	message.Header.Set(telemetrySiteHeader, envelope.GetSiteId())
	message.Header.Set(connectionsDomainHeader, envelope.GetDomain())
	message.Header.Set(connectionsListenPortHeader, strconv.FormatUint(uint64(envelope.GetListenPort()), 10))
	message.Header.Set(connectionsSubscriptionHeader, envelope.GetPackageSubscriptionId())
	message.Header.Set(connectionsPayloadDigestHeader, hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(connectionsCanonicalDigestHeader, hex.EncodeToString(envelope.GetCanonicalEventSha256()))
	message.Header.Set(connectionsEvidenceDigestHeader, hex.EncodeToString(envelope.GetEvidenceSha256()))
	message.Header.Set(connectionsWatermarkHeader, strconv.FormatUint(envelope.GetSourceWatermark(), 10))
	message.Header.Set(connectionsFinalizedThroughHeader, envelope.GetFinalizedThrough().AsTime().UTC().Format(time.RFC3339Nano))
	// A receipt gets one subject. The first publish wins; a changed payload cannot
	// overwrite it even after the JetStream message-id dedupe window expires.
	message.Header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	operationCtx, cancel := context.WithTimeout(ctx, p.config.OperationTimeout)
	defer cancel()
	ack, err := p.connectionsJS.PublishMsg(message, nats.Context(operationCtx))
	if err != nil {
		return TelemetryPublishResult{}, fmt.Errorf("publish connections telemetry record")
	}
	if ack == nil || ack.Stream != p.config.ConnectionsStream || ack.Sequence == 0 {
		return TelemetryPublishResult{}, fmt.Errorf("connections telemetry JetStream acknowledgement is invalid")
	}
	return TelemetryPublishResult{Stream: ack.Stream, Sequence: ack.Sequence, Duplicate: ack.Duplicate}, nil
}

func (p *NATSTelemetryPublisher) ConnectionsStream() string {
	if p == nil {
		return ""
	}
	return p.config.ConnectionsStream
}

func decodeConnectionsTelemetryPublication(publication TelemetryPublication) (*agentv1.ConnectionsMetricEnvelopeV1, []byte, error) {
	if !canonicalUUID(publication.NodeID) || !canonicalUUID(publication.TenantID) || !canonicalUUID(publication.SiteID) ||
		!validTelemetryID(publication.InstallationID) || !validTelemetryID(publication.BatchID) ||
		!validConnectionsReceiptID(publication.MessageID) ||
		publication.ConfigVersionID != "" || len(publication.Payload) == 0 || len(publication.Payload) > ConnectionsTelemetryMaxPayloadBytes {
		return nil, nil, fmt.Errorf("connections telemetry publication is invalid")
	}
	var envelope agentv1.ConnectionsMetricEnvelopeV1
	if err := proto.Unmarshal(publication.Payload, &envelope); err != nil || cacheControlMessageHasUnknown(envelope.ProtoReflect()) {
		return nil, nil, fmt.Errorf("connections telemetry publication is invalid")
	}
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&envelope)
	if err != nil || !bytes.Equal(canonical, publication.Payload) {
		return nil, nil, fmt.Errorf("connections telemetry publication is not canonical")
	}
	if envelope.GetTenantId() != publication.TenantID || envelope.GetInstallationId() != publication.InstallationID ||
		envelope.GetSiteId() != publication.SiteID || envelope.GetNodeId() != publication.NodeID ||
		envelope.GetDomain() != publication.Domain || envelope.GetListenPort() != publication.ListenPort ||
		publication.MessageID != connectionsTelemetryReceiptID(&envelope) ||
		(envelope.GetSchemaVersion() != 1 && envelope.GetSchemaVersion() != 2) ||
		!canonicalUUID(envelope.GetNodeId()) || !validTelemetryID(envelope.GetDomain()) || envelope.GetListenPort() == 0 || envelope.GetListenPort() > 65535 ||
		envelope.GetDependencyState() != agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY ||
		envelope.GetEvent() == nil || !validTelemetryID(envelope.GetEvent().GetEventId()) ||
		(envelope.GetSchemaVersion() == 1 && (envelope.GetConnections() == 0 || envelope.GetConfigVersionId() != "")) ||
		(envelope.GetSchemaVersion() == 2 && !canonicalUUID(envelope.GetConfigVersionId())) ||
		!validConnectionsDigest(envelope.GetCanonicalEventSha256()) || !validConnectionsDigest(envelope.GetEvidenceSha256()) ||
		envelope.GetSourceWatermark() == 0 || envelope.GetFinalizedThrough() == nil || envelope.GetFinalizedThrough().CheckValid() != nil ||
		envelope.GetEvent().GetOccurredTime() == nil || envelope.GetEvent().GetOccurredTime().CheckValid() != nil ||
		envelope.GetFinalizedThrough().AsTime().Before(envelope.GetEvent().GetOccurredTime().AsTime()) {
		return nil, nil, fmt.Errorf("connections telemetry publication is invalid")
	}
	return &envelope, canonical, nil
}

func (p *NATSTelemetryPublisher) Check(ctx context.Context) error {
	if p == nil || p.js == nil || p.cccoordJS == nil || p.connectionsJS == nil || p.l4JS == nil || ctx == nil {
		return fmt.Errorf("telemetry publisher is unavailable")
	}
	operationCtx, cancel := context.WithTimeout(ctx, p.config.OperationTimeout)
	defer cancel()
	info, err := p.js.StreamInfo(p.config.Stream, nats.Context(operationCtx))
	if err != nil || !validTelemetryStreamInfo(info) {
		return fmt.Errorf("telemetry stream is unavailable")
	}
	coordination, err := p.cccoordJS.StreamInfo(p.config.CCCoordinationStream, nats.Context(operationCtx))
	if err != nil || !validCCCoordinationStreamInfo(coordination) {
		return fmt.Errorf("CC coordination stream is unavailable")
	}
	connections, err := p.connectionsJS.StreamInfo(p.config.ConnectionsStream, nats.Context(operationCtx))
	if err != nil || !validConnectionsTelemetryStreamInfo(connections) {
		return fmt.Errorf("connections telemetry stream is unavailable")
	}
	l4, err := p.l4JS.StreamInfo(p.config.L4Stream, nats.Context(operationCtx))
	if err != nil || !validL4TelemetryStreamInfo(l4) {
		return fmt.Errorf("L4 telemetry stream is unavailable")
	}
	return nil
}

func validL4TelemetryStreamInfo(info *nats.StreamInfo) bool {
	if info == nil || !validNATSName(info.Config.Name) {
		return false
	}
	actual := info.Config
	expected := nats.StreamConfig{
		Name: actual.Name, Subjects: []string{L4TelemetrySubjectPrefix + ".*.*.*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 5_000_000, MaxBytes: 5 << 30,
		Discard: nats.DiscardNew, MaxAge: 30 * 24 * time.Hour, MaxMsgsPerSubject: -1, MaxMsgSize: L4TelemetryMaxPayloadBytes,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}
	actual.Description, expected.Description = "", ""
	actual.Metadata, expected.Metadata = nil, nil
	actual.Template, expected.Template = "", ""
	return reflect.DeepEqual(actual, expected)
}

func validTelemetryStreamInfo(info *nats.StreamInfo) bool {
	if info == nil || !validNATSName(info.Config.Name) {
		return false
	}
	actual := info.Config
	expected := nats.StreamConfig{
		Name: actual.Name, Subjects: []string{TelemetryIngestSubjectPrefix + ".*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 10_000_000, MaxBytes: 10 << 30,
		Discard: nats.DiscardNew, MaxAge: 0, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}
	actual.Description, expected.Description = "", ""
	actual.Metadata, expected.Metadata = nil, nil
	actual.Template, expected.Template = "", ""
	return reflect.DeepEqual(actual, expected)
}

func validCCCoordinationStreamInfo(info *nats.StreamInfo) bool {
	if info == nil || !validNATSName(info.Config.Name) {
		return false
	}
	actual := info.Config
	expected := nats.StreamConfig{
		Name: actual.Name, Subjects: []string{CCCoordinationSubjectPrefix + ".*.*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 2_000_000, MaxBytes: 2 << 30,
		Discard: nats.DiscardNew, MaxAge: 24 * time.Hour, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}
	actual.Description, expected.Description = "", ""
	actual.Metadata, expected.Metadata = nil, nil
	actual.Template, expected.Template = "", ""
	return reflect.DeepEqual(actual, expected)
}

func validConnectionsTelemetryStreamInfo(info *nats.StreamInfo) bool {
	if info == nil || !validNATSName(info.Config.Name) {
		return false
	}
	actual := info.Config
	expected := nats.StreamConfig{
		Name: actual.Name, Subjects: []string{ConnectionsTelemetrySubjectPrefix + ".*.*"},
		Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 1_000_000, MaxBytes: 2 << 30,
		Discard: nats.DiscardNew, MaxAge: 0, MaxMsgsPerSubject: 1, DiscardNewPerSubject: true,
		MaxMsgSize: 64 << 10, Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
	}
	actual.Description, expected.Description = "", ""
	actual.Metadata, expected.Metadata = nil, nil
	actual.Template, expected.Template = "", ""
	return reflect.DeepEqual(actual, expected)
}

func (p *NATSTelemetryPublisher) CheckConnections(ctx context.Context) error {
	if p == nil || p.connectionsJS == nil || ctx == nil {
		return fmt.Errorf("connections telemetry publisher is unavailable")
	}
	operationCtx, cancel := context.WithTimeout(ctx, p.config.OperationTimeout)
	defer cancel()
	info, err := p.connectionsJS.StreamInfo(p.config.ConnectionsStream, nats.Context(operationCtx))
	if err != nil || !validConnectionsTelemetryStreamInfo(info) {
		return fmt.Errorf("connections telemetry stream is unavailable")
	}
	return nil
}

type TelemetryHealthSnapshot struct {
	Degraded         bool   `json:"degraded"`
	AcceptedRecords  uint64 `json:"accepted_records"`
	DuplicateRecords uint64 `json:"duplicate_records"`
	PublishFailures  uint64 `json:"publish_failures"`
}

type TelemetryHealth struct {
	degraded         atomic.Bool
	acceptedRecords  atomic.Uint64
	duplicateRecords atomic.Uint64
	publishFailures  atomic.Uint64
}

func NewTelemetryHealth() *TelemetryHealth {
	health := &TelemetryHealth{}
	health.degraded.Store(true)
	return health
}

func (h *TelemetryHealth) RecordAccepted(duplicate bool) {
	if h == nil {
		return
	}
	h.acceptedRecords.Add(1)
	if duplicate {
		h.duplicateRecords.Add(1)
	}
	h.degraded.Store(false)
}

func (h *TelemetryHealth) RecordPublishFailure() {
	if h == nil {
		return
	}
	h.publishFailures.Add(1)
	h.degraded.Store(true)
}

func (h *TelemetryHealth) SetDependencyHealthy(healthy bool) {
	if h != nil {
		h.degraded.Store(!healthy)
	}
}

func (h *TelemetryHealth) Snapshot() TelemetryHealthSnapshot {
	if h == nil {
		return TelemetryHealthSnapshot{Degraded: true}
	}
	return TelemetryHealthSnapshot{
		Degraded: h.degraded.Load(), AcceptedRecords: h.acceptedRecords.Load(),
		DuplicateRecords: h.duplicateRecords.Load(), PublishFailures: h.publishFailures.Load(),
	}
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value && parsed != uuid.Nil
}
