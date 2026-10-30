package analytics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

const (
	IngestSchemaVersion      uint16 = 1
	IngestSubjectPrefix             = "cdnca.analytics.ingest.v1"
	AccessEnvelopeType              = "access.v1"
	SecurityEnvelopeType            = "security.v1"
	IngestSchemaVersionV2    uint16 = 2
	AccessEnvelopeTypeV2            = "access.v2"
	SecurityEnvelopeTypeV2          = "security.v2"
	AccessWindowEnvelopeType        = "access_window.v1"

	DefaultMaxIngestMessageBytes = 1 << 20
	DefaultMaxEventsPerEnvelope  = 1000
	DefaultMaxFutureSkew         = 5 * time.Minute
)

const (
	maxJSONStructureDepth      = 32
	maxJSONStructureTokens     = 1 << 18
	maxJSONStructureObjectKeys = 256
)

const (
	RejectInvalidJSON        = "INVALID_JSON"
	RejectMessageTooLarge    = "MESSAGE_TOO_LARGE"
	RejectUnsupportedVersion = "UNSUPPORTED_VERSION"
	RejectIdentityMismatch   = "IDENTITY_MISMATCH"
	RejectInvalidTime        = "INVALID_TIME"
	RejectInvalidEvent       = "INVALID_EVENT"
	RejectBatchLimit         = "BATCH_LIMIT"
)

type AccessIngestEnvelope struct {
	SchemaVersion         uint16        `json:"schema_version"`
	Type                  string        `json:"type"`
	MessageID             string        `json:"message_id"`
	ProducedAt            time.Time     `json:"produced_at"`
	TenantID              string        `json:"tenant_id"`
	NodeID                string        `json:"node_id"`
	PackageSubscriptionID string        `json:"package_subscription_id"`
	Events                []AccessEvent `json:"events"`
}

type SecurityIngestEnvelope struct {
	SchemaVersion         uint16          `json:"schema_version"`
	Type                  string          `json:"type"`
	MessageID             string          `json:"message_id"`
	ProducedAt            time.Time       `json:"produced_at"`
	TenantID              string          `json:"tenant_id"`
	NodeID                string          `json:"node_id"`
	PackageSubscriptionID string          `json:"package_subscription_id"`
	Events                []SecurityEvent `json:"events"`
}

type accessIngestEnvelopeV2 struct {
	SchemaVersion         uint16            `json:"schema_version"`
	Type                  string            `json:"type"`
	MessageID             string            `json:"message_id"`
	ProducedAt            time.Time         `json:"produced_at"`
	TenantID              string            `json:"tenant_id"`
	InstallationID        string            `json:"installation_id"`
	NodeID                string            `json:"node_id"`
	PackageSubscriptionID string            `json:"package_subscription_id"`
	Events                []json.RawMessage `json:"events"`
}

type securityIngestEnvelopeV2 struct {
	SchemaVersion         uint16            `json:"schema_version"`
	Type                  string            `json:"type"`
	MessageID             string            `json:"message_id"`
	ProducedAt            time.Time         `json:"produced_at"`
	TenantID              string            `json:"tenant_id"`
	InstallationID        string            `json:"installation_id"`
	NodeID                string            `json:"node_id"`
	PackageSubscriptionID string            `json:"package_subscription_id"`
	Events                []json.RawMessage `json:"events"`
}

type accessWindowIngestEnvelopeV1 struct {
	SchemaVersion         uint16                      `json:"schema_version"`
	Type                  string                      `json:"type"`
	MessageID             string                      `json:"message_id"`
	ProducedAt            time.Time                   `json:"produced_at"`
	TenantID              string                      `json:"tenant_id"`
	InstallationID        string                      `json:"installation_id"`
	NodeID                string                      `json:"node_id"`
	PackageSubscriptionID string                      `json:"package_subscription_id"`
	Events                []accessWindowIngestEventV1 `json:"events"`
}

type accessWindowIngestEventV1 struct {
	MetricVersion         uint16    `json:"metric_version"`
	EventID               string    `json:"event_id"`
	WindowStart           time.Time `json:"window_start"`
	WindowEnd             time.Time `json:"window_end"`
	TenantID              string    `json:"tenant_id"`
	PackageSubscriptionID string    `json:"package_subscription_id"`
	SiteID                string    `json:"site_id"`
	NodeID                string    `json:"node_id"`
	InstallationID        string    `json:"installation_id"`
	ConfigVersionID       string    `json:"config_version_id"`
	Host                  string    `json:"host"`
	ListenPort            uint16    `json:"listen_port"`
	SourceWatermark       uint64    `json:"source_watermark"`
	FinalizedThrough      time.Time `json:"finalized_through"`
	DependencyState       string    `json:"dependency_state"`
	EvidenceSHA256        string    `json:"evidence_sha256"`
}

type AccessWindowContributionV1 struct {
	MetricVersion         uint16
	EventID               string
	WindowStart           time.Time
	WindowEnd             time.Time
	TenantID              string
	PackageSubscriptionID string
	SiteID                string
	NodeID                string
	InstallationID        string
	ConfigVersionID       string
	Host                  string
	ListenPort            uint16
	SourceWatermark       uint64
	FinalizedThrough      time.Time
	DependencyState       string
	EvidenceSHA256        [sha256.Size]byte
}

type DecodedIngest struct {
	SchemaVersion             uint16
	Kind                      string
	MessageID                 string
	ProducedAt                time.Time
	TenantID                  string
	NodeID                    string
	PackageSubscriptionID     string
	InstallationID            string
	AccessEvents              []AccessEvent
	SecurityEvents            []SecurityEvent
	AccessWindowContributions []AccessWindowContributionV1
	SubscriptionMinutes       []SubscriptionMinute
	PayloadDigest             [sha256.Size]byte
}

// ConnectionsMetric is the validated, durable identity carried by the
// connections.v1 protobuf envelope. It is intentionally separate from the
// JSON access/security ingest model so an untrusted gauge cannot be mistaken
// for a request-derived metric.
type ConnectionsMetric struct {
	SchemaVersion         uint32
	ConfigVersionID       string
	EventID               string
	OccurredAt            time.Time
	TenantID              string
	InstallationID        string
	SiteID                string
	NodeID                string
	Domain                string
	ListenPort            uint16
	PackageSubscriptionID string
	Connections           uint64
	CanonicalEventSHA256  [sha256.Size]byte
	DependencyState       agentv1.ConnectionsDependencyStateV1
	FinalizedThrough      time.Time
	EvidenceSHA256        [sha256.Size]byte
	SourceWatermark       uint64
}

var ErrInvalidConnectionsMetric = errors.New("invalid connections metric envelope")

// DecodeConnectionsMetric accepts only a complete, ready, finalized
// connections.v1 protobuf message. Unknown protobuf fields are rejected so a
// future producer cannot silently bypass this validator.
func DecodeConnectionsMetric(payload []byte) (ConnectionsMetric, error) {
	if len(payload) == 0 {
		return ConnectionsMetric{}, ErrInvalidConnectionsMetric
	}
	envelope := new(agentv1.ConnectionsMetricEnvelopeV1)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, envelope); err != nil {
		return ConnectionsMetric{}, ErrInvalidConnectionsMetric
	}
	if len(envelope.ProtoReflect().GetUnknown()) != 0 {
		return ConnectionsMetric{}, ErrInvalidConnectionsMetric
	}
	if (envelope.GetSchemaVersion() != 1 && envelope.GetSchemaVersion() != 2) || envelope.GetEvent() == nil ||
		(envelope.GetSchemaVersion() == 1 && envelope.GetConfigVersionId() != "") ||
		(envelope.GetSchemaVersion() == 2 && (!validUUID(envelope.GetConfigVersionId()) || nilUUID(envelope.GetConfigVersionId()))) ||
		!validBatchID(envelope.GetEvent().GetEventId()) ||
		len(envelope.GetEvent().ProtoReflect().GetUnknown()) != 0 ||
		envelope.GetEvent().GetOccurredTime() == nil || envelope.GetEvent().GetOccurredTime().CheckValid() != nil ||
		!validUUID(envelope.GetTenantId()) || nilUUID(envelope.GetTenantId()) || strings.ToLower(envelope.GetTenantId()) != envelope.GetTenantId() ||
		!validUUID(envelope.GetSiteId()) || nilUUID(envelope.GetSiteId()) || strings.ToLower(envelope.GetSiteId()) != envelope.GetSiteId() ||
		!validUUID(envelope.GetNodeId()) || nilUUID(envelope.GetNodeId()) || strings.ToLower(envelope.GetNodeId()) != envelope.GetNodeId() ||
		!validConnectionDomain(envelope.GetDomain()) || envelope.GetListenPort() == 0 || envelope.GetListenPort() > 65535 ||
		(envelope.GetSchemaVersion() == 1 && (!validUUID(envelope.GetPackageSubscriptionId()) || nilUUID(envelope.GetPackageSubscriptionId()))) ||
		(envelope.GetSchemaVersion() == 2 && !validOptionalUUID(envelope.GetPackageSubscriptionId())) ||
		strings.ToLower(envelope.GetPackageSubscriptionId()) != envelope.GetPackageSubscriptionId() ||
		!validBatchID(envelope.GetInstallationId()) ||
		envelope.GetDependencyState() != agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY ||
		len(envelope.GetCanonicalEventSha256()) != sha256.Size || allZeroBytes(envelope.GetCanonicalEventSha256()) ||
		len(envelope.GetEvidenceSha256()) != sha256.Size || allZeroBytes(envelope.GetEvidenceSha256()) ||
		envelope.GetFinalizedThrough() == nil || envelope.GetFinalizedThrough().CheckValid() != nil || envelope.GetSourceWatermark() == 0 {
		return ConnectionsMetric{}, ErrInvalidConnectionsMetric
	}
	occurredAt := envelope.GetEvent().GetOccurredTime().AsTime().UTC()
	finalizedThrough := envelope.GetFinalizedThrough().AsTime().UTC()
	if finalizedThrough.Before(occurredAt) {
		return ConnectionsMetric{}, ErrInvalidConnectionsMetric
	}
	metric := ConnectionsMetric{
		SchemaVersion: envelope.GetSchemaVersion(), ConfigVersionID: envelope.GetConfigVersionId(), EventID: envelope.GetEvent().GetEventId(), OccurredAt: occurredAt,
		TenantID: envelope.GetTenantId(), InstallationID: envelope.GetInstallationId(), SiteID: envelope.GetSiteId(),
		NodeID: envelope.GetNodeId(), Domain: envelope.GetDomain(), ListenPort: uint16(envelope.GetListenPort()),
		PackageSubscriptionID: envelope.GetPackageSubscriptionId(), Connections: envelope.GetConnections(),
		DependencyState: envelope.GetDependencyState(), FinalizedThrough: finalizedThrough, SourceWatermark: envelope.GetSourceWatermark(),
	}
	copy(metric.CanonicalEventSHA256[:], envelope.GetCanonicalEventSha256())
	copy(metric.EvidenceSHA256[:], envelope.GetEvidenceSha256())
	return metric, nil
}

func allZeroBytes(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	for _, byteValue := range value {
		if byteValue != 0 {
			return false
		}
	}
	return true
}

func validConnectionDomain(value string) bool {
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil || strings.ToLower(value) != value ||
		strings.TrimSpace(value) != value || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

type IngestDecoderConfig struct {
	Now             func() time.Time
	MaxMessageBytes int
	MaxEvents       int
	MaxFutureSkew   time.Duration
}

type IngestDecoder struct {
	now             func() time.Time
	maxMessageBytes int
	maxEvents       int
	maxFutureSkew   time.Duration
}

type IngestRejection struct {
	Code string
}

func (rejection *IngestRejection) Error() string {
	return "analytics ingest rejected: " + rejection.Code
}

func RejectionCode(err error) string {
	var rejection *IngestRejection
	if errors.As(err, &rejection) {
		return rejection.Code
	}
	return ""
}

func NewIngestDecoder(config IngestDecoderConfig) (*IngestDecoder, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxMessageBytes == 0 {
		config.MaxMessageBytes = DefaultMaxIngestMessageBytes
	}
	if config.MaxEvents == 0 {
		config.MaxEvents = DefaultMaxEventsPerEnvelope
	}
	if config.MaxFutureSkew == 0 {
		config.MaxFutureSkew = DefaultMaxFutureSkew
	}
	if config.MaxMessageBytes <= 0 || config.MaxMessageBytes > DefaultMaxIngestMessageBytes ||
		config.MaxEvents <= 0 || config.MaxEvents > DefaultMaxEventsPerEnvelope || config.MaxFutureSkew <= 0 {
		return nil, ErrInvalidConfiguration
	}
	return &IngestDecoder{
		now: config.Now, maxMessageBytes: config.MaxMessageBytes,
		maxEvents: config.MaxEvents, maxFutureSkew: config.MaxFutureSkew,
	}, nil
}

func IngestSubject(nodeID string) (string, error) {
	if !validUUID(nodeID) || nilUUID(nodeID) || strings.ToLower(nodeID) != nodeID {
		return "", ErrInvalidInput
	}
	return IngestSubjectPrefix + "." + nodeID, nil
}

func ParseIngestSubject(subject string) (string, error) {
	prefix := IngestSubjectPrefix + "."
	if !strings.HasPrefix(subject, prefix) || strings.Count(subject, ".") != strings.Count(IngestSubjectPrefix, ".")+1 {
		return "", rejection(RejectIdentityMismatch)
	}
	nodeID := strings.TrimPrefix(subject, prefix)
	if !validUUID(nodeID) || nilUUID(nodeID) || strings.ToLower(nodeID) != nodeID {
		return "", rejection(RejectIdentityMismatch)
	}
	return nodeID, nil
}

func (decoder *IngestDecoder) Decode(subject, brokerMessageID string, payload []byte) (DecodedIngest, error) {
	if decoder == nil {
		return DecodedIngest{}, ErrInvalidConfiguration
	}
	if len(payload) == 0 {
		return DecodedIngest{}, rejection(RejectInvalidJSON)
	}
	if len(payload) > decoder.maxMessageBytes {
		return DecodedIngest{}, rejection(RejectMessageTooLarge)
	}
	if !utf8.Valid(payload) {
		return DecodedIngest{}, rejection(RejectInvalidJSON)
	}
	if err := validateUniqueJSONKeys(payload); err != nil {
		return DecodedIngest{}, rejection(RejectInvalidJSON)
	}
	nodeID, err := ParseIngestSubject(subject)
	if err != nil {
		return DecodedIngest{}, err
	}
	var probe struct {
		SchemaVersion uint16 `json:"schema_version"`
		Type          string `json:"type"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return DecodedIngest{}, rejection(RejectInvalidJSON)
	}
	switch {
	case probe.SchemaVersion == IngestSchemaVersion && probe.Type == AccessEnvelopeType:
		var envelope AccessIngestEnvelope
		if err := decodeStrictJSON(payload, &envelope); err != nil {
			return DecodedIngest{}, rejection(RejectInvalidJSON)
		}
		decoded := DecodedIngest{
			SchemaVersion: envelope.SchemaVersion, Kind: envelope.Type, MessageID: envelope.MessageID,
			ProducedAt: envelope.ProducedAt, TenantID: envelope.TenantID,
			PackageSubscriptionID: envelope.PackageSubscriptionID,
			NodeID:                envelope.NodeID, AccessEvents: envelope.Events,
			PayloadDigest: sha256.Sum256(payload),
		}
		if err := decoder.validate(decoded, nodeID, brokerMessageID); err != nil {
			return DecodedIngest{}, err
		}
		return decoded, nil
	case probe.SchemaVersion == IngestSchemaVersion && probe.Type == SecurityEnvelopeType:
		var envelope SecurityIngestEnvelope
		if err := decodeStrictJSON(payload, &envelope); err != nil {
			return DecodedIngest{}, rejection(RejectInvalidJSON)
		}
		decoded := DecodedIngest{
			SchemaVersion: envelope.SchemaVersion, Kind: envelope.Type, MessageID: envelope.MessageID,
			ProducedAt: envelope.ProducedAt, TenantID: envelope.TenantID,
			PackageSubscriptionID: envelope.PackageSubscriptionID,
			NodeID:                envelope.NodeID, SecurityEvents: envelope.Events,
			PayloadDigest: sha256.Sum256(payload),
		}
		if err := decoder.validate(decoded, nodeID, brokerMessageID); err != nil {
			return DecodedIngest{}, err
		}
		return decoded, nil
	case probe.SchemaVersion == IngestSchemaVersionV2 && probe.Type == AccessEnvelopeTypeV2:
		var envelope accessIngestEnvelopeV2
		if err := decodeStrictJSON(payload, &envelope); err != nil {
			return DecodedIngest{}, rejection(RejectInvalidJSON)
		}
		events, err := decodeAccessEventsV2(envelope.Events)
		if err != nil {
			return DecodedIngest{}, rejection(RejectInvalidJSON)
		}
		decoded := DecodedIngest{
			SchemaVersion: envelope.SchemaVersion, Kind: envelope.Type, MessageID: envelope.MessageID,
			ProducedAt: envelope.ProducedAt, TenantID: envelope.TenantID, InstallationID: envelope.InstallationID,
			PackageSubscriptionID: envelope.PackageSubscriptionID,
			NodeID:                envelope.NodeID, AccessEvents: events,
			PayloadDigest: sha256.Sum256(payload),
		}
		if err := decoder.validate(decoded, nodeID, brokerMessageID); err != nil {
			return DecodedIngest{}, err
		}
		return decoded, nil
	case probe.SchemaVersion == IngestSchemaVersionV2 && probe.Type == SecurityEnvelopeTypeV2:
		var envelope securityIngestEnvelopeV2
		if err := decodeStrictJSON(payload, &envelope); err != nil {
			return DecodedIngest{}, rejection(RejectInvalidJSON)
		}
		events, err := decodeSecurityEventsV2(envelope.Events)
		if err != nil {
			return DecodedIngest{}, rejection(RejectInvalidJSON)
		}
		decoded := DecodedIngest{
			SchemaVersion: envelope.SchemaVersion, Kind: envelope.Type, MessageID: envelope.MessageID,
			ProducedAt: envelope.ProducedAt, TenantID: envelope.TenantID, InstallationID: envelope.InstallationID,
			PackageSubscriptionID: envelope.PackageSubscriptionID,
			NodeID:                envelope.NodeID, SecurityEvents: events,
			PayloadDigest: sha256.Sum256(payload),
		}
		if err := decoder.validate(decoded, nodeID, brokerMessageID); err != nil {
			return DecodedIngest{}, err
		}
		return decoded, nil
	case probe.SchemaVersion == IngestSchemaVersion && probe.Type == AccessWindowEnvelopeType:
		var envelope accessWindowIngestEnvelopeV1
		if err := decodeStrictJSON(payload, &envelope); err != nil {
			return DecodedIngest{}, rejection(RejectInvalidJSON)
		}
		contributions, err := decodeAccessWindowContributionsV1(envelope.Events)
		if err != nil {
			return DecodedIngest{}, rejection(RejectInvalidEvent)
		}
		decoded := DecodedIngest{
			SchemaVersion: envelope.SchemaVersion, Kind: envelope.Type, MessageID: envelope.MessageID,
			ProducedAt: envelope.ProducedAt, TenantID: envelope.TenantID, InstallationID: envelope.InstallationID,
			PackageSubscriptionID: envelope.PackageSubscriptionID, NodeID: envelope.NodeID,
			AccessWindowContributions: contributions, PayloadDigest: sha256.Sum256(payload),
		}
		if err := decoder.validate(decoded, nodeID, brokerMessageID); err != nil {
			return DecodedIngest{}, err
		}
		return decoded, nil
	case probe.SchemaVersion == IngestSchemaVersion && probe.Type == SubscriptionMinuteEnvelopeType:
		return decoder.decodeSubscriptionMinute(payload, nodeID, brokerMessageID)
	default:
		return DecodedIngest{}, rejection(RejectUnsupportedVersion)
	}
}

func sha256Payload(payload []byte) [sha256.Size]byte { return sha256.Sum256(payload) }

func decodeAccessWindowContributionsV1(events []accessWindowIngestEventV1) ([]AccessWindowContributionV1, error) {
	contributions := make([]AccessWindowContributionV1, len(events))
	for index, event := range events {
		evidence, err := hex.DecodeString(event.EvidenceSHA256)
		if err != nil || len(evidence) != sha256.Size || allZeroBytes(evidence) {
			return nil, errors.New("invalid access window evidence")
		}
		contribution := AccessWindowContributionV1{
			MetricVersion: event.MetricVersion, EventID: event.EventID,
			WindowStart: event.WindowStart, WindowEnd: event.WindowEnd,
			TenantID: event.TenantID, PackageSubscriptionID: event.PackageSubscriptionID,
			SiteID: event.SiteID, NodeID: event.NodeID, InstallationID: event.InstallationID,
			ConfigVersionID: event.ConfigVersionID, Host: event.Host, ListenPort: event.ListenPort,
			SourceWatermark: event.SourceWatermark, FinalizedThrough: event.FinalizedThrough,
			DependencyState: event.DependencyState,
		}
		copy(contribution.EvidenceSHA256[:], evidence)
		contributions[index] = contribution
	}
	return contributions, nil
}

func decodeAccessEventsV2(encoded []json.RawMessage) ([]AccessEvent, error) {
	events := make([]AccessEvent, len(encoded))
	for index := range encoded {
		installationID, normalized, err := extractV2EventInstallation(encoded[index])
		if err != nil || decodeStrictJSON(normalized, &events[index]) != nil {
			return nil, errors.New("invalid access.v2 event")
		}
		events[index].InstallationID = installationID
	}
	return events, nil
}

func decodeSecurityEventsV2(encoded []json.RawMessage) ([]SecurityEvent, error) {
	events := make([]SecurityEvent, len(encoded))
	for index := range encoded {
		installationID, normalized, err := extractV2EventInstallation(encoded[index])
		if err != nil || decodeStrictJSON(normalized, &events[index]) != nil {
			return nil, errors.New("invalid security.v2 event")
		}
		events[index].InstallationID = installationID
	}
	return events, nil
}

func extractV2EventInstallation(encoded json.RawMessage) (string, []byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return "", nil, err
	}
	raw, ok := fields["installation_id"]
	if !ok {
		return "", nil, errors.New("missing v2 installation identity")
	}
	var installationID string
	if err := json.Unmarshal(raw, &installationID); err != nil || !validBatchID(installationID) {
		return "", nil, errors.New("invalid v2 installation identity")
	}
	delete(fields, "installation_id")
	normalized, err := json.Marshal(fields)
	return installationID, normalized, err
}

func (decoder *IngestDecoder) validate(decoded DecodedIngest, subjectNodeID, brokerMessageID string) error {
	v2 := decoded.SchemaVersion == IngestSchemaVersionV2
	authorityBound := v2 || decoded.Kind == AccessWindowEnvelopeType || decoded.Kind == SubscriptionMinuteEnvelopeType
	if decoded.SchemaVersion != IngestSchemaVersion && !v2 || !validBatchID(decoded.MessageID) ||
		brokerMessageID == "" || brokerMessageID != decoded.MessageID ||
		!validUUID(decoded.TenantID) || nilUUID(decoded.TenantID) ||
		!validOptionalUUID(decoded.PackageSubscriptionID) || decoded.PackageSubscriptionID != strings.ToLower(decoded.PackageSubscriptionID) ||
		!validUUID(decoded.NodeID) || nilUUID(decoded.NodeID) || decoded.NodeID != subjectNodeID ||
		(authorityBound && !validBatchID(decoded.InstallationID)) || (!authorityBound && decoded.InstallationID != "") {
		return rejection(RejectIdentityMismatch)
	}
	now := decoder.now().UTC()
	if decoded.ProducedAt.IsZero() || decoded.ProducedAt.Location() != time.UTC ||
		decoded.ProducedAt.After(now.Add(decoder.maxFutureSkew)) {
		return rejection(RejectInvalidTime)
	}
	switch decoded.Kind {
	case AccessEnvelopeType, AccessEnvelopeTypeV2:
		if (decoded.Kind == AccessEnvelopeTypeV2) != v2 {
			return rejection(RejectUnsupportedVersion)
		}
		if len(decoded.AccessEvents) == 0 || len(decoded.AccessEvents) > decoder.maxEvents || len(decoded.SecurityEvents) != 0 {
			return rejection(RejectBatchLimit)
		}
		identities := make(map[string]struct{}, len(decoded.AccessEvents))
		for _, event := range decoded.AccessEvents {
			if event.TaskID != nil || event.JA4 != nil && !edgeconfig.ValidJA4(*event.JA4) || validateAccessEvent(event) != nil ||
				(v2 && event.InstallationID != decoded.InstallationID) || (!v2 && event.InstallationID != "") ||
				!sameClaim(decoded, event.TenantID, event.PackageSubscriptionID, event.NodeID) ||
				!validEventTime(event.OccurredAt, decoded.ProducedAt, now, decoder.maxFutureSkew, 30*24*time.Hour) {
				return rejection(RejectInvalidEvent)
			}
			identity := accessIdentity(event)
			if _, duplicate := identities[identity]; duplicate {
				return rejection(RejectInvalidEvent)
			}
			identities[identity] = struct{}{}
		}
	case SecurityEnvelopeType, SecurityEnvelopeTypeV2:
		if (decoded.Kind == SecurityEnvelopeTypeV2) != v2 {
			return rejection(RejectUnsupportedVersion)
		}
		if len(decoded.SecurityEvents) == 0 || len(decoded.SecurityEvents) > decoder.maxEvents || len(decoded.AccessEvents) != 0 {
			return rejection(RejectBatchLimit)
		}
		identities := make(map[string]struct{}, len(decoded.SecurityEvents))
		for _, event := range decoded.SecurityEvents {
			if event.TaskID != nil || event.JA4 != nil && !edgeconfig.ValidJA4(*event.JA4) || validateSecurityEvent(event) != nil ||
				(v2 && event.InstallationID != decoded.InstallationID) || (!v2 && event.InstallationID != "") ||
				!sameClaim(decoded, event.TenantID, event.PackageSubscriptionID, event.NodeID) ||
				!validEventTime(event.OccurredAt, decoded.ProducedAt, now, decoder.maxFutureSkew, 90*24*time.Hour) {
				return rejection(RejectInvalidEvent)
			}
			identity := securityIdentity(event)
			if _, duplicate := identities[identity]; duplicate {
				return rejection(RejectInvalidEvent)
			}
			identities[identity] = struct{}{}
		}
	case AccessWindowEnvelopeType:
		if v2 || len(decoded.AccessWindowContributions) != 1 || len(decoded.AccessEvents) != 0 || len(decoded.SecurityEvents) != 0 {
			return rejection(RejectBatchLimit)
		}
		contribution := decoded.AccessWindowContributions[0]
		if contribution.MetricVersion != MetricVersion || !validBatchID(contribution.EventID) ||
			contribution.InstallationID != decoded.InstallationID ||
			!sameClaim(decoded, contribution.TenantID, contribution.PackageSubscriptionID, contribution.NodeID) ||
			!validUUID(contribution.SiteID) || nilUUID(contribution.SiteID) || strings.ToLower(contribution.SiteID) != contribution.SiteID ||
			!validUUID(contribution.ConfigVersionID) || nilUUID(contribution.ConfigVersionID) || strings.ToLower(contribution.ConfigVersionID) != contribution.ConfigVersionID ||
			!validConnectionDomain(contribution.Host) || contribution.ListenPort == 0 || contribution.SourceWatermark == 0 ||
			contribution.WindowStart.IsZero() || contribution.WindowStart.Location() != time.UTC ||
			!contribution.WindowStart.Equal(contribution.WindowStart.Truncate(time.Hour)) ||
			!contribution.WindowEnd.Equal(contribution.WindowStart.Add(time.Hour)) ||
			!decoded.ProducedAt.Equal(contribution.WindowEnd) || !contribution.FinalizedThrough.Equal(contribution.WindowEnd) ||
			contribution.DependencyState != "ready" || contribution.EvidenceSHA256 == ([sha256.Size]byte{}) ||
			!validEventTime(contribution.WindowEnd, decoded.ProducedAt, now, decoder.maxFutureSkew, 30*24*time.Hour) {
			return rejection(RejectInvalidEvent)
		}
	case SubscriptionMinuteEnvelopeType:
		if v2 || len(decoded.SubscriptionMinutes) != 1 || len(decoded.AccessEvents) != 0 || len(decoded.SecurityEvents) != 0 ||
			len(decoded.AccessWindowContributions) != 0 || decoded.PackageSubscriptionID == "" {
			return rejection(RejectBatchLimit)
		}
	default:
		return rejection(RejectUnsupportedVersion)
	}
	return nil
}

func sameClaim(decoded DecodedIngest, tenantID, subscriptionID, nodeID string) bool {
	return decoded.TenantID == tenantID && decoded.PackageSubscriptionID == subscriptionID && decoded.NodeID == nodeID
}

func validEventTime(occurredAt, producedAt, now time.Time, futureSkew, maxAge time.Duration) bool {
	return !occurredAt.IsZero() && occurredAt.Location() == time.UTC &&
		!occurredAt.After(producedAt.Add(futureSkew)) && !occurredAt.After(now.Add(futureSkew)) &&
		!occurredAt.Before(now.Add(-maxAge))
}

func decodeStrictJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func validateUniqueJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	budget := jsonStructureBudget{tokens: maxJSONStructureTokens}
	if err := consumeJSONValue(decoder, &budget, 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return errors.New("trailing JSON data")
	}
	return nil
}

type jsonStructureBudget struct {
	tokens int
}

func (budget *jsonStructureBudget) take() error {
	if budget == nil || budget.tokens <= 0 {
		return errors.New("JSON structure budget exceeded")
	}
	budget.tokens--
	return nil
}

func consumeJSONValue(decoder *json.Decoder, budget *jsonStructureBudget, depth int) error {
	if err := budget.take(); err != nil {
		return err
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxJSONStructureDepth && (delimiter == json.Delim('{') || delimiter == json.Delim('[')) {
		return errors.New("JSON structure depth exceeded")
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			if len(keys) >= maxJSONStructureObjectKeys {
				return errors.New("JSON object key budget exceeded")
			}
			if err := budget.take(); err != nil {
				return err
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON key")
			}
			keys[key] = struct{}{}
			if err := consumeJSONValue(decoder, budget, depth+1); err != nil {
				return err
			}
		}
		if err := budget.take(); err != nil {
			return err
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, budget, depth+1); err != nil {
				return err
			}
		}
		if err := budget.take(); err != nil {
			return err
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func rejection(code string) error {
	return &IngestRejection{Code: code}
}
