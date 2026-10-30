package eventspool

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	analyticsMetricVersion      uint16 = 1
	analyticsIngestVersionV2    uint16 = 2
	analyticsSubjectPrefix             = "cdnca.analytics.ingest.v1"
	analyticsAccessTypeV2              = "access.v2"
	analyticsSecurityTypeV2            = "security.v2"
	maxAnalyticsEnvelopeBytes          = 1 << 20
	maxAnalyticsEnvelopeEvents         = 1000
	connectionsSubjectPrefix           = "cdnca.connections.v1"
	maxConnectionsEnvelopeBytes        = 16 << 10
	l4SubjectPrefix                    = "cdnca.l4.sessions.v1"
)

type analyticsAccessEvent struct {
	MetricVersion         uint16            `json:"metric_version"`
	EventID               string            `json:"event_id"`
	OccurredAt            time.Time         `json:"occurred_at"`
	TenantID              string            `json:"tenant_id"`
	SiteID                string            `json:"site_id"`
	NodeID                string            `json:"node_id"`
	InstallationID        string            `json:"installation_id"`
	RequestID             string            `json:"request_id,omitempty"`
	TraceID               string            `json:"trace_id,omitempty"`
	ConfigVersion         string            `json:"config_version_id,omitempty"`
	CapturePolicyRevision uint64            `json:"capture_policy_revision,omitempty"`
	CapturePolicyDigest   string            `json:"capture_policy_digest,omitempty"`
	TaskID                *string           `json:"task_id"`
	Host                  string            `json:"host"`
	Path                  string            `json:"path"`
	ClientIP              string            `json:"client_ip"`
	CountryCode           string            `json:"country_code,omitempty"`
	Carrier               string            `json:"carrier,omitempty"`
	Method                string            `json:"method"`
	ListenPort            uint16            `json:"listen_port"`
	Protocol              string            `json:"protocol"`
	CacheStatus           string            `json:"cache_status"`
	UpstreamResult        string            `json:"upstream_result,omitempty"`
	StatusCode            uint16            `json:"status_code"`
	RequestBytes          uint64            `json:"request_bytes"`
	ResponseBytes         uint64            `json:"response_bytes"`
	DurationUS            uint64            `json:"duration_us"`
	JA4                   *string           `json:"ja4"`
	OriginConnectUS       *uint64           `json:"origin_connect_us"`
	OriginFirstByteUS     *uint64           `json:"origin_first_byte_us"`
	OriginTotalUS         *uint64           `json:"origin_total_us"`
	RequestHeaders        map[string]string `json:"request_headers"`
	ResponseHeaders       map[string]string `json:"response_headers"`
	RequestBody           map[string]any    `json:"request_body"`
	ResponseBody          map[string]any    `json:"response_body"`
	Blocked               bool              `json:"blocked,omitempty"`
	ClientBrowser         string            `json:"client_browser,omitempty"`
	ClientOS              string            `json:"client_os,omitempty"`
	UpstreamAddr          string            `json:"upstream_addr,omitempty"`
}

type analyticsSecurityEvent struct {
	MetricVersion         uint16            `json:"metric_version"`
	EventID               string            `json:"event_id"`
	OccurredAt            time.Time         `json:"occurred_at"`
	TenantID              string            `json:"tenant_id"`
	SiteID                string            `json:"site_id"`
	NodeID                string            `json:"node_id"`
	InstallationID        string            `json:"installation_id"`
	RequestID             string            `json:"request_id,omitempty"`
	TraceID               string            `json:"trace_id,omitempty"`
	ConfigVersion         string            `json:"config_version_id,omitempty"`
	CapturePolicyRevision uint64            `json:"capture_policy_revision,omitempty"`
	CapturePolicyDigest   string            `json:"capture_policy_digest,omitempty"`
	TaskID                *string           `json:"task_id"`
	Host                  string            `json:"host"`
	Path                  string            `json:"path"`
	ClientIP              string            `json:"client_ip"`
	CountryCode           string            `json:"country_code,omitempty"`
	Carrier               string            `json:"carrier,omitempty"`
	Method                string            `json:"method"`
	ListenPort            uint16            `json:"listen_port"`
	DestinationPort       uint16            `json:"destination_port,omitempty"`
	Protocol              string            `json:"protocol"`
	RequestClass          string            `json:"request_class"`
	EventType             string            `json:"event_type"`
	Action                string            `json:"action"`
	Severity              string            `json:"severity"`
	RuleID                string            `json:"rule_id,omitempty"`
	PolicyID              string            `json:"policy_id,omitempty"`
	Detector              string            `json:"detector,omitempty"`
	Matched               string            `json:"matched,omitempty"`
	UserAgent             string            `json:"user_agent,omitempty"`
	RequestBodyExcerpt    string            `json:"request_body_excerpt,omitempty"`
	Count                 uint32            `json:"count,omitempty"`
	StatusCode            uint16            `json:"status_code"`
	RequestBytes          uint64            `json:"request_bytes"`
	ResponseBytes         uint64            `json:"response_bytes"`
	JA4                   *string           `json:"ja4"`
	OriginConnectUS       *uint64           `json:"origin_connect_us"`
	OriginFirstByteUS     *uint64           `json:"origin_first_byte_us"`
	OriginTotalUS         *uint64           `json:"origin_total_us"`
	RequestHeaders        map[string]string `json:"request_headers"`
	ResponseHeaders       map[string]string `json:"response_headers"`
	RequestBody           map[string]any    `json:"request_body"`
	ResponseBody          map[string]any    `json:"response_body"`
}

type analyticsAccessEnvelope struct {
	SchemaVersion  uint16                 `json:"schema_version"`
	Type           string                 `json:"type"`
	MessageID      string                 `json:"message_id"`
	ProducedAt     time.Time              `json:"produced_at"`
	TenantID       string                 `json:"tenant_id"`
	InstallationID string                 `json:"installation_id"`
	NodeID         string                 `json:"node_id"`
	Events         []analyticsAccessEvent `json:"events"`
}

type analyticsSecurityEnvelope struct {
	SchemaVersion  uint16                   `json:"schema_version"`
	Type           string                   `json:"type"`
	MessageID      string                   `json:"message_id"`
	ProducedAt     time.Time                `json:"produced_at"`
	TenantID       string                   `json:"tenant_id"`
	InstallationID string                   `json:"installation_id"`
	NodeID         string                   `json:"node_id"`
	Events         []analyticsSecurityEvent `json:"events"`
}

func buildPublications(records []Record) ([]Publication, error) {
	if len(records) == 0 {
		return nil, nil
	}
	publications := make([]Publication, 0, (len(records)+maxAnalyticsEnvelopeEvents-1)/maxAnalyticsEnvelopeEvents)
	for start := 0; start < len(records); {
		end := start + 1
		for end < len(records) && end-start < maxAnalyticsEnvelopeEvents &&
			samePublicationDimension(records[start], records[end]) {
			end++
		}
		group, err := splitPublication(records[start:end])
		if err != nil {
			return nil, err
		}
		publications = append(publications, group...)
		start = end
	}
	return publications, nil
}

func samePublicationDimension(first, candidate Record) bool {
	if first.Type == EventAccessWindow || first.Type == EventSubscriptionMinute {
		return false
	}
	if candidate.Type != first.Type || candidate.TenantID != first.TenantID || candidate.NodeID != first.NodeID ||
		candidate.envelope.SiteID != first.envelope.SiteID || candidate.envelope.ConfigVersionID != first.envelope.ConfigVersionID ||
		candidate.envelope.CapturePolicyRevision != first.envelope.CapturePolicyRevision ||
		candidate.envelope.CapturePolicyDigest != first.envelope.CapturePolicyDigest {
		return false
	}
	if first.Type != EventAccess {
		if first.Type == EventL4Session || first.Type == EventL4Checkpoint {
			return candidate.envelope.StreamID == first.envelope.StreamID && candidate.envelope.ListenerID == first.envelope.ListenerID &&
				candidate.envelope.Protocol == first.envelope.Protocol && candidate.envelope.ListenPort == first.envelope.ListenPort &&
				candidate.envelope.PackageSubscriptionID == first.envelope.PackageSubscriptionID
		}
		return true
	}
	return candidate.envelope.Host == first.envelope.Host && candidate.envelope.ListenPort == first.envelope.ListenPort &&
		candidate.OccurredAt.Truncate(time.Hour).Equal(first.OccurredAt.Truncate(time.Hour))
}

func splitPublication(records []Record) ([]Publication, error) {
	publication, err := encodePublication(records)
	if err != nil {
		return nil, err
	}
	if len(publication.Payload) <= maxAnalyticsEnvelopeBytes {
		return []Publication{publication}, nil
	}
	if len(records) == 1 {
		return nil, ErrInvalidEvent
	}
	middle := len(records) / 2
	left, err := splitPublication(records[:middle])
	if err != nil {
		return nil, err
	}
	right, err := splitPublication(records[middle:])
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

func encodePublication(records []Record) (Publication, error) {
	if len(records) == 0 {
		return Publication{}, ErrInvalidEvent
	}
	first := records[0]
	last := records[len(records)-1]
	if first.Type == EventL4Session || first.Type == EventL4Checkpoint {
		return encodeL4Publication(records)
	}
	if first.Type == EventAccessWindow {
		return encodeAccessWindowPublication(records)
	}
	if first.Type == EventSubscriptionMinute {
		return encodeSubscriptionMinutePublication(records)
	}
	producedAt := first.OccurredAt
	accessEvents := make([]analyticsAccessEvent, 0, len(records))
	securityEvents := make([]analyticsSecurityEvent, 0, len(records))
	for index, record := range records {
		if record.Sequence != first.Sequence+uint64(index) || record.Type != first.Type || record.TenantID != first.TenantID ||
			record.NodeID != first.NodeID {
			return Publication{}, ErrCorruptState
		}
		envelope := record.envelope
		if validateEnvelope(envelope, identityStored) != nil || envelope.Sequence != record.Sequence || envelope.EventID != record.EventID || envelope.TenantID != record.TenantID || envelope.NodeID != record.NodeID {
			return Publication{}, ErrCorruptState
		}
		if envelope.SiteID != first.envelope.SiteID || envelope.ConfigVersionID != first.envelope.ConfigVersionID ||
			envelope.CapturePolicyRevision != first.envelope.CapturePolicyRevision ||
			envelope.CapturePolicyDigest != first.envelope.CapturePolicyDigest {
			return Publication{}, ErrCorruptState
		}
		if envelope.OccurredAt.After(producedAt) {
			producedAt = envelope.OccurredAt
		}
		switch first.Type {
		case EventAccess:
			accessEvents = append(accessEvents, analyticsAccessFrom(envelope))
		case EventSecurity:
			securityEvents = append(securityEvents, analyticsSecurityFrom(envelope))
		default:
			return Publication{}, ErrCorruptState
		}
	}
	var candidate any
	if first.Type == EventAccess {
		candidate = &analyticsAccessEnvelope{
			SchemaVersion: analyticsIngestVersionV2, Type: analyticsAccessTypeV2,
			ProducedAt: producedAt, TenantID: first.TenantID, NodeID: first.NodeID, Events: accessEvents,
		}
	} else {
		candidate = &analyticsSecurityEnvelope{
			SchemaVersion: analyticsIngestVersionV2, Type: analyticsSecurityTypeV2,
			ProducedAt: producedAt, TenantID: first.TenantID, NodeID: first.NodeID, Events: securityEvents,
		}
	}
	unsigned, err := json.Marshal(candidate)
	if err != nil {
		return Publication{}, ErrInvalidEvent
	}
	canonical, ok := canonicalPublicationV2Envelope(unsigned)
	if !ok {
		return Publication{}, ErrInvalidEvent
	}
	messageID := publicationV2MessageID(first.Sequence, last.Sequence, canonical)
	switch envelope := candidate.(type) {
	case *analyticsAccessEnvelope:
		envelope.MessageID = messageID
	case *analyticsSecurityEnvelope:
		envelope.MessageID = messageID
	}
	payload, err := json.Marshal(candidate)
	if err != nil {
		return Publication{}, ErrInvalidEvent
	}
	return Publication{
		Subject: analyticsSubjectPrefix + "." + strings.ToLower(first.NodeID), MessageID: messageID,
		Payload: payload, FirstSequence: first.Sequence, LastSequence: last.Sequence,
		LastEventID: last.EventID, EventCount: len(records),
	}, nil
}

func encodeL4Publication(records []Record) (Publication, error) {
	if len(records) == 0 {
		return Publication{}, ErrInvalidEvent
	}
	first, last := records[0], records[len(records)-1]
	envelope := &agentv1.L4SessionEnvelopeV1{
		SchemaVersion: 1, TenantId: first.TenantID, NodeId: first.NodeID,
		SiteId: first.envelope.SiteID, ConfigVersionId: first.envelope.ConfigVersionID,
		SourceWatermark: last.Sequence, Events: make([]*agentv1.L4SessionEventV1, 0, len(records)),
	}
	producedAt := first.OccurredAt
	evidence := sha256.New()
	for index, record := range records {
		if record.Sequence != first.Sequence+uint64(index) || record.Type != first.Type ||
			record.TenantID != first.TenantID || record.NodeID != first.NodeID ||
			record.envelope.SiteID != first.envelope.SiteID || record.envelope.ConfigVersionID != first.envelope.ConfigVersionID ||
			record.envelope.StreamID != first.envelope.StreamID || record.envelope.ListenerID != first.envelope.ListenerID ||
			record.envelope.PackageSubscriptionID != first.envelope.PackageSubscriptionID ||
			validateEnvelope(record.envelope, identityStored) != nil {
			return Publication{}, ErrCorruptState
		}
		item := record.envelope
		if record.Type == EventL4Checkpoint {
			// One envelope carries checkpoints or events, never both
			// (samePublicationDimension keeps the types apart).
			if item.OccurredAt.After(producedAt) {
				producedAt = item.OccurredAt
			}
			envelope.Checkpoints = append(envelope.Checkpoints, l4CheckpointProto(item))
			checkpointEvidence := contentDigest(item)
			_, _ = evidence.Write(checkpointEvidence[:])
			continue
		}
		if item.FinalizedAt.After(producedAt) {
			producedAt = item.FinalizedAt
		}
		evidenceBytes, err := hex.DecodeString(item.EvidenceSHA256)
		if err != nil || len(evidenceBytes) != sha256.Size {
			return Publication{}, ErrCorruptState
		}
		_, _ = evidence.Write(evidenceBytes)
		canonical := contentDigest(item)
		metadata := &commonv1.EventMetadata{
			EventId: item.EventID, RequestId: item.RequestID, OccurredTime: timestamppb.New(item.FinalizedAt), Traceparent: item.TraceID,
		}
		if item.TaskID != nil {
			value := *item.TaskID
			metadata.TaskId = &value
		}
		envelope.Events = append(envelope.Events, &agentv1.L4SessionEventV1{
			Event: metadata, TenantId: item.TenantID, NodeId: item.NodeID, SiteId: item.SiteID,
			StreamId: item.StreamID, ListenerId: item.ListenerID, ConfigVersionId: item.ConfigVersionID,
			ConfigRevision: item.ConfigRevision, Protocol: item.Protocol, ListenPort: uint32(item.ListenPort), SessionId: item.SessionID,
			StartedAt: timestamppb.New(item.StartedAt), FinalizedAt: timestamppb.New(item.FinalizedAt),
			BytesUp: item.RequestBytes, BytesDown: item.ResponseBytes, StatusCode: uint32(item.StatusCode), ErrorCode: item.ErrorCode,
			CanonicalEventSha256: append([]byte(nil), canonical[:]...), EvidenceSha256: evidenceBytes,
			SessionLog: l4SessionLogProto(item.L4Log), PackageSubscriptionId: item.PackageSubscriptionID,
			CheckpointedBytesUp: item.CheckpointedRequestBytes, CheckpointedBytesDown: item.CheckpointedResponseBytes,
		})
	}
	envelope.ProducedAt = timestamppb.New(producedAt)
	envelope.FinalizedThrough = timestamppb.New(producedAt)
	envelope.EvidenceSha256 = evidence.Sum(nil)
	envelope.MessageId = l4PublicationMessageID(envelope)
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
	if err != nil || len(payload) > maxAnalyticsEnvelopeBytes {
		return Publication{}, ErrInvalidEvent
	}
	return Publication{
		Subject: l4SubjectPrefix + "." + strings.ToLower(first.NodeID), MessageID: envelope.MessageId,
		Payload: payload, FirstSequence: first.Sequence, LastSequence: last.Sequence,
		LastEventID: last.EventID, EventCount: len(records),
	}, nil
}

func l4CheckpointProto(item Envelope) *agentv1.L4UsageCheckpointV1 {
	return &agentv1.L4UsageCheckpointV1{
		Event:    &commonv1.EventMetadata{EventId: item.EventID, OccurredTime: timestamppb.New(item.OccurredAt)},
		TenantId: item.TenantID, NodeId: item.NodeID, SiteId: item.SiteID, StreamId: item.StreamID, ListenerId: item.ListenerID,
		ConfigVersionId: item.ConfigVersionID, ConfigRevision: item.ConfigRevision, Protocol: item.Protocol,
		ListenPort: uint32(item.ListenPort), SessionId: item.SessionID, StartedAt: timestamppb.New(item.StartedAt),
		CheckpointAt: timestamppb.New(item.OccurredAt), Sequence: item.CheckpointSequence,
		BytesUp: item.RequestBytes, BytesDown: item.ResponseBytes, PackageSubscriptionId: item.PackageSubscriptionID,
	}
}

func l4SessionLogProto(log *L4SessionLog) *agentv1.L4SessionLogV1 {
	if log == nil {
		return nil
	}
	result := &agentv1.L4SessionLogV1{ClientIp: log.ClientIP, ClientPort: uint32(log.ClientPort), PeerIp: log.PeerIP,
		UpstreamAddr: log.UpstreamAddr, EndReason: log.EndReason}
	if log.UpstreamConnectMS != nil {
		value := *log.UpstreamConnectMS
		result.UpstreamConnectMs = &value
	}
	return result
}

func l4PublicationMessageID(envelope *agentv1.L4SessionEnvelopeV1) string {
	if envelope == nil {
		return ""
	}
	cloned := proto.Clone(envelope).(*agentv1.L4SessionEnvelopeV1)
	cloned.MessageId = ""
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(cloned)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(append([]byte("cdnca.l4.session.publication.v1\x00"), payload...))
	return "l4msg_" + hex.EncodeToString(digest[:])
}

func L4PublicationMessageID(envelope *agentv1.L4SessionEnvelopeV1) string {
	return l4PublicationMessageID(envelope)
}

func ValidL4Publication(publication Publication) bool {
	if publication.Subject == "" || publication.FirstSequence == 0 || publication.LastSequence < publication.FirstSequence ||
		publication.EventCount != int(publication.LastSequence-publication.FirstSequence+1) || len(publication.Payload) == 0 {
		return false
	}
	var envelope agentv1.L4SessionEnvelopeV1
	if proto.Unmarshal(publication.Payload, &envelope) != nil || len(envelope.ProtoReflect().GetUnknown()) != 0 ||
		envelope.GetSchemaVersion() != 1 || envelope.GetMessageId() != publication.MessageID ||
		envelope.GetSourceWatermark() != publication.LastSequence ||
		(len(envelope.GetEvents()) != 0) == (len(envelope.GetCheckpoints()) != 0) ||
		len(envelope.GetEvents())+len(envelope.GetCheckpoints()) != publication.EventCount ||
		publication.Subject != l4SubjectPrefix+"."+strings.ToLower(envelope.GetNodeId()) ||
		len(envelope.GetEvidenceSha256()) != sha256.Size || l4PublicationMessageID(&envelope) != publication.MessageID {
		return false
	}
	for index, checkpoint := range envelope.GetCheckpoints() {
		if checkpoint == nil || checkpoint.GetEvent() == nil || checkpoint.GetEvent().GetEventId() == "" ||
			checkpoint.GetTenantId() != envelope.GetTenantId() || checkpoint.GetNodeId() != envelope.GetNodeId() ||
			checkpoint.GetSiteId() != envelope.GetSiteId() || checkpoint.GetConfigVersionId() != envelope.GetConfigVersionId() ||
			checkpoint.GetSequence() == 0 ||
			index == len(envelope.GetCheckpoints())-1 && checkpoint.GetEvent().GetEventId() != publication.LastEventID {
			return false
		}
	}
	for index, event := range envelope.GetEvents() {
		if event == nil || event.GetEvent() == nil || event.GetEvent().GetEventId() == "" ||
			event.GetTenantId() != envelope.GetTenantId() || event.GetNodeId() != envelope.GetNodeId() ||
			event.GetSiteId() != envelope.GetSiteId() || event.GetConfigVersionId() != envelope.GetConfigVersionId() ||
			len(event.GetCanonicalEventSha256()) != sha256.Size || len(event.GetEvidenceSha256()) != sha256.Size ||
			index == len(envelope.GetEvents())-1 && event.GetEvent().GetEventId() != publication.LastEventID {
			return false
		}
	}
	return true
}

func publicationV2MessageID(firstSequence, lastSequence uint64, canonicalEnvelope []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.analytics.publication.v2\x00"))
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], firstSequence)
	_, _ = hash.Write(sequence[:])
	binary.BigEndian.PutUint64(sequence[:], lastSequence)
	_, _ = hash.Write(sequence[:])
	_, _ = hash.Write(canonicalEnvelope)
	return "msg_" + hex.EncodeToString(hash.Sum(nil))
}

func canonicalPublicationV2Envelope(payload []byte) ([]byte, bool) {
	if validateUniqueJSONKeys(payload) != nil {
		return nil, false
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(payload, &envelope) != nil {
		return nil, false
	}
	var messageID string
	if json.Unmarshal(envelope["message_id"], &messageID) != nil {
		return nil, false
	}
	envelope["message_id"] = json.RawMessage(`""`)
	canonical, err := json.Marshal(envelope)
	return canonical, err == nil
}

// publicationMessageID is the legacy access.v1/security.v1 identity.
func publicationMessageID(records []Record) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.analytics.publication.v1\x00"))
	for _, record := range records {
		var sequence [8]byte
		binary.BigEndian.PutUint64(sequence[:], record.Sequence)
		_, _ = hash.Write(sequence[:])
		digest := contentDigest(record.envelope)
		_, _ = hash.Write(digest[:])
	}
	return "msg_" + hex.EncodeToString(hash.Sum(nil))
}

// ValidPublicationMessageID verifies the content-bound identity emitted by this package.
func ValidPublicationMessageID(publication Publication) bool {
	if publication.FirstSequence == 0 || publication.LastSequence < publication.FirstSequence ||
		publication.EventCount != int(publication.LastSequence-publication.FirstSequence+1) {
		return false
	}
	var records []Record
	var envelopeType struct {
		SchemaVersion uint16 `json:"schema_version"`
		Type          string `json:"type"`
	}
	if err := json.Unmarshal(publication.Payload, &envelopeType); err != nil {
		return false
	}
	v2 := envelopeType.SchemaVersion == analyticsIngestVersionV2
	switch envelopeType.Type {
	case string(EventAccess), analyticsAccessTypeV2:
		var envelope analyticsAccessEnvelope
		if !decodePublicationEnvelope(publication.Payload, &envelope) || len(envelope.Events) != publication.EventCount ||
			envelope.SchemaVersion != envelopeType.SchemaVersion || envelope.MessageID != publication.MessageID ||
			envelope.InstallationID != "" ||
			(v2 && envelope.Type != analyticsAccessTypeV2) || (!v2 && (envelope.SchemaVersion != 1 || envelope.Type != string(EventAccess))) {
			return false
		}
		records = make([]Record, len(envelope.Events))
		for index, event := range envelope.Events {
			if event.InstallationID != "" {
				return false
			}
			stored := Envelope{
				SchemaVersion: SchemaVersion, Type: EventAccess, EventID: event.EventID,
				Sequence: publication.FirstSequence + uint64(index), OccurredAt: event.OccurredAt,
				TenantID: event.TenantID, SiteID: event.SiteID, NodeID: event.NodeID,
				ConfigVersionID: event.ConfigVersion, CapturePolicyRevision: event.CapturePolicyRevision,
				CapturePolicyDigest: event.CapturePolicyDigest, TaskID: event.TaskID, RequestID: event.RequestID,
				TraceID: event.TraceID, Host: event.Host, Path: event.Path, ClientIP: event.ClientIP,
				CountryCode: event.CountryCode, Carrier: event.Carrier, Method: event.Method, ListenPort: event.ListenPort,
				Protocol: event.Protocol, CacheStatus: event.CacheStatus, UpstreamResult: event.UpstreamResult,
				StatusCode: event.StatusCode, RequestBytes: event.RequestBytes, ResponseBytes: event.ResponseBytes,
				DurationUS: event.DurationUS, JA4: event.JA4, OriginConnectUS: event.OriginConnectUS,
				OriginFirstByteUS: event.OriginFirstByteUS, OriginTotalUS: event.OriginTotalUS,
				RequestHeaders: event.RequestHeaders, ResponseHeaders: event.ResponseHeaders,
				RequestBody: event.RequestBody, ResponseBody: event.ResponseBody, Blocked: event.Blocked,
				ClientBrowser: event.ClientBrowser, ClientOS: event.ClientOS, UpstreamAddr: event.UpstreamAddr,
			}
			if event.MetricVersion != analyticsMetricVersion || envelope.TenantID != stored.TenantID ||
				envelope.NodeID != stored.NodeID || validateEnvelope(stored, identityStored) != nil {
				return false
			}
			records[index] = recordForPublicationIdentity(stored)
		}
	case string(EventSecurity), analyticsSecurityTypeV2:
		var envelope analyticsSecurityEnvelope
		if !decodePublicationEnvelope(publication.Payload, &envelope) || len(envelope.Events) != publication.EventCount ||
			envelope.SchemaVersion != envelopeType.SchemaVersion || envelope.MessageID != publication.MessageID ||
			envelope.InstallationID != "" ||
			(v2 && envelope.Type != analyticsSecurityTypeV2) || (!v2 && (envelope.SchemaVersion != 1 || envelope.Type != string(EventSecurity))) {
			return false
		}
		records = make([]Record, len(envelope.Events))
		for index, event := range envelope.Events {
			if event.InstallationID != "" {
				return false
			}
			stored := Envelope{
				SchemaVersion: SchemaVersion, Type: EventSecurity, EventID: event.EventID,
				Sequence: publication.FirstSequence + uint64(index), OccurredAt: event.OccurredAt,
				TenantID: event.TenantID, SiteID: event.SiteID, NodeID: event.NodeID,
				ConfigVersionID: event.ConfigVersion, CapturePolicyRevision: event.CapturePolicyRevision,
				CapturePolicyDigest: event.CapturePolicyDigest, TaskID: event.TaskID, RequestID: event.RequestID,
				TraceID: event.TraceID, Host: event.Host, Path: event.Path, ClientIP: event.ClientIP,
				CountryCode: event.CountryCode, Carrier: event.Carrier, Method: event.Method,
				ListenPort: event.ListenPort, DestinationPort: event.DestinationPort, Protocol: event.Protocol, RequestClass: event.RequestClass,
				SecurityType: event.EventType,
				Action:       event.Action, Severity: event.Severity, RuleID: event.RuleID, StatusCode: event.StatusCode,
				PolicyID: event.PolicyID, Detector: event.Detector, Matched: event.Matched, UserAgent: event.UserAgent,
				RequestBodyExcerpt: event.RequestBodyExcerpt, Count: event.Count,
				RequestBytes: event.RequestBytes, ResponseBytes: event.ResponseBytes, JA4: event.JA4,
				OriginConnectUS: event.OriginConnectUS, OriginFirstByteUS: event.OriginFirstByteUS,
				OriginTotalUS: event.OriginTotalUS, RequestHeaders: event.RequestHeaders,
				ResponseHeaders: event.ResponseHeaders, RequestBody: event.RequestBody,
				ResponseBody: event.ResponseBody,
			}
			if event.MetricVersion != analyticsMetricVersion || envelope.TenantID != stored.TenantID ||
				envelope.NodeID != stored.NodeID || validateEnvelope(stored, identityStored) != nil {
				return false
			}
			records[index] = recordForPublicationIdentity(stored)
		}
	default:
		return false
	}
	if v2 {
		canonical, ok := canonicalPublicationV2Envelope(publication.Payload)
		return ok && publication.MessageID == publicationV2MessageID(publication.FirstSequence, publication.LastSequence, canonical)
	}
	return publication.MessageID == publicationMessageID(records)
}

func decodePublicationEnvelope(payload []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination) == nil && decoder.Decode(&struct{}{}) == io.EOF
}

func recordForPublicationIdentity(envelope Envelope) Record {
	return Record{
		Sequence: envelope.Sequence, EventID: envelope.EventID, TenantID: envelope.TenantID,
		NodeID: envelope.NodeID, Type: envelope.Type, OccurredAt: envelope.OccurredAt, envelope: envelope,
	}
}

func analyticsAccessFrom(event Envelope) analyticsAccessEvent {
	return analyticsAccessEvent{
		MetricVersion: analyticsMetricVersion, EventID: event.EventID, OccurredAt: event.OccurredAt,
		TenantID: event.TenantID, SiteID: event.SiteID, NodeID: event.NodeID,
		RequestID: event.RequestID, TraceID: event.TraceID, ConfigVersion: event.ConfigVersionID,
		CapturePolicyRevision: event.CapturePolicyRevision, CapturePolicyDigest: event.CapturePolicyDigest, TaskID: event.TaskID,
		Host: event.Host, Path: event.Path, ClientIP: event.ClientIP, CountryCode: event.CountryCode, Carrier: event.Carrier,
		Method: event.Method, ListenPort: event.ListenPort, Protocol: event.Protocol, CacheStatus: event.CacheStatus, UpstreamResult: event.UpstreamResult,
		StatusCode: event.StatusCode, RequestBytes: event.RequestBytes, ResponseBytes: event.ResponseBytes, DurationUS: event.DurationUS,
		JA4: event.JA4, OriginConnectUS: event.OriginConnectUS, OriginFirstByteUS: event.OriginFirstByteUS, OriginTotalUS: event.OriginTotalUS,
		RequestHeaders: event.RequestHeaders, ResponseHeaders: event.ResponseHeaders,
		RequestBody: event.RequestBody, ResponseBody: event.ResponseBody, Blocked: event.Blocked,
		ClientBrowser: event.ClientBrowser, ClientOS: event.ClientOS, UpstreamAddr: event.UpstreamAddr,
	}
}

func analyticsSecurityFrom(event Envelope) analyticsSecurityEvent {
	return analyticsSecurityEvent{
		MetricVersion: analyticsMetricVersion, EventID: event.EventID, OccurredAt: event.OccurredAt,
		TenantID: event.TenantID, SiteID: event.SiteID, NodeID: event.NodeID,
		RequestID: event.RequestID, TraceID: event.TraceID, ConfigVersion: event.ConfigVersionID,
		CapturePolicyRevision: event.CapturePolicyRevision, CapturePolicyDigest: event.CapturePolicyDigest, TaskID: event.TaskID,
		Host: event.Host, Path: event.Path, ClientIP: event.ClientIP, CountryCode: event.CountryCode, Carrier: event.Carrier,
		Method: event.Method, ListenPort: event.ListenPort, DestinationPort: event.DestinationPort, Protocol: event.Protocol, RequestClass: event.RequestClass,
		EventType: event.SecurityType, Action: event.Action, Severity: event.Severity, RuleID: event.RuleID,
		PolicyID: event.PolicyID, Detector: event.Detector, Matched: event.Matched, UserAgent: event.UserAgent,
		RequestBodyExcerpt: event.RequestBodyExcerpt, Count: event.Count,
		StatusCode: event.StatusCode, RequestBytes: event.RequestBytes, ResponseBytes: event.ResponseBytes,
		JA4: event.JA4, OriginConnectUS: event.OriginConnectUS, OriginFirstByteUS: event.OriginFirstByteUS, OriginTotalUS: event.OriginTotalUS,
		RequestHeaders: event.RequestHeaders, ResponseHeaders: event.ResponseHeaders,
		RequestBody: event.RequestBody, ResponseBody: event.ResponseBody,
	}
}

func validateConnectionsEnvelope(envelope *agentv1.ConnectionsMetricEnvelopeV1) error {
	if envelope == nil || (envelope.GetSchemaVersion() != 1 && envelope.GetSchemaVersion() != 2) || envelope.GetEvent() == nil {
		return ErrInvalidConnections
	}
	if envelope.GetDependencyState() != agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY {
		return ErrConnectionsUnavailable
	}
	event := envelope.GetEvent()
	if !idPattern.MatchString(event.GetEventId()) || len(event.GetEventId()) > 128 ||
		!validUUID(envelope.GetTenantId()) || !validUUID(envelope.GetInstallationId()) || !validUUID(envelope.GetSiteId()) ||
		!validBounded(envelope.GetPackageSubscriptionId(), 128) || !validUUID(envelope.GetNodeId()) ||
		!validConnectionsDomain(envelope.GetDomain()) || envelope.GetListenPort() == 0 || envelope.GetListenPort() > 65535 ||
		(envelope.GetSchemaVersion() == 1 && (envelope.GetConnections() == 0 || envelope.GetConfigVersionId() != "")) ||
		(envelope.GetSchemaVersion() == 2 && !validUUID(envelope.GetConfigVersionId())) ||
		len(envelope.GetCanonicalEventSha256()) != sha256.Size || allZeroBytes(envelope.GetCanonicalEventSha256()) ||
		len(envelope.GetEvidenceSha256()) != sha256.Size || allZeroBytes(envelope.GetEvidenceSha256()) ||
		envelope.GetSourceWatermark() == 0 || event.GetOccurredTime() == nil || event.GetOccurredTime().CheckValid() != nil ||
		envelope.GetFinalizedThrough() == nil || envelope.GetFinalizedThrough().CheckValid() != nil {
		return ErrInvalidConnections
	}
	occurred := event.GetOccurredTime().AsTime()
	finalized := envelope.GetFinalizedThrough().AsTime()
	if occurred.IsZero() || finalized.IsZero() || finalized.Before(occurred) {
		return ErrInvalidConnections
	}
	return nil
}

func validConnectionsDomain(value string) bool {
	if !validRequired(value, 128) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
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

func connectionsIdentityDigest(envelope *agentv1.ConnectionsMetricEnvelopeV1) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.connections.identity.v1\x00"))
	writeConnectionsPart(hash, envelope.GetTenantId())
	writeConnectionsPart(hash, envelope.GetInstallationId())
	writeConnectionsPart(hash, envelope.GetSiteId())
	writeConnectionsPart(hash, envelope.GetPackageSubscriptionId())
	writeConnectionsPart(hash, envelope.GetNodeId())
	writeConnectionsPart(hash, envelope.GetDomain())
	var listenPort [4]byte
	binary.BigEndian.PutUint32(listenPort[:], envelope.GetListenPort())
	_, _ = hash.Write(listenPort[:])
	writeConnectionsPart(hash, envelope.GetEvent().GetEventId())
	if occurred := envelope.GetEvent().GetOccurredTime(); occurred != nil {
		var timestamp [12]byte
		binary.BigEndian.PutUint64(timestamp[:8], uint64(occurred.GetSeconds()))
		binary.BigEndian.PutUint32(timestamp[8:], uint32(occurred.GetNanos()))
		_, _ = hash.Write(timestamp[:])
	}
	writeConnectionsPart(hash, envelope.GetCanonicalEventSha256())
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func writeConnectionsPart(destination hash.Hash, value any) {
	var encoded []byte
	switch value := value.(type) {
	case string:
		encoded = []byte(value)
	case []byte:
		encoded = value
	default:
		return
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write(encoded)
}

func connectionsMessageID(identity [sha256.Size]byte) string {
	return "conn_" + hex.EncodeToString(identity[:])
}

func connectionsPublication(entry connectionsQueueEntry) Publication {
	var envelope agentv1.ConnectionsMetricEnvelopeV1
	if err := proto.Unmarshal(entry.Payload, &envelope); err != nil {
		return Publication{}
	}
	return Publication{
		Subject:   connectionsSubjectPrefix + "." + strings.ToLower(envelope.GetInstallationId()),
		MessageID: entry.MessageID, Payload: append([]byte(nil), entry.Payload...),
		FirstSequence: entry.Sequence, LastSequence: entry.Sequence, LastEventID: entry.EventID, EventCount: 1,
	}
}

// ValidConnectionsPublication verifies the bounded protobuf carrier and its
// content-bound publication identity before a publisher accepts the message.
func ValidConnectionsPublication(publication Publication) bool {
	if publication.FirstSequence == 0 || publication.LastSequence != publication.FirstSequence ||
		publication.EventCount != 1 || publication.LastEventID == "" {
		return false
	}
	var envelope agentv1.ConnectionsMetricEnvelopeV1
	if proto.Unmarshal(publication.Payload, &envelope) != nil || validateConnectionsEnvelope(&envelope) != nil {
		return false
	}
	identity := connectionsIdentityDigest(&envelope)
	return publication.MessageID == connectionsMessageID(identity) && publication.LastEventID == envelope.GetEvent().GetEventId() &&
		publication.Subject == connectionsSubjectPrefix+"."+strings.ToLower(envelope.GetInstallationId())
}
