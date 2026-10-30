package analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrIngestHistoryGenerationChanged     = errors.New("analytics ingest history generation changed")
	ErrIngestHistoryGenerationUnavailable = errors.New("analytics ingest history generation unavailable")
	ErrIngestReceiptConflict              = errors.New("analytics ingest receipt conflicts with durable identity")
	ErrIngestRecoveryFenced               = errors.New("analytics ingest recovery claim was fenced")
	ErrIngestWriteOutcomeUnknown          = errors.New("analytics ingest write outcome is unknown")
)

const RejectReceiptConflict = "RECEIPT_CONFLICT"

type IngestHistoryGenerationV1 struct {
	InstallationID          string
	NATSDomain              string
	StreamName              string
	DurableName             string
	StreamCreatedUnixNano   uint64
	ConsumerCreatedUnixNano uint64
	HistoryEpoch            string
	HistoryStartSequence    uint64
}

type IngestReceiptKeyV1 struct {
	InstallationID          string
	NATSDomain              string
	StreamName              string
	DurableName             string
	StreamCreatedUnixNano   uint64
	ConsumerCreatedUnixNano uint64
	HistoryEpoch            string
	StreamSequence          uint64
}

type IngestReceiptV1 struct {
	SchemaVersion             uint16
	Key                       IngestReceiptKeyV1
	MessageID                 string
	PayloadSHA256             [sha256.Size]byte
	CanonicalEventSHA256      [sha256.Size]byte
	GenerationSHA256          [sha256.Size]byte
	ReceiptIdentitySHA256     [sha256.Size]byte
	ClickHouseToken           string
	RealtimeExpectedCounts    []RealtimeExpectedCountV1
	AccessWindowContributions []AccessWindowContributionV1
}

type RealtimeExpectedCountV1 struct {
	Hour       time.Time
	TenantID   string
	SiteID     string
	Host       string
	ListenPort uint16
	EventCount uint16
}

type IngestReceiptStateV1 uint8

const (
	IngestReceiptStateReceived IngestReceiptStateV1 = iota + 1
	IngestReceiptStatePrepared
	IngestReceiptStateBrokerAckObserved
)

type IngestReceiptReplayV1 uint8

const (
	IngestReceiptReplayConflict IngestReceiptReplayV1 = iota
	IngestReceiptReplaySame
)

type IngestHistoryProgressV1 struct {
	Generation              IngestHistoryGenerationV1
	BrokerConsumerAckFloor  uint64
	BrokerStreamAckFloor    uint64
	PreparedStreamFloor     uint64
	CommittedStreamAckFloor uint64
	Revision                uint64
}

type IngestBrokerHistorySnapshotV1 struct {
	Generation       IngestHistoryGenerationV1
	ConsumerAckFloor uint64
	StreamAckFloor   uint64
}

type IngestRecoveryClaimV1 struct {
	RecoveryID     string
	ClaimedBy      string
	Token          string
	LeaseExpiresAt time.Time
}

type IngestHistoryAuthorityV1 interface {
	Receive(context.Context, IngestReceiptV1) (IngestReceiptStateV1, error)
	MarkPrepared(context.Context, IngestReceiptV1) (IngestHistoryProgressV1, error)
	MarkBrokerAckObserved(context.Context, IngestReceiptKeyV1) error
	ReconcileBroker(context.Context, IngestRecoveryClaimV1, IngestBrokerHistorySnapshotV1) (IngestHistoryProgressV1, error)
	ScheduleRecovery(context.Context, IngestHistoryGenerationV1) error
	ClaimScheduledRecovery(context.Context, IngestHistoryGenerationV1) (IngestRecoveryClaimV1, bool, error)
	CompleteScheduledRecovery(context.Context, IngestRecoveryClaimV1) error
}

func ValidateIngestHistoryGenerationV1(generation IngestHistoryGenerationV1) error {
	if !validBatchID(generation.InstallationID) ||
		(generation.NATSDomain != "" && !validNATSName(generation.NATSDomain)) ||
		!validNATSName(generation.StreamName) || !validNATSName(generation.DurableName) ||
		generation.StreamCreatedUnixNano == 0 || generation.ConsumerCreatedUnixNano < generation.StreamCreatedUnixNano ||
		!validUUID(generation.HistoryEpoch) || nilUUID(generation.HistoryEpoch) || generation.HistoryStartSequence == 0 {
		return ErrInvalidInput
	}
	return nil
}

func ValidateIngestReceiptKeyV1(generation IngestHistoryGenerationV1, key IngestReceiptKeyV1) error {
	if err := ValidateIngestHistoryGenerationV1(generation); err != nil {
		return err
	}
	if key.InstallationID != generation.InstallationID || key.NATSDomain != generation.NATSDomain ||
		key.StreamName != generation.StreamName || key.DurableName != generation.DurableName ||
		key.StreamCreatedUnixNano != generation.StreamCreatedUnixNano || key.ConsumerCreatedUnixNano != generation.ConsumerCreatedUnixNano ||
		key.HistoryEpoch != generation.HistoryEpoch {
		return ErrIngestHistoryGenerationChanged
	}
	if key.StreamSequence < generation.HistoryStartSequence {
		return ErrInvalidInput
	}
	return nil
}

func NewIngestReceiptV1(generation IngestHistoryGenerationV1, sequence uint64, decoded DecodedIngest) (IngestReceiptV1, error) {
	if err := ValidateIngestHistoryGenerationV1(generation); err != nil {
		return IngestReceiptV1{}, err
	}
	if decoded.InstallationID != generation.InstallationID || decoded.MessageID == "" || decoded.PayloadDigest == ([sha256.Size]byte{}) {
		return IngestReceiptV1{}, ErrInvalidInput
	}
	key := IngestReceiptKeyV1{
		InstallationID: generation.InstallationID, NATSDomain: generation.NATSDomain,
		StreamName: generation.StreamName, DurableName: generation.DurableName,
		StreamCreatedUnixNano: generation.StreamCreatedUnixNano, ConsumerCreatedUnixNano: generation.ConsumerCreatedUnixNano,
		HistoryEpoch: generation.HistoryEpoch, StreamSequence: sequence,
	}
	if err := ValidateIngestReceiptKeyV1(generation, key); err != nil {
		return IngestReceiptV1{}, err
	}
	canonical, err := CanonicalIngestDigestV1(decoded)
	if err != nil {
		return IngestReceiptV1{}, err
	}
	generationDigest := canonicalGenerationDigestV1(generation)
	receipt := IngestReceiptV1{
		SchemaVersion: 1, Key: key, MessageID: decoded.MessageID, PayloadSHA256: decoded.PayloadDigest,
		CanonicalEventSHA256: canonical, GenerationSHA256: generationDigest,
	}
	receipt.RealtimeExpectedCounts, err = realtimeExpectedCountsV1(decoded)
	if err != nil {
		return IngestReceiptV1{}, err
	}
	receipt.AccessWindowContributions = append([]AccessWindowContributionV1(nil), decoded.AccessWindowContributions...)
	if err := validateAccessWindowContributionsV1(receipt.AccessWindowContributions); err != nil {
		return IngestReceiptV1{}, err
	}
	receipt.ReceiptIdentitySHA256 = receiptIdentityDigestV1(receipt)
	receipt.ClickHouseToken = ClickHouseIngestTokenV1(receipt)
	return receipt, nil
}

func realtimeExpectedCountsV1(decoded DecodedIngest) ([]RealtimeExpectedCountV1, error) {
	if decoded.Kind != AccessEnvelopeType && decoded.Kind != AccessEnvelopeTypeV2 {
		return nil, nil
	}
	type dimension struct {
		hour       int64
		tenantID   string
		siteID     string
		host       string
		listenPort uint16
	}
	counts := make(map[dimension]uint16)
	for _, event := range decoded.AccessEvents {
		key := dimension{
			hour: event.OccurredAt.Truncate(time.Hour).Unix(), tenantID: strings.ToLower(event.TenantID),
			siteID: strings.ToLower(event.SiteID), host: strings.ToLower(event.Host), listenPort: event.ListenPort,
		}
		if counts[key] == ^uint16(0) {
			return nil, ErrInvalidInput
		}
		counts[key]++
	}
	result := make([]RealtimeExpectedCountV1, 0, len(counts))
	for key, count := range counts {
		result = append(result, RealtimeExpectedCountV1{
			Hour: time.Unix(key.hour, 0).UTC(), TenantID: key.tenantID, SiteID: key.siteID,
			Host: key.host, ListenPort: key.listenPort, EventCount: count,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if !left.Hour.Equal(right.Hour) {
			return left.Hour.Before(right.Hour)
		}
		if left.TenantID != right.TenantID {
			return left.TenantID < right.TenantID
		}
		if left.SiteID != right.SiteID {
			return left.SiteID < right.SiteID
		}
		if left.Host != right.Host {
			return left.Host < right.Host
		}
		return left.ListenPort < right.ListenPort
	})
	return result, nil
}

func ClassifyIngestReceiptReplayV1(persisted, candidate IngestReceiptV1) (IngestReceiptReplayV1, error) {
	if persisted.Key != candidate.Key {
		if persisted.Key.InstallationID != candidate.Key.InstallationID || persisted.Key.NATSDomain != candidate.Key.NATSDomain ||
			persisted.Key.StreamName != candidate.Key.StreamName || persisted.Key.DurableName != candidate.Key.DurableName ||
			persisted.Key.StreamCreatedUnixNano != candidate.Key.StreamCreatedUnixNano || persisted.Key.ConsumerCreatedUnixNano != candidate.Key.ConsumerCreatedUnixNano ||
			persisted.Key.HistoryEpoch != candidate.Key.HistoryEpoch {
			return IngestReceiptReplayConflict, ErrIngestHistoryGenerationChanged
		}
		return IngestReceiptReplayConflict, ErrIngestReceiptConflict
	}
	if persisted.SchemaVersion != candidate.SchemaVersion || persisted.MessageID != candidate.MessageID ||
		persisted.PayloadSHA256 != candidate.PayloadSHA256 || persisted.CanonicalEventSHA256 != candidate.CanonicalEventSHA256 ||
		persisted.GenerationSHA256 != candidate.GenerationSHA256 || persisted.ReceiptIdentitySHA256 != candidate.ReceiptIdentitySHA256 ||
		persisted.ClickHouseToken != candidate.ClickHouseToken {
		return IngestReceiptReplayConflict, ErrIngestReceiptConflict
	}
	return IngestReceiptReplaySame, nil
}

func CanonicalIngestDigestV1(decoded DecodedIngest) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	validVersionKind := decoded.SchemaVersion == IngestSchemaVersion &&
		(decoded.Kind == AccessEnvelopeType || decoded.Kind == SecurityEnvelopeType || decoded.Kind == AccessWindowEnvelopeType ||
			decoded.Kind == SubscriptionMinuteEnvelopeType) ||
		decoded.SchemaVersion == IngestSchemaVersionV2 && (decoded.Kind == AccessEnvelopeTypeV2 || decoded.Kind == SecurityEnvelopeTypeV2)
	if !validVersionKind || decoded.MessageID == "" ||
		decoded.ProducedAt.IsZero() || decoded.ProducedAt.Location() != time.UTC || !validUUID(decoded.TenantID) ||
		!validOptionalUUID(decoded.PackageSubscriptionID) ||
		!validUUID(decoded.NodeID) || !validInstallation(decoded.InstallationID) || decoded.PayloadDigest == ([sha256.Size]byte{}) {
		return digest, ErrInvalidInput
	}
	for _, event := range decoded.AccessEvents {
		if !validOptionalUUID(event.PackageSubscriptionID) || event.PackageSubscriptionID != decoded.PackageSubscriptionID {
			return digest, ErrInvalidInput
		}
	}
	for _, event := range decoded.SecurityEvents {
		if !validOptionalUUID(event.PackageSubscriptionID) || event.PackageSubscriptionID != decoded.PackageSubscriptionID {
			return digest, ErrInvalidInput
		}
	}
	for _, contribution := range decoded.AccessWindowContributions {
		if contribution.TenantID != decoded.TenantID || contribution.NodeID != decoded.NodeID ||
			contribution.InstallationID != decoded.InstallationID ||
			contribution.PackageSubscriptionID != decoded.PackageSubscriptionID {
			return digest, ErrInvalidInput
		}
	}
	value := map[string]any{
		"schema_version": decoded.SchemaVersion, "kind": decoded.Kind, "message_id": decoded.MessageID,
		"produced_at": decoded.ProducedAt.UTC().Format(time.RFC3339Nano), "tenant_id": decoded.TenantID,
		"package_subscription_id": decoded.PackageSubscriptionID, "node_id": decoded.NodeID, "installation_id": decoded.InstallationID,
		"payload_sha256":  hex.EncodeToString(decoded.PayloadDigest[:]),
		"access_events":   canonicalAccessEventsV1(decoded.AccessEvents),
		"security_events": canonicalSecurityEventsV1(decoded.SecurityEvents),
	}
	if decoded.Kind == AccessWindowEnvelopeType {
		value["access_window_contributions"] = canonicalAccessWindowContributionsV1(decoded.AccessWindowContributions)
	}
	if decoded.Kind == SubscriptionMinuteEnvelopeType {
		value["subscription_minutes"] = canonicalSubscriptionMinutesV1(decoded.SubscriptionMinutes)
	}
	encoded, err := canonicalJSONV1(value)
	if err != nil {
		return digest, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func canonicalAccessWindowContributionsV1(contributions []AccessWindowContributionV1) []any {
	values := make([]any, 0, len(contributions))
	for _, contribution := range contributions {
		values = append(values, map[string]any{
			"metric_version": contribution.MetricVersion, "event_id": contribution.EventID,
			"window_start": contribution.WindowStart.UTC().Format(time.RFC3339Nano),
			"window_end":   contribution.WindowEnd.UTC().Format(time.RFC3339Nano),
			"tenant_id":    contribution.TenantID, "package_subscription_id": contribution.PackageSubscriptionID,
			"site_id": contribution.SiteID, "node_id": contribution.NodeID,
			"installation_id": contribution.InstallationID, "config_version_id": contribution.ConfigVersionID,
			"host": contribution.Host, "listen_port": contribution.ListenPort,
			"source_watermark":  contribution.SourceWatermark,
			"finalized_through": contribution.FinalizedThrough.UTC().Format(time.RFC3339Nano),
			"dependency_state":  contribution.DependencyState,
			"evidence_sha256":   hex.EncodeToString(contribution.EvidenceSHA256[:]),
		})
	}
	return values
}

func validateAccessWindowContributionsV1(contributions []AccessWindowContributionV1) error {
	if len(contributions) > 1 {
		return ErrIngestReceiptConflict
	}
	for _, contribution := range contributions {
		if contribution.MetricVersion != MetricVersion || !validBatchID(contribution.EventID) ||
			contribution.WindowStart.IsZero() || contribution.WindowStart.Location() != time.UTC ||
			!contribution.WindowStart.Equal(contribution.WindowStart.Truncate(time.Hour)) ||
			!contribution.WindowEnd.Equal(contribution.WindowStart.Add(time.Hour)) ||
			!contribution.FinalizedThrough.Equal(contribution.WindowEnd) ||
			!validUUID(contribution.TenantID) || nilUUID(contribution.TenantID) || strings.ToLower(contribution.TenantID) != contribution.TenantID ||
			!validOptionalUUID(contribution.PackageSubscriptionID) || strings.ToLower(contribution.PackageSubscriptionID) != contribution.PackageSubscriptionID ||
			!validUUID(contribution.SiteID) || nilUUID(contribution.SiteID) || strings.ToLower(contribution.SiteID) != contribution.SiteID ||
			!validUUID(contribution.NodeID) || nilUUID(contribution.NodeID) || strings.ToLower(contribution.NodeID) != contribution.NodeID ||
			!validInstallation(contribution.InstallationID) ||
			!validUUID(contribution.ConfigVersionID) || nilUUID(contribution.ConfigVersionID) || strings.ToLower(contribution.ConfigVersionID) != contribution.ConfigVersionID ||
			!validConnectionDomain(contribution.Host) || contribution.ListenPort == 0 || contribution.SourceWatermark == 0 ||
			contribution.DependencyState != "ready" || contribution.EvidenceSHA256 == ([sha256.Size]byte{}) {
			return ErrIngestReceiptConflict
		}
	}
	return nil
}

func canonicalAccessEventsV1(events []AccessEvent) []any {
	values := make([]any, 0, len(events))
	for _, event := range events {
		value := map[string]any{
			"metric_version": event.MetricVersion, "event_id": event.EventID, "occurred_at": event.OccurredAt.UTC().Format(time.RFC3339Nano),
			"tenant_id": event.TenantID, "package_subscription_id": event.PackageSubscriptionID,
			"site_id": event.SiteID, "node_id": event.NodeID, "request_id": event.RequestID,
			"trace_id": event.TraceID, "config_version_id": event.ConfigVersion, "host": event.Host, "path": event.Path,
			"client_ip": event.ClientIP, "country_code": event.CountryCode, "carrier": event.Carrier, "method": event.Method,
			"protocol": event.Protocol, "cache_status": event.CacheStatus, "upstream_result": event.UpstreamResult,
			"status_code": event.StatusCode, "request_bytes": event.RequestBytes, "response_bytes": event.ResponseBytes,
			"duration_us": event.DurationUS, "request_headers": event.RequestHeaders, "response_headers": event.ResponseHeaders,
			"request_body": event.RequestBody, "response_body": event.ResponseBody, "task_id": event.TaskID,
			"installation_id": event.InstallationID, "ja4": event.JA4, "origin_connect_us": event.OriginConnectUS,
			"origin_first_byte_us": event.OriginFirstByteUS, "origin_total_us": event.OriginTotalUS,
		}
		if event.ListenPort != 0 {
			value["listen_port"] = event.ListenPort
		}
		// Only present when set, so digests of untagged events are unchanged.
		if event.Blocked {
			value["blocked"] = true
		}
		if event.ClientBrowser != "" {
			value["client_browser"] = event.ClientBrowser
		}
		if event.ClientOS != "" {
			value["client_os"] = event.ClientOS
		}
		if event.UpstreamAddr != "" {
			value["upstream_addr"] = event.UpstreamAddr
		}
		// Province is filled after decode (ingest geo enrichment), so a
		// receipt's digest never has it; present only when set.
		if event.Province != "" {
			value["province"] = event.Province
		}
		values = append(values, value)
	}
	return values
}

func canonicalSecurityEventsV1(events []SecurityEvent) []any {
	values := make([]any, 0, len(events))
	for _, event := range events {
		value := map[string]any{
			"metric_version": event.MetricVersion, "event_id": event.EventID, "occurred_at": event.OccurredAt.UTC().Format(time.RFC3339Nano),
			"tenant_id": event.TenantID, "package_subscription_id": event.PackageSubscriptionID,
			"site_id": event.SiteID, "node_id": event.NodeID, "request_id": event.RequestID,
			"trace_id": event.TraceID, "config_version_id": event.ConfigVersion, "host": event.Host, "path": event.Path,
			"client_ip": event.ClientIP, "country_code": event.CountryCode, "carrier": event.Carrier,
			"event_type": event.EventType, "action": event.Action, "severity": event.Severity, "rule_id": event.RuleID,
			"status_code": event.StatusCode, "request_bytes": event.RequestBytes, "response_bytes": event.ResponseBytes,
			"request_headers": event.RequestHeaders, "response_headers": event.ResponseHeaders, "request_body": event.RequestBody,
			"response_body": event.ResponseBody, "task_id": event.TaskID, "installation_id": event.InstallationID,
			"ja4": event.JA4, "origin_connect_us": event.OriginConnectUS, "origin_first_byte_us": event.OriginFirstByteUS,
			"origin_total_us": event.OriginTotalUS,
		}
		if event.Method != "" || event.ListenPort != 0 || event.DestinationPort != 0 || event.Protocol != "" || event.RequestClass != "" {
			value["method"] = event.Method
			value["listen_port"] = event.ListenPort
			value["destination_port"] = event.DestinationPort
			value["protocol"] = event.Protocol
			value["request_class"] = event.RequestClass
		}
		// Attack evidence (ge-waf S4) only when present: events without it
		// keep their digest.
		for key, field := range map[string]string{"policy_id": event.PolicyID, "detector": event.Detector,
			"matched": event.Matched, "user_agent": event.UserAgent, "request_body_excerpt": event.RequestBodyExcerpt} {
			if field != "" {
				value[key] = field
			}
		}
		if event.Province != "" {
			value["province"] = event.Province
		}
		// count only for an aggregated line: other events keep their digest
		if event.Count != 0 {
			value["count"] = event.Count
		}
		values = append(values, value)
	}
	return values
}

func canonicalGenerationDigestV1(generation IngestHistoryGenerationV1) [sha256.Size]byte {
	encoded, _ := canonicalJSONV1(map[string]any{
		"installation_id": generation.InstallationID, "nats_domain": generation.NATSDomain,
		"stream_name": generation.StreamName, "durable_name": generation.DurableName,
		"stream_created_unix_nano": generation.StreamCreatedUnixNano, "consumer_created_unix_nano": generation.ConsumerCreatedUnixNano,
		"history_epoch": generation.HistoryEpoch, "history_start_sequence": generation.HistoryStartSequence,
	})
	return sha256.Sum256(encoded)
}

func receiptIdentityDigestV1(receipt IngestReceiptV1) [sha256.Size]byte {
	encoded, _ := canonicalJSONV1(map[string]any{
		"schema_version": receipt.SchemaVersion, "key": receipt.Key, "message_id": receipt.MessageID,
		"payload_sha256": hex.EncodeToString(receipt.PayloadSHA256[:]), "canonical_event_sha256": hex.EncodeToString(receipt.CanonicalEventSHA256[:]),
		"generation_sha256": hex.EncodeToString(receipt.GenerationSHA256[:]), "clickhouse_token": receipt.ClickHouseToken,
	})
	return sha256.Sum256(encoded)
}

func ClickHouseIngestTokenV1(receipt IngestReceiptV1) string {
	values := []string{
		"analytics-history-v1", receipt.Key.InstallationID, receipt.Key.NATSDomain, receipt.Key.StreamName,
		receipt.Key.DurableName, strconv.FormatUint(receipt.Key.StreamCreatedUnixNano, 10), strconv.FormatUint(receipt.Key.ConsumerCreatedUnixNano, 10),
		receipt.Key.HistoryEpoch, strconv.FormatUint(receipt.Key.StreamSequence, 10), hex.EncodeToString(receipt.PayloadSHA256[:]),
	}
	digest := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return "analytics-history-v1-" + hex.EncodeToString(digest[:])
}

func NewIngestHistoryProgressV1(generation IngestHistoryGenerationV1) (IngestHistoryProgressV1, error) {
	if err := ValidateIngestHistoryGenerationV1(generation); err != nil {
		return IngestHistoryProgressV1{}, err
	}
	start := generation.HistoryStartSequence - 1
	return IngestHistoryProgressV1{Generation: generation, BrokerConsumerAckFloor: start, BrokerStreamAckFloor: start,
		PreparedStreamFloor: start, CommittedStreamAckFloor: start, Revision: 1}, nil
}

func PrepareIngestHistoryV1(progress IngestHistoryProgressV1, sequence uint64) (IngestHistoryProgressV1, error) {
	if err := ValidateIngestHistoryGenerationV1(progress.Generation); err != nil || progress.Revision == 0 || sequence < progress.Generation.HistoryStartSequence {
		return progress, ErrInvalidInput
	}
	if sequence <= progress.PreparedStreamFloor {
		return progress, nil
	}
	progress.PreparedStreamFloor = sequence
	progress.CommittedStreamAckFloor = min(progress.PreparedStreamFloor, progress.BrokerStreamAckFloor)
	progress.Revision++
	return progress, nil
}

func ReconcileIngestHistoryV1(progress IngestHistoryProgressV1, snapshot IngestBrokerHistorySnapshotV1) (IngestHistoryProgressV1, error) {
	if snapshot.Generation != progress.Generation {
		return progress, ErrIngestHistoryGenerationChanged
	}
	start := progress.Generation.HistoryStartSequence - 1
	// The consumer sequence counts redeliveries, so its ack floor may exceed
	// the stream ack floor (same precondition as PG analytics_history_reconcile_recovery_098).
	if snapshot.StreamAckFloor < start {
		return progress, ErrInvalidInput
	}
	changed := false
	if snapshot.ConsumerAckFloor > progress.BrokerConsumerAckFloor {
		progress.BrokerConsumerAckFloor, changed = snapshot.ConsumerAckFloor, true
	}
	if snapshot.StreamAckFloor > progress.BrokerStreamAckFloor {
		progress.BrokerStreamAckFloor, changed = snapshot.StreamAckFloor, true
	}
	committed := min(progress.PreparedStreamFloor, progress.BrokerStreamAckFloor)
	if committed != progress.CommittedStreamAckFloor {
		progress.CommittedStreamAckFloor, changed = committed, true
	}
	if changed {
		progress.Revision++
	}
	return progress, nil
}

func canonicalJSONV1(value any) ([]byte, error) {
	var encoded bytes.Buffer
	if err := writeCanonicalJSONV1(&encoded, value); err != nil {
		return nil, err
	}
	return encoded.Bytes(), nil
}

func writeCanonicalJSONV1(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case string:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		output.Write(encoded)
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case json.Number:
		if !json.Valid([]byte(typed)) {
			return ErrInvalidInput
		}
		output.WriteString(typed.String())
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonicalJSONV1(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonicalJSONV1(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := writeCanonicalJSONV1(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		var generic any
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		if err := decoder.Decode(&generic); err != nil {
			return err
		}
		return writeCanonicalJSONV1(output, generic)
	}
	return nil
}
