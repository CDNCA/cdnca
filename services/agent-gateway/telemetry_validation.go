package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/protobuf/proto"
)

const (
	telemetrySchemaVersion   = 1
	telemetrySchemaVersionV2 = 2
	telemetryMetricVersion   = 1
	telemetryMaxFutureSkew   = 5 * time.Minute

	telemetryMaxCaptureHeaderValueBytes = 16 << 10
	telemetryMaxCaptureBodyBytes        = 1 << 20
	telemetryMaxCaptureBodyDepth        = 8
	telemetryMaxCaptureBodyKeyBytes     = 128
	telemetryMaxCaptureObjectKeys       = 128
	telemetryRedactedCaptureValue       = "[REDACTED]"
)

type telemetryAuthorization struct {
	installationID     string
	tenantID           string
	configBySite       map[telemetryScopeKey]string
	subscriptionBySite map[telemetryScopeKey]string
	// scoped is set when the Agent negotiated scoped_records. Sites may then
	// belong to tenants other than the node owner, and every record must name
	// its scope; recordAuthorization narrows the view to that one tenant.
	scoped bool
	// tenantByScope and scopeBySite exist only for a scoped session. A
	// configuration scope is an access scope ID, never a tenant ID.
	tenantByScope map[string]string
	scopeBySite   map[telemetryScopeKey]string
}

type telemetryScopeKey struct {
	siteID          string
	configVersionID string
}

// validateTelemetryAuthorization accepts sites of other tenants only for a
// scoped_records session; a legacy session stays fail-closed on any site whose
// tenant differs from the node owner.
func validateTelemetryAuthorization(response *controlv1.GetNodeAuthorizationResponse, scopedRecords ...bool) (telemetryAuthorization, error) {
	scoped := len(scopedRecords) == 1 && scopedRecords[0]
	// A scoped session attributes every record through its site's scope, so it
	// does not depend on (or compare) the node owner's top-level tenant.
	if response == nil || !validTelemetryID(response.InstallationId) ||
		(!scoped && !canonicalUUID(response.TenantId)) || (scoped && response.TenantId != "" && !canonicalUUID(response.TenantId)) ||
		len(response.TelemetrySiteScopes) > telemetryMaxAuthorizationSites {
		return telemetryAuthorization{}, fmt.Errorf("telemetry authorization is incomplete")
	}
	authorization := telemetryAuthorization{
		installationID:     response.InstallationId,
		tenantID:           response.TenantId,
		configBySite:       make(map[telemetryScopeKey]string, len(response.TelemetrySiteScopes)),
		subscriptionBySite: make(map[telemetryScopeKey]string, len(response.TelemetrySiteScopes)),
		scoped:             scoped,
	}
	if scoped {
		authorization.tenantByScope = make(map[string]string)
		authorization.scopeBySite = make(map[telemetryScopeKey]string, len(response.TelemetrySiteScopes))
	}
	for _, scope := range response.TelemetrySiteScopes {
		if scope == nil || !canonicalUUID(scope.SiteId) || !canonicalUUID(scope.ConfigVersionId) ||
			(scope.PackageSubscriptionId != "" && !canonicalUUID(scope.PackageSubscriptionId)) ||
			!canonicalUUID(scope.TenantId) || (!scoped && scope.TenantId != response.TenantId) {
			return telemetryAuthorization{}, fmt.Errorf("telemetry authorization scope is invalid")
		}
		key := telemetryScopeKey{siteID: scope.SiteId, configVersionID: scope.ConfigVersionId}
		if _, duplicate := authorization.configBySite[key]; duplicate {
			return telemetryAuthorization{}, fmt.Errorf("telemetry authorization scope is duplicated")
		}
		authorization.configBySite[key] = scope.TenantId
		authorization.subscriptionBySite[key] = scope.PackageSubscriptionId
		if scoped {
			if !canonicalUUID(scope.ConfigurationScopeId) {
				return telemetryAuthorization{}, fmt.Errorf("scoped telemetry authorization site has no configuration scope")
			}
			if tenantID, exists := authorization.tenantByScope[scope.ConfigurationScopeId]; exists && tenantID != scope.TenantId {
				return telemetryAuthorization{}, fmt.Errorf("telemetry authorization maps one configuration scope to several tenants")
			}
			authorization.tenantByScope[scope.ConfigurationScopeId] = scope.TenantId
			authorization.scopeBySite[key] = scope.ConfigurationScopeId
		}
	}
	return authorization, nil
}

// recordAuthorization returns the authorization one record is validated and
// published under. A legacy session uses the node owner unchanged and must not
// name a scope. A scoped session requires a configuration scope the node
// carries; the view keeps only that scope's sites and carries that scope's
// tenant, so a payload whose tenant or site belongs elsewhere fails the
// existing per-kind checks and the record is published under the site's tenant.
func (authorization telemetryAuthorization) recordAuthorization(scopeID *string) (telemetryAuthorization, error) {
	if !authorization.scoped {
		if scopeID != nil {
			return telemetryAuthorization{}, fmt.Errorf("telemetry record scope was not negotiated")
		}
		return authorization, nil
	}
	if scopeID == nil || !canonicalUUID(*scopeID) {
		return telemetryAuthorization{}, fmt.Errorf("scoped telemetry record must name its configuration scope")
	}
	tenantID, carried := authorization.tenantByScope[*scopeID]
	if !carried {
		return telemetryAuthorization{}, fmt.Errorf("telemetry record scope is not carried by this node")
	}
	view := telemetryAuthorization{
		installationID: authorization.installationID, tenantID: tenantID, scoped: true,
		tenantByScope:      map[string]string{*scopeID: tenantID},
		scopeBySite:        make(map[telemetryScopeKey]string),
		configBySite:       make(map[telemetryScopeKey]string),
		subscriptionBySite: make(map[telemetryScopeKey]string),
	}
	for key, siteScope := range authorization.scopeBySite {
		if siteScope == *scopeID {
			view.scopeBySite[key] = siteScope
			view.configBySite[key] = authorization.configBySite[key]
			view.subscriptionBySite[key] = authorization.subscriptionBySite[key]
		}
	}
	return view, nil
}

type validatedTelemetryRecord struct {
	record          *agentv1.TelemetryRecord
	tenantID        string
	siteID          string
	configVersionID string
}

func validateTelemetryBatch(
	batch *agentv1.TelemetryBatch,
	expectedSequence uint64,
	identity nodeIdentity,
	authorization telemetryAuthorization,
	config TelemetryConfig,
	now time.Time,
) ([]validatedTelemetryRecord, error) {
	if batch == nil || !validTelemetryID(batch.BatchId) || len(batch.Records) == 0 ||
		len(batch.Records) > int(config.MaximumRecordsPerBatch) || proto.Size(batch) > config.MaximumBatchBytes {
		return nil, fmt.Errorf("telemetry batch is missing or exceeds its limits")
	}
	if batch.FirstSequence == 0 || batch.FirstSequence != expectedSequence || batch.LastSequence < batch.FirstSequence {
		return nil, fmt.Errorf("telemetry batch sequence is invalid")
	}
	if batch.Records[0] == nil || batch.Records[0].FirstSequence != batch.FirstSequence ||
		batch.Records[len(batch.Records)-1] == nil || batch.Records[len(batch.Records)-1].LastSequence != batch.LastSequence {
		return nil, fmt.Errorf("telemetry batch boundary is invalid")
	}

	validated := make([]validatedTelemetryRecord, 0, len(batch.Records))
	messageIDs := make(map[string]struct{}, len(batch.Records))
	eventIDs := make(map[string]struct{})
	nextSequence := batch.FirstSequence
	for _, record := range batch.Records {
		if record == nil || record.FirstSequence != nextSequence || record.LastSequence < record.FirstSequence ||
			record.EventCount == 0 || uint64(record.EventCount) != record.LastSequence-record.FirstSequence+1 ||
			!validTelemetryID(record.MessageId) || !validTelemetryID(record.LastEventId) ||
			len(record.Payload) == 0 || len(record.Payload) > config.MaximumRecordBytes {
			return nil, fmt.Errorf("telemetry record is invalid")
		}
		recordAuthorization, err := authorization.recordAuthorization(record.ConfigurationScopeId)
		if err != nil {
			return nil, err
		}
		if _, duplicate := messageIDs[record.MessageId]; duplicate {
			return nil, fmt.Errorf("telemetry message identity is duplicated")
		}
		messageIDs[record.MessageId] = struct{}{}
		ids, siteID, configVersionID, err := validateTelemetryPayload(record, identity.NodeID, recordAuthorization, now.UTC())
		if err != nil {
			return nil, err
		}
		subscriptionID := recordAuthorization.subscriptionBySite[telemetryScopeKey{siteID: siteID, configVersionID: configVersionID}]
		if record.Kind == agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1 {
			if record.PackageSubscriptionId != "" {
				return nil, fmt.Errorf("L4 telemetry package subscription hint is forbidden")
			}
		} else {
			if record.PackageSubscriptionId != "" && record.PackageSubscriptionId != subscriptionID {
				return nil, fmt.Errorf("telemetry package subscription hint conflicts with authorization")
			}
			if err := bindTelemetryPackageSubscription(record, subscriptionID, recordAuthorization.installationID); err != nil ||
				len(record.Payload) > config.MaximumRecordBytes {
				return nil, fmt.Errorf("telemetry package subscription binding failed")
			}
			record.PackageSubscriptionId = subscriptionID
		}
		switch record.Kind {
		case agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_WINDOW_V1, agentv1.TelemetryKind_TELEMETRY_KIND_SUBSCRIPTION_MINUTE_V1:
		case agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V1:
			kind := "access.v1"
			if record.Kind == agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V1 {
				kind = "security.v1"
			}
			if record.MessageId != telemetryMessageID(identity.NodeID, recordAuthorization.tenantID, siteID, configVersionID,
				kind, ids[0], ids[len(ids)-1]) {
				return nil, fmt.Errorf("telemetry message identity is invalid")
			}
		case agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V2, agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V2:
		case agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1:
			if record.MessageId != l4TelemetryMessageIDFromPayload(record.Payload) {
				return nil, fmt.Errorf("L4 telemetry message identity is invalid")
			}
		default:
			return nil, fmt.Errorf("telemetry kind is unsupported")
		}
		for _, eventID := range ids {
			if _, duplicate := eventIDs[eventID]; duplicate {
				return nil, fmt.Errorf("telemetry event identity is duplicated")
			}
			eventIDs[eventID] = struct{}{}
		}
		validated = append(validated, validatedTelemetryRecord{
			record: record, tenantID: recordAuthorization.tenantID, siteID: siteID, configVersionID: configVersionID,
		})
		if record.LastSequence == ^uint64(0) {
			nextSequence = 0
		} else {
			nextSequence = record.LastSequence + 1
		}
	}
	if batch.LastSequence != batch.Records[len(batch.Records)-1].LastSequence {
		return nil, fmt.Errorf("telemetry batch boundary is invalid")
	}
	if proto.Size(batch) > config.MaximumBatchBytes {
		return nil, fmt.Errorf("telemetry batch exceeds its limit after authority binding")
	}
	if batch.BatchId != telemetryBatchID(batch.Records) {
		return nil, fmt.Errorf("telemetry batch identity is invalid")
	}
	return validated, nil
}

func telemetryMessageID(nodeID, tenantID, siteID, configVersionID, kind, firstEventID, lastEventID string) string {
	digest := sha256.Sum256([]byte(nodeID + "\x00" + tenantID + "\x00" + siteID + "\x00" + configVersionID + "\x00" +
		kind + "\x00" + firstEventID + "\x00" + lastEventID))
	return "msg_" + hex.EncodeToString(digest[:])
}

func telemetryBatchID(records []*agentv1.TelemetryRecord) string {
	hash := sha256.New()
	for _, record := range records {
		_, _ = hash.Write([]byte(record.MessageId))
		_, _ = hash.Write([]byte{0})
		_, _ = fmt.Fprintf(hash, "%d:%d:%s\n", record.FirstSequence, record.LastSequence, record.LastEventId)
	}
	return "batch_" + hex.EncodeToString(hash.Sum(nil))
}

type telemetryAccessEnvelope struct {
	SchemaVersion         uint16                 `json:"schema_version"`
	Type                  string                 `json:"type"`
	MessageID             string                 `json:"message_id"`
	ProducedAt            time.Time              `json:"produced_at"`
	TenantID              string                 `json:"tenant_id"`
	PackageSubscriptionID string                 `json:"package_subscription_id,omitempty"`
	NodeID                string                 `json:"node_id"`
	Events                []telemetryAccessEvent `json:"events"`
}

type telemetrySecurityEnvelope struct {
	SchemaVersion         uint16                   `json:"schema_version"`
	Type                  string                   `json:"type"`
	MessageID             string                   `json:"message_id"`
	ProducedAt            time.Time                `json:"produced_at"`
	TenantID              string                   `json:"tenant_id"`
	PackageSubscriptionID string                   `json:"package_subscription_id,omitempty"`
	NodeID                string                   `json:"node_id"`
	Events                []telemetrySecurityEvent `json:"events"`
}

type telemetryAccessEnvelopeV2 struct {
	SchemaVersion         uint16                   `json:"schema_version"`
	Type                  string                   `json:"type"`
	MessageID             string                   `json:"message_id"`
	ProducedAt            time.Time                `json:"produced_at"`
	TenantID              string                   `json:"tenant_id"`
	PackageSubscriptionID string                   `json:"package_subscription_id,omitempty"`
	NodeID                string                   `json:"node_id"`
	InstallationID        string                   `json:"installation_id"`
	Events                []telemetryAccessEventV2 `json:"events"`
}

type telemetrySecurityEnvelopeV2 struct {
	SchemaVersion         uint16                     `json:"schema_version"`
	Type                  string                     `json:"type"`
	MessageID             string                     `json:"message_id"`
	ProducedAt            time.Time                  `json:"produced_at"`
	TenantID              string                     `json:"tenant_id"`
	PackageSubscriptionID string                     `json:"package_subscription_id,omitempty"`
	NodeID                string                     `json:"node_id"`
	InstallationID        string                     `json:"installation_id"`
	Events                []telemetrySecurityEventV2 `json:"events"`
}

type telemetryAccessEvent struct {
	MetricVersion         uint16                  `json:"metric_version"`
	EventID               string                  `json:"event_id"`
	OccurredAt            time.Time               `json:"occurred_at"`
	TenantID              string                  `json:"tenant_id"`
	PackageSubscriptionID string                  `json:"package_subscription_id,omitempty"`
	SiteID                string                  `json:"site_id"`
	NodeID                string                  `json:"node_id"`
	RequestID             string                  `json:"request_id,omitempty"`
	TraceID               string                  `json:"trace_id,omitempty"`
	ConfigVersion         string                  `json:"config_version_id,omitempty"`
	CapturePolicyRevision uint64                  `json:"capture_policy_revision,omitempty"`
	CapturePolicyDigest   string                  `json:"capture_policy_digest,omitempty"`
	TaskID                *string                 `json:"task_id,omitempty"`
	Host                  string                  `json:"host"`
	Path                  string                  `json:"path"`
	ClientIP              string                  `json:"client_ip"`
	CountryCode           string                  `json:"country_code,omitempty"`
	Carrier               string                  `json:"carrier,omitempty"`
	Method                string                  `json:"method"`
	Protocol              string                  `json:"protocol"`
	CacheStatus           string                  `json:"cache_status"`
	UpstreamResult        string                  `json:"upstream_result,omitempty"`
	StatusCode            uint16                  `json:"status_code"`
	RequestBytes          uint64                  `json:"request_bytes"`
	ResponseBytes         uint64                  `json:"response_bytes"`
	DurationUS            uint64                  `json:"duration_us"`
	JA4                   *string                 `json:"ja4,omitempty"`
	OriginConnectUS       *uint64                 `json:"origin_connect_us,omitempty"`
	OriginFirstByteUS     *uint64                 `json:"origin_first_byte_us,omitempty"`
	OriginTotalUS         *uint64                 `json:"origin_total_us,omitempty"`
	RequestHeaders        telemetryCaptureHeaders `json:"request_headers,omitempty"`
	ResponseHeaders       telemetryCaptureHeaders `json:"response_headers,omitempty"`
	RequestBody           telemetryCaptureBody    `json:"request_body,omitempty"`
	ResponseBody          telemetryCaptureBody    `json:"response_body,omitempty"`
	// Blocked (FX60): the node answered a block page itself; package traffic
	// may exclude it. Omitted when false.
	Blocked bool `json:"blocked,omitempty"`
	// ClientBrowser / ClientOS: the client's User-Agent families the node
	// logs (edgeconfig.TelemetryClientBrowsers / TelemetryClientOSes).
	ClientBrowser string `json:"client_browser,omitempty"`
	ClientOS      string `json:"client_os,omitempty"`
	// UpstreamAddr (fix-upstreamaddr): the origin address(es) the node sent
	// the request to, at most 64 bytes; upstream_result stays the diagnostic code.
	UpstreamAddr string `json:"upstream_addr,omitempty"`
}

type telemetrySecurityEvent struct {
	MetricVersion         uint16    `json:"metric_version"`
	EventID               string    `json:"event_id"`
	OccurredAt            time.Time `json:"occurred_at"`
	TenantID              string    `json:"tenant_id"`
	PackageSubscriptionID string    `json:"package_subscription_id,omitempty"`
	SiteID                string    `json:"site_id"`
	NodeID                string    `json:"node_id"`
	RequestID             string    `json:"request_id,omitempty"`
	TraceID               string    `json:"trace_id,omitempty"`
	ConfigVersion         string    `json:"config_version_id,omitempty"`
	CapturePolicyRevision uint64    `json:"capture_policy_revision,omitempty"`
	CapturePolicyDigest   string    `json:"capture_policy_digest,omitempty"`
	TaskID                *string   `json:"task_id,omitempty"`
	Host                  string    `json:"host"`
	Path                  string    `json:"path"`
	ClientIP              string    `json:"client_ip"`
	CountryCode           string    `json:"country_code,omitempty"`
	Carrier               string    `json:"carrier,omitempty"`
	Method                string    `json:"method"`
	ListenPort            uint16    `json:"listen_port"`
	DestinationPort       uint16    `json:"destination_port,omitempty"`
	Protocol              string    `json:"protocol"`
	RequestClass          string    `json:"request_class"`
	EventType             string    `json:"event_type"`
	Action                string    `json:"action"`
	Severity              string    `json:"severity"`
	RuleID                string    `json:"rule_id,omitempty"`
	PolicyID              string    `json:"policy_id,omitempty"`
	Detector              string    `json:"detector,omitempty"`
	Matched               string    `json:"matched,omitempty"`
	UserAgent             string    `json:"user_agent,omitempty"`
	RequestBodyExcerpt    string    `json:"request_body_excerpt,omitempty"`
	// Count: requests an aggregated line stands for (sec-log-agg); 0 = one.
	Count             uint32                  `json:"count,omitempty"`
	StatusCode        uint16                  `json:"status_code"`
	RequestBytes      uint64                  `json:"request_bytes"`
	ResponseBytes     uint64                  `json:"response_bytes"`
	JA4               *string                 `json:"ja4,omitempty"`
	OriginConnectUS   *uint64                 `json:"origin_connect_us,omitempty"`
	OriginFirstByteUS *uint64                 `json:"origin_first_byte_us,omitempty"`
	OriginTotalUS     *uint64                 `json:"origin_total_us,omitempty"`
	RequestHeaders    telemetryCaptureHeaders `json:"request_headers,omitempty"`
	ResponseHeaders   telemetryCaptureHeaders `json:"response_headers,omitempty"`
	RequestBody       telemetryCaptureBody    `json:"request_body,omitempty"`
	ResponseBody      telemetryCaptureBody    `json:"response_body,omitempty"`
}

type telemetryAccessEventV2 struct {
	telemetryAccessEvent
	InstallationID string `json:"installation_id"`
	ListenPort     uint16 `json:"listen_port"`
}

type telemetrySecurityEventV2 struct {
	telemetrySecurityEvent
	InstallationID string `json:"installation_id"`
}

type telemetryCaptureHeaders map[string]string

func (headers *telemetryCaptureHeaders) UnmarshalJSON(payload []byte) error {
	payload = bytes.TrimSpace(payload)
	if bytes.Equal(payload, []byte("null")) {
		*headers = nil
		return nil
	}
	if len(payload) == 0 || payload[0] != '{' {
		return fmt.Errorf("telemetry capture headers must be an object")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return err
	}
	decoded := make(telemetryCaptureHeaders, len(raw))
	for name, value := range raw {
		value = bytes.TrimSpace(value)
		if len(value) == 0 || value[0] != '"' {
			return fmt.Errorf("telemetry capture header value must be a string")
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return err
		}
		decoded[name] = text
	}
	*headers = decoded
	return nil
}

type telemetryCaptureBody map[string]any

func (body *telemetryCaptureBody) UnmarshalJSON(payload []byte) error {
	payload = bytes.TrimSpace(payload)
	if bytes.Equal(payload, []byte("null")) {
		*body = nil
		return nil
	}
	if len(payload) == 0 || payload[0] != '{' {
		return fmt.Errorf("telemetry capture body must be an object")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*body = decoded
	return nil
}

func validateTelemetryPayload(
	record *agentv1.TelemetryRecord,
	nodeID string,
	authorization telemetryAuthorization,
	now time.Time,
) ([]string, string, string, error) {
	if record.Kind != agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1 &&
		(!utf8.Valid(record.Payload) || validateTelemetryUniqueJSONKeys(record.Payload) != nil) {
		return nil, "", "", fmt.Errorf("telemetry payload is not strict JSON")
	}
	switch record.Kind {
	case agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_WINDOW_V1:
		return validateAccessWindowTelemetry(record, nodeID, authorization, now)
	case agentv1.TelemetryKind_TELEMETRY_KIND_SUBSCRIPTION_MINUTE_V1:
		return validateSubscriptionMinuteTelemetry(record, nodeID, authorization, now)
	case agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1:
		return validateL4TelemetryPayload(record, nodeID, authorization, now)
	case agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1:
		var envelope telemetryAccessEnvelope
		if err := decodeStrictTelemetryJSON(record.Payload, &envelope); err != nil ||
			envelope.SchemaVersion != telemetrySchemaVersion || envelope.Type != "access.v1" ||
			envelope.MessageID != record.MessageId || envelope.TenantID != authorization.tenantID || envelope.NodeID != nodeID ||
			!validProducedAt(envelope.ProducedAt, now) || len(envelope.Events) != int(record.EventCount) {
			return nil, "", "", fmt.Errorf("telemetry access envelope is invalid")
		}
		ids := make([]string, 0, len(envelope.Events))
		var siteID, configVersionID, capturePolicyDigest string
		var capturePolicyRevision uint64
		for index, event := range envelope.Events {
			if !validTelemetryAccessEvent(event, envelope, authorization, now) {
				return nil, "", "", fmt.Errorf("telemetry access event is invalid")
			}
			if index == 0 {
				siteID, configVersionID = event.SiteID, event.ConfigVersion
				capturePolicyRevision, capturePolicyDigest = event.CapturePolicyRevision, event.CapturePolicyDigest
			} else if event.SiteID != siteID || event.ConfigVersion != configVersionID ||
				event.CapturePolicyRevision != capturePolicyRevision || event.CapturePolicyDigest != capturePolicyDigest {
				return nil, "", "", fmt.Errorf("telemetry access record mixes authority scopes")
			}
			ids = append(ids, event.EventID)
		}
		if len(ids) == 0 || ids[len(ids)-1] != record.LastEventId ||
			envelope.PackageSubscriptionID != "" &&
				envelope.PackageSubscriptionID != authorization.subscriptionBySite[telemetryScopeKey{siteID: siteID, configVersionID: configVersionID}] {
			return nil, "", "", fmt.Errorf("telemetry access boundary is invalid")
		}
		return ids, siteID, configVersionID, nil
	case agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V1:
		var envelope telemetrySecurityEnvelope
		if err := decodeStrictTelemetryJSON(record.Payload, &envelope); err != nil ||
			envelope.SchemaVersion != telemetrySchemaVersion || envelope.Type != "security.v1" ||
			envelope.MessageID != record.MessageId || envelope.TenantID != authorization.tenantID || envelope.NodeID != nodeID ||
			!validProducedAt(envelope.ProducedAt, now) || len(envelope.Events) != int(record.EventCount) {
			return nil, "", "", fmt.Errorf("telemetry security envelope is invalid")
		}
		ids := make([]string, 0, len(envelope.Events))
		var siteID, configVersionID, capturePolicyDigest string
		var capturePolicyRevision uint64
		for index, event := range envelope.Events {
			if !validTelemetrySecurityEvent(event, envelope, authorization, now) {
				return nil, "", "", fmt.Errorf("telemetry security event is invalid")
			}
			if index == 0 {
				siteID, configVersionID = event.SiteID, event.ConfigVersion
				capturePolicyRevision, capturePolicyDigest = event.CapturePolicyRevision, event.CapturePolicyDigest
			} else if event.SiteID != siteID || event.ConfigVersion != configVersionID ||
				event.CapturePolicyRevision != capturePolicyRevision || event.CapturePolicyDigest != capturePolicyDigest {
				return nil, "", "", fmt.Errorf("telemetry security record mixes authority scopes")
			}
			ids = append(ids, event.EventID)
		}
		if len(ids) == 0 || ids[len(ids)-1] != record.LastEventId ||
			envelope.PackageSubscriptionID != "" &&
				envelope.PackageSubscriptionID != authorization.subscriptionBySite[telemetryScopeKey{siteID: siteID, configVersionID: configVersionID}] {
			return nil, "", "", fmt.Errorf("telemetry security boundary is invalid")
		}
		return ids, siteID, configVersionID, nil
	case agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V2:
		var envelope telemetryAccessEnvelopeV2
		if err := decodeStrictTelemetryJSON(record.Payload, &envelope); err != nil ||
			envelope.SchemaVersion != telemetrySchemaVersionV2 || envelope.Type != "access.v2" ||
			envelope.MessageID != record.MessageId || envelope.TenantID != authorization.tenantID || envelope.NodeID != nodeID ||
			envelope.InstallationID != "" || !validProducedAt(envelope.ProducedAt, now) ||
			len(envelope.Events) != int(record.EventCount) {
			return nil, "", "", fmt.Errorf("telemetry access v2 envelope is invalid")
		}
		if !validTelemetryV2MessageID(record) {
			return nil, "", "", fmt.Errorf("telemetry access v2 message identity is invalid")
		}
		baseEnvelope := telemetryAccessEnvelope{
			ProducedAt: envelope.ProducedAt, TenantID: envelope.TenantID, NodeID: envelope.NodeID,
		}
		ids := make([]string, 0, len(envelope.Events))
		var siteID, configVersionID, capturePolicyDigest string
		var capturePolicyRevision uint64
		for index, event := range envelope.Events {
			if event.InstallationID != "" || !validTelemetryAccessEvent(event.telemetryAccessEvent, baseEnvelope, authorization, now) {
				return nil, "", "", fmt.Errorf("telemetry access v2 event is invalid")
			}
			if index == 0 {
				siteID, configVersionID = event.SiteID, event.ConfigVersion
				capturePolicyRevision, capturePolicyDigest = event.CapturePolicyRevision, event.CapturePolicyDigest
			} else if event.SiteID != siteID || event.ConfigVersion != configVersionID ||
				event.CapturePolicyRevision != capturePolicyRevision || event.CapturePolicyDigest != capturePolicyDigest {
				return nil, "", "", fmt.Errorf("telemetry access v2 record mixes authority scopes")
			}
			ids = append(ids, event.EventID)
		}
		if len(ids) == 0 || ids[len(ids)-1] != record.LastEventId ||
			envelope.PackageSubscriptionID != "" &&
				envelope.PackageSubscriptionID != authorization.subscriptionBySite[telemetryScopeKey{siteID: siteID, configVersionID: configVersionID}] {
			return nil, "", "", fmt.Errorf("telemetry access v2 boundary is invalid")
		}
		return ids, siteID, configVersionID, nil
	case agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V2:
		var envelope telemetrySecurityEnvelopeV2
		if err := decodeStrictTelemetryJSON(record.Payload, &envelope); err != nil ||
			envelope.SchemaVersion != telemetrySchemaVersionV2 || envelope.Type != "security.v2" ||
			envelope.MessageID != record.MessageId || envelope.TenantID != authorization.tenantID || envelope.NodeID != nodeID ||
			envelope.InstallationID != "" || !validProducedAt(envelope.ProducedAt, now) ||
			len(envelope.Events) != int(record.EventCount) {
			return nil, "", "", fmt.Errorf("telemetry security v2 envelope is invalid")
		}
		if !validTelemetryV2MessageID(record) {
			return nil, "", "", fmt.Errorf("telemetry security v2 message identity is invalid")
		}
		baseEnvelope := telemetrySecurityEnvelope{
			ProducedAt: envelope.ProducedAt, TenantID: envelope.TenantID, NodeID: envelope.NodeID,
		}
		ids := make([]string, 0, len(envelope.Events))
		var siteID, configVersionID, capturePolicyDigest string
		var capturePolicyRevision uint64
		for index, event := range envelope.Events {
			if event.InstallationID != "" || !validTelemetrySecurityEvent(event.telemetrySecurityEvent, baseEnvelope, authorization, now) {
				return nil, "", "", fmt.Errorf("telemetry security v2 event is invalid")
			}
			if index == 0 {
				siteID, configVersionID = event.SiteID, event.ConfigVersion
				capturePolicyRevision, capturePolicyDigest = event.CapturePolicyRevision, event.CapturePolicyDigest
			} else if event.SiteID != siteID || event.ConfigVersion != configVersionID ||
				event.CapturePolicyRevision != capturePolicyRevision || event.CapturePolicyDigest != capturePolicyDigest {
				return nil, "", "", fmt.Errorf("telemetry security v2 record mixes authority scopes")
			}
			ids = append(ids, event.EventID)
		}
		if len(ids) == 0 || ids[len(ids)-1] != record.LastEventId ||
			envelope.PackageSubscriptionID != "" &&
				envelope.PackageSubscriptionID != authorization.subscriptionBySite[telemetryScopeKey{siteID: siteID, configVersionID: configVersionID}] {
			return nil, "", "", fmt.Errorf("telemetry security v2 boundary is invalid")
		}
		return ids, siteID, configVersionID, nil
	default:
		return nil, "", "", fmt.Errorf("telemetry kind is unsupported")
	}
}

func validateL4TelemetryPayload(record *agentv1.TelemetryRecord, nodeID string, authorization telemetryAuthorization, now time.Time) ([]string, string, string, error) {
	var envelope agentv1.L4SessionEnvelopeV1
	if err := proto.Unmarshal(record.Payload, &envelope); err != nil || cacheControlMessageHasUnknown(envelope.ProtoReflect()) {
		return nil, "", "", fmt.Errorf("L4 telemetry envelope is invalid")
	}
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&envelope)
	if err != nil || !bytes.Equal(canonical, record.Payload) || envelope.GetSchemaVersion() != 1 ||
		envelope.GetMessageId() != record.GetMessageId() || envelope.GetTenantId() != authorization.tenantID ||
		envelope.GetNodeId() != nodeID || !canonicalUUID(envelope.GetSiteId()) || !canonicalUUID(envelope.GetConfigVersionId()) ||
		authorization.configBySite[telemetryScopeKey{siteID: envelope.GetSiteId(), configVersionID: envelope.GetConfigVersionId()}] != envelope.GetTenantId() ||
		envelope.GetSourceWatermark() != record.GetLastSequence() || len(envelope.GetEvidenceSha256()) != sha256.Size ||
		envelope.GetProducedAt() == nil || envelope.GetProducedAt().CheckValid() != nil ||
		envelope.GetFinalizedThrough() == nil || envelope.GetFinalizedThrough().CheckValid() != nil ||
		len(envelope.GetEvents())+len(envelope.GetCheckpoints()) != int(record.GetEventCount()) ||
		(len(envelope.GetEvents()) != 0) == (len(envelope.GetCheckpoints()) != 0) {
		// events or checkpoints (L4-USAGE-01), never both, never none
		return nil, "", "", fmt.Errorf("L4 telemetry envelope is invalid")
	}
	producedAt, finalizedThrough := envelope.GetProducedAt().AsTime(), envelope.GetFinalizedThrough().AsTime()
	if !validProducedAt(producedAt, now) || finalizedThrough.After(producedAt) || finalizedThrough.After(now.Add(telemetryMaxFutureSkew)) {
		return nil, "", "", fmt.Errorf("L4 telemetry envelope time is invalid")
	}
	ids := make([]string, 0, len(envelope.GetEvents()))
	// L4_PACKAGE_ATTRIBUTION: every fact names the package its forward had in
	// that release, exactly as the authorization binds it ("" = none).
	subscriptionID := authorization.subscriptionBySite[telemetryScopeKey{siteID: envelope.GetSiteId(), configVersionID: envelope.GetConfigVersionId()}]
	for _, event := range envelope.GetEvents() {
		if event == nil || event.GetEvent() == nil || !validTelemetryID(event.GetEvent().GetEventId()) ||
			event.GetPackageSubscriptionId() != subscriptionID ||
			event.GetTenantId() != envelope.GetTenantId() || event.GetNodeId() != nodeID ||
			event.GetSiteId() != envelope.GetSiteId() || event.GetConfigVersionId() != envelope.GetConfigVersionId() ||
			!canonicalUUID(event.GetStreamId()) || !canonicalUUID(event.GetListenerId()) || event.GetConfigRevision() == 0 ||
			(event.GetProtocol() != "tcp" && event.GetProtocol() != "udp") || event.GetListenPort() == 0 || event.GetListenPort() > 65535 ||
			!validTelemetryID(event.GetSessionId()) || event.GetStartedAt() == nil || event.GetStartedAt().CheckValid() != nil ||
			event.GetFinalizedAt() == nil || event.GetFinalizedAt().CheckValid() != nil ||
			event.GetStartedAt().AsTime().After(event.GetFinalizedAt().AsTime()) || event.GetFinalizedAt().AsTime().After(finalizedThrough) ||
			event.GetEvent().GetOccurredTime() == nil || event.GetEvent().GetOccurredTime().CheckValid() != nil ||
			!event.GetEvent().GetOccurredTime().AsTime().Equal(event.GetFinalizedAt().AsTime()) ||
			(event.GetStatusCode() != 0 && (event.GetStatusCode() < 100 || event.GetStatusCode() > 599)) ||
			!telemetryBounded(event.GetErrorCode(), 128) || len(event.GetCanonicalEventSha256()) != sha256.Size ||
			len(event.GetEvidenceSha256()) != sha256.Size || !telemetryBounded(event.GetEvent().GetTraceparent(), 128) ||
			!validL4SessionLog(event.GetSessionLog()) ||
			event.GetCheckpointedBytesUp() > event.GetBytesUp() || event.GetCheckpointedBytesDown() > event.GetBytesDown() ||
			(event.GetCheckpointedBytesUp() != 0 || event.GetCheckpointedBytesDown() != 0) && event.GetProtocol() != "tcp" {
			return nil, "", "", fmt.Errorf("L4 telemetry event is invalid")
		}
		ids = append(ids, event.GetEvent().GetEventId())
	}
	// L4-USAGE-01: usage of TCP sessions still in progress since their
	// previous checkpoint; billed at checkpoint_at.
	for _, checkpoint := range envelope.GetCheckpoints() {
		if checkpoint == nil || checkpoint.GetEvent() == nil || !validTelemetryID(checkpoint.GetEvent().GetEventId()) ||
			checkpoint.GetPackageSubscriptionId() != subscriptionID ||
			checkpoint.GetTenantId() != envelope.GetTenantId() || checkpoint.GetNodeId() != nodeID ||
			checkpoint.GetSiteId() != envelope.GetSiteId() || checkpoint.GetConfigVersionId() != envelope.GetConfigVersionId() ||
			!canonicalUUID(checkpoint.GetStreamId()) || !canonicalUUID(checkpoint.GetListenerId()) || checkpoint.GetConfigRevision() == 0 ||
			checkpoint.GetProtocol() != "tcp" || checkpoint.GetListenPort() == 0 || checkpoint.GetListenPort() > 65535 ||
			!validTelemetryID(checkpoint.GetSessionId()) || checkpoint.GetSequence() == 0 ||
			checkpoint.GetBytesUp() == 0 && checkpoint.GetBytesDown() == 0 ||
			checkpoint.GetStartedAt() == nil || checkpoint.GetStartedAt().CheckValid() != nil ||
			checkpoint.GetCheckpointAt() == nil || checkpoint.GetCheckpointAt().CheckValid() != nil ||
			checkpoint.GetStartedAt().AsTime().After(checkpoint.GetCheckpointAt().AsTime()) ||
			checkpoint.GetCheckpointAt().AsTime().After(finalizedThrough) ||
			checkpoint.GetEvent().GetOccurredTime() == nil || checkpoint.GetEvent().GetOccurredTime().CheckValid() != nil ||
			!checkpoint.GetEvent().GetOccurredTime().AsTime().Equal(checkpoint.GetCheckpointAt().AsTime()) ||
			!telemetryBounded(checkpoint.GetEvent().GetTraceparent(), 128) {
			return nil, "", "", fmt.Errorf("L4 telemetry checkpoint is invalid")
		}
		ids = append(ids, checkpoint.GetEvent().GetEventId())
	}
	if ids[len(ids)-1] != record.GetLastEventId() ||
		l4TelemetryMessageID(&envelope) != envelope.GetMessageId() {
		return nil, "", "", fmt.Errorf("L4 telemetry boundary is invalid")
	}
	return ids, envelope.GetSiteId(), envelope.GetConfigVersionId(), nil
}

// l4SessionEndReasons are the end reasons of agentv1.L4SessionLogV1.
var l4SessionEndReasons = map[string]bool{"closed": true, "killed": true, "geo_blocked": true, "rate_limited": true,
	"banned": true, "conn_limited": true, "bad_request": true, "forbidden": true, "upstream_failed": true,
	"internal_error": true, "config_error": true, "guard_blocked": true}

// validL4SessionLog checks the optional session log of an L4 event
// (session_log, tcp/udp v7): canonical addresses and a known end reason.
func validL4SessionLog(log *agentv1.L4SessionLogV1) bool {
	if log == nil {
		return true
	}
	client, err := netip.ParseAddr(log.GetClientIp())
	if err != nil || client.String() != log.GetClientIp() || log.GetClientPort() > 65535 ||
		!l4SessionEndReasons[log.GetEndReason()] || len(log.GetUpstreamAddr()) > 64 ||
		log.UpstreamConnectMs != nil && log.GetUpstreamConnectMs() > 3_600_000 {
		return false
	}
	if log.GetPeerIp() != "" {
		if peer, err := netip.ParseAddr(log.GetPeerIp()); err != nil || peer.String() != log.GetPeerIp() || peer == client {
			return false
		}
	}
	if log.GetUpstreamAddr() != "" {
		if _, err := netip.ParseAddrPort(log.GetUpstreamAddr()); err != nil {
			return false
		}
	}
	return true
}

func l4TelemetryMessageIDFromPayload(payload []byte) string {
	var envelope agentv1.L4SessionEnvelopeV1
	if proto.Unmarshal(payload, &envelope) != nil {
		return ""
	}
	return l4TelemetryMessageID(&envelope)
}

func l4TelemetryMessageID(envelope *agentv1.L4SessionEnvelopeV1) string {
	if envelope == nil {
		return ""
	}
	clone := proto.Clone(envelope).(*agentv1.L4SessionEnvelopeV1)
	clone.MessageId = ""
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(clone)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(append([]byte("cdnca.l4.session.publication.v1\x00"), payload...))
	return "l4msg_" + hex.EncodeToString(digest[:])
}

func validTelemetryV2MessageID(record *agentv1.TelemetryRecord) bool {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(record.Payload, &envelope); err != nil {
		return false
	}
	envelope["message_id"] = json.RawMessage(`""`)
	canonical, err := json.Marshal(envelope)
	return err == nil && record.MessageId == telemetryV2MessageID(record.FirstSequence, record.LastSequence, canonical)
}

func telemetryV2MessageID(firstSequence, lastSequence uint64, canonical []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("cdnca.analytics.publication.v2\x00"))
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], firstSequence)
	_, _ = digest.Write(encoded[:])
	binary.BigEndian.PutUint64(encoded[:], lastSequence)
	_, _ = digest.Write(encoded[:])
	_, _ = digest.Write(canonical)
	return "msg_" + hex.EncodeToString(digest.Sum(nil))
}

func validTelemetryAccessEvent(event telemetryAccessEvent, envelope telemetryAccessEnvelope, authorization telemetryAuthorization, now time.Time) bool {
	return validTelemetryEventBase(event.MetricVersion, event.EventID, event.OccurredAt, envelope.ProducedAt,
		event.TenantID, event.PackageSubscriptionID, event.SiteID, event.NodeID, event.ConfigVersion,
		envelope.TenantID, envelope.NodeID, authorization, now, 30*24*time.Hour) &&
		telemetryBounded(event.RequestID, 128) && telemetryBounded(event.TraceID, 128) &&
		telemetryRequired(event.Host, 253) && telemetryRequired(event.Path, 4096) && telemetryCapturePathSafe(event.Path) && net.ParseIP(event.ClientIP) != nil &&
		telemetryBounded(event.CountryCode, 8) && telemetryBounded(event.Carrier, 128) && telemetryRequired(event.Method, 32) &&
		telemetryRequired(event.Protocol, 32) && telemetryRequired(event.CacheStatus, 32) && telemetryBounded(event.UpstreamResult, 64) &&
		validTelemetryCapturePolicyIdentity(event.CapturePolicyRevision, event.CapturePolicyDigest) &&
		event.StatusCode >= 100 && event.StatusCode <= 599 && validTelemetryCaptures(event.RequestHeaders, event.ResponseHeaders, event.RequestBody, event.ResponseBody) &&
		event.TaskID == nil && (event.JA4 == nil || edgeconfig.ValidJA4(*event.JA4)) &&
		validTelemetryOriginTiming(event.OriginConnectUS, event.OriginFirstByteUS, event.OriginTotalUS) &&
		(event.ClientBrowser == "" || slices.Contains(edgeconfig.TelemetryClientBrowsers, event.ClientBrowser)) &&
		(event.ClientOS == "" || slices.Contains(edgeconfig.TelemetryClientOSes, event.ClientOS)) &&
		telemetryBounded(event.UpstreamAddr, 64)
}

func validTelemetrySecurityEvent(event telemetrySecurityEvent, envelope telemetrySecurityEnvelope, authorization telemetryAuthorization, now time.Time) bool {
	return validTelemetryEventBase(event.MetricVersion, event.EventID, event.OccurredAt, envelope.ProducedAt,
		event.TenantID, event.PackageSubscriptionID, event.SiteID, event.NodeID, event.ConfigVersion,
		envelope.TenantID, envelope.NodeID, authorization, now, 90*24*time.Hour) &&
		telemetryBounded(event.RequestID, 128) && telemetryBounded(event.TraceID, 128) &&
		telemetryRequired(event.Host, 253) && telemetryRequired(event.Path, 4096) && telemetryCapturePathSafe(event.Path) && net.ParseIP(event.ClientIP) != nil &&
		telemetryBounded(event.CountryCode, 8) && telemetryBounded(event.Carrier, 128) &&
		telemetryRequired(event.Method, 32) && validTelemetrySecurityTransport(event) && validTelemetryRequestClass(event.RequestClass) &&
		telemetryRequired(event.EventType, 64) &&
		telemetryRequired(event.Action, 64) && telemetryRequired(event.Severity, 32) && telemetryBounded(event.RuleID, 128) &&
		validTelemetryCapturePolicyIdentity(event.CapturePolicyRevision, event.CapturePolicyDigest) &&
		(event.StatusCode == 0 || event.StatusCode >= 100 && event.StatusCode <= 599) &&
		validTelemetryCaptures(event.RequestHeaders, event.ResponseHeaders, event.RequestBody, event.ResponseBody) &&
		event.TaskID == nil && (event.JA4 == nil || edgeconfig.ValidJA4(*event.JA4)) &&
		validTelemetryOriginTiming(event.OriginConnectUS, event.OriginFirstByteUS, event.OriginTotalUS) &&
		validTelemetrySecurityEvidence(event)
}

// validTelemetrySecurityEvidence bounds the attack evidence (ge-waf S4):
// the deciding policy, detector, matched fragment, User-Agent and body excerpt.
func validTelemetrySecurityEvidence(event telemetrySecurityEvent) bool {
	return (event.PolicyID == "" || canonicalUUID(event.PolicyID)) && telemetryBounded(event.Detector, 16) &&
		len(event.Matched) <= 256 && utf8.ValidString(event.Matched) &&
		len(event.UserAgent) <= 512 && utf8.ValidString(event.UserAgent) &&
		len(event.RequestBodyExcerpt) <= 1024 && utf8.ValidString(event.RequestBodyExcerpt) &&
		event.Count <= 1_000_000_000
}

func validTelemetryCapturePolicyIdentity(revision uint64, digest string) bool {
	if revision == 0 || digest == "" {
		return revision == 0 && digest == ""
	}
	if revision > 1<<53-1 || len(digest) != 64 {
		return false
	}
	for _, character := range digest {
		if character < '0' || character > '9' && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validTelemetryRequestClass(value string) bool {
	switch value {
	case "standard", "websocket", "sse", "task_stream", "import", "acme", "health", "network":
		return true
	default:
		return false
	}
}

func validTelemetrySecurityTransport(event telemetrySecurityEvent) bool {
	if event.RequestClass == "network" {
		switch event.Protocol {
		case "tcp", "udp":
			return event.ListenPort == event.DestinationPort && event.DestinationPort > 0
		case "icmp":
			return event.ListenPort == 0 && event.DestinationPort == 0
		default:
			return false
		}
	}
	return event.ListenPort > 0 && event.DestinationPort == 0 &&
		(event.Protocol == "http" || event.Protocol == "https")
}

func validTelemetryCaptures(requestHeaders, responseHeaders telemetryCaptureHeaders, requestBody, responseBody telemetryCaptureBody) bool {
	return validTelemetryCaptureHeaders(requestHeaders) && validTelemetryCaptureHeaders(responseHeaders) &&
		validTelemetryCaptureBody(requestBody) && validTelemetryCaptureBody(responseBody)
}

func validTelemetryCaptureHeaders(headers telemetryCaptureHeaders) bool {
	if len(headers) > telemetryMaxCaptureObjectKeys {
		return false
	}
	for name, value := range headers {
		if !validTelemetryCaptureHeaderName(name) || !utf8.ValidString(value) || len(value) > telemetryMaxCaptureHeaderValueBytes ||
			telemetrySensitiveCaptureName(name) && value != telemetryRedactedCaptureValue {
			return false
		}
	}
	return true
}

func validTelemetryCaptureHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			continue
		}
		return false
	}
	return true
}

func validTelemetryCaptureBody(body telemetryCaptureBody) bool {
	if body == nil {
		return true
	}
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > telemetryMaxCaptureBodyBytes {
		return false
	}
	keys := 0
	for name, value := range body {
		keys++
		if keys > telemetryMaxCaptureObjectKeys || !validTelemetryCaptureBodyKey(name) || !validTelemetryCaptureValue(name, value, 0, &keys) {
			return false
		}
	}
	return true
}

func validTelemetryCaptureValue(name string, value any, depth int, keys *int) bool {
	if depth > telemetryMaxCaptureBodyDepth {
		return false
	}
	if telemetrySensitiveCaptureName(name) {
		text, ok := value.(string)
		return ok && text == telemetryRedactedCaptureValue
	}
	switch typed := value.(type) {
	case nil, bool, json.Number, float64:
		return true
	case string:
		return utf8.ValidString(typed)
	case []any:
		for _, item := range typed {
			if !validTelemetryCaptureValue("", item, depth+1, keys) {
				return false
			}
		}
		return true
	case map[string]any:
		for childName, item := range typed {
			*keys++
			if *keys > telemetryMaxCaptureObjectKeys || !validTelemetryCaptureBodyKey(childName) || !validTelemetryCaptureValue(childName, item, depth+1, keys) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func validTelemetryOptionalText(value *string, limit int) bool {
	return value == nil || telemetryRequired(*value, limit)
}

func validTelemetryOriginTiming(connect, firstByte, total *uint64) bool {
	return (connect == nil || firstByte == nil || *connect <= *firstByte) &&
		(firstByte == nil || total == nil || *firstByte <= *total) &&
		(connect == nil || total == nil || *connect <= *total)
}

func validTelemetryCaptureBodyKey(value string) bool {
	return value != "" && len(value) <= telemetryMaxCaptureBodyKeyBytes && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func telemetryCapturePathSafe(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return false
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return false
	}
	for name, values := range query {
		if telemetrySensitiveCaptureName(name) {
			for _, item := range values {
				if item != telemetryRedactedCaptureValue {
					return false
				}
			}
		}
	}
	return true
}

func telemetrySensitiveCaptureName(value string) bool {
	runes := []rune(value)
	var tokenized strings.Builder
	tokenized.Grow(len(value))
	for index, character := range runes {
		if index > 0 && unicode.IsUpper(character) &&
			(unicode.IsLower(runes[index-1]) || unicode.IsDigit(runes[index-1]) ||
				unicode.IsUpper(runes[index-1]) && index+1 < len(runes) && unicode.IsLower(runes[index+1])) {
			tokenized.WriteByte(' ')
		}
		tokenized.WriteRune(unicode.ToLower(character))
	}
	lower := tokenized.String()
	replacer := strings.NewReplacer("-", " ", "_", " ", ".", " ", "[", " ", "]", " ")
	for _, part := range strings.Fields(replacer.Replace(lower)) {
		switch part {
		case "authorization", "cookie", "password", "passwd", "token", "key", "apikey", "secret", "certificate", "cert", "privatekey", "setcookie":
			return true
		}
	}
	return lower == "set-cookie" || strings.Contains(lower, "authorization")
}

func validTelemetryEventBase(
	metricVersion uint16,
	eventID string,
	occurredAt, producedAt time.Time,
	tenantID, packageSubscriptionID, siteID, nodeID, configVersionID, envelopeTenantID, envelopeNodeID string,
	authorization telemetryAuthorization,
	now time.Time,
	maxAge time.Duration,
) bool {
	if metricVersion != telemetryMetricVersion || !validTelemetryID(eventID) ||
		tenantID != envelopeTenantID || nodeID != envelopeNodeID || !canonicalUUID(siteID) || !canonicalUUID(configVersionID) ||
		authorization.configBySite[telemetryScopeKey{siteID: siteID, configVersionID: configVersionID}] != tenantID ||
		(packageSubscriptionID != "" && authorization.subscriptionBySite[telemetryScopeKey{
			siteID: siteID, configVersionID: configVersionID}] != packageSubscriptionID) {
		return false
	}
	return !occurredAt.IsZero() && occurredAt.Location() == time.UTC &&
		!occurredAt.After(producedAt.Add(telemetryMaxFutureSkew)) && !occurredAt.After(now.Add(telemetryMaxFutureSkew)) &&
		!occurredAt.Before(now.Add(-maxAge))
}

func bindTelemetryPackageSubscription(record *agentv1.TelemetryRecord, subscriptionID, installationID string) error {
	switch record.Kind {
	case agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_WINDOW_V1:
		return bindAccessWindowTelemetry(record, subscriptionID, installationID)
	case agentv1.TelemetryKind_TELEMETRY_KIND_SUBSCRIPTION_MINUTE_V1:
		return bindSubscriptionMinuteTelemetry(record, subscriptionID, installationID)
	case agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1:
		var envelope telemetryAccessEnvelope
		if err := json.Unmarshal(record.Payload, &envelope); err != nil {
			return err
		}
		envelope.PackageSubscriptionID = subscriptionID
		for index := range envelope.Events {
			envelope.Events[index].PackageSubscriptionID = subscriptionID
		}
		payload, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		record.Payload = payload
	case agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V1:
		var envelope telemetrySecurityEnvelope
		if err := json.Unmarshal(record.Payload, &envelope); err != nil {
			return err
		}
		envelope.PackageSubscriptionID = subscriptionID
		for index := range envelope.Events {
			envelope.Events[index].PackageSubscriptionID = subscriptionID
		}
		payload, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		record.Payload = payload
	case agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V2:
		var envelope telemetryAccessEnvelopeV2
		if err := json.Unmarshal(record.Payload, &envelope); err != nil {
			return err
		}
		envelope.PackageSubscriptionID = subscriptionID
		envelope.InstallationID = installationID
		for index := range envelope.Events {
			envelope.Events[index].PackageSubscriptionID = subscriptionID
			envelope.Events[index].InstallationID = installationID
		}
		payload, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		record.Payload = payload
	case agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V2:
		var envelope telemetrySecurityEnvelopeV2
		if err := json.Unmarshal(record.Payload, &envelope); err != nil {
			return err
		}
		envelope.PackageSubscriptionID = subscriptionID
		envelope.InstallationID = installationID
		for index := range envelope.Events {
			envelope.Events[index].PackageSubscriptionID = subscriptionID
			envelope.Events[index].InstallationID = installationID
		}
		payload, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		record.Payload = payload
	case agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1:
		if subscriptionID != "" {
			return fmt.Errorf("L4 telemetry does not accept a package subscription binding")
		}
	default:
		return fmt.Errorf("telemetry kind is unsupported")
	}
	return nil
}

func validProducedAt(producedAt, now time.Time) bool {
	return !producedAt.IsZero() && producedAt.Location() == time.UTC && !producedAt.After(now.Add(telemetryMaxFutureSkew))
}

func validTelemetryID(value string) bool {
	if !telemetryRequired(value, 128) {
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

func telemetryRequired(value string, limit int) bool {
	return value != "" && telemetryBounded(value, limit)
}

func telemetryBounded(value string, limit int) bool {
	return len(value) <= limit && strings.TrimSpace(value) == value
}

func decodeStrictTelemetryJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func validateTelemetryUniqueJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := consumeTelemetryJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func consumeTelemetryJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON key")
			}
			keys[key] = struct{}{}
			if err := consumeTelemetryJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeTelemetryJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	return nil
}
