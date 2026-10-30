package eventspool

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	redactedValue        = "[REDACTED]"
	maxCaptureObjectKeys = 128
)

var (
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

func ParseSourceLine(line []byte, policy CapturePolicy) (Envelope, error) {
	return parseSourceLine(line, policy, nil)
}

func ParseSourceLineBound(line []byte, policy CapturePolicy, identity TrustedIdentity) (Envelope, error) {
	return parseSourceLine(line, policy, &identity)
}

func ParseL4SourceLineBound(line []byte, identity TrustedIdentity) (Envelope, error) {
	if len(line) == 0 || len(line) > 1<<20 || bytes.IndexAny(line, "\r\n") >= 0 || !json.Valid(line) ||
		validateUniqueJSONKeys(line) != nil || !validUUID(identity.EnrollmentNodeID) || !validUUID(identity.TenantID) ||
		!validUUID(identity.SiteID) || !validUUID(identity.ConfigVersionID) || !validUUID(identity.StreamID) ||
		!validUUID(identity.ListenerID) || identity.ConfigRevision == 0 || identity.ConfigRevision > 1<<53-1 ||
		!validOptionalPackageSubscription(identity.PackageSubscriptionID) {
		return Envelope{}, ErrInvalidEvent
	}
	var source struct {
		Time       string `json:"time"`
		Connection string `json:"connection"`
		// PID ($pid, L4-USAGE-01): the worker that served the session, to
		// match it to its live registry entry; absent in older lines.
		PID           *string     `json:"pid"`
		Protocol      string      `json:"protocol"`
		ServerPort    string      `json:"server_port"`
		Status        string      `json:"status"`
		BytesSent     uint64      `json:"bytes_sent"`
		BytesReceived uint64      `json:"bytes_received"`
		SessionTime   json.Number `json:"session_time"`
		// l4_session_v2 (session_log): all present or none.
		Client              *string `json:"client"`
		RemoteAddr          *string `json:"remote_addr"`
		RemotePort          *string `json:"remote_port"`
		ProxyProtocolPort   *string `json:"proxy_protocol_port"`
		UpstreamAddr        *string `json:"upstream_addr"`
		UpstreamConnectTime *string `json:"upstream_connect_time"`
		EndReason           *string `json:"end_reason"`
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&source); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Envelope{}, ErrInvalidEvent
	}
	// nginx $time_iso8601 带数值时区（+00:00/+08:00）；合法 RFC3339 按瞬间归一 UTC，
	// 不以 Location 指针判定外部格式。
	finalized, err := time.Parse(time.RFC3339, source.Time)
	finalized = finalized.UTC()
	port, portErr := strconv.ParseUint(source.ServerPort, 10, 16)
	status, statusErr := strconv.ParseUint(source.Status, 10, 16)
	durationSeconds, durationErr := strconv.ParseFloat(source.SessionTime.String(), 64)
	protocol := strings.ToLower(source.Protocol)
	if err != nil || portErr != nil || port == 0 || statusErr != nil || status > 599 ||
		durationErr != nil || durationSeconds < 0 || durationSeconds > 31*24*60*60 ||
		(protocol != "tcp" && protocol != "udp") || !idPattern.MatchString(source.Connection) {
		return Envelope{}, ErrInvalidEvent
	}
	worker := ""
	if source.PID != nil {
		pid, err := strconv.ParseUint(*source.PID, 10, 32)
		if err != nil || pid == 0 || strconv.FormatUint(pid, 10) != *source.PID {
			return Envelope{}, ErrInvalidEvent
		}
		worker = *source.PID
	}
	duration := time.Duration(durationSeconds * float64(time.Second))
	evidence := sha256.Sum256(line)
	errorCode := ""
	if status < 200 || status >= 300 {
		errorCode = "l4_status_" + source.Status
	}
	envelope := Envelope{
		SchemaVersion: SchemaVersion, Type: EventL4Session, OccurredAt: finalized.UTC(),
		TenantID: identity.TenantID, SiteID: identity.SiteID, NodeID: identity.EnrollmentNodeID,
		ConfigVersionID: identity.ConfigVersionID, StreamID: identity.StreamID, ListenerID: identity.ListenerID,
		ConfigRevision: identity.ConfigRevision, PackageSubscriptionID: identity.PackageSubscriptionID,
		SessionID: source.Connection, Protocol: protocol, ListenPort: uint16(port),
		StatusCode: uint16(status), RequestBytes: source.BytesReceived, ResponseBytes: source.BytesSent,
		StartedAt: finalized.Add(-duration).UTC(), FinalizedAt: finalized.UTC(), ErrorCode: errorCode,
		EvidenceSHA256: hex.EncodeToString(evidence[:]), l4Worker: worker,
	}
	fields := []*string{source.Client, source.RemoteAddr, source.RemotePort, source.ProxyProtocolPort,
		source.UpstreamAddr, source.UpstreamConnectTime, source.EndReason}
	present := 0
	for _, field := range fields {
		if field != nil {
			present++
		}
	}
	if present != 0 {
		if present != len(fields) {
			return Envelope{}, ErrInvalidEvent
		}
		log, err := l4SessionLogFromSource(uint16(status), *source.Client, *source.RemoteAddr, *source.RemotePort,
			*source.ProxyProtocolPort, *source.UpstreamAddr, *source.UpstreamConnectTime, *source.EndReason)
		if err != nil {
			return Envelope{}, err
		}
		envelope.L4Log = log
	}
	if validateEnvelope(envelope, identitySource) != nil {
		return Envelope{}, ErrInvalidEvent
	}
	return envelope, nil
}

// l4EndReasons are the session log end reasons (agentv1.L4SessionLogV1);
// guard_blocked: refused by an L4 guard rule (banned: during a ban).
var l4EndReasons = map[string]bool{"closed": true, "killed": true, "geo_blocked": true, "rate_limited": true,
	"banned": true, "conn_limited": true, "bad_request": true, "forbidden": true, "upstream_failed": true,
	"internal_error": true, "config_error": true, "guard_blocked": true}

// l4SessionLogFromSource builds the session log of an l4_session_v2 line.
// nginx writes "" or "-" for unset variables; upstream variables list every
// origin tried, the last one is the session's.
func l4SessionLogFromSource(status uint16, client, remote, remotePort, proxyPort, upstream, connect, reason string) (*L4SessionLog, error) {
	unset := func(value string) bool { return value == "" || value == "-" }
	last := func(value string) string {
		if index := strings.LastIndex(value, ","); index >= 0 {
			value = value[index+1:]
		}
		return strings.TrimSpace(value)
	}
	port := func(value string) (uint16, bool) {
		if unset(value) {
			return 0, true
		}
		parsed, err := strconv.ParseUint(value, 10, 16)
		return uint16(parsed), err == nil
	}
	peer, err := netip.ParseAddr(remote)
	if err != nil {
		return nil, ErrInvalidEvent
	}
	log := &L4SessionLog{ClientIP: peer.String()}
	clientPort, ok := port(remotePort)
	if !ok {
		return nil, ErrInvalidEvent
	}
	if !unset(client) {
		address, err := netip.ParseAddr(client)
		if err != nil || address.Zone() != "" {
			return nil, ErrInvalidEvent
		}
		if address != peer {
			// A trusted proxy's client: its port is the PROXY header's.
			log.ClientIP, log.PeerIP = address.String(), peer.String()
			if clientPort, ok = port(proxyPort); !ok {
				return nil, ErrInvalidEvent
			}
		}
	}
	log.ClientPort = clientPort
	if value := last(upstream); !unset(value) {
		if _, err := netip.ParseAddrPort(value); err != nil {
			return nil, ErrInvalidEvent
		}
		log.UpstreamAddr = value
	}
	if value := last(connect); !unset(value) {
		seconds, err := strconv.ParseFloat(value, 64)
		if err != nil || seconds < 0 || seconds > 3600 {
			return nil, ErrInvalidEvent
		}
		milliseconds := uint32(seconds*1000 + 0.5)
		log.UpstreamConnectMS = &milliseconds
	}
	switch {
	case !unset(reason):
		log.EndReason = reason
	case status >= 200 && status < 300:
		log.EndReason = "closed"
	case status == 400:
		log.EndReason = "bad_request"
	case status == 403:
		log.EndReason = "forbidden"
	case status == 502:
		log.EndReason = "upstream_failed"
	case status == 503:
		log.EndReason = "conn_limited"
	default:
		log.EndReason = "internal_error"
	}
	if !l4EndReasons[log.EndReason] {
		return nil, ErrInvalidEvent
	}
	return log, nil
}

func validL4SessionLog(log *L4SessionLog) bool {
	if log == nil {
		return true
	}
	client, err := netip.ParseAddr(log.ClientIP)
	if err != nil || client.String() != log.ClientIP || !l4EndReasons[log.EndReason] || len(log.UpstreamAddr) > 64 {
		return false
	}
	if log.PeerIP != "" {
		if peer, err := netip.ParseAddr(log.PeerIP); err != nil || peer.String() != log.PeerIP || peer == client {
			return false
		}
	}
	if log.UpstreamAddr != "" {
		if _, err := netip.ParseAddrPort(log.UpstreamAddr); err != nil {
			return false
		}
	}
	return log.UpstreamConnectMS == nil || *log.UpstreamConnectMS <= 3_600_000
}

func parseSourceLine(line []byte, policy CapturePolicy, identity *TrustedIdentity) (Envelope, error) {
	policy, err := normalizeCapturePolicy(policy)
	if err != nil {
		return Envelope{}, err
	}
	if len(line) == 0 || len(line) > policy.MaxEventBytes || bytes.IndexByte(line, '\n') >= 0 || bytes.IndexByte(line, '\r') >= 0 ||
		!json.Valid(line) || validateUniqueJSONKeys(line) != nil {
		return Envelope{}, ErrInvalidEvent
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var source struct {
		Envelope
		Connection         *string `json:"connection"`
		ConnectionRequests *uint64 `json:"connection_requests"`
	}
	if err := decoder.Decode(&source); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Envelope{}, ErrInvalidEvent
	}
	if (source.Connection == nil) != (source.ConnectionRequests == nil) {
		return Envelope{}, ErrInvalidEvent
	}
	if source.Connection != nil {
		connection, err := strconv.ParseUint(*source.Connection, 10, 64)
		if err != nil || connection == 0 || strconv.FormatUint(connection, 10) != *source.Connection ||
			*source.ConnectionRequests == 0 || source.Type != EventAccess {
			return Envelope{}, ErrInvalidEvent
		}
	}
	envelope := source.Envelope
	// $cdnca_ja4 is empty without a TLS fingerprint (plain HTTP, HTTP/3,
	// runtime without the module); anything else must be one JA4 exactly.
	if envelope.JA4 != nil && *envelope.JA4 == "" {
		envelope.JA4 = nil
	}
	envelope.OccurredAt = envelope.OccurredAt.UTC()
	envelope.EventID = ""
	envelope.Sequence = 0
	if identity != nil {
		if identity.ListenPort != 0 && (envelope.Type == EventAccess || envelope.Type == EventSecurity) {
			if envelope.ListenPort != 0 && envelope.ListenPort != identity.ListenPort {
				return Envelope{}, ErrInvalidEvent
			}
			envelope.ListenPort = identity.ListenPort
		}
		envelope.TenantID = identity.TenantID
		envelope.SiteID = identity.SiteID
		envelope.NodeID = identity.EnrollmentNodeID
		envelope.ConfigVersionID = identity.ConfigVersionID
		envelope.CapturePolicyRevision = identity.CapturePolicyRevision
		envelope.CapturePolicyDigest = identity.CapturePolicyDigest
	}
	if err := validateEnvelope(envelope, identitySource); err != nil {
		return Envelope{}, err
	}
	envelope, err = sanitizeEnvelope(envelope, policy)
	if err != nil {
		return Envelope{}, err
	}
	envelope = sanitizeSecurityEvidence(envelope, policy)
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > policy.MaxEventBytes {
		return Envelope{}, ErrInvalidEvent
	}
	return envelope, nil
}

func encodeEnvelope(envelope Envelope) ([]byte, error) {
	if err := validateEnvelope(envelope, identityStored); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, ErrInvalidEvent
	}
	return append(encoded, '\n'), nil
}

type identityState uint8

const (
	identitySource identityState = iota
	identityPending
	identityStored
)

func validateEnvelope(envelope Envelope, identity identityState) error {
	if envelope.SchemaVersion != SchemaVersion || (envelope.Type != EventAccess && envelope.Type != EventSecurity && envelope.Type != EventL4Session && envelope.Type != EventAccessWindow && envelope.Type != EventSubscriptionMinute && envelope.Type != EventL4Checkpoint) ||
		(envelope.CheckpointSequence != 0 && envelope.Type != EventL4Checkpoint) ||
		((envelope.CheckpointedRequestBytes != 0 || envelope.CheckpointedResponseBytes != 0) && envelope.Type != EventL4Session) ||
		(envelope.SubscriptionMinute != nil && envelope.Type != EventSubscriptionMinute) ||
		(envelope.Blocked && envelope.Type != EventAccess) ||
		((envelope.ClientBrowser != "" || envelope.ClientOS != "") && envelope.Type != EventAccess) ||
		(envelope.UpstreamAddr != "" && envelope.Type != EventAccess) || !validBounded(envelope.UpstreamAddr, 64) ||
		!validClientFamily(envelope.ClientBrowser, edgeconfig.TelemetryClientBrowsers) ||
		!validClientFamily(envelope.ClientOS, edgeconfig.TelemetryClientOSes) ||
		(envelope.Type != EventAccessWindow && envelope.SourceWatermark != 0) ||
		envelope.OccurredAt.IsZero() || envelope.OccurredAt.Location() != time.UTC ||
		!validUUID(envelope.TenantID) || !validUUID(envelope.SiteID) || !validUUID(envelope.NodeID) ||
		!validRequired(envelope.ConfigVersionID, 128) || envelope.InstallationID != "" ||
		!validCapturePolicyIdentity(envelope.CapturePolicyRevision, envelope.CapturePolicyDigest) ||
		envelope.TaskID != nil || envelope.JA4 != nil && !edgeconfig.ValidJA4(*envelope.JA4) ||
		!validOriginTiming(envelope.OriginConnectUS, envelope.OriginFirstByteUS, envelope.OriginTotalUS) ||
		!validBounded(envelope.RequestID, 128) || !validBounded(envelope.TraceID, 128) ||
		!validBounded(envelope.CountryCode, 8) || !validBounded(envelope.Carrier, 128) ||
		(envelope.L4Log != nil && (envelope.Type != EventL4Session || !validL4SessionLog(envelope.L4Log))) ||
		!validSecurityEvidence(envelope) {
		return ErrInvalidEvent
	}
	switch identity {
	case identitySource:
		if envelope.EventID != "" || envelope.Sequence != 0 {
			return ErrInvalidEvent
		}
	case identityPending:
		if !idPattern.MatchString(envelope.EventID) || envelope.Sequence != 0 {
			return ErrInvalidEvent
		}
	case identityStored:
		if !idPattern.MatchString(envelope.EventID) || envelope.Sequence == 0 {
			return ErrInvalidEvent
		}
	default:
		return ErrInvalidEvent
	}
	switch envelope.Type {
	case EventAccessWindow:
		if !validAccessWindowRecord(envelope) {
			return ErrInvalidEvent
		}
	case EventSubscriptionMinute:
		if !validSubscriptionMinuteRecord(envelope) {
			return ErrInvalidEvent
		}
	case EventAccess:
		if !validHTTPEventIdentity(envelope) || !validRequired(envelope.Method, 32) || !validRequired(envelope.Protocol, 32) || !validRequired(envelope.CacheStatus, 32) ||
			!validBounded(envelope.UpstreamResult, 64) || envelope.StatusCode < 100 || envelope.StatusCode > 599 ||
			envelope.RequestClass != "" || envelope.SecurityType != "" ||
			envelope.Action != "" || envelope.Severity != "" || envelope.RuleID != "" {
			return ErrInvalidEvent
		}
	case EventSecurity:
		if !validHTTPEventIdentity(envelope) || !validRequired(envelope.SecurityType, 64) || !validRequired(envelope.Action, 64) || !validRequired(envelope.Severity, 32) ||
			!validBounded(envelope.RuleID, 128) || (envelope.StatusCode != 0 && (envelope.StatusCode < 100 || envelope.StatusCode > 599)) ||
			!validRequired(envelope.Method, 32) || !validSecurityTransport(envelope) || !validSecurityRequestClass(envelope.RequestClass) ||
			envelope.CacheStatus != "" || envelope.UpstreamResult != "" || envelope.DurationUS != 0 {
			return ErrInvalidEvent
		}
	case EventL4Session:
		if !validUUID(envelope.ConfigVersionID) || !validUUID(envelope.StreamID) || !validUUID(envelope.ListenerID) ||
			envelope.ConfigRevision == 0 || envelope.ConfigRevision > 1<<53-1 || !idPattern.MatchString(envelope.SessionID) ||
			!validOptionalPackageSubscription(envelope.PackageSubscriptionID) ||
			(envelope.Protocol != "tcp" && envelope.Protocol != "udp") || envelope.ListenPort == 0 || envelope.StatusCode > 599 ||
			envelope.StartedAt.IsZero() || envelope.FinalizedAt.IsZero() || envelope.StartedAt.Location() != time.UTC ||
			envelope.FinalizedAt.Location() != time.UTC || envelope.StartedAt.After(envelope.FinalizedAt) ||
			!envelope.OccurredAt.Equal(envelope.FinalizedAt) || !validBounded(envelope.ErrorCode, 64) || !validHexSHA256(envelope.EvidenceSHA256) ||
			envelope.Host != "" || envelope.Path != "" || envelope.ClientIP != "" || envelope.Method != "" ||
			envelope.CacheStatus != "" || envelope.UpstreamResult != "" || envelope.SecurityType != "" ||
			envelope.Action != "" || envelope.Severity != "" || envelope.RuleID != "" || envelope.DurationUS != 0 {
			return ErrInvalidEvent
		}
	case EventL4Checkpoint:
		// TCP only (UDP sessions end with their reply); a delta that moved
		// bytes; no end of session, status, evidence or session log.
		if !validUUID(envelope.ConfigVersionID) || !validUUID(envelope.StreamID) || !validUUID(envelope.ListenerID) ||
			envelope.ConfigRevision == 0 || envelope.ConfigRevision > 1<<53-1 || !idPattern.MatchString(envelope.SessionID) ||
			!validOptionalPackageSubscription(envelope.PackageSubscriptionID) || envelope.Protocol != "tcp" ||
			envelope.ListenPort == 0 || envelope.CheckpointSequence == 0 || envelope.RequestBytes == 0 && envelope.ResponseBytes == 0 ||
			envelope.StartedAt.IsZero() || envelope.StartedAt.Location() != time.UTC || envelope.StartedAt.After(envelope.OccurredAt) ||
			!envelope.FinalizedAt.IsZero() || envelope.StatusCode != 0 || envelope.ErrorCode != "" || envelope.EvidenceSHA256 != "" ||
			envelope.L4Log != nil || envelope.Host != "" || envelope.Path != "" || envelope.ClientIP != "" || envelope.Method != "" ||
			envelope.CacheStatus != "" || envelope.UpstreamResult != "" || envelope.SecurityType != "" ||
			envelope.Action != "" || envelope.Severity != "" || envelope.RuleID != "" || envelope.DurationUS != 0 {
			return ErrInvalidEvent
		}
	}
	return nil
}

// validSecurityEvidence bounds the attack evidence fields; only security
// events carry them.
func validSecurityEvidence(envelope Envelope) bool {
	if envelope.Type != EventSecurity {
		return envelope.PolicyID == "" && envelope.Detector == "" && envelope.Matched == "" && envelope.UserAgent == "" &&
			envelope.RequestBodyExcerpt == "" && envelope.Count == 0
	}
	return (envelope.PolicyID == "" || validUUID(envelope.PolicyID)) && validBounded(envelope.Detector, 16) &&
		len(envelope.Matched) <= 256 && utf8.ValidString(envelope.Matched) &&
		len(envelope.UserAgent) <= 512 && utf8.ValidString(envelope.UserAgent) &&
		len(envelope.RequestBodyExcerpt) <= 1024 && utf8.ValidString(envelope.RequestBodyExcerpt) &&
		envelope.Count <= MaxSecurityEventCount
}

// MaxSecurityEventCount bounds an aggregated security line's count.
const MaxSecurityEventCount = 1_000_000_000

func validHTTPEventIdentity(envelope Envelope) bool {
	return validRequired(envelope.Host, 253) && validRequired(envelope.Path, 4096) && net.ParseIP(envelope.ClientIP) != nil &&
		envelope.StreamID == "" && envelope.ListenerID == "" && envelope.SessionID == "" && envelope.ConfigRevision == 0 &&
		envelope.PackageSubscriptionID == "" &&
		envelope.StartedAt.IsZero() && envelope.FinalizedAt.IsZero() && envelope.ErrorCode == "" && envelope.EvidenceSHA256 == ""
}

// validOptionalPackageSubscription: none, or a canonical non-nil UUID.
func validOptionalPackageSubscription(value string) bool {
	return value == "" || (validUUID(value) && value == strings.ToLower(value) && value != "00000000-0000-0000-0000-000000000000")
}

func validHexSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func validCapturePolicyIdentity(revision uint64, digest string) bool {
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

func validSecurityRequestClass(value string) bool {
	switch value {
	case "standard", "websocket", "sse", "task_stream", "import", "acme", "health", "network":
		return true
	default:
		return false
	}
}

func validSecurityTransport(envelope Envelope) bool {
	if envelope.RequestClass == "network" {
		switch envelope.Protocol {
		case "tcp", "udp":
			return envelope.ListenPort == envelope.DestinationPort && envelope.DestinationPort > 0
		case "icmp":
			return envelope.ListenPort == 0 && envelope.DestinationPort == 0
		default:
			return false
		}
	}
	return envelope.ListenPort > 0 && envelope.DestinationPort == 0 &&
		(envelope.Protocol == "http" || envelope.Protocol == "https")
}

func sanitizeEnvelope(envelope Envelope, policy CapturePolicy) (Envelope, error) {
	if !capturePolicyMatches(envelope.Method, envelope.Path, policy) {
		envelope.RequestHeaders = nil
		envelope.ResponseHeaders = nil
		envelope.RequestBody = nil
		envelope.ResponseBody = nil
		var err error
		envelope.Path, err = redactURL(envelope.Path)
		if err != nil {
			return Envelope{}, ErrInvalidEvent
		}
		return envelope, nil
	}
	requestHeaders, err := filterHeaders(envelope.RequestHeaders, policy.RequestHeaders, policy.MaxHeaderValueBytes)
	if err != nil {
		return Envelope{}, err
	}
	responseHeaders, err := filterHeaders(envelope.ResponseHeaders, policy.ResponseHeaders, policy.MaxHeaderValueBytes)
	if err != nil {
		return Envelope{}, err
	}
	requestBody, err := filterBody(envelope.RequestBody, policy.RequestBodyFields, policy.MaxHeaderValueBytes, policy.MaxBodyBytes)
	if err != nil {
		return Envelope{}, err
	}
	responseBody, err := filterBody(envelope.ResponseBody, policy.ResponseBodyFields, policy.MaxHeaderValueBytes, policy.MaxBodyBytes)
	if err != nil {
		return Envelope{}, err
	}
	envelope.RequestHeaders = requestHeaders
	envelope.ResponseHeaders = responseHeaders
	envelope.RequestBody = requestBody
	envelope.ResponseBody = responseBody
	envelope.Path, err = redactURL(envelope.Path)
	if err != nil {
		return Envelope{}, ErrInvalidEvent
	}
	return envelope, nil
}

func normalizeCapturePolicy(policy CapturePolicy) (CapturePolicy, error) {
	if len(policy.RequestHeaders) > 0 || len(policy.ResponseHeaders) > 0 || len(policy.RequestBodyFields) > 0 || len(policy.ResponseBodyFields) > 0 {
		policy.Enabled = true
	}
	if policy.MaxHeaderValueBytes == 0 {
		policy.MaxHeaderValueBytes = 4096
	}
	if policy.MaxBodyBytes == 0 {
		policy.MaxBodyBytes = 64 << 10
	}
	if policy.MaxEventBytes == 0 {
		policy.MaxEventBytes = 1 << 20
	}
	if !validCaptureMethods(policy.Methods) || !validCaptureURIPrefixes(policy.URIPrefixes) ||
		!policy.Enabled && (len(policy.Methods) != 0 || len(policy.URIPrefixes) != 0) {
		return CapturePolicy{}, ErrInvalidConfig
	}
	if policy.MaxHeaderValueBytes < 1 || policy.MaxHeaderValueBytes > 16<<10 ||
		policy.MaxBodyBytes < 1 || policy.MaxBodyBytes > 1<<20 || policy.MaxEventBytes < 256 || policy.MaxEventBytes > 1<<20 ||
		len(policy.RequestHeaders) > maxCaptureObjectKeys || len(policy.ResponseHeaders) > maxCaptureObjectKeys ||
		len(policy.RequestBodyFields) > maxCaptureObjectKeys || len(policy.ResponseBodyFields) > maxCaptureObjectKeys {
		return CapturePolicy{}, ErrInvalidConfig
	}
	if !policy.Enabled {
		policy.Methods = nil
		policy.URIPrefixes = nil
		policy.RequestHeaders = nil
		policy.ResponseHeaders = nil
		policy.RequestBodyFields = nil
		policy.ResponseBodyFields = nil
	}
	return policy, nil
}

func validCaptureMethods(values []string) bool {
	if len(values) > maxCaptureObjectKeys {
		return false
	}
	previous := ""
	for _, value := range values {
		switch value {
		case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		default:
			return false
		}
		if previous >= value {
			return false
		}
		previous = value
	}
	return true
}

func validCaptureURIPrefixes(values []string) bool {
	if len(values) > maxCaptureObjectKeys {
		return false
	}
	previous := ""
	for _, value := range values {
		if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
			value[0] != '/' || strings.ContainsAny(value, "?#\r\n\x00") || previous >= value {
			return false
		}
		previous = value
	}
	return true
}

func capturePolicyMatches(method, requestURI string, policy CapturePolicy) bool {
	if !policy.Enabled {
		return false
	}
	methodMatch := len(policy.Methods) == 0
	for _, candidate := range policy.Methods {
		if method == candidate {
			methodMatch = true
			break
		}
	}
	if !methodMatch {
		return false
	}
	if len(policy.URIPrefixes) == 0 {
		return true
	}
	path := requestURI
	if index := strings.IndexByte(path, '?'); index >= 0 {
		path = path[:index]
	}
	for _, prefix := range policy.URIPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func filterHeaders(values map[string]string, allowlist []string, maximum int) (map[string]string, error) {
	allowed := make(map[string]struct{}, len(allowlist))
	for _, name := range allowlist {
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "" || !validHeaderName(canonical) {
			return nil, ErrInvalidConfig
		}
		allowed[strings.ToLower(canonical)] = struct{}{}
	}
	if len(allowed) == 0 || values == nil {
		return nil, nil
	}
	if len(values) > maxCaptureObjectKeys {
		return nil, ErrInvalidEvent
	}
	result := make(map[string]string, len(values))
	for name, value := range values {
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "" || !validHeaderName(canonical) {
			return nil, ErrInvalidEvent
		}
		if _, ok := allowed[strings.ToLower(canonical)]; !ok {
			continue
		}
		if !utf8.ValidString(value) || len(value) > maximum {
			return nil, ErrInvalidEvent
		}
		if sensitiveName(canonical) {
			value = redactedValue
		}
		result[canonical] = value
	}
	return result, nil
}

func filterBody(values map[string]any, allowlist []string, maximumValue, maximumBody int) (map[string]any, error) {
	if len(allowlist) == 0 || values == nil {
		return nil, nil
	}
	allowed := make(map[string]struct{}, len(allowlist))
	for _, name := range allowlist {
		if !validBodyKey(name) {
			return nil, ErrInvalidConfig
		}
		allowed[name] = struct{}{}
	}
	if len(values) > maxCaptureObjectKeys {
		return nil, ErrInvalidEvent
	}
	result := make(map[string]any)
	keys := len(values)
	for name, value := range values {
		if _, ok := allowed[name]; !ok {
			continue
		}
		if sensitiveName(name) {
			result[name] = redactedValue
			continue
		}
		sanitized, err := redactValue(value, 0, maximumValue, &keys)
		if err != nil {
			return nil, err
		}
		result[name] = sanitized
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maximumBody {
		return nil, ErrInvalidEvent
	}
	return result, nil
}

func redactValue(value any, depth, maximumValue int, keys *int) (any, error) {
	if depth > 8 {
		return nil, ErrInvalidEvent
	}
	switch typed := value.(type) {
	case nil, bool, json.Number:
		return typed, nil
	case float64:
		return typed, nil
	case string:
		if !utf8.ValidString(typed) || len(typed) > maximumValue {
			return nil, ErrInvalidEvent
		}
		return typed, nil
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			var err error
			result[index], err = redactValue(item, depth+1, maximumValue, keys)
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	case map[string]any:
		result := make(map[string]any, len(typed))
		for name, item := range typed {
			*keys++
			if *keys > maxCaptureObjectKeys {
				return nil, ErrInvalidEvent
			}
			if !validBodyKey(name) {
				return nil, ErrInvalidEvent
			}
			if sensitiveName(name) {
				result[name] = redactedValue
				continue
			}
			value, err := redactValue(item, depth+1, maximumValue, keys)
			if err != nil {
				return nil, err
			}
			result[name] = value
		}
		return result, nil
	default:
		return nil, ErrInvalidEvent
	}
}

func validOriginTiming(connect, firstByte, total *uint64) bool {
	return (connect == nil || firstByte == nil || *connect <= *firstByte) &&
		(firstByte == nil || total == nil || *firstByte <= *total) &&
		(connect == nil || total == nil || *connect <= *total)
}

func redactURL(value string) (string, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	changed := false
	for name := range query {
		if sensitiveName(name) {
			query.Set(name, redactedValue)
			changed = true
		}
	}
	if changed {
		parsed.RawQuery = query.Encode()
	}
	return parsed.RequestURI(), nil
}

func sensitiveName(value string) bool {
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
	parts := strings.Fields(replacer.Replace(lower))
	for _, part := range parts {
		switch part {
		case "authorization", "cookie", "password", "passwd", "token", "key", "apikey", "secret", "certificate", "cert", "privatekey", "setcookie":
			return true
		}
	}
	return lower == "set-cookie" || strings.Contains(lower, "authorization")
}

func validUUID(value string) bool {
	return uuidPattern.MatchString(value) && !strings.EqualFold(value, "00000000-0000-0000-0000-000000000000")
}

func validRequired(value string, maximum int) bool {
	return value != "" && validBounded(value, maximum)
}

func validBounded(value string, maximum int) bool {
	return len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value
}

func validHeaderName(value string) bool {
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

func validBodyKey(value string) bool {
	return value != "" && len(value) <= 128 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func validateUniqueJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return ErrInvalidEvent
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
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
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidEvent
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidEvent
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidEvent
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidEvent
		}
	default:
		return ErrInvalidEvent
	}
	return nil
}

// validClientFamily: empty (not logged) or one of the node's fixed families.
func validClientFamily(value string, families []string) bool {
	if value == "" {
		return true
	}
	for _, family := range families {
		if value == family {
			return true
		}
	}
	return false
}
