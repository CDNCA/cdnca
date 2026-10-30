package eventspool

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

const SchemaVersion uint16 = 1

type EventType string

const (
	EventAccess       EventType = "access.v1"
	EventSecurity     EventType = "security.v1"
	EventL4Session    EventType = "l4_session.v1"
	EventAccessWindow EventType = "access_window.v1"
	// EventSubscriptionMinute: ADR 0012 §6.2 per subscription minute
	// statistics (subscription_minute.go).
	EventSubscriptionMinute EventType = "subscription_minute.v1"
	// EventL4Checkpoint: L4-USAGE-01 usage of a TCP session still in
	// progress since its previous checkpoint (internal/l4usage); published on
	// the L4 session channel (agentv1.L4UsageCheckpointV1).
	EventL4Checkpoint EventType = "l4_checkpoint.v1"
)

var (
	ErrInvalidConfig         = errors.New("invalid event spool configuration")
	ErrInvalidEvent          = errors.New("invalid edge telemetry event")
	ErrUnsafePath            = errors.New("unsafe event spool path")
	ErrCorruptState          = errors.New("corrupt event spool state")
	ErrConflict              = errors.New("event spool conflict")
	ErrBackpressure          = errors.New("event spool soft watermark reached")
	ErrHardLimit             = errors.New("event spool hard watermark reached")
	ErrAgeLimit              = errors.New("event spool age watermark reached")
	ErrTenantLimit           = errors.New("event spool tenant quota reached")
	ErrAckOrder              = errors.New("event spool acknowledgement is out of order")
	ErrInvalidAck            = errors.New("event spool publisher acknowledgement is invalid")
	ErrTailGap               = errors.New("event log rotation gap")
	ErrTailRotatedPartial    = errors.New("rotated event log has incomplete trailing line")
	ErrTailRotationAmbiguous = errors.New("event log rotation is ambiguous")
	// ErrLineNotReady: TailConfig.Resolve cannot bind the line yet.
	ErrLineNotReady = errors.New("event log line is not ready to bind")
	// ErrLineSkipped: TailConfig.Resolve binds the line to no event on
	// purpose (an L2 hop, fix-l2trust): consumed, neither spooled nor
	// quarantined.
	ErrLineSkipped            = errors.New("event log line is not an event")
	ErrQuarantineLimit        = errors.New("event quarantine capacity reached")
	ErrInvalidConnections     = errors.New("invalid connections metric envelope")
	ErrConnectionsUnavailable = errors.New("connections metric source unavailable")
	ErrConnectionsConflict    = errors.New("connections metric identity conflict")
	ErrConnectionsWatermark   = errors.New("connections metric source watermark is not monotonic")
)

type Envelope struct {
	SchemaVersion         uint16    `json:"schema_version"`
	Type                  EventType `json:"type"`
	EventID               string    `json:"event_id,omitempty"`
	Sequence              uint64    `json:"sequence,omitempty"`
	OccurredAt            time.Time `json:"occurred_at"`
	TenantID              string    `json:"tenant_id"`
	SiteID                string    `json:"site_id"`
	NodeID                string    `json:"node_id"`
	ConfigVersionID       string    `json:"config_version_id"`
	InstallationID        string    `json:"installation_id"`
	CapturePolicyRevision uint64    `json:"capture_policy_revision,omitempty"`
	CapturePolicyDigest   string    `json:"capture_policy_digest,omitempty"`
	TaskID                *string   `json:"task_id"`
	RequestID             string    `json:"request_id,omitempty"`
	TraceID               string    `json:"trace_id,omitempty"`
	Host                  string    `json:"host"`
	Path                  string    `json:"path"`
	ClientIP              string    `json:"client_ip"`
	CountryCode           string    `json:"country_code,omitempty"`
	Carrier               string    `json:"carrier,omitempty"`
	Method                string    `json:"method,omitempty"`
	ListenPort            uint16    `json:"listen_port,omitempty"`
	DestinationPort       uint16    `json:"destination_port,omitempty"`
	Protocol              string    `json:"protocol,omitempty"`
	RequestClass          string    `json:"request_class,omitempty"`
	CacheStatus           string    `json:"cache_status,omitempty"`
	UpstreamResult        string    `json:"upstream_result,omitempty"`
	StatusCode            uint16    `json:"status_code"`
	RequestBytes          uint64    `json:"request_bytes"`
	ResponseBytes         uint64    `json:"response_bytes"`
	DurationUS            uint64    `json:"duration_us,omitempty"`
	JA4                   *string   `json:"ja4"`
	OriginConnectUS       *uint64   `json:"origin_connect_us"`
	OriginFirstByteUS     *uint64   `json:"origin_first_byte_us"`
	OriginTotalUS         *uint64   `json:"origin_total_us"`
	SecurityType          string    `json:"security_type,omitempty"`
	Action                string    `json:"action,omitempty"`
	Severity              string    `json:"severity,omitempty"`
	RuleID                string    `json:"rule_id,omitempty"`
	// Attack evidence of a WAF / ACL security event (ge-waf S4): the deciding
	// policy, the detector and matched fragment, the User-Agent and a request
	// body excerpt. Security events only; omitted when empty.
	PolicyID           string `json:"policy_id,omitempty"`
	Detector           string `json:"detector,omitempty"`
	Matched            string `json:"matched,omitempty"`
	UserAgent          string `json:"user_agent,omitempty"`
	RequestBodyExcerpt string `json:"request_body_excerpt,omitempty"`
	// Count is how many requests one aggregated security line stands for
	// (CC challenge page / 429 per minute, sec-log-agg); 0 = one request.
	Count           uint32            `json:"count,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	RequestBody     map[string]any    `json:"request_body"`
	ResponseBody    map[string]any    `json:"response_body"`
	StreamID        string            `json:"stream_id,omitempty"`
	ListenerID      string            `json:"listener_id,omitempty"`
	SessionID       string            `json:"session_id,omitempty"`
	ConfigRevision  uint64            `json:"config_revision,omitempty"`
	// PackageSubscriptionID: the package of an l4_session.v1 event's forward
	// (L4_PACKAGE_ATTRIBUTION); omitted when it has none.
	PackageSubscriptionID string    `json:"package_subscription_id,omitempty"`
	StartedAt             time.Time `json:"started_at,omitempty"`
	FinalizedAt           time.Time `json:"finalized_at,omitempty"`
	ErrorCode             string    `json:"error_code,omitempty"`
	// CheckpointSequence is an l4_checkpoint.v1 record's sequence in its
	// session (from 1); its RequestBytes/ResponseBytes are the delta.
	CheckpointSequence uint32 `json:"checkpoint_sequence,omitempty"`
	// CheckpointedRequestBytes/ResponseBytes: the bytes of an l4_session.v1
	// session already billed by its checkpoints (L4-USAGE-01).
	CheckpointedRequestBytes  uint64 `json:"checkpointed_request_bytes,omitempty"`
	CheckpointedResponseBytes uint64 `json:"checkpointed_response_bytes,omitempty"`
	EvidenceSHA256            string `json:"evidence_sha256,omitempty"`
	SourceWatermark           uint64 `json:"source_watermark,omitempty"`
	// Blocked marks an access the node answered with a block page itself
	// (FX60); omitted when false so untagged records keep their encoding.
	Blocked bool `json:"blocked,omitempty"`
	// ClientBrowser / ClientOS are the node's User-Agent families
	// (edgeconfig.TelemetryClientBrowsers / TelemetryClientOSes) of an access
	// event; omitted when empty.
	ClientBrowser string `json:"client_browser,omitempty"`
	ClientOS      string `json:"client_os,omitempty"`
	// UpstreamAddr is the origin address(es) an access event was sent to
	// ($upstream_addr, at most 64 bytes); omitted when not sent to origin.
	// upstream_result is the diagnostic code, not the address.
	UpstreamAddr string `json:"upstream_addr,omitempty"`
	// L4Log is the session log of an l4_session.v1 event from a stream with
	// session_log (l4_session_v2 lines); nil otherwise.
	L4Log *L4SessionLog `json:"l4_log,omitempty"`
	// SubscriptionMinute is the payload of a subscription_minute.v1 record;
	// nil otherwise.
	SubscriptionMinute *SubscriptionMinute `json:"subscription_minute,omitempty"`
	// l4Worker is the nginx worker pid of an l4_session.v1 source line
	// ("pid"), only in memory: it matches the session to its live registry
	// entry (L4WorkerConnection) and is never stored.
	l4Worker string
}

// L4WorkerConnection is the live registry token "<worker pid>:<connection>"
// of an l4_session.v1 event parsed from a line with its worker pid; "" else.
func (envelope Envelope) L4WorkerConnection() string {
	if envelope.Type != EventL4Session || envelope.l4Worker == "" {
		return ""
	}
	return envelope.l4Worker + ":" + envelope.SessionID
}

// L4SessionLog mirrors agentv1.L4SessionLogV1.
type L4SessionLog struct {
	ClientIP          string  `json:"client_ip"`
	ClientPort        uint16  `json:"client_port,omitempty"`
	PeerIP            string  `json:"peer_ip,omitempty"`
	UpstreamAddr      string  `json:"upstream_addr,omitempty"`
	UpstreamConnectMS *uint32 `json:"upstream_connect_ms,omitempty"`
	EndReason         string  `json:"end_reason"`
}

type CapturePolicy struct {
	Enabled             bool
	Methods             []string
	URIPrefixes         []string
	RequestHeaders      []string
	ResponseHeaders     []string
	RequestBodyFields   []string
	ResponseBodyFields  []string
	MaxHeaderValueBytes int
	MaxBodyBytes        int
	MaxEventBytes       int
}

type PressureMode string

const (
	PressureBackpressure PressureMode = "backpressure"
	PressureSample       PressureMode = "sample"
)

type Config struct {
	Root                string
	MaxEventBytes       int
	MaxSegmentBytes     int64
	SoftLimitBytes      int64
	HardLimitBytes      int64
	MaxTenantBytes      int64
	MaxBatchEvents      int
	PressureMode        PressureMode
	AccessSampleEvery   uint32
	SecuritySampleEvery uint32
	SoftAgeLimit        time.Duration
	HardAgeLimit        time.Duration
	Now                 func() time.Time
}

type Record struct {
	Sequence   uint64
	EventID    string
	TenantID   string
	NodeID     string
	Type       EventType
	OccurredAt time.Time
	Payload    []byte
	Size       int64
	digest     [32]byte
	envelope   Envelope
}

type AppendResult struct {
	EventID   string
	Sequence  uint64
	Duplicate bool
	Sampled   bool
	// Expired: the event is older than the hard age limit; it was skipped
	// (not stored) and counted in Stats.ExpiredEvents.
	Expired bool
}

type Stats struct {
	NextSequence     uint64           `json:"next_sequence"`
	AckedSequence    uint64           `json:"acked_sequence"`
	PendingEvents    int              `json:"pending_events"`
	SegmentBytes     int64            `json:"segment_bytes"`
	PeakBytes        int64            `json:"peak_bytes"`
	TenantBytes      map[string]int64 `json:"tenant_bytes"`
	LastAlertCode    string           `json:"last_alert_code,omitempty"`
	OldestOccurredAt time.Time        `json:"oldest_occurred_at,omitempty"`
	OldestAgeSeconds uint64           `json:"oldest_age_seconds"`
	AgePressure      string           `json:"age_pressure"`
	ExpiredEvents    uint64           `json:"expired_events"`
}

type Publication struct {
	Subject       string
	MessageID     string
	Payload       []byte
	FirstSequence uint64
	LastSequence  uint64
	LastEventID   string
	EventCount    int
}

type PublishAck struct {
	Acknowledged int
}

type Publisher interface {
	Publish(context.Context, []Publication) (PublishAck, error)
}

// ConnectionsMetricEnvelope is the generated, versioned carrier used by the
// durable connections queue. Keeping the alias here avoids a second wire
// representation in the edge spool package.
type ConnectionsMetricEnvelope = agentv1.ConnectionsMetricEnvelopeV1

type ConnectionsAppendResult struct {
	EventID         string
	SourceWatermark uint64
	Duplicate       bool
}

type ConnectionsPublishResult struct {
	Published           int
	PublishedMessages   int
	LastSourceWatermark uint64
	Attempts            int
}

type PublishResult struct {
	Published         int
	PublishedMessages int
	LastSequence      uint64
	Attempts          int
}

type RetryConfig struct {
	InitialBackoff  time.Duration
	MaximumBackoff  time.Duration
	MaximumAttempts int
	Sleep           func(context.Context, time.Duration) error
}

type Issue struct {
	Code       string `json:"code"`
	Generation uint64 `json:"generation"`
	Offset     int64  `json:"offset"`
}

type TailResult struct {
	CompletedLines      int
	AppendedEvents      int
	SampledEvents       int
	DuplicateEvents     int
	ExpiredEvents       int
	QuarantinedLines    int
	SkippedLines        int
	RotationFilesHashed int
	RotationBytesHashed int64
	Issues              []Issue
}

type TrustedIdentity struct {
	ListenPort            uint16
	EnrollmentNodeID      string
	TenantID              string
	SiteID                string
	ConfigVersionID       string
	CapturePolicyRevision uint64
	CapturePolicyDigest   string
	StreamID              string
	ListenerID            string
	ConfigRevision        uint64
	// PackageSubscriptionID is the L4 forward's package in its release
	// (L4_PACKAGE_ATTRIBUTION); "" for a forward without a package.
	PackageSubscriptionID string
}

type TailConfig struct {
	SourcePath         string
	StateDir           string
	Identity           TrustedIdentity
	MaxLineBytes       int
	MaxBatchEvents     int
	MaxQuarantineBytes int64
	CapturePolicy      CapturePolicy
	Now                func() time.Time
	EventType          EventType
	// Resolve, for a source shared by many sites (dynamic routing,
	// agents/edge-agent/internal/dyntelemetry), gives each line its own
	// identity and capture policy instead of Identity/CapturePolicy, and the
	// line to parse. ErrLineNotReady stops the tail before that line (it is
	// read again next time); ErrLineSkipped consumes it without an event;
	// any other error quarantines the line.
	// Identity.EnrollmentNodeID is still required; its other fields are
	// unused.
	Resolve func(line []byte) (ResolvedLine, error)
}

// ResolvedLine is a line of a shared source bound to its identity.
type ResolvedLine struct {
	Line          []byte
	Identity      TrustedIdentity
	CapturePolicy CapturePolicy
}

type BatchSink interface {
	AppendBatch(context.Context, []Envelope) ([]AppendResult, error)
}
