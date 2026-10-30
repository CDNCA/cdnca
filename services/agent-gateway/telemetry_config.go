package gateway

import (
	"fmt"
	"math"
	"time"
)

const (
	TelemetryIngestStream               = "ANALYTICS_INGEST_V1"
	TelemetryIngestSubjectPrefix        = "cdnca.analytics.ingest.v1"
	CCCoordinationStream                = "SECURITY_CC_COORDINATION_V1"
	CCCoordinationSubjectPrefix         = "cdnca.security.cccoord.v1"
	ConnectionsTelemetryIngestStream    = "CONNECTIONS_INGEST_V1"
	ConnectionsTelemetrySubjectPrefix   = "cdnca.connections.v1"
	ConnectionsTelemetryMaxPayloadBytes = 16 << 10
	L4TelemetryIngestStream             = "L4_SESSIONS_INGEST_V1"
	L4TelemetrySubjectPrefix            = "cdnca.l4.sessions.v1"
	L4TelemetryMaxPayloadBytes          = 1 << 20

	telemetryProtocolMajor         = 1
	telemetryProtocolMinor         = 0
	telemetryMaxAuthorizationSites = 10_000
	telemetryGRPCEnvelopeOverhead  = 64 << 10
)

type TelemetryConfig struct {
	MaximumRecordsPerBatch uint32
	MaximumRecordBytes     int
	MaximumBatchBytes      int
	PublishTimeout         time.Duration
	RetryAfter             time.Duration
}

func DefaultTelemetryConfig() TelemetryConfig {
	return TelemetryConfig{
		MaximumRecordsPerBatch: 32,
		MaximumRecordBytes:     1 << 20,
		MaximumBatchBytes:      4 << 20,
		PublishTimeout:         5 * time.Second,
		RetryAfter:             time.Second,
	}
}

func (c TelemetryConfig) validate() error {
	if c.MaximumRecordsPerBatch == 0 || c.MaximumRecordBytes <= 0 || c.MaximumBatchBytes <= 0 {
		return fmt.Errorf("telemetry batch and record limits must be positive")
	}
	if c.MaximumRecordBytes > c.MaximumBatchBytes {
		return fmt.Errorf("telemetry record limit must not exceed the batch limit")
	}
	if c.MaximumRecordBytes > math.MaxUint32 || c.MaximumBatchBytes > math.MaxInt32-telemetryGRPCEnvelopeOverhead {
		return fmt.Errorf("telemetry wire limits are too large")
	}
	if c.PublishTimeout <= 0 || c.RetryAfter <= 0 {
		return fmt.Errorf("telemetry durations must be positive")
	}
	return nil
}

func (c TelemetryConfig) grpcReceiveLimit() int {
	return c.MaximumBatchBytes + telemetryGRPCEnvelopeOverhead
}
