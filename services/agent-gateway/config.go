package gateway

import (
	"fmt"
	"math"
	"time"

	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
)

const (
	defaultMaxMessageBytes       = 1 << 20
	defaultMaxArtifactBytes      = 128 << 20
	defaultMaxArtifactChunkBytes = 256 << 10
	defaultMaxMetadataBytes      = 4 << 10
	defaultMaxIdentifierBytes    = 128
	defaultMaxActiveDeployments  = 128
	defaultMaxCapabilities       = 64
	defaultMaxCommandArtifacts   = 128
	defaultMaxDeploymentChecks   = 64
	defaultMaxPendingCommands    = 8
	defaultMessageReplayWindow   = 1024
)

// Config contains only process-local transport and protocol limits. Node
// authorization remains a control-plane decision.
type Config struct {
	GatewayInstanceID string
	GatewayVersion    string
	SupportedVersions *commonv1.ProtocolVersionRange

	MaxReceiveMessageBytes  int
	MaxSendMessageBytes     int
	MaxArtifactBytes        uint64
	MaxArtifactChunkBytes   int
	MaxRequestMetadataBytes int
	MaxEventMetadataBytes   int
	MaxIdentifierBytes      int
	MaxActiveDeployments    int
	MaxCapabilities         int
	MaxCommandArtifacts     int
	MaxDeploymentChecks     int
	MaxPendingCommands      int
	MessageIDReplayWindow   int
	MaxConcurrentStreams    uint32

	HandshakeTimeout        time.Duration
	ControlDecisionTimeout  time.Duration
	ArtifactTransferTimeout time.Duration
	CommandOperationTimeout time.Duration
	HeartbeatPersistTimeout time.Duration
	HeartbeatInterval       time.Duration
	OfflineAfter            time.Duration
	KeepaliveTime           time.Duration
	KeepaliveTimeout        time.Duration
	MinimumClientPingTime   time.Duration
	ConnectionTimeout       time.Duration
}

func DefaultConfig() Config {
	return Config{
		SupportedVersions: &commonv1.ProtocolVersionRange{
			Minimum: &commonv1.ProtocolVersion{Major: 1, Minor: 0},
			Maximum: &commonv1.ProtocolVersion{Major: 1, Minor: 0},
		},
		MaxReceiveMessageBytes:  defaultMaxMessageBytes,
		MaxSendMessageBytes:     defaultMaxMessageBytes,
		MaxArtifactBytes:        defaultMaxArtifactBytes,
		MaxArtifactChunkBytes:   defaultMaxArtifactChunkBytes,
		MaxRequestMetadataBytes: defaultMaxMetadataBytes,
		MaxEventMetadataBytes:   defaultMaxMetadataBytes,
		MaxIdentifierBytes:      defaultMaxIdentifierBytes,
		MaxActiveDeployments:    defaultMaxActiveDeployments,
		MaxCapabilities:         defaultMaxCapabilities,
		MaxCommandArtifacts:     defaultMaxCommandArtifacts,
		MaxDeploymentChecks:     defaultMaxDeploymentChecks,
		MaxPendingCommands:      defaultMaxPendingCommands,
		MessageIDReplayWindow:   defaultMessageReplayWindow,
		MaxConcurrentStreams:    1024,
		HandshakeTimeout:        10 * time.Second,
		ControlDecisionTimeout:  5 * time.Second,
		ArtifactTransferTimeout: 5 * time.Minute,
		CommandOperationTimeout: 5 * time.Second,
		HeartbeatPersistTimeout: 5 * time.Second,
		HeartbeatInterval:       15 * time.Second,
		OfflineAfter:            45 * time.Second,
		KeepaliveTime:           30 * time.Second,
		KeepaliveTimeout:        10 * time.Second,
		MinimumClientPingTime:   10 * time.Second,
		ConnectionTimeout:       10 * time.Second,
	}
}

func (c Config) validate() error {
	if c.GatewayInstanceID == "" || c.GatewayVersion == "" {
		return fmt.Errorf("gateway instance ID and version are required")
	}
	if err := validateVersionRange(c.SupportedVersions); err != nil {
		return fmt.Errorf("gateway protocol versions: %w", err)
	}
	if c.MaxReceiveMessageBytes <= 0 || c.MaxSendMessageBytes <= 0 || c.MaxArtifactBytes == 0 || c.MaxArtifactChunkBytes <= 0 {
		return fmt.Errorf("message and artifact limits must be positive")
	}
	if uint64(c.MaxArtifactChunkBytes) > c.MaxArtifactBytes {
		return fmt.Errorf("artifact chunk limit must not exceed the artifact limit")
	}
	if c.MaxRequestMetadataBytes <= 0 || c.MaxEventMetadataBytes <= 0 || c.MaxIdentifierBytes <= 0 {
		return fmt.Errorf("metadata limits must be positive")
	}
	if c.MaxActiveDeployments <= 0 || c.MaxCapabilities <= 0 || c.MaxCommandArtifacts <= 0 || c.MaxDeploymentChecks <= 0 || c.MaxPendingCommands <= 0 || c.MessageIDReplayWindow <= 0 || c.MaxConcurrentStreams == 0 {
		return fmt.Errorf("collection and concurrency limits must be positive")
	}
	if c.MessageIDReplayWindow > math.MaxUint32 || c.MaxArtifactChunkBytes > math.MaxUint32 {
		return fmt.Errorf("wire limits must fit uint32")
	}
	if c.HandshakeTimeout <= 0 || c.ControlDecisionTimeout <= 0 || c.ArtifactTransferTimeout <= 0 || c.CommandOperationTimeout <= 0 || c.HeartbeatPersistTimeout <= 0 || c.HeartbeatInterval <= 0 || c.OfflineAfter <= 0 {
		return fmt.Errorf("protocol durations must be positive")
	}
	if c.OfflineAfter <= c.HeartbeatInterval {
		return fmt.Errorf("offline duration must exceed heartbeat interval")
	}
	if c.KeepaliveTime <= 0 || c.KeepaliveTimeout <= 0 || c.MinimumClientPingTime <= 0 || c.ConnectionTimeout <= 0 {
		return fmt.Errorf("transport durations must be positive")
	}
	return nil
}
