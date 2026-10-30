package gatewayclient

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
)

const ConfigurationBundleMediaType = edgeconfig.ConfigurationBundleMediaType

var (
	ErrInvalidConfiguration = errors.New("invalid gateway client configuration")
	ErrInvalidMessage       = errors.New("invalid gateway message")
	ErrCommandConflict      = errors.New("deployment command conflicts with durable state")
	ErrArtifactIntegrity    = errors.New("artifact integrity verification failed")
	ErrUnsupportedCommand   = errors.New("deployment command is not supported")
	ErrPermanentProtocol    = errors.New("permanent gateway protocol failure")
)

type DeploymentManager interface {
	Process(context.Context, deployment.Command) (deployment.Result, error)
	Pointers() (deployment.Pointers, error)
}

type Config struct {
	NodeID                       string
	BootID                       string
	ArtifactEncryptionKeyID      string
	ArtifactDecryptionPrivateKey []byte
	JournalDir                   string
	SupportedVersions            *commonv1.ProtocolVersionRange
	Capabilities                 *agentv1.AgentCapabilities
	MaxCommandBytes              int
	MaxStatusBytes               int
	MaxArtifactBytes             uint64
	MaxDecompressedBytes         int64
	MaxArtifactChunkBytes        uint32
	MaxActiveDeployments         int
	CommandQueueSize             int
	HandshakeTimeout             time.Duration
	FetchTimeout                 time.Duration
	InitialBackoff               time.Duration
	MaximumBackoff               time.Duration
}

func DefaultConfig() Config {
	return Config{
		SupportedVersions: &commonv1.ProtocolVersionRange{
			Minimum: &commonv1.ProtocolVersion{Major: 1},
			Maximum: &commonv1.ProtocolVersion{Major: 1},
		},
		MaxCommandBytes:       1 << 20,
		MaxStatusBytes:        256 << 10,
		MaxArtifactBytes:      128 << 20,
		MaxDecompressedBytes:  128 << 20,
		MaxArtifactChunkBytes: 1 << 20,
		MaxActiveDeployments:  128,
		CommandQueueSize:      32,
		HandshakeTimeout:      10 * time.Second,
		FetchTimeout:          2 * time.Minute,
		InitialBackoff:        250 * time.Millisecond,
		MaximumBackoff:        30 * time.Second,
	}
}

func (c Config) validate() error {
	if !canonicalUUID(c.NodeID) || !canonicalUUID(c.BootID) {
		return fmt.Errorf("%w: node_id and boot_id must be canonical UUIDs", ErrInvalidConfiguration)
	}
	if !boundedMetadata(c.ArtifactEncryptionKeyID, true) {
		return fmt.Errorf("%w: artifact encryption key ID is required", ErrInvalidConfiguration)
	}
	if len(c.ArtifactDecryptionPrivateKey) != 0 {
		if len(c.ArtifactDecryptionPrivateKey) != 32 {
			return fmt.Errorf("%w: artifact decryption private key is invalid", ErrInvalidConfiguration)
		}
		privateKey, err := ecdh.X25519().NewPrivateKey(c.ArtifactDecryptionPrivateKey)
		if err != nil {
			return fmt.Errorf("%w: artifact decryption private key is invalid", ErrInvalidConfiguration)
		}
		digest := sha256.Sum256(privateKey.PublicKey().Bytes())
		if c.ArtifactEncryptionKeyID != "x25519:"+hex.EncodeToString(digest[:]) {
			return fmt.Errorf("%w: artifact decryption key does not match its key ID", ErrInvalidConfiguration)
		}
	}
	if err := validateVersionRange(c.SupportedVersions); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
	}
	if c.Capabilities == nil || !boundedMetadata(c.Capabilities.AgentVersion, true) || !boundedMetadata(c.Capabilities.BuildId, false) || !boundedMetadata(c.Capabilities.OperatingSystem, false) || !boundedMetadata(c.Capabilities.Architecture, false) || !boundedMetadata(c.Capabilities.OpenrestyVersion, false) || len(c.Capabilities.Features) > 64 {
		return fmt.Errorf("%w: agent capabilities are required", ErrInvalidConfiguration)
	}
	seen := make(map[agentv1.CapabilityName]struct{}, len(c.Capabilities.Features))
	for _, capability := range c.Capabilities.Features {
		if capability == nil || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED || capability.ApiVersion == 0 {
			return fmt.Errorf("%w: invalid capability", ErrInvalidConfiguration)
		}
		if _, known := agentv1.CapabilityName_name[int32(capability.Name)]; !known {
			return fmt.Errorf("%w: unknown capability", ErrInvalidConfiguration)
		}
		if _, exists := seen[capability.Name]; exists {
			return fmt.Errorf("%w: duplicate capability", ErrInvalidConfiguration)
		}
		seen[capability.Name] = struct{}{}
	}
	if c.JournalDir == "" || c.MaxCommandBytes <= 0 || c.MaxStatusBytes <= 0 || c.MaxArtifactBytes == 0 || c.MaxDecompressedBytes <= 0 || c.MaxArtifactChunkBytes == 0 || c.MaxActiveDeployments <= 0 || c.CommandQueueSize <= 0 {
		return fmt.Errorf("%w: storage and size limits must be positive", ErrInvalidConfiguration)
	}
	if c.MaxArtifactBytes > math.MaxInt64 || uint64(c.MaxArtifactChunkBytes) > c.MaxArtifactBytes {
		return fmt.Errorf("%w: artifact limits are inconsistent", ErrInvalidConfiguration)
	}
	if c.HandshakeTimeout <= 0 || c.FetchTimeout <= 0 || c.InitialBackoff <= 0 || c.MaximumBackoff < c.InitialBackoff {
		return fmt.Errorf("%w: invalid timeout or reconnect policy", ErrInvalidConfiguration)
	}
	return nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func validateVersionRange(value *commonv1.ProtocolVersionRange) error {
	if value == nil || value.Minimum == nil || value.Maximum == nil || value.Minimum.Major == 0 || value.Maximum.Major == 0 {
		return fmt.Errorf("protocol version range is incomplete")
	}
	if compareVersion(value.Minimum, value.Maximum) > 0 {
		return fmt.Errorf("minimum protocol version exceeds maximum")
	}
	return nil
}

func compareVersion(left, right *commonv1.ProtocolVersion) int {
	if left.Major < right.Major || left.Major == right.Major && left.Minor < right.Minor {
		return -1
	}
	if left.Major == right.Major && left.Minor == right.Minor {
		return 0
	}
	return 1
}

func versionInRange(version *commonv1.ProtocolVersion, supported *commonv1.ProtocolVersionRange) bool {
	return version != nil && validateVersionRange(supported) == nil && compareVersion(version, supported.Minimum) >= 0 && compareVersion(version, supported.Maximum) <= 0
}
