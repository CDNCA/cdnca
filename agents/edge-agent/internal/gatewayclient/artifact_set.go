package gatewayclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
)

const (
	artifactSetAPIVersion = 1
	ipIntelAPIVersion     = 2
)

// errArtifactCapabilitiesChanged: an applied node artifact set changed what
// this Agent may declare (IP_INTEL); reconnect so the next hello says so.
var errArtifactCapabilitiesChanged = errors.New("node artifact set changed the declared capabilities")

// ArtifactSetRuntime executes node artifact set deployments (ARTIFACT_SET v1).
type ArtifactSetRuntime interface {
	// PutObject stores a verified segment object under its digest.
	PutObject(digest string, data []byte) error
	// Apply applies a verified set; setSHA256 is the digest of its signed bytes.
	Apply(set artifactset.Set, setSHA256 string, now time.Time) (artifactset.Receipt, error)
	// IPIntelReady reports whether the active set holds an installed IP
	// intelligence library.
	IPIntelReady() bool
}

func WithArtifactSetRuntime(runtime ArtifactSetRuntime) ClientOption {
	return func(client *Client) error {
		if runtime == nil {
			return fmt.Errorf("%w: artifact set runtime is required", ErrInvalidConfiguration)
		}
		client.artifactSets = runtime
		return nil
	}
}

func artifactSetMediaType(command *agentv1.DeploymentCommand) string {
	if command == nil || command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY || len(command.Artifacts) != 1 ||
		command.Artifacts[0] == nil || command.Artifacts[0].Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION {
		return ""
	}
	switch mediaType := command.Artifacts[0].MediaType; mediaType {
	case artifactset.MediaTypeSet, artifactset.MediaTypeSegment:
		return mediaType
	}
	return ""
}

func isArtifactSetCommand(command *agentv1.DeploymentCommand) bool {
	return artifactSetMediaType(command) != ""
}

// validateArtifactSetRoutedCommand checks segment and set commands, then
// falls through to the other specialized routes.
func validateArtifactSetRoutedCommand(command *agentv1.DeploymentCommand, config Config, now time.Time) error {
	mediaType := artifactSetMediaType(command)
	if mediaType == "" {
		return validateErrorPageRoutedCommand(command, config, now)
	}
	descriptor := command.Artifacts[0]
	limit := uint64(artifactset.MaxSegmentBytes)
	if mediaType == artifactset.MediaTypeSet {
		limit = artifactset.MaxSetBytes
	}
	if command.Attempt == 0 || descriptor.SizeBytes == 0 || descriptor.SizeBytes > limit ||
		descriptor.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
		descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE ||
		descriptor.RecipientKeyId != nil ||
		descriptor.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 {
		return fmt.Errorf("%w: invalid node artifact set transport", ErrInvalidMessage)
	}
	validationCopy := proto.Clone(command).(*agentv1.DeploymentCommand)
	validationCopy.Artifacts[0].MediaType = ConfigurationBundleMediaType
	return validateCommand(validationCopy, config, now)
}

func (c *Client) executeArtifactSetRecord(ctx context.Context, gateway agentv1.AgentGatewayServiceClient, record *durableRecord, command *agentv1.DeploymentCommand, maximumChunkBytes uint32) error {
	if c.artifactSets == nil {
		return c.finishArtifactSetFailure(record.RecordKey, command, ErrUnsupportedCommand)
	}
	descriptor := command.Artifacts[0]
	if record.ArtifactOffset > descriptor.SizeBytes {
		return c.finishArtifactSetFailure(record.RecordKey, command, ErrArtifactIntegrity)
	}
	wire, err := fetchSignedArtifact(ctx, gateway, c.store, record, command, descriptor, maximumChunkBytes, c.config, c.trust, c.now)
	if err != nil {
		commandExpired := errors.Is(err, context.DeadlineExceeded) && !c.now().Before(command.DeadlineTime.AsTime())
		if ctx.Err() != nil || !errors.Is(err, ErrArtifactIntegrity) && !commandExpired {
			return err
		}
		return c.finishArtifactSetFailure(record.RecordKey, command, err)
	}
	if descriptor.MediaType == artifactset.MediaTypeSegment {
		// The descriptor's signed digest is the segment's content address.
		if err := c.artifactSets.PutObject(fmt.Sprintf("%x", descriptor.Sha256), wire); err != nil {
			return c.finishArtifactSetFailure(record.RecordKey, command, err)
		}
		return c.store.appendStatuses(record.RecordKey, artifactSetSuccessStatuses(command, c.now(), "ARTIFACT_SEGMENT", "segment object stored", nil), true)
	}
	set, err := artifactset.Verify(wire, c.trust.Ed25519Key)
	if err != nil {
		return c.finishArtifactSetFailure(record.RecordKey, command, errors.Join(ErrArtifactIntegrity, err))
	}
	receipt, err := c.artifactSets.Apply(set, artifactset.Digest(wire), c.now())
	if err != nil {
		return c.finishArtifactSetFailure(record.RecordKey, command, err)
	}
	encoded, err := artifactset.EncodeReceipt(receipt)
	if err != nil {
		return c.finishArtifactSetFailure(record.RecordKey, command, err)
	}
	if receipt.Result != artifactset.ResultApplied {
		status := failedStatus(command, 2, c.now(), commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION,
			"node artifact set "+receipt.Result+"; the last known good set is kept", receipt.Result == artifactset.ResultPending)
		status.RunningConfigUnchanged = true
		status.ArtifactSetReceipt = encoded
		return c.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{status}, true)
	}
	return c.store.appendStatuses(record.RecordKey, artifactSetSuccessStatuses(command, c.now(), "ARTIFACT_SET", "node artifact set applied", encoded), true)
}

func artifactSetSuccessStatuses(command *agentv1.DeploymentCommand, at time.Time, code, summary string, receipt []byte) []*agentv1.DeploymentStatus {
	statuses := []*agentv1.DeploymentStatus{
		statusFor(command, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, at, true, code+"_STAGED", "node artifact staged", 0),
		statusFor(command, 3, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED, at, true, code+"_PRECHECKED", "node artifact verified", 0),
		statusFor(command, 4, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, at, true, code+"_ACTIVATED", summary, 0),
		statusFor(command, 5, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, at, true, code+"_HEALTHY", summary, 0),
	}
	statuses[3].ArtifactSetReceipt = receipt
	return statuses
}

func (c *Client) finishArtifactSetFailure(key string, command *agentv1.DeploymentCommand, err error) error {
	code, summary := commonv1.ErrorCode_ERROR_CODE_INTERNAL, "node artifact operation failed"
	switch {
	case errors.Is(err, ErrArtifactIntegrity):
		code, summary = commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "node artifact was rejected"
	case errors.Is(err, ErrUnsupportedCommand):
		code, summary = commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "node artifact set runtime is unavailable"
	case errors.Is(err, context.DeadlineExceeded):
		code, summary = commonv1.ErrorCode_ERROR_CODE_DEADLINE_EXCEEDED, "node artifact command deadline expired"
	}
	status := failedStatus(command, 2, c.now(), code, summary, false)
	status.RunningConfigUnchanged = true
	return c.store.appendStatuses(key, []*agentv1.DeploymentStatus{status}, true)
}

// dynamicCapabilities are the node artifact set capabilities this Agent may
// declare now.
func (c *Client) dynamicCapabilities() []*agentv1.Capability {
	if c.artifactSets == nil {
		return nil
	}
	capabilities := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET, ApiVersion: artifactSetAPIVersion}}
	if c.artifactSets.IPIntelReady() {
		capabilities = append(capabilities, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: ipIntelAPIVersion})
	}
	return capabilities
}

// commandConfig is c.config with the dynamic capabilities, for checking a
// command's required capabilities against what this Agent declared.
func (c *Client) commandConfig() Config {
	config := c.config
	dynamic := c.dynamicCapabilities()
	if len(dynamic) == 0 {
		return config
	}
	config.Capabilities = proto.Clone(c.config.Capabilities).(*agentv1.AgentCapabilities)
	for _, capability := range dynamic {
		if !hasCapability(config.Capabilities, capability.Name) {
			config.Capabilities.Features = append(config.Capabilities.Features, capability)
		}
	}
	return config
}
