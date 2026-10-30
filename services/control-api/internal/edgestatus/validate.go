package edgestatus

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	DefaultSubjectPrefix    = "cdnca.agent.deployment-status"
	DefaultMaxStatusBytes   = 1 << 20
	DefaultMaxChecks        = 64
	DefaultMaxMetadataBytes = 2048
	DefaultMaxFutureSkew    = 5 * time.Minute
)

type ValidatorConfig struct {
	SubjectPrefix    string
	MaxStatusBytes   int
	MaxChecks        int
	MaxMetadataBytes int
	MaxFutureSkew    time.Duration
}

func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		SubjectPrefix: DefaultSubjectPrefix, MaxStatusBytes: DefaultMaxStatusBytes,
		MaxChecks: DefaultMaxChecks, MaxMetadataBytes: DefaultMaxMetadataBytes,
		MaxFutureSkew: DefaultMaxFutureSkew,
	}
}

type Validator struct {
	config ValidatorConfig
	now    func() time.Time
}

func NewValidator(config ValidatorConfig) (*Validator, error) {
	if !validSubjectPrefix(config.SubjectPrefix) || config.MaxStatusBytes <= 0 ||
		config.MaxChecks <= 0 || config.MaxMetadataBytes <= 0 || config.MaxFutureSkew <= 0 {
		return nil, fmt.Errorf("%w: validator configuration", ErrInvalidStatus)
	}
	return &Validator{config: config, now: time.Now}, nil
}

func (v *Validator) Decode(subject string, payload []byte) (Envelope, error) {
	nodeID, subjectEventID, err := statusIdentityFromSubject(v.config.SubjectPrefix, subject)
	if err != nil {
		return Envelope{}, err
	}
	if len(payload) == 0 || len(payload) > v.config.MaxStatusBytes {
		return Envelope{}, fmt.Errorf("%w: payload size", ErrInvalidStatus)
	}
	status := new(agentv1.DeploymentStatus)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, status); err != nil || hasUnknown(status.ProtoReflect()) {
		return Envelope{}, fmt.Errorf("%w: protobuf payload", ErrInvalidStatus)
	}
	deploymentID, configID, eventID, requestID, err := v.validateStatus(status)
	if err != nil {
		return Envelope{}, err
	}
	if subjectEventID != uuid.Nil && subjectEventID != eventID {
		return Envelope{}, fmt.Errorf("%w: subject event ID", ErrInvalidStatus)
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil || len(canonical) > v.config.MaxStatusBytes {
		return Envelope{}, fmt.Errorf("%w: deterministic payload", ErrInvalidStatus)
	}
	return Envelope{
		NodeID: nodeID, DeploymentID: deploymentID, ConfigID: configID,
		EventID: eventID, RequestID: requestID, Status: status,
		Payload: canonical, Digest: sha256.Sum256(canonical),
	}, nil
}

func (v *Validator) validateStatus(status *agentv1.DeploymentStatus) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, error) {
	if status.Event == nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: event metadata", ErrInvalidStatus)
	}
	deploymentID, err := canonicalUUID(status.DeploymentId)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: deployment ID", ErrInvalidStatus)
	}
	configID, err := canonicalUUID(status.ConfigVersionId)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: config version ID", ErrInvalidStatus)
	}
	eventID, err := canonicalUUID(status.Event.EventId)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: event ID", ErrInvalidStatus)
	}
	requestID, err := canonicalUUID(status.Event.RequestId)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: request ID", ErrInvalidStatus)
	}
	if status.Event.OccurredTime == nil || status.Event.OccurredTime.CheckValid() != nil ||
		status.Event.OccurredTime.AsTime().After(v.now().Add(v.config.MaxFutureSkew)) {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: occurrence time", ErrInvalidStatus)
	}
	if status.Event.CausationId != nil {
		if _, err := canonicalUUID(status.Event.GetCausationId()); err != nil {
			return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: causation ID", ErrInvalidStatus)
		}
	}
	if status.Event.CorrelationId != "" {
		if _, err := canonicalUUID(status.Event.CorrelationId); err != nil {
			return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: correlation ID", ErrInvalidStatus)
		}
	}
	if !validMetadata(status.Event.Traceparent, 512) ||
		(status.Event.TaskId != nil && !validIdentifier(status.Event.GetTaskId(), 128)) {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: event correlation metadata", ErrInvalidStatus)
	}
	if status.Attempt == 0 || uint64(status.Attempt) > math.MaxInt32 ||
		status.TransitionSequence == 0 || status.TransitionSequence > math.MaxInt64 {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: attempt or transition sequence", ErrInvalidStatus)
	}
	if _, known := agentv1.NodeDeploymentState_name[int32(status.State)]; !known ||
		status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_UNSPECIFIED {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: deployment state", ErrInvalidStatus)
	}
	if status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED && !status.RunningConfigUnchanged {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: failed status changed running config", ErrInvalidStatus)
	}
	if len(status.Checks) > v.config.MaxChecks {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: check count", ErrInvalidStatus)
	}
	seenChecks := make(map[string]struct{}, len(status.Checks))
	for _, check := range status.Checks {
		if check == nil || !validIdentifier(check.Name, 128) || !validMetadata(check.Summary, v.config.MaxMetadataBytes) ||
			(check.LatencyDuration != nil && (check.LatencyDuration.CheckValid() != nil || check.LatencyDuration.AsDuration() < 0)) {
			return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: deployment check", ErrInvalidStatus)
		}
		if _, exists := seenChecks[check.Name]; exists {
			return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: duplicate deployment check", ErrInvalidStatus)
		}
		seenChecks[check.Name] = struct{}{}
	}
	failed := status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED ||
		status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED
	if failed != (status.Error != nil) {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: protocol error/state mismatch", ErrInvalidStatus)
	}
	if status.Error != nil && !v.validProtocolError(status.Error) {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: protocol error", ErrInvalidStatus)
	}
	if !validArtifactSetReceiptShape(status) {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("%w: node artifact set receipt", ErrInvalidStatus)
	}
	if _, err := normalizeStatusActiveIdentity(status); err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, err
	}
	return deploymentID, configID, eventID, requestID, nil
}

type normalizedStatusActiveIdentity struct {
	ConfigID uuid.UUID
	Schema   int32
	Digest   []byte
}

func normalizeStatusActiveIdentity(status *agentv1.DeploymentStatus) (*normalizedStatusActiveIdentity, error) {
	capability := status.ActiveConfigIdentityCapability
	identity := status.ActiveConfigIdentity
	if capability == nil {
		if identity != nil {
			return nil, fmt.Errorf("%w: active config identity capability", ErrInvalidStatus)
		}
		return nil, nil
	}
	if capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY || capability.ApiVersion != 1 {
		return nil, fmt.Errorf("%w: active config identity capability", ErrInvalidStatus)
	}
	if identity == nil {
		return nil, nil
	}
	if status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY &&
		status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED {
		return nil, fmt.Errorf("%w: nonterminal active config identity", ErrInvalidStatus)
	}
	if identity.Schema != agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1 ||
		len(identity.ArtifactSha256) != sha256.Size || identity.ConfigVersionId != status.ConfigVersionId {
		return nil, fmt.Errorf("%w: active config identity tuple", ErrInvalidStatus)
	}
	configID, err := canonicalUUID(identity.ConfigVersionId)
	if err != nil || configID == uuid.Nil {
		return nil, fmt.Errorf("%w: active config identity config version", ErrInvalidStatus)
	}
	return &normalizedStatusActiveIdentity{
		ConfigID: configID, Schema: int32(identity.Schema), Digest: append([]byte(nil), identity.ArtifactSha256...),
	}, nil
}

func (v *Validator) validProtocolError(value *commonv1.ProtocolError) bool {
	if value.Code == commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED || value.Message == "" ||
		!validMetadata(value.Message, v.config.MaxMetadataBytes) || len(value.FieldViolations) > v.config.MaxChecks ||
		(value.RetryAfterDuration != nil && (value.RetryAfterDuration.CheckValid() != nil || value.RetryAfterDuration.AsDuration() < 0)) {
		return false
	}
	if _, known := commonv1.ErrorCode_name[int32(value.Code)]; !known {
		return false
	}
	for _, violation := range value.FieldViolations {
		if violation == nil || !validIdentifier(violation.Field, 128) || violation.Description == "" ||
			!validMetadata(violation.Description, v.config.MaxMetadataBytes) {
			return false
		}
	}
	return true
}

func hasUnknown(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsList() && field.Kind() == protoreflect.MessageKind:
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if hasUnknown(list.Get(index).Message()) {
					unknown = true
					return false
				}
			}
		case field.IsMap() && field.MapValue().Kind() == protoreflect.MessageKind:
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				unknown = hasUnknown(item.Message())
				return !unknown
			})
		case field.Kind() == protoreflect.MessageKind:
			unknown = hasUnknown(value.Message())
		}
		return !unknown
	})
	return unknown
}

func statusIdentityFromSubject(prefix, subject string) (uuid.UUID, uuid.UUID, error) {
	wanted := prefix + "."
	if !strings.HasPrefix(subject, wanted) {
		return uuid.Nil, uuid.Nil, fmt.Errorf("%w: subject prefix", ErrInvalidStatus)
	}
	parts := strings.Split(strings.TrimPrefix(subject, wanted), ".")
	if len(parts) == 1 {
		nodeID, err := canonicalUUID(parts[0])
		if err != nil {
			return uuid.Nil, uuid.Nil, fmt.Errorf("%w: subject node ID", ErrInvalidStatus)
		}
		return nodeID, uuid.Nil, nil
	}
	if len(parts) != 3 || parts[0] != "generic-v2" {
		return uuid.Nil, uuid.Nil, fmt.Errorf("%w: subject identity", ErrInvalidStatus)
	}
	nodeID, err := canonicalUUID(parts[1])
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("%w: subject node ID", ErrInvalidStatus)
	}
	eventID, err := canonicalUUID(parts[2])
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("%w: subject event ID", ErrInvalidStatus)
	}
	return nodeID, eventID, nil
}

func canonicalUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, fmt.Errorf("not a canonical UUID")
	}
	return parsed, nil
}

func validIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func validMetadata(value string, maximum int) bool {
	return len(value) <= maximum && strings.TrimSpace(value) == value && !bytes.ContainsAny([]byte(value), "\x00\r\n")
}

func validSubjectPrefix(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if !validIdentifier(token, 128) {
			return false
		}
	}
	return true
}
