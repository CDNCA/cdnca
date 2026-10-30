package nodepresence

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

type ValidatorConfig struct {
	SubjectPrefix        string
	MaxHeartbeatBytes    int
	MaxActiveDeployments int
	MaxFutureSkew        time.Duration
	MaxPastAge           time.Duration
}

type Validator struct {
	config ValidatorConfig
	now    func() time.Time
}

func NewValidator(config ValidatorConfig) (*Validator, error) {
	if !validSubjectPrefix(config.SubjectPrefix) || config.MaxHeartbeatBytes <= 0 ||
		config.MaxActiveDeployments <= 0 || config.MaxFutureSkew <= 0 || config.MaxPastAge <= 0 {
		return nil, fmt.Errorf("%w: invalid validator configuration", ErrInvalidHeartbeat)
	}
	return &Validator{config: config, now: time.Now}, nil
}

func (v *Validator) Decode(subject string, payload []byte) (Envelope, error) {
	nodeID, err := nodeIDFromSubject(v.config.SubjectPrefix, subject)
	if err != nil {
		return Envelope{}, err
	}
	if len(payload) == 0 || len(payload) > v.config.MaxHeartbeatBytes {
		return Envelope{}, fmt.Errorf("%w: payload size", ErrInvalidHeartbeat)
	}
	heartbeat := new(agentv1.Heartbeat)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, heartbeat); err != nil {
		return Envelope{}, fmt.Errorf("%w: protobuf", ErrInvalidHeartbeat)
	}
	if err := v.validateHeartbeat(heartbeat); err != nil {
		return Envelope{}, err
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(heartbeat)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: deterministic protobuf", ErrInvalidHeartbeat)
	}
	return Envelope{NodeID: nodeID, Heartbeat: heartbeat, Digest: sha256.Sum256(canonical)}, nil
}

func (v *Validator) validateHeartbeat(heartbeat *agentv1.Heartbeat) error {
	if heartbeat.Event == nil || heartbeat.Runtime == nil || heartbeat.Resources == nil {
		return fmt.Errorf("%w: required heartbeat fields", ErrInvalidHeartbeat)
	}
	if _, err := canonicalUUID(heartbeat.Event.EventId); err != nil {
		return fmt.Errorf("%w: event ID", ErrInvalidHeartbeat)
	}
	if _, err := canonicalUUID(heartbeat.Event.RequestId); err != nil {
		return fmt.Errorf("%w: request ID", ErrInvalidHeartbeat)
	}
	now := v.now()
	if heartbeat.Event.OccurredTime == nil || heartbeat.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("%w: occurrence time", ErrInvalidHeartbeat)
	}
	occurredAt := heartbeat.Event.OccurredTime.AsTime()
	if occurredAt.After(now.Add(v.config.MaxFutureSkew)) || occurredAt.Before(now.Add(-v.config.MaxPastAge)) {
		return fmt.Errorf("%w: occurrence time", ErrInvalidHeartbeat)
	}
	if heartbeat.SessionEpoch == 0 || heartbeat.SessionEpoch > math.MaxInt64 ||
		heartbeat.HeartbeatSequence == 0 || heartbeat.HeartbeatSequence > math.MaxInt64 {
		return fmt.Errorf("%w: heartbeat version", ErrInvalidHeartbeat)
	}
	if heartbeat.AgentVersion != nil && !validReportedAgentVersion(heartbeat.GetAgentVersion()) {
		return fmt.Errorf("%w: agent version", ErrInvalidHeartbeat)
	}
	if err := validateOptionalUUID(heartbeat.CurrentConfigVersionId); err != nil {
		return fmt.Errorf("%w: current config version", ErrInvalidHeartbeat)
	}
	if err := validateOptionalUUID(heartbeat.PreviousConfigVersionId); err != nil {
		return fmt.Errorf("%w: previous config version", ErrInvalidHeartbeat)
	}
	if err := validateOptionalUUID(heartbeat.Runtime.LoadedConfigVersionId); err != nil {
		return fmt.Errorf("%w: loaded config version", ErrInvalidHeartbeat)
	}
	if !validRuntimeState(heartbeat.Runtime.OpenrestyState) || !validRuntimeState(heartbeat.Runtime.FirewallState) {
		return fmt.Errorf("%w: runtime state", ErrInvalidHeartbeat)
	}
	if _, known := agentv1.MarketProbeRole_name[int32(heartbeat.Runtime.MarketProbe)]; !known {
		return fmt.Errorf("%w: market probe role", ErrInvalidHeartbeat)
	}
	if !validNativeRuntime(heartbeat.Runtime.NativeRuntime) {
		return fmt.Errorf("%w: native runtime", ErrInvalidHeartbeat)
	}
	if heartbeat.Resources.FilesystemAvailableBytes > heartbeat.Resources.FilesystemTotalBytes {
		return fmt.Errorf("%w: filesystem usage", ErrInvalidHeartbeat)
	}
	if len(heartbeat.ActiveDeployments) > v.config.MaxActiveDeployments {
		return fmt.Errorf("%w: active deployment count", ErrInvalidHeartbeat)
	}
	seen := make(map[string]struct{}, len(heartbeat.ActiveDeployments))
	for _, deployment := range heartbeat.ActiveDeployments {
		if deployment == nil || deployment.Attempt == 0 || !validDeploymentState(deployment.State) {
			return fmt.Errorf("%w: active deployment", ErrInvalidHeartbeat)
		}
		if _, err := canonicalUUID(deployment.DeploymentId); err != nil {
			return fmt.Errorf("%w: deployment ID", ErrInvalidHeartbeat)
		}
		if _, err := canonicalUUID(deployment.ConfigVersionId); err != nil {
			return fmt.Errorf("%w: deployment config version", ErrInvalidHeartbeat)
		}
		key := fmt.Sprintf("%s:%d", deployment.DeploymentId, deployment.Attempt)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate active deployment", ErrInvalidHeartbeat)
		}
		seen[key] = struct{}{}
	}
	if err := validateHeartbeatActiveIdentities(heartbeat); err != nil {
		return err
	}
	if _, err := normalizeScopedConfigIdentities(heartbeat); err != nil {
		return err
	}
	return nil
}

// maxScopedConfigIdentities matches the agent.v1 limit on reported scopes.
const maxScopedConfigIdentities = 256

type normalizedScopedConfigIdentity struct {
	ScopeID                    uuid.UUID
	Current, Previous          *normalizedActiveConfigIdentity
	CurrentID, PreviousID      *uuid.UUID
	ApplyDeploymentID          uuid.UUID
	ApplyAttempt               uint32
	ApplyConfigID              uuid.UUID
	ApplyState, ApplyErrorCode string
	ApplyFinishedAt            *time.Time
}

// normalizeScopedConfigIdentities checks the MULTI_TENANT_RUNTIME identity
// list (agent.v1 ScopedConfigIdentity): one entry per scope, a current
// version or a first apply result in each, and the legacy fields mirroring
// a single entry or left empty for several.
func normalizeScopedConfigIdentities(heartbeat *agentv1.Heartbeat) ([]normalizedScopedConfigIdentity, error) {
	entries := heartbeat.ScopedConfigIdentities
	if len(entries) == 0 {
		return nil, nil
	}
	if len(entries) > maxScopedConfigIdentities || heartbeat.ActiveConfigIdentityCapability == nil {
		return nil, fmt.Errorf("%w: scoped config identities", ErrInvalidHeartbeat)
	}
	result := make([]normalizedScopedConfigIdentity, 0, len(entries))
	seen := make(map[uuid.UUID]struct{}, len(entries))
	for _, entry := range entries {
		if entry == nil {
			return nil, fmt.Errorf("%w: scoped config identity", ErrInvalidHeartbeat)
		}
		scopeID, err := canonicalUUID(entry.ConfigurationScopeId)
		if err != nil || scopeID == uuid.Nil {
			return nil, fmt.Errorf("%w: scoped config identity scope", ErrInvalidHeartbeat)
		}
		if _, duplicate := seen[scopeID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate scoped config identity", ErrInvalidHeartbeat)
		}
		seen[scopeID] = struct{}{}
		value := normalizedScopedConfigIdentity{ScopeID: scopeID}
		if (entry.CurrentConfigVersionId == nil) != (entry.CurrentConfigIdentity == nil) ||
			(entry.PreviousConfigVersionId == nil) != (entry.PreviousConfigIdentity == nil) ||
			entry.PreviousConfigVersionId != nil && entry.CurrentConfigVersionId == nil {
			return nil, fmt.Errorf("%w: scoped config identity pairs", ErrInvalidHeartbeat)
		}
		if value.Current, err = normalizeActiveConfigIdentity(entry.CurrentConfigIdentity, entry.CurrentConfigVersionId); err != nil {
			return nil, fmt.Errorf("%w: scoped current config identity", ErrInvalidHeartbeat)
		}
		if value.Previous, err = normalizeActiveConfigIdentity(entry.PreviousConfigIdentity, entry.PreviousConfigVersionId); err != nil {
			return nil, fmt.Errorf("%w: scoped previous config identity", ErrInvalidHeartbeat)
		}
		if value.Current != nil {
			value.CurrentID = &value.Current.ConfigID
		}
		if value.Previous != nil {
			if value.Previous.ConfigID == value.Current.ConfigID {
				return nil, fmt.Errorf("%w: scoped previous equals current", ErrInvalidHeartbeat)
			}
			value.PreviousID = &value.Previous.ConfigID
		}
		if apply := entry.LastApplyResult; apply != nil {
			if value.ApplyDeploymentID, err = canonicalUUID(apply.DeploymentId); err != nil {
				return nil, fmt.Errorf("%w: scoped apply deployment", ErrInvalidHeartbeat)
			}
			if value.ApplyConfigID, err = canonicalUUID(apply.ConfigVersionId); err != nil || apply.Attempt == 0 ||
				uint64(apply.Attempt) > math.MaxInt32 {
				return nil, fmt.Errorf("%w: scoped apply identity", ErrInvalidHeartbeat)
			}
			value.ApplyAttempt = apply.Attempt
			switch apply.State {
			case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY:
				value.ApplyState = "healthy"
			case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED:
				value.ApplyState = "failed"
			case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED:
				value.ApplyState = "reverted"
			case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED:
				value.ApplyState = "rollback_failed"
			case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED:
				value.ApplyState = "superseded"
			default:
				return nil, fmt.Errorf("%w: scoped apply state", ErrInvalidHeartbeat)
			}
			failed := value.ApplyState == "failed" || value.ApplyState == "rollback_failed"
			name, known := commonv1.ErrorCode_name[int32(apply.ErrorCode)]
			if !known || failed != (apply.ErrorCode != commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED) {
				return nil, fmt.Errorf("%w: scoped apply error", ErrInvalidHeartbeat)
			}
			if failed {
				value.ApplyErrorCode = strings.TrimPrefix(name, "ERROR_CODE_")
			}
			if apply.FinishedTime != nil {
				if apply.FinishedTime.CheckValid() != nil {
					return nil, fmt.Errorf("%w: scoped apply finish time", ErrInvalidHeartbeat)
				}
				finishedAt := apply.FinishedTime.AsTime().UTC().Truncate(time.Microsecond)
				value.ApplyFinishedAt = &finishedAt
			}
		} else if value.Current == nil {
			return nil, fmt.Errorf("%w: empty scoped config identity", ErrInvalidHeartbeat)
		}
		result = append(result, value)
	}
	legacyMatches := func(id *string, identity *agentv1.ActiveConfigIdentity, want *normalizedActiveConfigIdentity) bool {
		got, err := normalizeActiveConfigIdentity(identity, id)
		if err != nil || (id == nil) != (want == nil) || (got == nil) != (want == nil) {
			return false
		}
		return want == nil || got.ConfigID == want.ConfigID && bytes.Equal(got.Digest, want.Digest)
	}
	if len(result) == 1 {
		if !legacyMatches(heartbeat.CurrentConfigVersionId, heartbeat.CurrentConfigIdentity, result[0].Current) ||
			!legacyMatches(heartbeat.PreviousConfigVersionId, heartbeat.PreviousConfigIdentity, result[0].Previous) {
			return nil, fmt.Errorf("%w: legacy identity does not mirror the single scope", ErrInvalidHeartbeat)
		}
	} else if heartbeat.CurrentConfigVersionId != nil || heartbeat.CurrentConfigIdentity != nil ||
		heartbeat.PreviousConfigVersionId != nil || heartbeat.PreviousConfigIdentity != nil ||
		heartbeat.Runtime.LoadedConfigVersionId != nil || heartbeat.Runtime.LoadedConfigIdentity != nil {
		return nil, fmt.Errorf("%w: legacy identity with several scopes", ErrInvalidHeartbeat)
	}
	return result, nil
}

type normalizedActiveConfigIdentity struct {
	ConfigID uuid.UUID
	Schema   int32
	Digest   []byte
}

func validateHeartbeatActiveIdentities(heartbeat *agentv1.Heartbeat) error {
	capability := heartbeat.ActiveConfigIdentityCapability
	hasIdentity := heartbeat.CurrentConfigIdentity != nil || heartbeat.PreviousConfigIdentity != nil ||
		heartbeat.Runtime.LoadedConfigIdentity != nil
	for _, deployment := range heartbeat.ActiveDeployments {
		hasIdentity = hasIdentity || deployment.ObservedActiveConfigIdentity != nil
	}
	if capability == nil {
		if hasIdentity {
			return fmt.Errorf("%w: active config identity capability", ErrInvalidHeartbeat)
		}
		return nil
	}
	if capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY || capability.ApiVersion != 1 {
		return fmt.Errorf("%w: active config identity capability", ErrInvalidHeartbeat)
	}
	for _, pair := range []struct {
		name      string
		identity  *agentv1.ActiveConfigIdentity
		companion *string
	}{
		{name: "current", identity: heartbeat.CurrentConfigIdentity, companion: heartbeat.CurrentConfigVersionId},
		{name: "previous", identity: heartbeat.PreviousConfigIdentity, companion: heartbeat.PreviousConfigVersionId},
		{name: "loaded", identity: heartbeat.Runtime.LoadedConfigIdentity, companion: heartbeat.Runtime.LoadedConfigVersionId},
	} {
		if _, err := normalizeActiveConfigIdentity(pair.identity, pair.companion); err != nil {
			return fmt.Errorf("%w: %s active config identity", ErrInvalidHeartbeat, pair.name)
		}
	}
	for _, deployment := range heartbeat.ActiveDeployments {
		if deployment.ObservedActiveConfigIdentity != nil &&
			deployment.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY &&
			deployment.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED {
			return fmt.Errorf("%w: active deployment identity state", ErrInvalidHeartbeat)
		}
		companion := deployment.ConfigVersionId
		if _, err := normalizeActiveConfigIdentity(deployment.ObservedActiveConfigIdentity, &companion); err != nil {
			return fmt.Errorf("%w: active deployment config identity", ErrInvalidHeartbeat)
		}
	}
	return nil
}

func normalizeActiveConfigIdentity(identity *agentv1.ActiveConfigIdentity, companion *string) (*normalizedActiveConfigIdentity, error) {
	if identity == nil {
		return nil, nil
	}
	if companion == nil || identity.Schema != agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1 ||
		len(identity.ArtifactSha256) != sha256.Size || identity.ConfigVersionId != *companion {
		return nil, fmt.Errorf("invalid active config identity")
	}
	configID, err := canonicalUUID(identity.ConfigVersionId)
	if err != nil || configID == uuid.Nil {
		return nil, fmt.Errorf("invalid active config identity config version")
	}
	return &normalizedActiveConfigIdentity{
		ConfigID: configID, Schema: int32(identity.Schema), Digest: append([]byte(nil), identity.ArtifactSha256...),
	}, nil
}

func validReportedAgentVersion(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._+:-", character) {
			continue
		}
		return false
	}
	return true
}

func nodeIDFromSubject(prefix, subject string) (uuid.UUID, error) {
	wanted := prefix + "."
	if !strings.HasPrefix(subject, wanted) || strings.Contains(strings.TrimPrefix(subject, wanted), ".") {
		return uuid.Nil, fmt.Errorf("%w: heartbeat subject", ErrInvalidHeartbeat)
	}
	parsed, err := canonicalUUID(strings.TrimPrefix(subject, wanted))
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: subject node ID", ErrInvalidHeartbeat)
	}
	return parsed, nil
}

// canonicalUUID accepts non-nil lowercase RFC 4122/9562 UUIDs, versions 1 through 8.
func canonicalUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	version := parsed.Version()
	if err != nil || parsed == uuid.Nil || parsed.String() != value || parsed.Variant() != uuid.RFC4122 ||
		version < 1 || version > 8 {
		return uuid.Nil, fmt.Errorf("not a canonical UUID")
	}
	return parsed, nil
}

func validateOptionalUUID(value *string) error {
	if value == nil {
		return nil
	}
	_, err := canonicalUUID(*value)
	return err
}

func validRuntimeState(state agentv1.RuntimeState) bool {
	_, known := agentv1.RuntimeState_name[int32(state)]
	return known && state != agentv1.RuntimeState_RUNTIME_STATE_UNSPECIFIED
}

// MarketProbeRole is the stored node_presence.market_probe_role of a
// heartbeat role; nil for UNSPECIFIED (an Agent that does not report it).
func MarketProbeRole(role agentv1.MarketProbeRole) *string {
	var value string
	switch role {
	case agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY:
		value = MarketProbeRoleProbeOnly
	case agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET:
		value = MarketProbeRoleJoinMarket
	case agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED:
		value = MarketProbeRoleDisabled
	default:
		return nil
	}
	return &value
}

// NativeRuntime is the stored node_presence.native_runtime_* of a heartbeat
// (migration 468): all nil when the node did not report it.
type NativeRuntime struct {
	State, Release, PreviousRelease, ErrorCode *string
}

func nativeRuntimeColumns(status *agentv1.NativeRuntimeStatus) NativeRuntime {
	var state string
	switch status.GetState() {
	case agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_SWITCHED:
		state = NativeRuntimeSwitched
	case agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_UNCHANGED:
		state = NativeRuntimeUnchanged
	case agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK:
		state = NativeRuntimeRolledBack
	default:
		return NativeRuntime{}
	}
	optional := func(value string) *string {
		if value == "" {
			return nil
		}
		return &value
	}
	columns := NativeRuntime{State: &state, Release: optional(status.Release), PreviousRelease: optional(status.PreviousRelease)}
	if state == NativeRuntimeRolledBack {
		columns.ErrorCode = optional(status.ErrorCode)
	}
	return columns
}

// validNativeRuntime mirrors the 468 checks: absent, or a known state with
// lowercase sha256 releases and an error code only after a rollback.
func validNativeRuntime(status *agentv1.NativeRuntimeStatus) bool {
	if status == nil {
		return true
	}
	if _, known := agentv1.NativeRuntimeState_name[int32(status.State)]; !known ||
		status.State == agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_UNSPECIFIED {
		return false
	}
	for _, release := range []string{status.Release, status.PreviousRelease} {
		if release != "" && !nativeRuntimeReleasePattern.MatchString(release) {
			return false
		}
	}
	return status.ErrorCode == "" || status.State == agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK &&
		nativeRuntimeCodePattern.MatchString(status.ErrorCode)
}

var (
	nativeRuntimeReleasePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nativeRuntimeCodePattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

const (
	NativeRuntimeSwitched   = "switched"
	NativeRuntimeUnchanged  = "unchanged"
	NativeRuntimeRolledBack = "rolled_back"
)

const (
	MarketProbeRoleProbeOnly  = "probe_only"
	MarketProbeRoleJoinMarket = "join_market"
	MarketProbeRoleDisabled   = "disabled"
)

func validDeploymentState(state agentv1.NodeDeploymentState) bool {
	_, known := agentv1.NodeDeploymentState_name[int32(state)]
	return known && state != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_UNSPECIFIED
}

func validSubjectPrefix(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if token == "" {
			return false
		}
		for _, char := range token {
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') || char == '-' || char == '_' {
				continue
			}
			return false
		}
	}
	return true
}
