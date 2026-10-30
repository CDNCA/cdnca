package gateway

import (
	"fmt"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

// multiTenantRuntimeAPIVersion is MULTI_TENANT_RUNTIME v1: per-scope releases,
// per-scope rollback, and scoped_config_identities on hello, heartbeat and
// terminal deployment status. Nodes that do not declare it keep the legacy
// single-scope wire contract unchanged.
const multiTenantRuntimeAPIVersion uint32 = 1

// maxScopedConfigIdentities bounds one report. It is far above the expected
// tenant count per node and keeps a hello comfortably inside message limits.
const maxScopedConfigIdentities = 256

func multiTenantRuntimeCapability() *agentv1.Capability {
	return &agentv1.Capability{
		Name:       agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME,
		ApiVersion: multiTenantRuntimeAPIVersion,
	}
}

func multiTenantRuntimeCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME {
			continue
		}
		if seen || capability.ApiVersion != multiTenantRuntimeAPIVersion {
			return false, fmt.Errorf("multi-tenant runtime capability is duplicated or unsupported")
		}
		seen = true
	}
	return seen, nil
}

func gatewayHelloHasMultiTenantRuntimeV1(hello *agentv1.GatewayHello) bool {
	if hello == nil {
		return false
	}
	for _, capability := range hello.EnabledCapabilities {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME &&
			capability.ApiVersion == multiTenantRuntimeAPIVersion {
			return true
		}
	}
	return false
}

// validateScopedConfigIdentities checks one scoped snapshot. Every entry names a
// distinct non-nil canonical scope and carries a current release, a last apply
// result, or both. Versions and identities travel together, and previous
// requires current.
func (g *Gateway) validateScopedConfigIdentities(name string, entries []*agentv1.ScopedConfigIdentity) error {
	if len(entries) > maxScopedConfigIdentities {
		return fmt.Errorf("%s exceed their size limit", name)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry == nil {
			return fmt.Errorf("%s entry is missing", name)
		}
		if err := g.validateScopeID(name+".configuration_scope_id", entry.ConfigurationScopeId); err != nil {
			return err
		}
		if _, exists := seen[entry.ConfigurationScopeId]; exists {
			return fmt.Errorf("%s configuration scopes must be unique", name)
		}
		seen[entry.ConfigurationScopeId] = struct{}{}
		if (entry.CurrentConfigVersionId == nil) != (entry.CurrentConfigIdentity == nil) ||
			(entry.PreviousConfigVersionId == nil) != (entry.PreviousConfigIdentity == nil) {
			return fmt.Errorf("%s versions and identities must be reported together", name)
		}
		if entry.CurrentConfigVersionId == nil {
			if entry.PreviousConfigVersionId != nil {
				return fmt.Errorf("%s previous release requires a current release", name)
			}
			if entry.LastApplyResult == nil {
				return fmt.Errorf("%s entry has neither a current release nor an apply result", name)
			}
		} else {
			currentID := entry.GetCurrentConfigVersionId()
			if err := g.validateUUID(name+".current_config_version_id", currentID); err != nil {
				return err
			}
			if err := g.validateActiveConfigIdentity(name+".current_config_identity", entry.CurrentConfigIdentity, currentID); err != nil {
				return err
			}
		}
		if entry.PreviousConfigVersionId != nil {
			previousID := entry.GetPreviousConfigVersionId()
			if err := g.validateUUID(name+".previous_config_version_id", previousID); err != nil {
				return err
			}
			if previousID == entry.GetCurrentConfigVersionId() {
				return fmt.Errorf("%s current and previous versions must differ", name)
			}
			if err := g.validateActiveConfigIdentity(name+".previous_config_identity", entry.PreviousConfigIdentity, previousID); err != nil {
				return err
			}
		}
		if entry.LastApplyResult != nil {
			if err := g.validateScopedApplyResult(name+".last_apply_result", entry.LastApplyResult); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *Gateway) validateScopeID(name, value string) error {
	if err := g.validateUUID(name, value); err != nil {
		return err
	}
	if value == uuid.Nil.String() {
		return fmt.Errorf("%s must not be nil", name)
	}
	return nil
}

func (g *Gateway) validateScopedApplyResult(name string, result *agentv1.ScopedApplyResult) error {
	if err := g.validateUUID(name+".deployment_id", result.DeploymentId); err != nil {
		return err
	}
	if result.Attempt == 0 {
		return fmt.Errorf("%s attempt must be positive", name)
	}
	if err := g.validateUUID(name+".config_version_id", result.ConfigVersionId); err != nil {
		return err
	}
	if result.FinishedTime == nil || result.FinishedTime.CheckValid() != nil {
		return fmt.Errorf("%s finished time is invalid", name)
	}
	failed := false
	switch result.State {
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED:
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED:
		failed = true
	default:
		return fmt.Errorf("%s state must be terminal", name)
	}
	if _, known := commonv1.ErrorCode_name[int32(result.ErrorCode)]; !known ||
		failed != (result.ErrorCode != commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED) {
		return fmt.Errorf("%s error code does not match its state", name)
	}
	return nil
}

// validateScopedLegacyMirror keeps old control planes correct: a node holding
// one scope with a current release looks exactly like a legacy node, while a
// node holding several scopes has no single node-wide version to report.
func validateScopedLegacyMirror(name string, entries []*agentv1.ScopedConfigIdentity, currentID, previousID *string, current, previous *agentv1.ActiveConfigIdentity) error {
	if len(entries) == 0 {
		return nil
	}
	if len(entries) == 1 && entries[0].CurrentConfigVersionId != nil {
		entry := entries[0]
		if !equalOptionalString(currentID, entry.CurrentConfigVersionId) || !proto.Equal(current, entry.CurrentConfigIdentity) ||
			!equalOptionalString(previousID, entry.PreviousConfigVersionId) || !proto.Equal(previous, entry.PreviousConfigIdentity) {
			return fmt.Errorf("%s single scope must mirror the legacy identity", name)
		}
		return nil
	}
	if currentID != nil || previousID != nil || current != nil || previous != nil {
		return fmt.Errorf("%s must omit the legacy node-wide identity", name)
	}
	return nil
}

func equalOptionalString(left, right *string) bool {
	return (left == nil) == (right == nil) && (left == nil || *left == *right)
}

func scopedLegacyLoadedIdentityAllowed(entries []*agentv1.ScopedConfigIdentity) bool {
	return len(entries) == 0 || len(entries) == 1 && entries[0].CurrentConfigVersionId != nil
}

func (g *Gateway) validateHelloScopedConfigIdentities(hello *agentv1.AgentHello, capable bool) error {
	if len(hello.ScopedConfigIdentities) == 0 {
		return nil
	}
	if !capable {
		return fmt.Errorf("hello scoped config identities require the multi-tenant runtime capability")
	}
	if err := g.validateScopedConfigIdentities("hello.scoped_config_identities", hello.ScopedConfigIdentities); err != nil {
		return err
	}
	return validateScopedLegacyMirror("hello.scoped_config_identities", hello.ScopedConfigIdentities,
		hello.CurrentConfigVersionId, hello.PreviousConfigVersionId, hello.CurrentConfigIdentity, hello.PreviousConfigIdentity)
}

func (g *Gateway) validateHeartbeatScopedConfigIdentities(heartbeat *agentv1.Heartbeat, negotiated bool) error {
	if len(heartbeat.ScopedConfigIdentities) == 0 {
		return nil
	}
	if !negotiated {
		return fmt.Errorf("heartbeat scoped config identities were not negotiated")
	}
	if err := g.validateScopedConfigIdentities("heartbeat.scoped_config_identities", heartbeat.ScopedConfigIdentities); err != nil {
		return err
	}
	if err := validateScopedLegacyMirror("heartbeat.scoped_config_identities", heartbeat.ScopedConfigIdentities,
		heartbeat.CurrentConfigVersionId, heartbeat.PreviousConfigVersionId, heartbeat.CurrentConfigIdentity, heartbeat.PreviousConfigIdentity); err != nil {
		return err
	}
	if !scopedLegacyLoadedIdentityAllowed(heartbeat.ScopedConfigIdentities) && heartbeat.Runtime != nil &&
		(heartbeat.Runtime.LoadedConfigVersionId != nil || heartbeat.Runtime.LoadedConfigIdentity != nil) {
		return fmt.Errorf("heartbeat scoped config identities must omit the node-wide loaded identity")
	}
	return nil
}

// multiTenantOnlyDeploymentState reports the states that exist only on a
// negotiated MULTI_TENANT_RUNTIME session.
func multiTenantOnlyDeploymentState(state agentv1.NodeDeploymentState) bool {
	switch state {
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED:
		return true
	default:
		return false
	}
}

func (g *Gateway) validateDeploymentStatusScope(status *agentv1.DeploymentStatus, negotiated bool) error {
	if !negotiated {
		if status.ConfigurationScopeId != nil || multiTenantOnlyDeploymentState(status.State) {
			return fmt.Errorf("deployment status scope fields were not negotiated")
		}
		return nil
	}
	// A scoped command's statuses carry its scope (checked against the command
	// in validateDeploymentStatusScopeCommandBinding); the multi-tenant-only
	// states never exist without one.
	if status.ConfigurationScopeId == nil {
		if multiTenantOnlyDeploymentState(status.State) {
			return fmt.Errorf("deployment status configuration scope is required")
		}
		return nil
	}
	if err := g.validateScopeID("deployment_status.configuration_scope_id", status.GetConfigurationScopeId()); err != nil {
		return err
	}
	if status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED && !status.RunningConfigUnchanged {
		return fmt.Errorf("superseded deployment status must preserve the running configuration")
	}
	return nil
}

// validateDeploymentStatusScopeCommandBinding ties a status to its command on
// a multi-tenant session: a scoped command's statuses carry exactly its scope
// and an unscoped command's carry none.
func validateDeploymentStatusScopeCommandBinding(status *agentv1.DeploymentStatus, command *agentv1.DeploymentCommand) error {
	if command == nil {
		return fmt.Errorf("deployment status has no command")
	}
	if (status.ConfigurationScopeId == nil) != (command.ConfigurationScopeId == nil) ||
		status.GetConfigurationScopeId() != command.GetConfigurationScopeId() {
		return fmt.Errorf("deployment status configuration scope does not match its command")
	}
	return nil
}
