package gateway

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	cacheControlAPIVersion = 1
	maximumCacheTargets    = 500
)

var stableCacheCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func cacheControlCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL {
			continue
		}
		if seen {
			return false, fmt.Errorf("cache control capability is duplicated")
		}
		seen = true
		if capability.ApiVersion != cacheControlAPIVersion {
			return false, fmt.Errorf("cache control capability version is unsupported")
		}
	}
	return seen, nil
}

func (g *Gateway) validateCacheControlCommand(command *agentv1.CacheControlCommand, authenticatedNodeID string) error {
	if command == nil || proto.Size(command) > g.config.MaxSendMessageBytes {
		return fmt.Errorf("cache command is missing or exceeds its size limit")
	}
	if cacheControlMessageHasUnknown(command.ProtoReflect()) {
		return fmt.Errorf("cache command contains unknown fields")
	}
	if err := g.validateEventMetadata(command.Event); err != nil || command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("cache command event is invalid")
	}
	for name, value := range map[string]string{
		"scope_id": command.ScopeId, "tenant_id": command.TenantId, "site_id": command.SiteId, "node_id": command.NodeId,
		"control_operation_id": command.ControlOperationId, "lease_id": command.LeaseId,
	} {
		if err := g.validateUUID("cache_command."+name, value); err != nil {
			return err
		}
	}
	if command.NodeId != authenticatedNodeID {
		return fmt.Errorf("cache command node does not match the authenticated session")
	}
	if command.Attempt == 0 || command.ConfigRevision == 0 ||
		g.validateIdentifier("cache_command.config_version_id", command.ConfigVersionId, true) != nil {
		return fmt.Errorf("cache command attempt or configuration identity is invalid")
	}
	wantTaskID := "cc-" + command.ControlOperationId + "-" + command.NodeId + "-" + strconv.FormatUint(uint64(command.Attempt), 10)
	if command.TaskId != wantTaskID || len(command.TaskId) > g.config.MaxIdentifierBytes ||
		command.Event.TaskId == nil || command.Event.GetTaskId() != command.TaskId {
		return fmt.Errorf("cache command task identity is invalid")
	}
	if !validCacheActionScope(command.Action, command.Scope) || command.Priority != agentv1.CacheControlPriority_CACHE_CONTROL_PRIORITY_NORMAL ||
		len(command.RequestDigest) != sha256.Size || command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil {
		return fmt.Errorf("cache command policy is invalid")
	}
	if len(command.Targets) == 0 || len(command.Targets) > maximumCacheTargets {
		return fmt.Errorf("cache command targets are missing or exceed their size limit")
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(command.Targets))
	seenOrdinals := make(map[uint32]struct{}, len(command.Targets))
	for index, target := range command.Targets {
		if target == nil || target.Index != uint32(index) || target.TargetOrdinal == 0 || len(target.Sha256) != sha256.Size ||
			len(target.CanonicalUrl) > 16<<10 || strings.TrimSpace(target.CanonicalUrl) != target.CanonicalUrl {
			return fmt.Errorf("cache command target binding is invalid")
		}
		if _, exists := seenOrdinals[target.TargetOrdinal]; exists {
			return fmt.Errorf("cache command target ordinals must be unique")
		}
		seenOrdinals[target.TargetOrdinal] = struct{}{}
		digest := sha256.Sum256([]byte(target.CanonicalUrl))
		if !bytes.Equal(target.Sha256, digest[:]) {
			return fmt.Errorf("cache command target digest is invalid")
		}
		if command.Action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_SITE {
			if index != 0 || target.CanonicalUrl != "" {
				return fmt.Errorf("site purge must contain one empty canonical target")
			}
		} else if target.CanonicalUrl == "" {
			return fmt.Errorf("cache command canonical URL is required")
		}
		if _, exists := seen[digest]; exists {
			return fmt.Errorf("cache command targets must be unique")
		}
		seen[digest] = struct{}{}
	}
	return nil
}

func validCacheActionScope(action agentv1.CacheControlAction, scope agentv1.CacheControlScope) bool {
	return action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_EXACT && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL ||
		action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_PREFIX && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_DIRECTORY ||
		action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_SITE && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_SITE ||
		action == agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PREWARM && scope == agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL
}

func (g *Gateway) validateCacheControlStatus(status *agentv1.CacheControlStatus, authenticatedNodeID string) error {
	if status == nil || proto.Size(status) > g.config.MaxReceiveMessageBytes {
		return fmt.Errorf("cache status is missing or exceeds its size limit")
	}
	if cacheControlMessageHasUnknown(status.ProtoReflect()) {
		return fmt.Errorf("cache status contains unknown fields")
	}
	if err := g.validateEventMetadata(status.Event); err != nil || status.Event.OccurredTime == nil || status.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("cache status event is invalid")
	}
	for name, value := range map[string]string{
		"scope_id": status.ScopeId, "tenant_id": status.TenantId, "site_id": status.SiteId, "node_id": status.NodeId,
		"control_operation_id": status.ControlOperationId, "lease_id": status.LeaseId,
	} {
		if err := g.validateUUID("cache_status."+name, value); err != nil {
			return err
		}
	}
	if status.NodeId != authenticatedNodeID || status.Attempt == 0 || status.ConfigRevision == 0 ||
		g.validateIdentifier("cache_status.config_version_id", status.ConfigVersionId, true) != nil ||
		!validCacheActionScope(status.Action, status.Scope) || len(status.RequestDigest) != sha256.Size ||
		status.TransitionSequence == 0 || !status.ActiveConfigUnchanged {
		return fmt.Errorf("cache status identity or policy is invalid")
	}
	wantTaskID := "cc-" + status.ControlOperationId + "-" + status.NodeId + "-" + strconv.FormatUint(uint64(status.Attempt), 10)
	if status.TaskId != wantTaskID || status.Event.TaskId == nil || status.Event.GetTaskId() != status.TaskId {
		return fmt.Errorf("cache status task identity is invalid")
	}
	terminal, expectedSequence := true, uint64(3)
	switch status.State {
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_DELIVERED:
		terminal, expectedSequence = false, 1
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_RUNNING:
		terminal, expectedSequence = false, 2
	case agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED,
		agentv1.CacheControlState_CACHE_CONTROL_STATE_PARTIAL_FAILED,
		agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED,
		agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED:
	default:
		return fmt.Errorf("cache status state is invalid")
	}
	if status.TransitionSequence != expectedSequence {
		return fmt.Errorf("cache status transition sequence is invalid")
	}
	if !terminal && len(status.Results) != 0 {
		return fmt.Errorf("non-terminal cache status must not include results")
	}
	if terminal && len(status.Results) == 0 {
		return fmt.Errorf("terminal cache status must include results")
	}
	if status.State == agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED && status.ErrorCode != "" {
		return fmt.Errorf("successful cache status must not include an error code")
	}
	if len(status.Results) > maximumCacheTargets || len(status.Summary) > g.config.MaxEventMetadataBytes ||
		(status.ErrorCode != "" && !stableCacheCodePattern.MatchString(status.ErrorCode)) {
		return fmt.Errorf("cache status details exceed their limits")
	}
	succeeded := 0
	seenOrdinals := make(map[uint32]struct{}, len(status.Results))
	for index, result := range status.Results {
		if result == nil || result.Index != uint32(index) || result.TargetOrdinal == 0 || len(result.Sha256) != sha256.Size ||
			result.State == agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_UNSPECIFIED ||
			result.CompletedTime == nil || result.CompletedTime.CheckValid() != nil || result.Attempts == 0 ||
			!stableCacheCodePattern.MatchString(result.ResultCode) || result.CauseCode != "" && !stableCacheCodePattern.MatchString(result.CauseCode) {
			return fmt.Errorf("cache status target result is invalid")
		}
		if _, exists := seenOrdinals[result.TargetOrdinal]; exists {
			return fmt.Errorf("cache status target ordinals must be unique")
		}
		seenOrdinals[result.TargetOrdinal] = struct{}{}
		if _, known := agentv1.CacheControlTargetState_name[int32(result.State)]; !known {
			return fmt.Errorf("cache status target state is invalid")
		}
		if result.State == agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS ||
			result.State == agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SKIPPED {
			succeeded++
		}
	}
	if terminal {
		switch status.State {
		case agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED:
			if succeeded != len(status.Results) {
				return fmt.Errorf("successful cache status must not include failed results")
			}
		case agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED,
			agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED:
			if succeeded != 0 {
				return fmt.Errorf("failed or cancelled cache status must contain only failed results")
			}
		case agentv1.CacheControlState_CACHE_CONTROL_STATE_PARTIAL_FAILED:
			if succeeded == 0 || succeeded == len(status.Results) {
				return fmt.Errorf("partial cache status must contain successful and failed results")
			}
		}
	}
	return nil
}

func cacheControlMessageHasUnknown(message protoreflect.Message) bool {
	if !message.IsValid() || len(message.GetUnknown()) != 0 {
		return true
	}
	hasUnknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.IsList() && field.Message() != nil {
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if cacheControlMessageHasUnknown(list.Get(index).Message()) {
					hasUnknown = true
					return false
				}
			}
			return !hasUnknown
		}
		if field.IsMap() && field.MapValue().Message() != nil {
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				hasUnknown = cacheControlMessageHasUnknown(item.Message())
				return !hasUnknown
			})
			return !hasUnknown
		}
		if field.Message() != nil && cacheControlMessageHasUnknown(value.Message()) {
			hasUnknown = true
			return false
		}
		return true
	})
	return hasUnknown
}
