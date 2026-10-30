package firewalldispatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	StatePending   = "pending"
	StatePublished = "published"
	StateAcked     = "acked"
	StateRetryable = "retryable"
	StateFailed    = "failed"
)

var (
	ErrIntegrity      = errors.New("firewall dispatcher durable command failed integrity validation")
	ErrStatusConflict = errors.New("firewall status conflicts with durable command")
	ErrClaimLost      = errors.New("firewall dispatcher transaction lost its fenced row")
)

type BatchResult struct {
	Claimed    int
	Published  int
	Duplicates int
	Retryable  int
	Exhausted  int
}

type AckDisposition uint8

const (
	AckRejected AckDisposition = iota
	AckSettled
	AckReplayed
	AckRescued
)

type claimedCommand struct {
	id                    uuid.UUID
	installationID        string
	tenantScopeID         uuid.UUID
	siteID                uuid.UUID
	nodeID                uuid.UUID
	policyID              uuid.UUID
	policyKind            string
	publicationID         uuid.UUID
	globalRevision        int64
	policyVersion         int64
	expectedActiveVersion int64
	idempotencyKey        string
	state                 string
	attempts              int
	commandBytes          []byte
	commandSHA256         [sha256.Size]byte
}

type publishAck struct {
	stream    string
	sequence  uint64
	duplicate bool
}

type publishFailure struct{ code string }

func validateClaim(claim claimedCommand, now time.Time, maxBytes int, subjectPrefix string, enforceDeadline bool) (*agentv1.FirewallCommand, string, string, publishFailure) {
	if claim.id == uuid.Nil || strings.TrimSpace(claim.installationID) == "" && claim.installationID != "" ||
		claim.tenantScopeID == uuid.Nil || claim.siteID == uuid.Nil || claim.nodeID == uuid.Nil ||
		claim.policyVersion <= 0 || claim.expectedActiveVersion < 0 || claim.policyVersion != claim.expectedActiveVersion+1 ||
		claim.attempts < 0 || claim.attempts >= 16 ||
		(claim.state != StatePending && claim.state != StateRetryable) ||
		len(claim.commandBytes) == 0 || len(claim.commandBytes) > maxBytes {
		return nil, "", "", publishFailure{code: "database_identity_invalid"}
	}
	command := new(agentv1.FirewallCommand)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(claim.commandBytes, command); err != nil || messageHasUnknown(command.ProtoReflect()) {
		return nil, "", "", publishFailure{code: "command_decode_invalid"}
	}
	deterministic, err := (proto.MarshalOptions{Deterministic: true}).Marshal(command)
	if err != nil || !bytes.Equal(deterministic, claim.commandBytes) {
		return nil, "", "", publishFailure{code: "command_not_deterministic"}
	}
	if command.Event == nil || !canonicalUUID(command.Event.EventId) || !canonicalUUID(command.Event.RequestId) ||
		command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil || command.Event.TaskId == nil ||
		command.Event.GetTaskId() != command.TaskId || !validMetadata(command.Event.Traceparent) ||
		!validMetadata(command.Event.CorrelationId) || command.Event.CausationId != nil && !canonicalUUID(command.Event.GetCausationId()) {
		return nil, "", "", publishFailure{code: "command_event_invalid"}
	}
	expectedTaskRevision := claim.policyVersion
	if claim.policyKind == "global" {
		expectedTaskRevision = claim.globalRevision
	}
	if expectedTaskRevision <= 0 || command.Schema != agentv1.FirewallSchema_FIREWALL_SCHEMA_V1 || !canonicalUUID(command.TaskId) ||
		command.TaskRevision != uint64(expectedTaskRevision) || !canonicalUUID(command.IdempotencyKey) ||
		command.IdempotencyKey != claim.idempotencyKey || command.TenantId != claim.tenantScopeID.String() ||
		command.SiteId != claim.siteID.String() || command.NodeId != claim.nodeID.String() ||
		command.PolicyVersion != uint64(claim.policyVersion) || command.ExpectedActivePolicyVersion != uint64(claim.expectedActiveVersion) ||
		command.PolicyVersion != command.ExpectedActivePolicyVersion+1 || !validDispatchPolicyIdentity(command.PolicyKind, command.PolicyId) {
		return nil, "", "", publishFailure{code: "command_scope_invalid"}
	}
	if command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil ||
		enforceDeadline && !command.DeadlineTime.AsTime().After(now) {
		return nil, "", "", publishFailure{code: "command_deadline_invalid"}
	}
	if !validOperation(command) || len(command.Targets) > 4096 {
		return nil, "", "", publishFailure{code: "command_operation_invalid"}
	}
	seen := make(map[string]struct{}, len(command.Targets))
	for index, target := range command.Targets {
		if target == nil || target.Ordinal != uint32(index+1) || target.TenantId != command.TenantId || target.SiteId != command.SiteId ||
			!validIdentifier(target.Source) || len(target.Source) > 64 || !validIdentifier(target.ReasonCode) {
			return nil, "", "", publishFailure{code: "command_target_invalid"}
		}
		prefix, err := netip.ParsePrefix(target.Cidr)
		if err != nil || prefix != prefix.Masked() || prefix.String() != target.Cidr || prefix.Bits() == 0 ||
			prefix.Addr().Is4In6() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().IsLinkLocalUnicast() {
			return nil, "", "", publishFailure{code: "command_target_invalid"}
		}
		if !validTargetProtocolPorts(target.Protocol, target.PortStart, target.PortEnd) {
			return nil, "", "", publishFailure{code: "command_target_invalid"}
		}
		targetKey := fmt.Sprintf("%s\x00%d\x00%d\x00%d", target.Cidr, target.Protocol, target.PortStart, target.PortEnd)
		if _, exists := seen[targetKey]; exists {
			return nil, "", "", publishFailure{code: "command_target_invalid"}
		}
		seen[targetKey] = struct{}{}
		if target.Action != agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_ALLOW && target.Action != agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_DENY {
			return nil, "", "", publishFailure{code: "command_target_invalid"}
		}
	}
	withoutDigest := proto.Clone(command).(*agentv1.FirewallCommand)
	withoutDigest.CommandSha256 = nil
	withoutDigest.Signature = nil
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(withoutDigest)
	digest := sha256.Sum256(canonical)
	if err != nil || !bytes.Equal(command.CommandSha256, digest[:]) || !bytes.Equal(claim.commandSHA256[:], digest[:]) {
		return nil, "", "", publishFailure{code: "command_digest_mismatch"}
	}
	if !validCommandSignatureMetadata(command) || claim.policyKind == "global" && len(command.Signature) != 64 {
		return nil, "", "", publishFailure{code: "command_signature_invalid"}
	}
	return command, subjectPrefix + "." + claim.nodeID.String(), stableMessageID(digest), publishFailure{}
}

func validDispatchPolicyIdentity(kind, id string) bool {
	if kind == "" && id == "" {
		return true
	}
	return (kind == "acl" || kind == "global") && canonicalUUID(id)
}

func validCommandSignatureMetadata(command *agentv1.FirewallCommand) bool {
	if len(command.Signature) == 0 && command.SigningKeyId == "" &&
		command.SignatureAlgorithm == agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_UNSPECIFIED {
		return true
	}
	return command.SignatureAlgorithm == agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 &&
		validIdentifier(command.SigningKeyId) && len(command.Signature) == 64
}

func validTargetProtocolPorts(protocol agentv1.FirewallProtocol, start, end uint32) bool {
	switch protocol {
	case agentv1.FirewallProtocol_FIREWALL_PROTOCOL_UNSPECIFIED, agentv1.FirewallProtocol_FIREWALL_PROTOCOL_ANY,
		agentv1.FirewallProtocol_FIREWALL_PROTOCOL_ICMP:
		return start == 0 && end == 0
	case agentv1.FirewallProtocol_FIREWALL_PROTOCOL_TCP, agentv1.FirewallProtocol_FIREWALL_PROTOCOL_UDP:
		return start == 0 && end == 0 || start > 0 && end >= start && end <= 65535
	default:
		return false
	}
}

func validateStatus(payload []byte, claim claimedCommand, maxBytes int) (string, error) {
	if len(payload) == 0 || len(payload) > maxBytes {
		return "", ErrStatusConflict
	}
	status := new(agentv1.FirewallStatus)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, status); err != nil || messageHasUnknown(status.ProtoReflect()) {
		return "", ErrStatusConflict
	}
	deterministic, err := (proto.MarshalOptions{Deterministic: true}).Marshal(status)
	if err != nil || !bytes.Equal(deterministic, payload) {
		return "", ErrStatusConflict
	}
	command, _, _, failed := validateClaim(withStateForValidation(claim), time.Time{}, 1<<20, CommandSubjectPrefix, false)
	if failed.code != "" || command == nil {
		return "", ErrStatusConflict
	}
	if status.Event == nil || !canonicalUUID(status.Event.EventId) || status.Event.OccurredTime == nil ||
		status.Event.OccurredTime.CheckValid() != nil || status.Event.CausationId == nil || status.Event.TaskId == nil ||
		status.Event.RequestId != command.Event.RequestId || status.Event.GetCausationId() != command.Event.EventId ||
		status.Event.GetTaskId() != command.TaskId || !validMetadata(status.Event.Traceparent) || !validMetadata(status.Event.CorrelationId) ||
		status.Schema != command.Schema || status.TaskId != command.TaskId || status.TaskRevision != command.TaskRevision ||
		status.IdempotencyKey != command.IdempotencyKey || status.TenantId != command.TenantId || status.SiteId != command.SiteId ||
		status.NodeId != command.NodeId || status.PolicyVersion != command.PolicyVersion ||
		status.ExpectedActivePolicyVersion != command.ExpectedActivePolicyVersion || status.Operation != command.Operation ||
		status.RecoveryReason != command.RecoveryReason || !bytes.Equal(status.CommandSha256, command.CommandSha256) ||
		status.StatusRevision == 0 {
		return "", ErrStatusConflict
	}
	switch status.State {
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_APPLIED:
		if command.Operation != agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY || status.ActivePolicyVersion != command.PolicyVersion ||
			status.ActivePolicyUnchanged || status.ErrorCode != "" {
			return "", ErrStatusConflict
		}
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED:
		rollbackFailed := status.ErrorCode == "ROLLBACK_FAILED" && status.ActivePolicyVersion == 0 && !status.ActivePolicyUnchanged
		if !rollbackFailed && (status.ActivePolicyVersion != command.ExpectedActivePolicyVersion || !status.ActivePolicyUnchanged) ||
			!validIdentifier(status.ErrorCode) {
			return "", ErrStatusConflict
		}
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_ROLLED_BACK:
		if command.Operation == agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY {
			if status.ActivePolicyVersion != command.ExpectedActivePolicyVersion || !status.ActivePolicyUnchanged || !validIdentifier(status.ErrorCode) {
				return "", ErrStatusConflict
			}
		} else if status.ActivePolicyVersion != command.PolicyVersion || status.ActivePolicyUnchanged || status.ErrorCode != "" {
			return "", ErrStatusConflict
		}
	default:
		return "", ErrStatusConflict
	}
	fingerprint := sha256.Sum256(payload)
	return "ack-sha256:" + hex.EncodeToString(fingerprint[:]), nil
}

func withStateForValidation(claim claimedCommand) claimedCommand {
	claim.state = StatePending
	if claim.attempts >= 16 {
		claim.attempts = 0
	}
	return claim
}

func validOperation(command *agentv1.FirewallCommand) bool {
	if command.Operation == agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY {
		return command.RecoveryReason == agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE
	}
	return command.Operation == agentv1.FirewallOperation_FIREWALL_OPERATION_RECOVER &&
		command.RecoveryReason != agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_UNSPECIFIED &&
		command.RecoveryReason != agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE
}

func stableMessageID(digest [sha256.Size]byte) string { return hex.EncodeToString(digest[:]) }

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for index, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || index > 0 && strings.ContainsRune("._:-", char) {
			continue
		}
		return false
	}
	return true
}

func validMetadata(value string) bool { return len(value) <= 512 && strings.TrimSpace(value) == value }

func messageHasUnknown(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	fields := message.Descriptor().Fields()
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		if field.Message() == nil || !message.Has(field) {
			continue
		}
		if field.IsList() {
			list := message.Get(field).List()
			for item := 0; item < list.Len(); item++ {
				if messageHasUnknown(list.Get(item).Message()) {
					return true
				}
			}
		} else if messageHasUnknown(message.Get(field).Message()) {
			return true
		}
	}
	return false
}

func integrityError(code string) error { return fmt.Errorf("%w: %s", ErrIntegrity, code) }
