package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

// CommandBus is the Gateway's narrow durable messaging boundary. Implementations
// must not acknowledge a command until CommandDelivery.Ack succeeds.
type CommandBus interface {
	Subscribe(context.Context, string) (CommandSubscription, error)
	PublishStatus(context.Context, string, *agentv1.DeploymentStatus) (DeploymentStatusPublication, error)
}

// FirewallCommandBus is the typed durable boundary for scoped firewall
// commands. It is deliberately separate from CommandBus so firewall bytes can
// never be decoded as a DeploymentCommand.
type FirewallCommandBus interface {
	SubscribeFirewall(context.Context, string) (FirewallCommandSubscription, error)
	PublishFirewallStatus(context.Context, string, *agentv1.FirewallStatus) (FirewallStatusPublication, error)
}

type DeploymentStatusPublication struct {
	Stream   string
	Sequence uint64
}

type FirewallStatusPublication struct {
	Stream   string
	Sequence uint64
	Replayed bool
}

type CommandSubscription interface {
	Next(context.Context) (CommandDelivery, error)
	Close() error
}

type CommandDelivery interface {
	Command() *agentv1.DeploymentCommand
	Ack(context.Context) error
	Nak(context.Context) error
}

type FirewallCommandSubscription interface {
	Next(context.Context) (FirewallCommandDelivery, error)
	Close() error
}

type FirewallCommandDelivery interface {
	Command() *agentv1.FirewallCommand
	Ack(context.Context) error
	Nak(context.Context) error
}

type pendingCommand struct {
	command    *agentv1.DeploymentCommand
	deliveries []CommandDelivery
}

type pendingCommandSet map[deploymentKey]*pendingCommand

func (p pendingCommandSet) deliveryCount() int {
	count := 0
	for _, command := range p {
		count += len(command.deliveries)
	}
	return count
}

type pendingFirewallCommand struct {
	command    *agentv1.FirewallCommand
	deliveries []FirewallCommandDelivery
}

type pendingFirewallCommandSet map[string]*pendingFirewallCommand

func (p pendingFirewallCommandSet) deliveryCount() int {
	count := 0
	for _, command := range p {
		count += len(command.deliveries)
	}
	return count
}

type commandReceive struct {
	delivery CommandDelivery
	err      error
}

type firewallCommandReceive struct {
	delivery FirewallCommandDelivery
	err      error
}

type sessionCommandSource struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription CommandSubscription
	next         <-chan commandReceive
}

func newSessionCommandSource(ctx context.Context, bus CommandBus, nodeID string) (*sessionCommandSource, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := bus.Subscribe(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, err
	}
	return &sessionCommandSource{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

func (s *sessionCommandSource) arm() {
	if s.next != nil {
		return
	}
	next := make(chan commandReceive, 1)
	s.next = next
	go func() {
		delivery, err := s.subscription.Next(s.ctx)
		next <- commandReceive{delivery: delivery, err: err}
	}()
}

type sessionFirewallCommandSource struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription FirewallCommandSubscription
	next         <-chan firewallCommandReceive
}

func newSessionFirewallCommandSource(ctx context.Context, bus FirewallCommandBus, nodeID string) (*sessionFirewallCommandSource, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := bus.SubscribeFirewall(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, err
	}
	return &sessionFirewallCommandSource{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

func (s *sessionFirewallCommandSource) arm() {
	if s.next != nil {
		return
	}
	next := make(chan firewallCommandReceive, 1)
	s.next = next
	go func() {
		delivery, err := s.subscription.Next(s.ctx)
		next <- firewallCommandReceive{delivery: delivery, err: err}
	}()
}

func stopSessionCommands(source *sessionCommandSource, pending pendingCommandSet, timeout time.Duration) {
	for key, command := range pending {
		for _, delivery := range command.deliveries {
			nakCommand(delivery, timeout)
		}
		delete(pending, key)
	}
	if source == nil {
		return
	}
	source.cancel()
	_ = source.subscription.Close()
	if source.next != nil {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case result := <-source.next:
			nakCommand(result.delivery, timeout)
		case <-timer.C:
		}
	}
}

func nakCommand(delivery CommandDelivery, timeout time.Duration) {
	if delivery == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = delivery.Nak(ctx)
}

func stopSessionFirewallCommands(source *sessionFirewallCommandSource, pending pendingFirewallCommandSet, timeout time.Duration) {
	for key, command := range pending {
		for _, delivery := range command.deliveries {
			nakFirewallCommand(delivery, timeout)
		}
		delete(pending, key)
	}
	if source == nil {
		return
	}
	source.cancel()
	_ = source.subscription.Close()
	if source.next != nil {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case result := <-source.next:
			nakFirewallCommand(result.delivery, timeout)
		case <-timer.C:
		}
	}
}

func nakFirewallCommand(delivery FirewallCommandDelivery, timeout time.Duration) {
	if delivery == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = delivery.Nak(ctx)
}

func ackFirewallCommand(delivery FirewallCommandDelivery, timeout time.Duration) error {
	if delivery == nil {
		return fmt.Errorf("firewall command delivery is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return delivery.Ack(ctx)
}

const maxFirewallCommandBytes = 1 << 20
const maxFirewallCIDRTargets = 4096

func validateFirewallCommand(command *agentv1.FirewallCommand, nodeID string) error {
	if command == nil || proto.Size(command) > maxFirewallCommandBytes {
		return fmt.Errorf("firewall command is missing or exceeds its size limit")
	}
	if cacheControlMessageHasUnknown(command.ProtoReflect()) {
		return fmt.Errorf("firewall command contains unknown fields")
	}
	if command.Event == nil || !canonicalUUID(command.Event.EventId) || !canonicalUUID(command.Event.RequestId) ||
		command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil ||
		!validFirewallMetadata(command.Event.Traceparent) || !validFirewallMetadata(command.Event.CorrelationId) ||
		command.Event.TaskId == nil || command.Event.GetTaskId() != command.TaskId ||
		command.Event.CausationId != nil && !canonicalUUID(command.Event.GetCausationId()) {
		return fmt.Errorf("firewall command event identity is invalid")
	}
	if command.Schema != agentv1.FirewallSchema_FIREWALL_SCHEMA_V1 {
		return fmt.Errorf("firewall command schema is unsupported")
	}
	if !validFirewallIdentifier(command.TaskId) || command.TaskRevision == 0 || !canonicalUUID(command.IdempotencyKey) {
		return fmt.Errorf("firewall command task identity is invalid")
	}
	if !canonicalUUID(command.TenantId) || !canonicalUUID(command.SiteId) || !canonicalUUID(command.NodeId) || command.NodeId != nodeID {
		return fmt.Errorf("firewall command scope is invalid")
	}
	if command.PolicyVersion == 0 || command.PolicyVersion != command.ExpectedActivePolicyVersion+1 ||
		!validGatewayFirewallPolicyIdentity(command.PolicyKind, command.PolicyId) ||
		command.TaskRevision <= command.ExpectedActivePolicyVersion {
		return fmt.Errorf("firewall command policy ordering is invalid")
	}
	switch command.Operation {
	case agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY:
		if command.RecoveryReason != agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE {
			return fmt.Errorf("firewall apply command recovery reason is invalid")
		}
	case agentv1.FirewallOperation_FIREWALL_OPERATION_RECOVER:
		if command.RecoveryReason == agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_UNSPECIFIED ||
			command.RecoveryReason == agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE {
			return fmt.Errorf("firewall recovery command reason is invalid")
		}
	default:
		return fmt.Errorf("firewall command operation is invalid")
	}
	now := time.Now()
	if command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil || !command.DeadlineTime.AsTime().After(now) ||
		command.DeadlineTime.AsTime().After(now.Add(24*time.Hour)) {
		return fmt.Errorf("firewall command deadline is invalid")
	}
	if len(command.Targets) > maxFirewallCIDRTargets {
		return fmt.Errorf("firewall command targets exceed their limit")
	}
	seenCIDRs := make(map[string]struct{}, len(command.Targets))
	for index, target := range command.Targets {
		if target == nil || target.Ordinal != uint32(index+1) || target.TenantId != command.TenantId || target.SiteId != command.SiteId ||
			!validFirewallIdentifier(target.Source) || len(target.Source) > 64 || !validFirewallIdentifier(target.ReasonCode) {
			return fmt.Errorf("firewall command target identity is invalid")
		}
		switch target.Action {
		case agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_ALLOW, agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_DENY:
		default:
			return fmt.Errorf("firewall command target action is invalid")
		}
		if !validFirewallProtocolPorts(target.Protocol, target.PortStart, target.PortEnd) {
			return fmt.Errorf("firewall command target protocol or port range is invalid")
		}
		prefix, err := netip.ParsePrefix(target.Cidr)
		address := prefix.Addr()
		if err != nil || prefix != prefix.Masked() || prefix.String() != target.Cidr || address.Is4In6() || address.IsUnspecified() ||
			address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || prefix.Bits() == 0 {
			return fmt.Errorf("firewall command target CIDR is invalid")
		}
		targetKey := fmt.Sprintf("%s\x00%d\x00%d\x00%d", target.Cidr, target.Protocol, target.PortStart, target.PortEnd)
		if _, exists := seenCIDRs[targetKey]; exists {
			return fmt.Errorf("firewall command target CIDR is duplicated")
		}
		seenCIDRs[targetKey] = struct{}{}
		if target.ExpirationTime != nil && (target.ExpirationTime.CheckValid() != nil || !target.ExpirationTime.AsTime().After(now)) {
			return fmt.Errorf("firewall command target expiration is invalid")
		}
	}
	withoutDigest := proto.Clone(command).(*agentv1.FirewallCommand)
	withoutDigest.CommandSha256 = nil
	withoutDigest.Signature = nil
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(withoutDigest)
	if err != nil || len(command.CommandSha256) != sha256.Size {
		return fmt.Errorf("firewall command digest is invalid")
	}
	digest := sha256.Sum256(canonical)
	if !bytes.Equal(command.CommandSha256, digest[:]) {
		return fmt.Errorf("firewall command digest does not match its immutable bytes")
	}
	unsigned := len(command.Signature) == 0 && command.SigningKeyId == "" &&
		command.SignatureAlgorithm == agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_UNSPECIFIED
	signed := len(command.Signature) == 64 && validFirewallIdentifier(command.SigningKeyId) &&
		command.SignatureAlgorithm == agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519
	if !unsigned && !signed {
		return fmt.Errorf("firewall command signature metadata is invalid")
	}
	return nil
}

func validGatewayFirewallPolicyIdentity(kind, id string) bool {
	if kind == "" && id == "" {
		return true
	}
	return (kind == "acl" || kind == "global") && canonicalUUID(id)
}

func validFirewallProtocolPorts(protocol agentv1.FirewallProtocol, start, end uint32) bool {
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

func validateFirewallStatus(status *agentv1.FirewallStatus, command *agentv1.FirewallCommand, nodeID string) error {
	if status == nil || command == nil || proto.Size(status) > maxFirewallCommandBytes {
		return fmt.Errorf("firewall status is missing or exceeds its size limit")
	}
	if err := validateFirewallStatusEnvelope(status, nodeID); err != nil {
		return err
	}
	if status.Event.RequestId != command.Event.RequestId || status.Event.CausationId == nil ||
		status.Event.GetCausationId() != command.Event.EventId || status.Event.TaskId == nil || status.Event.GetTaskId() != command.TaskId {
		return fmt.Errorf("firewall status event does not match its command")
	}
	if status.Schema != agentv1.FirewallSchema_FIREWALL_SCHEMA_V1 || status.NodeId != nodeID || status.NodeId != command.NodeId ||
		status.TaskId != command.TaskId || status.TaskRevision != command.TaskRevision || status.IdempotencyKey != command.IdempotencyKey ||
		status.TenantId != command.TenantId || status.SiteId != command.SiteId || status.PolicyVersion != command.PolicyVersion ||
		status.ExpectedActivePolicyVersion != command.ExpectedActivePolicyVersion || status.Operation != command.Operation ||
		status.RecoveryReason != command.RecoveryReason || !bytes.Equal(status.CommandSha256, command.CommandSha256) {
		return fmt.Errorf("firewall status does not match its command identity")
	}
	if status.StatusRevision == 0 {
		return fmt.Errorf("firewall status revision is invalid")
	}
	switch status.State {
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_APPLIED:
		if command.Operation != agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY || status.ActivePolicyVersion != command.PolicyVersion ||
			status.ActivePolicyUnchanged || status.ErrorCode != "" {
			return fmt.Errorf("applied firewall status has the wrong active policy version")
		}
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED:
		rollbackFailed := status.ErrorCode == "ROLLBACK_FAILED" && status.ActivePolicyVersion == 0 && !status.ActivePolicyUnchanged
		if !rollbackFailed && (status.ActivePolicyVersion != command.ExpectedActivePolicyVersion || !status.ActivePolicyUnchanged) ||
			!validFirewallIdentifier(status.ErrorCode) {
			return fmt.Errorf("failed firewall status does not preserve the active policy")
		}
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_ROLLED_BACK:
		if command.Operation == agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY {
			if status.ActivePolicyVersion != command.ExpectedActivePolicyVersion || !status.ActivePolicyUnchanged ||
				!validFirewallIdentifier(status.ErrorCode) {
				return fmt.Errorf("rolled back firewall status does not preserve the active policy")
			}
		} else if status.ActivePolicyVersion != command.PolicyVersion || status.ActivePolicyUnchanged || status.ErrorCode != "" {
			return fmt.Errorf("firewall recovery status does not activate the requested policy")
		}
	default:
		return fmt.Errorf("firewall status state is invalid")
	}
	return nil
}

func validateFirewallStatusEnvelope(status *agentv1.FirewallStatus, nodeID string) error {
	if status == nil || proto.Size(status) > maxFirewallCommandBytes {
		return fmt.Errorf("firewall status is missing or exceeds its size limit")
	}
	if cacheControlMessageHasUnknown(status.ProtoReflect()) || status.Event == nil || !canonicalUUID(status.Event.EventId) ||
		!canonicalUUID(status.Event.RequestId) || status.Event.OccurredTime == nil || status.Event.OccurredTime.CheckValid() != nil ||
		!validFirewallMetadata(status.Event.Traceparent) || !validFirewallMetadata(status.Event.CorrelationId) ||
		status.Event.CausationId == nil || !canonicalUUID(status.Event.GetCausationId()) || status.Event.TaskId == nil {
		return fmt.Errorf("firewall status identity is invalid")
	}
	if status.Schema != agentv1.FirewallSchema_FIREWALL_SCHEMA_V1 || !canonicalUUID(status.NodeId) || status.NodeId != nodeID ||
		!validFirewallIdentifier(status.TaskId) || status.TaskRevision == 0 || !canonicalUUID(status.IdempotencyKey) ||
		!canonicalUUID(status.TenantId) || !canonicalUUID(status.SiteId) || status.PolicyVersion == 0 ||
		status.PolicyVersion != status.ExpectedActivePolicyVersion+1 || status.Event.GetTaskId() != status.TaskId ||
		len(status.CommandSha256) != sha256.Size || status.StatusRevision == 0 {
		return fmt.Errorf("firewall status identity is invalid")
	}
	switch status.Operation {
	case agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY:
		if status.RecoveryReason != agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE {
			return fmt.Errorf("firewall status apply reason is invalid")
		}
	case agentv1.FirewallOperation_FIREWALL_OPERATION_RECOVER:
		if status.RecoveryReason == agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_UNSPECIFIED ||
			status.RecoveryReason == agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE {
			return fmt.Errorf("firewall status recovery reason is invalid")
		}
	default:
		return fmt.Errorf("firewall status operation is invalid")
	}
	if status.State != agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_APPLIED &&
		status.State != agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED &&
		status.State != agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_ROLLED_BACK {
		return fmt.Errorf("firewall status state is invalid")
	}
	return nil
}

func validFirewallIdentifier(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func validFirewallMetadata(value string) bool {
	return len(value) <= 512 && strings.TrimSpace(value) == value
}

func firewallCommandIdentity(command *agentv1.FirewallCommand) string {
	if command == nil {
		return ""
	}
	return command.NodeId + ":" + command.TaskId + ":" + fmt.Sprint(command.TaskRevision) + ":" + command.IdempotencyKey + ":" + hex.EncodeToString(command.CommandSha256)
}

func firewallStatusIdentity(command *agentv1.FirewallCommand) string {
	return firewallCommandIdentity(command)
}

func firewallStatusCommandIdentity(status *agentv1.FirewallStatus) string {
	if status == nil {
		return ""
	}
	return status.NodeId + ":" + status.TaskId + ":" + fmt.Sprint(status.TaskRevision) + ":" + status.IdempotencyKey + ":" + hex.EncodeToString(status.CommandSha256)
}

func firewallStatusEqual(left, right *agentv1.FirewallStatus) bool {
	if left == nil || right == nil || left.Event == nil || right.Event == nil ||
		left.Event.OccurredTime == nil || right.Event.OccurredTime == nil ||
		left.Event.OccurredTime.CheckValid() != nil || right.Event.OccurredTime.CheckValid() != nil {
		return false
	}
	stableLeft := proto.Clone(left).(*agentv1.FirewallStatus)
	stableRight := proto.Clone(right).(*agentv1.FirewallStatus)
	stableLeft.Event.OccurredTime = nil
	stableRight.Event.OccurredTime = nil
	return proto.Equal(stableLeft, stableRight)
}

type deploymentKey struct {
	deploymentID  string
	attempt       uint32
	configVersion string
}

func commandKey(command *agentv1.DeploymentCommand) deploymentKey {
	return deploymentKey{
		deploymentID:  command.GetDeploymentId(),
		attempt:       command.GetAttempt(),
		configVersion: command.GetConfigVersionId(),
	}
}

func statusKey(status *agentv1.DeploymentStatus) deploymentKey {
	return deploymentKey{
		deploymentID:  status.GetDeploymentId(),
		attempt:       status.GetAttempt(),
		configVersion: status.GetConfigVersionId(),
	}
}
