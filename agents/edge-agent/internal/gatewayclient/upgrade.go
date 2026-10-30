package gatewayclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const edgeUpgradeStatusStream = "AGENT_DEPLOYMENT_STATUS"

type UpgradeRuntime interface {
	Ready() bool
	Recover(context.Context) error
	AcceptCommand(context.Context, []byte) error
	PendingStatuses(context.Context) ([]updater.QueuedUpgradeStatus, error)
	AcknowledgeStatus(context.Context, string, string, string) (bool, error)
}

type upgradeStatusAcknowledgementRuntime interface {
	PendingStatusAcknowledgements(context.Context) ([]updater.UpgradeStatusAcknowledgement, error)
	PersistStatusAcknowledgement(context.Context, updater.UpgradeStatusAcknowledgement) (bool, error)
	ConfirmStatusAcknowledgement(context.Context, updater.UpgradeStatusAcknowledgement) (bool, error)
}

type upgradeStatusPublicationAcknowledger interface {
	AcknowledgeStatusWithPublication(context.Context, updater.UpgradeStatusAcknowledgement) (bool, error)
}

func WithUpgradeRuntime(runtime UpgradeRuntime) ClientOption {
	return func(client *Client) error {
		if runtime == nil || !runtime.Ready() {
			return fmt.Errorf("%w: upgrade runtime is not ready", ErrInvalidConfiguration)
		}
		client.upgrades = runtime
		return nil
	}
}

func (s *TrustStore) Ed25519Keys() (map[string]ed25519.PublicKey, error) {
	if s == nil || len(s.keys) == 0 {
		return nil, fmt.Errorf("%w: upgrade trust store is empty", ErrInvalidConfiguration)
	}
	result := make(map[string]ed25519.PublicKey, len(s.keys))
	for keyID, value := range s.keys {
		key, ok := value.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: upgrade trust requires Ed25519 keys", ErrInvalidConfiguration)
		}
		result[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return result, nil
}

type upgradeQueuedStatus struct {
	StatusID  string
	CommandID string
	Revision  uint64
	State     updater.EdgeUpgradeState
	Encoded   []byte
	Digest    [sha256.Size]byte
}

type upgradeWorkItem struct {
	encoded []byte
	digest  [sha256.Size]byte
	recover bool
}

type upgradeWorkResult struct {
	item upgradeWorkItem
	err  error
}

func validateUpgradeCommandEnvelope(command *agentv1.UpgradeCommand) ([]byte, error) {
	if command == nil || len(command.Command) == 0 || len(command.CommandSha256) != sha256.Size {
		return nil, fmt.Errorf("%w: invalid upgrade command envelope", ErrInvalidMessage)
	}
	digest := sha256.Sum256(command.Command)
	if !bytes.Equal(digest[:], command.CommandSha256) {
		return nil, fmt.Errorf("%w: upgrade command digest mismatch", ErrInvalidMessage)
	}
	return append([]byte(nil), command.Command...), nil
}

func queuedUpgradeStatus(status updater.QueuedUpgradeStatus) upgradeQueuedStatus {
	return upgradeQueuedStatus{
		StatusID: status.Status.StatusID, CommandID: status.Status.CommandID,
		Revision: status.Status.StatusRevision, State: status.Status.State,
		Encoded: append([]byte(nil), status.Encoded...),
		Digest:  sha256.Sum256(status.Encoded),
	}
}

func validateUpgradeStatusAck(ack *agentv1.UpgradeStatusAck, status upgradeQueuedStatus, statusPubAckCapability ...bool) error {
	if ack == nil || ack.StatusEventId != status.StatusID || ack.CommandId != status.CommandID ||
		ack.StatusRevision != status.Revision || len(ack.StatusSha256) != sha256.Size ||
		!bytes.Equal(ack.StatusSha256, status.Digest[:]) || ack.PersistedTime == nil || ack.PersistedTime.CheckValid() != nil {
		return fmt.Errorf("%w: invalid upgrade status acknowledgement", ErrInvalidMessage)
	}
	statusPubAckEnabled := len(statusPubAckCapability) == 1 && statusPubAckCapability[0]
	if statusPubAckEnabled && (ack.PublishedStream != edgeUpgradeStatusStream || ack.PublishedSequence == 0) ||
		!statusPubAckEnabled && (ack.PublishedStream != "" || ack.PublishedSequence != 0) {
		return fmt.Errorf("%w: invalid upgrade status publication acknowledgement", ErrInvalidMessage)
	}
	return nil
}

func upgradeStatusAcknowledgement(ack *agentv1.UpgradeStatusAck) (updater.UpgradeStatusAcknowledgement, *agentv1.UpgradeStatusAckReceipt, error) {
	if ack == nil || cacheControlMessageHasUnknown(ack.ProtoReflect()) || !canonicalUUID(ack.StatusEventId) ||
		!canonicalUUID(ack.CommandId) || ack.StatusRevision == 0 || len(ack.StatusSha256) != sha256.Size ||
		ack.PersistedTime == nil || ack.PersistedTime.CheckValid() != nil ||
		ack.PublishedStream != edgeUpgradeStatusStream || ack.PublishedSequence == 0 {
		return updater.UpgradeStatusAcknowledgement{}, nil, fmt.Errorf("%w: invalid upgrade status acknowledgement receipt source", ErrInvalidMessage)
	}
	exact, err := (proto.MarshalOptions{Deterministic: true}).Marshal(ack)
	if err != nil {
		return updater.UpgradeStatusAcknowledgement{}, nil, fmt.Errorf("%w: marshal upgrade status acknowledgement: %v", ErrInvalidMessage, err)
	}
	digest := sha256.Sum256(exact)
	acknowledgement := updater.UpgradeStatusAcknowledgement{
		StatusID: ack.StatusEventId, CommandID: ack.CommandId, StatusRevision: ack.StatusRevision,
		StatusSHA256: hex.EncodeToString(ack.StatusSha256), PersistedAt: ack.PersistedTime.AsTime().UTC(),
		PublishedStream: ack.PublishedStream, PublishedSequence: ack.PublishedSequence,
		Encoded: append([]byte(nil), exact...), SHA256: hex.EncodeToString(digest[:]),
	}
	receipt := upgradeStatusAckReceipt(acknowledgement)
	return acknowledgement, receipt, nil
}

func upgradeStatusAckReceipt(acknowledgement updater.UpgradeStatusAcknowledgement) *agentv1.UpgradeStatusAckReceipt {
	statusDigest, statusErr := hex.DecodeString(acknowledgement.StatusSHA256)
	ackDigest, ackErr := hex.DecodeString(acknowledgement.SHA256)
	if statusErr != nil || ackErr != nil {
		return nil
	}
	return &agentv1.UpgradeStatusAckReceipt{
		StatusEventId: acknowledgement.StatusID, CommandId: acknowledgement.CommandID,
		StatusRevision: acknowledgement.StatusRevision, StatusSha256: statusDigest,
		PersistedTime:   timestamppb.New(acknowledgement.PersistedAt.UTC()),
		PublishedStream: acknowledgement.PublishedStream, PublishedSequence: acknowledgement.PublishedSequence,
		AckSha256: ackDigest,
	}
}

func validateUpgradeStatusAckReceipt(receipt *agentv1.UpgradeStatusAckReceipt, acknowledgement updater.UpgradeStatusAcknowledgement) error {
	expected := upgradeStatusAckReceipt(acknowledgement)
	if receipt == nil || expected == nil || cacheControlMessageHasUnknown(receipt.ProtoReflect()) ||
		!proto.Equal(receipt, expected) {
		return fmt.Errorf("%w: upgrade status acknowledgement receipt does not match durable state", ErrInvalidMessage)
	}
	return nil
}

func gatewayHelloHasEdgeUpgradeV1(hello *agentv1.GatewayHello) bool {
	if hello == nil {
		return false
	}
	for _, capability := range hello.EnabledCapabilities {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE && capability.ApiVersion == 1 {
			return true
		}
	}
	return false
}

func gatewayHelloEdgeUpgradeCapabilities(hello *agentv1.GatewayHello) (bool, bool, error) {
	upgrade := gatewayHelloHasEdgeUpgradeV1(hello)
	pubAck := false
	if hello == nil {
		return false, false, nil
	}
	for _, capability := range hello.EnabledCapabilities {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK {
			continue
		}
		if pubAck {
			return false, false, fmt.Errorf("%w: Gateway upgrade status PubAck capability is duplicated", ErrInvalidMessage)
		}
		pubAck = true
		if capability.ApiVersion != 1 {
			return false, false, fmt.Errorf("%w: Gateway upgrade status PubAck capability is unsupported", ErrInvalidMessage)
		}
	}
	if pubAck && !upgrade {
		return false, false, fmt.Errorf("%w: Gateway upgrade status PubAck capability requires edge upgrade v1", ErrInvalidMessage)
	}
	return upgrade, pubAck, nil
}

func gatewayHelloEdgeUpgradeExtendedCapabilities(hello *agentv1.GatewayHello, offered *agentv1.AgentCapabilities) (bool, bool, bool, bool, error) {
	upgrade, pubAck, err := gatewayHelloEdgeUpgradeCapabilities(hello)
	if err != nil {
		return false, false, false, false, err
	}
	if upgrade && !offeredUpgradeCapabilityV1(offered, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE) {
		return false, false, false, false, fmt.Errorf("%w: Gateway enabled an invalid or unoffered edge upgrade capability", ErrInvalidMessage)
	}
	if pubAck && !offeredUpgradeCapabilityV1(offered, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK) {
		return false, false, false, false, fmt.Errorf("%w: Gateway enabled an invalid or unoffered upgrade status PubAck capability", ErrInvalidMessage)
	}
	receipt, prepareActivate := false, false
	seen := make(map[agentv1.CapabilityName]bool, 2)
	if hello != nil {
		for _, capability := range hello.EnabledCapabilities {
			if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT &&
				capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE {
				continue
			}
			if seen[capability.Name] || capability.ApiVersion != 1 || !offeredUpgradeCapabilityV1(offered, capability.Name) {
				return false, false, false, false, fmt.Errorf("%w: Gateway enabled an invalid or unoffered extended upgrade capability", ErrInvalidMessage)
			}
			seen[capability.Name] = true
			if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT {
				receipt = true
			} else {
				prepareActivate = true
			}
		}
	}
	if receipt && (!upgrade || !pubAck) || prepareActivate && !upgrade {
		return false, false, false, false, fmt.Errorf("%w: Gateway extended upgrade capability dependency is missing", ErrInvalidMessage)
	}
	return upgrade, pubAck, receipt, prepareActivate, nil
}

func offeredUpgradeCapabilityV1(capabilities *agentv1.AgentCapabilities, name agentv1.CapabilityName) bool {
	seen := false
	if capabilities == nil {
		return false
	}
	for _, capability := range capabilities.Features {
		if capability == nil || capability.Name != name {
			continue
		}
		if seen || capability.ApiVersion != 1 {
			return false
		}
		seen = true
	}
	return seen
}

func ensureEdgeUpgradeCapability(capabilities *agentv1.AgentCapabilities) {
	if capabilities == nil {
		return
	}
	if !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1,
		})
	}
	if !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK, ApiVersion: 1,
		})
	}
}

func ensureEdgeUpgradeCapabilities(capabilities *agentv1.AgentCapabilities, runtime UpgradeRuntime) {
	if capabilities == nil {
		return
	}
	for _, name := range []agentv1.CapabilityName{
		agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE,
		agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK,
		agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT,
		agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE,
	} {
		capabilities.Features = removeCapability(capabilities.Features, name)
	}
	if runtime == nil || !runtime.Ready() {
		return
	}
	ensureEdgeUpgradeCapability(capabilities)
	receipt, prepareActivate := actualEdgeUpgradeRuntimeCapabilities(runtime)
	if receipt {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT, ApiVersion: 1,
		})
	}
	if prepareActivate {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE, ApiVersion: 1,
		})
	}
}

func actualEdgeUpgradeRuntimeCapabilities(runtime UpgradeRuntime) (bool, bool) {
	actual, ok := runtime.(*updater.UpgradeRuntime)
	if !ok || !actual.Ready() {
		return false, false
	}
	return actual.StatusAcknowledgementReceiptsEnabled(), actual.InstallerProtocolVersion() == updater.InstallerProtocolV2
}

func (c *Client) pendingUpgradeStatuses(ctx context.Context) ([]upgradeQueuedStatus, error) {
	if c.upgrades == nil {
		return nil, nil
	}
	statuses, err := c.upgrades.PendingStatuses(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]upgradeQueuedStatus, 0, len(statuses))
	for _, status := range statuses {
		result = append(result, queuedUpgradeStatus(status))
	}
	return result, nil
}

func (c *Client) sendPendingUpgradeStatuses(ctx context.Context,
	stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64,
	sent map[string][sha256.Size]byte,
) (uint64, error) {
	statuses, err := c.pendingUpgradeStatuses(ctx)
	if err != nil {
		return sequence, err
	}
	for _, status := range statuses {
		if digest, exists := sent[status.StatusID]; exists {
			if digest != status.Digest {
				return sequence, fmt.Errorf("%w: upgrade status identity changed within the session", ErrInvalidMessage)
			}
			continue
		}
		sequence++
		if err := stream.Send(&agentv1.ConnectRequest{
			Stream: streamMetadata(sequence, c.now()),
			Payload: &agentv1.ConnectRequest_UpgradeStatus{UpgradeStatus: &agentv1.UpgradeStatus{
				Status: append([]byte(nil), status.Encoded...), StatusSha256: append([]byte(nil), status.Digest[:]...),
			}},
		}); err != nil {
			return sequence, err
		}
		sent[status.StatusID] = status.Digest
	}
	return sequence, nil
}

func (c *Client) acknowledgeUpgradeStatus(ctx context.Context, ack *agentv1.UpgradeStatusAck, statusPubAckCapability ...bool) (bool, error) {
	statuses, err := c.pendingUpgradeStatuses(ctx)
	if err != nil {
		return false, err
	}
	for _, status := range statuses {
		if status.StatusID != ack.GetStatusEventId() {
			continue
		}
		if err := validateUpgradeStatusAck(ack, status, statusPubAckCapability...); err != nil {
			return false, err
		}
		var acked bool
		if len(statusPubAckCapability) == 1 && statusPubAckCapability[0] {
			runtime, ok := c.upgrades.(upgradeStatusPublicationAcknowledger)
			if !ok {
				return false, fmt.Errorf("%w: upgrade runtime cannot persist publication identity", ErrInvalidMessage)
			}
			acknowledgement, _, conversionErr := upgradeStatusAcknowledgement(ack)
			if conversionErr != nil {
				return false, conversionErr
			}
			acked, err = runtime.AcknowledgeStatusWithPublication(ctx, acknowledgement)
		} else {
			acked, err = c.upgrades.AcknowledgeStatus(ctx, status.StatusID, status.CommandID, hex.EncodeToString(status.Digest[:]))
		}
		if err != nil || !acked {
			return false, fmt.Errorf("%w: upgrade status acknowledgement was not persisted", ErrInvalidMessage)
		}
		return status.State == updater.EdgeUpgradeStateAccepted, nil
	}
	return false, fmt.Errorf("%w: upgrade status acknowledgement does not match the durable outbox", ErrInvalidMessage)
}

func (c *Client) persistUpgradeStatusAcknowledgement(ctx context.Context, ack *agentv1.UpgradeStatusAck) (bool, *agentv1.UpgradeStatusAckReceipt, error) {
	runtime, ok := c.upgrades.(upgradeStatusAcknowledgementRuntime)
	if !ok {
		return false, nil, fmt.Errorf("%w: upgrade status acknowledgement receipts are unavailable", ErrInvalidMessage)
	}
	statuses, err := c.pendingUpgradeStatuses(ctx)
	if err != nil {
		return false, nil, err
	}
	for _, status := range statuses {
		if status.StatusID != ack.GetStatusEventId() {
			continue
		}
		if err := validateUpgradeStatusAck(ack, status, true); err != nil {
			return false, nil, err
		}
		acknowledgement, receipt, err := upgradeStatusAcknowledgement(ack)
		if err != nil {
			return false, nil, err
		}
		accepted, err := runtime.PersistStatusAcknowledgement(ctx, acknowledgement)
		if err != nil {
			return false, nil, err
		}
		return accepted, receipt, nil
	}
	return false, nil, fmt.Errorf("%w: upgrade status acknowledgement does not match the durable outbox", ErrInvalidMessage)
}

func (c *Client) pendingUpgradeStatusAcknowledgements(ctx context.Context) ([]*agentv1.UpgradeStatusAckReceipt, error) {
	runtime, ok := c.upgrades.(upgradeStatusAcknowledgementRuntime)
	if !ok {
		return nil, nil
	}
	acknowledgements, err := runtime.PendingStatusAcknowledgements(ctx)
	if err != nil {
		return nil, err
	}
	receipts := make([]*agentv1.UpgradeStatusAckReceipt, 0, len(acknowledgements))
	for _, acknowledgement := range acknowledgements {
		receipt := upgradeStatusAckReceipt(acknowledgement)
		if receipt == nil {
			return nil, fmt.Errorf("%w: invalid durable upgrade status acknowledgement", ErrInvalidMessage)
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

func (c *Client) confirmUpgradeStatusAcknowledgement(ctx context.Context, receipt *agentv1.UpgradeStatusAckReceipt) (bool, error) {
	runtime, ok := c.upgrades.(upgradeStatusAcknowledgementRuntime)
	if !ok {
		return false, fmt.Errorf("%w: upgrade status acknowledgement receipts are unavailable", ErrInvalidMessage)
	}
	acknowledgements, err := runtime.PendingStatusAcknowledgements(ctx)
	if err != nil {
		return false, err
	}
	for _, acknowledgement := range acknowledgements {
		if acknowledgement.StatusID != receipt.GetStatusEventId() {
			continue
		}
		if err := validateUpgradeStatusAckReceipt(receipt, acknowledgement); err != nil {
			return false, err
		}
		return runtime.ConfirmStatusAcknowledgement(ctx, acknowledgement)
	}
	return false, fmt.Errorf("%w: upgrade status acknowledgement receipt does not match pending durable state", ErrInvalidMessage)
}

func sendUpgradeStatusAckReceipt(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, receipt *agentv1.UpgradeStatusAckReceipt, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{
		Stream:  streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_UpgradeStatusAckReceipt{UpgradeStatusAckReceipt: receipt},
	})
}

// runUpgradeWork recovers accepted upgrades or accepts a new command. A frozen
// node (expired service ticket) does not accept new upgrade
// commands: the command stays unacknowledged and the control plane delivers it
// again on a later session, once a renewed ticket unfroze the node.
func (c *Client) runUpgradeWork(ctx context.Context, item upgradeWorkItem) error {
	if item.recover {
		return c.upgrades.Recover(ctx)
	}
	if c.installationFrozen() {
		slog.Warn("upgrade command refused while the node is frozen", "reason", InstallationFrozenReason)
		return nil
	}
	return c.upgrades.AcceptCommand(ctx, item.encoded)
}
