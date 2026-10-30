package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	UpgradeCommandSchema         = "cdnca.edge.upgrade.command/v1"
	UpgradeStatusSchema          = "cdnca.edge.upgrade.status/v1"
	UpgradeCommandStream         = "AGENT_COMMANDS"
	UpgradeStatusStream          = "AGENT_DEPLOYMENT_STATUS"
	UpgradeCommandSubjectPrefix  = "cdnca.agent.commands.upgrade"
	UpgradeStatusSubjectPrefix   = "cdnca.agent.deployment-status.upgrade"
	UpgradeStatusV2SubjectPrefix = "cdnca.agent.deployment-status.upgrade-v2"
	UpgradePayloadSHA256Header   = "X-CDNCA-Payload-SHA256"
	UpgradeMessageKeyHeader      = "X-CDNCA-Message-Key"
	upgradeExecutionV2Schema     = "cdnca.upgrade.execution/v2"
	maxUpgradeWireBytes          = 256 << 10
	maxUpgradePlanRevision       = uint64(1<<63 - 1)
)

var upgradeSafeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type UpgradeCommandBus interface {
	SubscribeUpgrade(context.Context, string) (UpgradeCommandSubscription, error)
	PublishUpgradeStatus(context.Context, string, []byte) (UpgradeStatusPublication, error)
}

type UpgradeCommandSubscription interface {
	Next(context.Context) (UpgradeCommandDelivery, error)
	Close() error
}

type UpgradeCommandDelivery interface {
	Command() UpgradeCommandRecord
	Ack(context.Context) error
	Nak(context.Context) error
}

type UpgradeStatusPublication struct {
	Stream   string
	Sequence uint64
}

type upgradeCommandWire struct {
	Schema                string `json:"schema"`
	CommandID             string `json:"command_id"`
	PlanID                string `json:"plan_id"`
	PlanRevision          uint64 `json:"plan_revision"`
	BatchID               string `json:"batch_id"`
	InstallationID        string `json:"installation_id"`
	NodeID                string `json:"node_id"`
	Action                string `json:"action"`
	SignedExecution       []byte `json:"signed_execution"`
	SignedExecutionSHA256 string `json:"signed_execution_sha256"`
}

type upgradeStatusWire struct {
	Schema                 string    `json:"schema"`
	StatusID               string    `json:"status_id"`
	StatusRevision         uint64    `json:"status_revision"`
	CommandID              string    `json:"command_id"`
	PlanID                 string    `json:"plan_id"`
	PlanRevision           uint64    `json:"plan_revision"`
	InstallationID         string    `json:"installation_id"`
	NodeID                 string    `json:"node_id"`
	CommandSHA256          string    `json:"command_sha256"`
	State                  string    `json:"state"`
	CurrentVersion         string    `json:"current_version"`
	PreviousVersion        string    `json:"previous_version"`
	InstallerTransactionID string    `json:"installer_transaction_id"`
	ErrorCode              string    `json:"error_code"`
	AlertRequired          bool      `json:"alert_required"`
	ObservedAt             time.Time `json:"observed_at"`
}

type upgradeExecutionEnvelopeWire struct {
	ControlAlgorithm string          `json:"control_algorithm"`
	ControlKeyID     string          `json:"control_key_id"`
	Execution        json.RawMessage `json:"execution"`
	ControlSignature string          `json:"control_signature"`
	EdgeAlgorithm    string          `json:"edge_algorithm"`
	EdgeKeyID        string          `json:"edge_key_id"`
	EdgeSignature    string          `json:"edge_signature"`
}

type upgradeExecutionRolloutWire struct {
	Schema       string `json:"schema"`
	PlanID       string `json:"plan_id"`
	PlanRevision uint64 `json:"plan_revision"`
	BatchID      string `json:"batch_id"`
}

type UpgradeCommandRecord struct {
	CommandID      string
	PlanID         string
	PlanRevision   uint64
	BatchID        string
	InstallationID string
	NodeID         string
	Encoded        []byte
	SHA256         [sha256.Size]byte
}

type UpgradeStatusRecord struct {
	StatusID       string
	StatusRevision uint64
	CommandID      string
	PlanID         string
	PlanRevision   uint64
	InstallationID string
	NodeID         string
	State          string
	Encoded        []byte
	SHA256         [sha256.Size]byte
}

func decodeUpgradeCommandRecord(encoded []byte) (UpgradeCommandRecord, error) {
	var wire upgradeCommandWire
	if decodeCanonicalUpgradeJSON(encoded, &wire) != nil || wire.Schema != UpgradeCommandSchema ||
		!canonicalUpgradeUUID(wire.CommandID) || !canonicalUpgradeUUID(wire.PlanID) || wire.PlanRevision == 0 ||
		!upgradeSafeIDPattern.MatchString(wire.BatchID) || !canonicalUpgradeUUID(wire.InstallationID) ||
		!canonicalUpgradeUUID(wire.NodeID) || (wire.Action != "upgrade" && wire.Action != "rollback") ||
		len(wire.SignedExecution) == 0 || len(wire.SignedExecution) > maxUpgradeWireBytes || len(wire.SignedExecutionSHA256) != 64 {
		return UpgradeCommandRecord{}, errors.New("invalid upgrade command")
	}
	signedDigest := sha256.Sum256(wire.SignedExecution)
	if wire.SignedExecutionSHA256 != hex.EncodeToString(signedDigest[:]) {
		return UpgradeCommandRecord{}, errors.New("invalid upgrade command")
	}
	rollout, err := decodeUpgradeExecutionRollout(wire.SignedExecution)
	if err != nil || rollout.PlanID != wire.PlanID || rollout.PlanRevision != wire.PlanRevision ||
		rollout.BatchID != wire.BatchID {
		return UpgradeCommandRecord{}, errors.New("invalid upgrade command")
	}
	return UpgradeCommandRecord{
		CommandID: wire.CommandID, PlanID: wire.PlanID, PlanRevision: wire.PlanRevision,
		BatchID:        wire.BatchID,
		InstallationID: wire.InstallationID, NodeID: wire.NodeID,
		Encoded: append([]byte(nil), encoded...), SHA256: sha256.Sum256(encoded),
	}, nil
}

func decodeUpgradeExecutionRollout(encoded []byte) (upgradeExecutionRolloutWire, error) {
	if validateTelemetryUniqueJSONKeys(encoded) != nil {
		return upgradeExecutionRolloutWire{}, errors.New("invalid upgrade execution")
	}
	var envelope upgradeExecutionEnvelopeWire
	if decodeCanonicalUpgradeJSON(encoded, &envelope) != nil || len(envelope.Execution) == 0 {
		return upgradeExecutionRolloutWire{}, errors.New("invalid upgrade execution")
	}
	var rollout upgradeExecutionRolloutWire
	if err := json.Unmarshal(envelope.Execution, &rollout); err != nil || rollout.Schema != upgradeExecutionV2Schema ||
		!canonicalUpgradeUUID(rollout.PlanID) || rollout.PlanRevision == 0 ||
		rollout.PlanRevision > maxUpgradePlanRevision || !canonicalUpgradeUUID(rollout.BatchID) {
		return upgradeExecutionRolloutWire{}, errors.New("invalid upgrade execution")
	}
	return rollout, nil
}

func decodeUpgradeStatusRecord(encoded []byte) (UpgradeStatusRecord, error) {
	var wire upgradeStatusWire
	if decodeCanonicalUpgradeJSON(encoded, &wire) != nil || wire.Schema != UpgradeStatusSchema ||
		!canonicalUpgradeUUID(wire.StatusID) || wire.StatusRevision == 0 || !canonicalUpgradeUUID(wire.CommandID) ||
		!canonicalUpgradeUUID(wire.PlanID) || wire.PlanRevision == 0 || !canonicalUpgradeUUID(wire.InstallationID) ||
		!canonicalUpgradeUUID(wire.NodeID) || len(wire.CommandSHA256) != 64 || !validUpgradeState(wire.State) ||
		wire.ObservedAt.IsZero() || wire.ObservedAt.Location() != time.UTC ||
		(wire.InstallerTransactionID != "" && !upgradeSafeIDPattern.MatchString(wire.InstallerTransactionID)) ||
		(wire.ErrorCode != "" && !upgradeSafeIDPattern.MatchString(wire.ErrorCode)) {
		return UpgradeStatusRecord{}, errors.New("invalid upgrade status")
	}
	if _, err := hex.DecodeString(wire.CommandSHA256); err != nil {
		return UpgradeStatusRecord{}, errors.New("invalid upgrade status")
	}
	return UpgradeStatusRecord{
		StatusID: wire.StatusID, StatusRevision: wire.StatusRevision, CommandID: wire.CommandID,
		PlanID: wire.PlanID, PlanRevision: wire.PlanRevision,
		InstallationID: wire.InstallationID, NodeID: wire.NodeID, State: wire.State,
		Encoded: append([]byte(nil), encoded...), SHA256: sha256.Sum256(encoded),
	}, nil
}

func decodeCanonicalUpgradeJSON(encoded []byte, destination any) error {
	if len(encoded) == 0 || len(encoded) > maxUpgradeWireBytes {
		return errors.New("invalid upgrade wire size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("invalid upgrade wire trailing data")
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return errors.New("upgrade wire is not canonical JSON")
	}
	return nil
}

func canonicalUpgradeUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validUpgradeState(value string) bool {
	switch value {
	case "accepted", "claimed", "installing", "healthy", "failed", "rolling_back", "rolled_back", "uncertain":
		return true
	default:
		return false
	}
}

type pendingUpgradeCommand struct {
	command    UpgradeCommandRecord
	deliveries []UpgradeCommandDelivery
}

type pendingUpgradeCommandSet map[string]*pendingUpgradeCommand

func (p pendingUpgradeCommandSet) deliveryCount() int {
	count := 0
	for _, command := range p {
		count += len(command.deliveries)
	}
	return count
}

type upgradeCommandReceive struct {
	delivery UpgradeCommandDelivery
	err      error
}

type sessionUpgradeCommandSource struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription UpgradeCommandSubscription
	next         <-chan upgradeCommandReceive
}

func newSessionUpgradeCommandSource(ctx context.Context, bus UpgradeCommandBus, nodeID string) (*sessionUpgradeCommandSource, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := bus.SubscribeUpgrade(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, err
	}
	return &sessionUpgradeCommandSource{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

func (s *sessionUpgradeCommandSource) arm() {
	if s == nil || s.next != nil {
		return
	}
	next := make(chan upgradeCommandReceive, 1)
	s.next = next
	go func() {
		delivery, err := s.subscription.Next(s.ctx)
		next <- upgradeCommandReceive{delivery: delivery, err: err}
	}()
}

func stopSessionUpgradeCommands(source *sessionUpgradeCommandSource, pending pendingUpgradeCommandSet, timeout time.Duration) {
	for key, command := range pending {
		for _, delivery := range command.deliveries {
			nakUpgradeCommand(delivery, timeout)
		}
		delete(pending, key)
	}
	if source == nil {
		return
	}
	source.cancel()
	_ = source.subscription.Close()
	if source.next == nil {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-source.next:
		nakUpgradeCommand(result.delivery, timeout)
	case <-timer.C:
	}
}

func nakUpgradeCommand(delivery UpgradeCommandDelivery, timeout time.Duration) {
	if delivery == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = delivery.Nak(ctx)
}

func (g *Gateway) ConfigureUpgradeMessaging(upgrades UpgradeCommandBus) error {
	if g == nil || isNilInterface(upgrades) {
		return fmt.Errorf("upgrade command bus is required")
	}
	if g.upgrades != nil {
		return fmt.Errorf("upgrade command bus is already configured")
	}
	g.upgrades = upgrades
	if receipts, ok := upgrades.(upgradeStatusAckStore); ok {
		g.upgradeReceipts = receipts
	}
	return nil
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (g *Gateway) applyUpgradeAuthorization(ctx context.Context, nodeID string,
	source *sessionUpgradeCommandSource, pending pendingUpgradeCommandSet, wasAllowed, isAllowed bool,
) (*sessionUpgradeCommandSource, error) {
	if g.upgrades == nil || wasAllowed == isAllowed {
		return source, nil
	}
	if !isAllowed {
		stopSessionUpgradeCommands(source, pending, g.config.CommandOperationTimeout)
		return nil, nil
	}
	created, err := newSessionUpgradeCommandSource(ctx, g.upgrades, nodeID)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "could not subscribe to node upgrade commands")
	}
	return created, nil
}

func (g *Gateway) persistUpgradeStatusAndAckCommand(ctx context.Context, nodeID, installationID string, encoded []byte,
	pending pendingUpgradeCommandSet, statusPubAckCapability ...bool) (*agentv1.UpgradeStatusAck, error) {
	record, err := decodeUpgradeStatusRecord(encoded)
	if err != nil || record.NodeID != nodeID || record.InstallationID != installationID {
		return nil, status.Error(codes.InvalidArgument, "upgrade status is invalid")
	}
	var acceptedCommand *pendingUpgradeCommand
	if record.State == "accepted" {
		acceptedCommand = pending[record.CommandID]
		if acceptedCommand != nil && (acceptedCommand.command.NodeID != nodeID ||
			acceptedCommand.command.PlanID != record.PlanID || acceptedCommand.command.PlanRevision != record.PlanRevision ||
			acceptedCommand.command.InstallationID != installationID ||
			hex.EncodeToString(acceptedCommand.command.SHA256[:]) != commandStatusDigest(record.Encoded)) {
			return nil, status.Error(codes.FailedPrecondition, "upgrade status conflicts with the in-flight command")
		}
	}
	statusPubAckEnabled := len(statusPubAckCapability) >= 1 && statusPubAckCapability[0]
	statusAckReceiptEnabled := len(statusPubAckCapability) >= 2 && statusPubAckCapability[1]
	statusAckPersistenceEnabled := statusPubAckEnabled && g.upgradeReceipts != nil
	if statusAckReceiptEnabled && (!statusPubAckEnabled || g.upgradeReceipts == nil) {
		return nil, status.Error(codes.FailedPrecondition, "upgrade status acknowledgement receipts are unavailable")
	}
	var ack *agentv1.UpgradeStatusAck
	if statusAckPersistenceEnabled {
		operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		records, loadErr := g.upgradeReceipts.listUpgradeStatusAcks(operationCtx, nodeID, g.config.MaxPendingCommands)
		cancel()
		if loadErr != nil {
			return nil, status.Error(codes.Unavailable, "upgrade status acknowledgements could not be loaded")
		}
		persisted, found, findErr := findUpgradeStatusAck(records, nodeID, installationID, record)
		if findErr != nil {
			return nil, status.Error(codes.FailedPrecondition, "upgrade status conflicts with a durable acknowledgement")
		}
		if found {
			ack = persisted.Ack
		} else if statusAckReceiptEnabled && len(records) >= g.config.MaxPendingCommands {
			return nil, status.Error(codes.ResourceExhausted, "upgrade status acknowledgements exceed their limit")
		}
	}
	if ack == nil {
		publication, publishErr := g.upgrades.PublishUpgradeStatus(ctx, nodeID, record.Encoded)
		if publishErr != nil || publication.Stream != UpgradeStatusStream || publication.Sequence == 0 {
			return nil, status.Error(codes.Unavailable, "upgrade status could not be durably published")
		}
		ack = &agentv1.UpgradeStatusAck{
			StatusEventId: record.StatusID, CommandId: record.CommandID, StatusRevision: record.StatusRevision,
			StatusSha256: append([]byte(nil), record.SHA256[:]...), PersistedTime: timestamppb.New(g.now().UTC()),
		}
		if statusPubAckEnabled {
			ack.PublishedStream = publication.Stream
			ack.PublishedSequence = publication.Sequence
		}
		if statusAckPersistenceEnabled {
			operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
			candidate := upgradeStatusAckRecord{NodeID: nodeID, InstallationID: installationID, Ack: ack}
			var persisted upgradeStatusAckRecord
			var saveErr error
			if statusAckReceiptEnabled {
				persisted, saveErr = g.upgradeReceipts.saveUpgradeStatusAck(operationCtx, candidate, g.config.MaxPendingCommands)
			} else {
				persisted, saveErr = g.upgradeReceipts.saveUpgradeStatusAckHorizon(operationCtx, candidate, g.config.MaxPendingCommands)
			}
			cancel()
			if saveErr != nil {
				switch {
				case errors.Is(saveErr, errUpgradeStatusAckConflict):
					return nil, status.Error(codes.FailedPrecondition, "upgrade status acknowledgement conflicts with durable state")
				case errors.Is(saveErr, errUpgradeStatusAckLimit):
					return nil, status.Error(codes.ResourceExhausted, "upgrade status acknowledgements exceed their limit")
				default:
					return nil, status.Error(codes.Unavailable, "upgrade status acknowledgement could not be persisted")
				}
			}
			ack = persisted.Ack
		}
	}
	if record.State == "accepted" {
		if acceptedCommand == nil {
			if !statusPubAckEnabled {
				return nil, nil
			}
			return ack, nil
		}
		for len(acceptedCommand.deliveries) != 0 {
			delivery := acceptedCommand.deliveries[0]
			operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
			err = delivery.Ack(operationCtx)
			cancel()
			if err != nil {
				return nil, status.Error(codes.Unavailable, "upgrade command could not be acknowledged")
			}
			acceptedCommand.deliveries = acceptedCommand.deliveries[1:]
		}
		delete(pending, record.CommandID)
	}
	return ack, nil
}

func commandStatusDigest(encoded []byte) string {
	var wire upgradeStatusWire
	if decodeCanonicalUpgradeJSON(encoded, &wire) != nil {
		return ""
	}
	return wire.CommandSHA256
}

func controlUpgradeMessageID(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return "control-upgrade-v1-" + hex.EncodeToString(digest[:])
}
