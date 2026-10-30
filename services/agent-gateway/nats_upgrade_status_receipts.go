package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

const (
	UpgradeStatusProofSubjectPrefix       = "cdnca.agent.deployment-status.upgrade-proof"
	UpgradeStatusIdentitySubjectPrefix    = UpgradeStatusProofSubjectPrefix + ".status"
	upgradeStatusAckLedgerSchema          = "cdnca.gateway.upgrade-status-ack-ledger/v1"
	upgradeStatusAckConfirmationSchema    = "cdnca.gateway.upgrade-status-ack-confirmation/v1"
	upgradeCommandCompletionSchema        = "cdnca.gateway.upgrade-command-completion/v1"
	legacyUpgradeStatusIdentitySchema     = "cdnca.gateway.upgrade-status-identity/v1"
	upgradeStatusIdentitySchema           = "cdnca.gateway.upgrade-status-identity/v2"
	upgradeStatusReservationSchema        = "cdnca.gateway.upgrade-status-reservation/v1"
	upgradeStatusMigrationSchema          = "cdnca.gateway.upgrade-status-migration/v1"
	upgradeStatusAckLedgerMessageIDPrefix = "gateway-upgrade-status-ack-ledger-v1-"
	upgradeStatusAckProofMessageIDPrefix  = "gateway-upgrade-status-ack-confirmation-v1-"
	upgradeCommandCompletionIDPrefix      = "gateway-upgrade-command-completion-v1-"
	upgradeStatusIdentityMessageIDPrefix  = "gateway-upgrade-status-identity-v2-"
	upgradeStatusReservationIDPrefix      = "gateway-upgrade-status-reservation-v1-"
	upgradeStatusMigrationIDPrefix        = "gateway-upgrade-status-migration-v1-"
	upgradeStatusV2MessageIDPrefix        = "gateway-upgrade-status-v2-"
	upgradeStatusMigrationSubject         = UpgradeStatusIdentitySubjectPrefix + ".migration.progress"
)

var errUpgradeStatusIdentityConflict = errors.New("upgrade status identity conflicts with durable state")
var errUpgradeStatusMigrationInProgress = errors.New("upgrade status legacy migration is in progress")

type upgradeStatusAckRecordWire struct {
	InstallationID string `json:"installation_id"`
	Ack            []byte `json:"ack"`
	AckSHA256      string `json:"ack_sha256"`
}

type upgradeStatusAckLedgerWire struct {
	Schema           string                       `json:"schema"`
	NodeID           string                       `json:"node_id"`
	PreviousSequence uint64                       `json:"previous_sequence"`
	Pending          []upgradeStatusAckRecordWire `json:"pending"`
}

type upgradeStatusAckConfirmationWire struct {
	Schema         string `json:"schema"`
	NodeID         string `json:"node_id"`
	InstallationID string `json:"installation_id"`
	Ack            []byte `json:"ack"`
	AckSHA256      string `json:"ack_sha256"`
	Receipt        []byte `json:"receipt"`
}

type upgradeCommandCompletionWire struct {
	Schema        string                     `json:"schema"`
	NodeID        string                     `json:"node_id"`
	CommandSHA256 string                     `json:"command_sha256"`
	Status        []byte                     `json:"status"`
	Record        upgradeStatusAckRecordWire `json:"record"`
}

type upgradeStatusIdentityWire struct {
	Schema              string `json:"schema"`
	NodeID              string `json:"node_id"`
	StatusID            string `json:"status_id"`
	StatusRevision      uint64 `json:"status_revision"`
	CommandID           string `json:"command_id"`
	PlanID              string `json:"plan_id"`
	PlanRevision        uint64 `json:"plan_revision"`
	InstallationID      string `json:"installation_id"`
	StatusSHA256        string `json:"status_sha256"`
	ReservationSequence uint64 `json:"reservation_sequence,omitempty"`
	LegacyMigration     bool   `json:"legacy_migration,omitempty"`
	PublishedStream     string `json:"published_stream"`
	PublishedSequence   uint64 `json:"published_sequence"`
	Status              []byte `json:"status"`
}

type upgradeStatusReservationWire struct {
	Schema         string `json:"schema"`
	NodeID         string `json:"node_id"`
	StatusID       string `json:"status_id"`
	StatusRevision uint64 `json:"status_revision"`
	CommandID      string `json:"command_id"`
	PlanID         string `json:"plan_id"`
	PlanRevision   uint64 `json:"plan_revision"`
	InstallationID string `json:"installation_id"`
	StatusSHA256   string `json:"status_sha256"`
	Status         []byte `json:"status"`
}

type upgradeStatusMigrationWire struct {
	Schema                   string `json:"schema"`
	HorizonSequence          uint64 `json:"horizon_sequence"`
	NextSequence             uint64 `json:"next_sequence"`
	PreviousProgressSequence uint64 `json:"previous_progress_sequence"`
	Complete                 bool   `json:"complete"`
}

type upgradeStatusMigrationState struct {
	HorizonSequence  uint64
	NextSequence     uint64
	ProgressSequence uint64
	Complete         bool
}

type upgradeStatusIdentityState struct {
	ReservationSequence uint64
	Publication         UpgradeStatusPublication
}

func upgradeStatusAckLedgerSubject(nodeID string) string {
	return UpgradeStatusProofSubjectPrefix + ".pending." + nodeID
}

func upgradeStatusAckConfirmationSubject(nodeID string, digest [sha256.Size]byte) string {
	return UpgradeStatusProofSubjectPrefix + ".confirmed." + nodeID + "." + hex.EncodeToString(digest[:])
}

func upgradeCommandCompletionSubject(nodeID, installationID, commandID string) string {
	return UpgradeStatusProofSubjectPrefix + ".completed." + nodeID + "." + installationID + "." + commandID
}

func upgradeStatusIdentitySubject(nodeID, statusID string) string {
	return UpgradeStatusIdentitySubjectPrefix + "." + nodeID + "." + statusID
}

func upgradeStatusV2Subject(statusID string) string {
	return UpgradeStatusV2SubjectPrefix + "." + statusID
}

func validUpgradeStatusMigrationState(state upgradeStatusMigrationState) bool {
	if state.NextSequence == 0 {
		return false
	}
	if state.HorizonSequence == 0 {
		return state.NextSequence == 1 && state.Complete
	}
	return state.NextSequence <= state.HorizonSequence+1 &&
		state.Complete == (state.NextSequence == state.HorizonSequence+1)
}

func upgradeStatusMigrationMessage(state upgradeStatusMigrationState, previousSequence uint64) (*nats.Msg, error) {
	if !validUpgradeStatusMigrationState(state) || state.ProgressSequence != previousSequence {
		return nil, fmt.Errorf("upgrade status migration candidate is invalid")
	}
	wire := upgradeStatusMigrationWire{
		Schema: upgradeStatusMigrationSchema, HorizonSequence: state.HorizonSequence,
		NextSequence: state.NextSequence, PreviousProgressSequence: previousSequence, Complete: state.Complete,
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maxUpgradeWireBytes {
		return nil, fmt.Errorf("upgrade status migration progress exceeds its size limit")
	}
	payloadDigest := sha256.Sum256(encoded)
	message := nats.NewMsg(upgradeStatusMigrationSubject)
	message.Data = encoded
	message.Header.Set(nats.MsgIdHdr, upgradeStatusMigrationIDPrefix+hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	message.Header.Set(nats.ExpectedLastSubjSeqHdr, strconv.FormatUint(previousSequence, 10))
	message.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(UpgradeMessageKeyHeader, "legacy-migration")
	return message, nil
}

func decodeUpgradeStatusMigrationMessage(message *nats.RawStreamMsg) (upgradeStatusMigrationState, error) {
	if message == nil || message.Subject != upgradeStatusMigrationSubject || message.Sequence == 0 {
		return upgradeStatusMigrationState{}, fmt.Errorf("upgrade status migration progress identity is invalid")
	}
	var wire upgradeStatusMigrationWire
	if decodeCanonicalUpgradeJSON(message.Data, &wire) != nil || wire.Schema != upgradeStatusMigrationSchema ||
		wire.HorizonSequence >= message.Sequence || wire.PreviousProgressSequence >= message.Sequence {
		return upgradeStatusMigrationState{}, fmt.Errorf("upgrade status migration progress payload is invalid")
	}
	state := upgradeStatusMigrationState{
		HorizonSequence: wire.HorizonSequence, NextSequence: wire.NextSequence,
		ProgressSequence: message.Sequence, Complete: wire.Complete,
	}
	if !validUpgradeStatusMigrationState(state) {
		return upgradeStatusMigrationState{}, fmt.Errorf("upgrade status migration progress payload is invalid")
	}
	payloadDigest := sha256.Sum256(message.Data)
	if !exactUpgradeHeaders(message.Header, map[string]string{
		nats.MsgIdHdr:               upgradeStatusMigrationIDPrefix + hex.EncodeToString(payloadDigest[:]),
		nats.ExpectedStreamHdr:      UpgradeStatusStream,
		nats.ExpectedLastSubjSeqHdr: strconv.FormatUint(wire.PreviousProgressSequence, 10),
		UpgradePayloadSHA256Header:  hex.EncodeToString(payloadDigest[:]), UpgradeMessageKeyHeader: "legacy-migration",
	}) {
		return upgradeStatusMigrationState{}, fmt.Errorf("upgrade status migration progress headers are invalid")
	}
	return state, nil
}

func (b *NATSUpgradeCommandBus) loadUpgradeStatusMigrationState(ctx context.Context) (
	upgradeStatusMigrationState, bool, error,
) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) {
		return upgradeStatusMigrationState{}, false, fmt.Errorf("upgrade status migration lookup is invalid")
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	message, err := b.js.GetLastMsg(UpgradeStatusStream, upgradeStatusMigrationSubject, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return upgradeStatusMigrationState{}, false, nil
	}
	if err != nil {
		return upgradeStatusMigrationState{}, false, fmt.Errorf("load upgrade status migration progress: %w", err)
	}
	state, err := decodeUpgradeStatusMigrationMessage(message)
	if err != nil {
		return upgradeStatusMigrationState{}, false, err
	}
	return state, true, nil
}

func (b *NATSUpgradeCommandBus) persistUpgradeStatusMigrationState(ctx context.Context,
	candidate upgradeStatusMigrationState, previousSequence uint64,
) (upgradeStatusMigrationState, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || candidate.ProgressSequence != previousSequence {
		return upgradeStatusMigrationState{}, fmt.Errorf("upgrade status migration publication is invalid")
	}
	message, err := upgradeStatusMigrationMessage(candidate, previousSequence)
	if err != nil {
		return upgradeStatusMigrationState{}, err
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	ack, publishErr := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(UpgradeStatusStream),
		nats.ExpectLastSequencePerSubject(previousSequence))
	cancel()
	persisted, found, loadErr := b.loadUpgradeStatusMigrationState(ctx)
	consistent := found && persisted.ProgressSequence > previousSequence
	if loadErr != nil || !consistent {
		if publishErr != nil {
			return upgradeStatusMigrationState{}, fmt.Errorf("publish upgrade status migration progress: %w", publishErr)
		}
		if loadErr != nil {
			return upgradeStatusMigrationState{}, loadErr
		}
		return upgradeStatusMigrationState{}, fmt.Errorf("upgrade status migration persistence returned inconsistent state")
	}
	if publishErr == nil {
		if err := b.validateUpgradeProofPublication(ctx, ack, message); err != nil {
			return upgradeStatusMigrationState{}, fmt.Errorf("upgrade status migration returned an invalid PubAck: %w", err)
		}
	}
	return persisted, nil
}

func upgradeStatusReservationMessage(record UpgradeStatusRecord) (*nats.Msg, error) {
	if !canonicalUpgradeUUID(record.NodeID) || !canonicalUpgradeUUID(record.StatusID) || record.Encoded == nil {
		return nil, fmt.Errorf("upgrade status reservation candidate is invalid")
	}
	wire := upgradeStatusReservationWire{
		Schema: upgradeStatusReservationSchema, NodeID: record.NodeID, StatusID: record.StatusID,
		StatusRevision: record.StatusRevision, CommandID: record.CommandID, PlanID: record.PlanID,
		PlanRevision: record.PlanRevision, InstallationID: record.InstallationID,
		StatusSHA256: hex.EncodeToString(record.SHA256[:]), Status: append([]byte(nil), record.Encoded...),
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maxUpgradeWireBytes {
		return nil, fmt.Errorf("upgrade status reservation exceeds its size limit")
	}
	payloadDigest := sha256.Sum256(encoded)
	message := nats.NewMsg(upgradeStatusIdentitySubject(record.NodeID, record.StatusID))
	message.Data = encoded
	message.Header.Set(nats.MsgIdHdr, upgradeStatusReservationIDPrefix+hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	message.Header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	message.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(UpgradeMessageKeyHeader, record.StatusID)
	return message, nil
}

func upgradeStatusIdentityMessage(record UpgradeStatusRecord, reservationSequence uint64,
	publication UpgradeStatusPublication,
) (*nats.Msg, error) {
	if !canonicalUpgradeUUID(record.NodeID) || !canonicalUpgradeUUID(record.StatusID) || publication.Stream != UpgradeStatusStream ||
		reservationSequence == 0 || publication.Sequence == 0 || publication.Sequence == reservationSequence || record.Encoded == nil {
		return nil, fmt.Errorf("upgrade status identity candidate is invalid")
	}
	wire := upgradeStatusIdentityWire{
		Schema: upgradeStatusIdentitySchema, NodeID: record.NodeID, StatusID: record.StatusID,
		StatusRevision: record.StatusRevision, CommandID: record.CommandID, PlanID: record.PlanID,
		PlanRevision: record.PlanRevision, InstallationID: record.InstallationID,
		StatusSHA256: hex.EncodeToString(record.SHA256[:]), ReservationSequence: reservationSequence,
		LegacyMigration:   publication.Sequence < reservationSequence,
		PublishedStream:   publication.Stream,
		PublishedSequence: publication.Sequence, Status: append([]byte(nil), record.Encoded...),
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maxUpgradeWireBytes {
		return nil, fmt.Errorf("upgrade status identity exceeds its size limit")
	}
	payloadDigest := sha256.Sum256(encoded)
	message := nats.NewMsg(upgradeStatusIdentitySubject(record.NodeID, record.StatusID))
	message.Data = encoded
	message.Header.Set(nats.MsgIdHdr, upgradeStatusIdentityMessageIDPrefix+hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	message.Header.Set(nats.ExpectedLastSubjSeqHdr, strconv.FormatUint(reservationSequence, 10))
	message.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(UpgradeMessageKeyHeader, record.StatusID)
	return message, nil
}

func legacyUpgradeStatusIdentityMessage(record UpgradeStatusRecord, publication UpgradeStatusPublication) (*nats.Msg, error) {
	if !canonicalUpgradeUUID(record.NodeID) || !canonicalUpgradeUUID(record.StatusID) ||
		publication.Stream != UpgradeStatusStream || publication.Sequence == 0 || record.Encoded == nil {
		return nil, fmt.Errorf("legacy upgrade status identity candidate is invalid")
	}
	wire := upgradeStatusIdentityWire{
		Schema: legacyUpgradeStatusIdentitySchema, NodeID: record.NodeID, StatusID: record.StatusID,
		StatusRevision: record.StatusRevision, CommandID: record.CommandID, PlanID: record.PlanID,
		PlanRevision: record.PlanRevision, InstallationID: record.InstallationID,
		StatusSHA256: hex.EncodeToString(record.SHA256[:]), PublishedStream: publication.Stream,
		PublishedSequence: publication.Sequence, Status: append([]byte(nil), record.Encoded...),
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maxUpgradeWireBytes {
		return nil, fmt.Errorf("legacy upgrade status identity exceeds its size limit")
	}
	payloadDigest := sha256.Sum256(encoded)
	message := nats.NewMsg(upgradeStatusIdentitySubject(record.NodeID, record.StatusID))
	message.Data = encoded
	message.Header.Set(nats.MsgIdHdr, "gateway-upgrade-status-identity-v1-"+hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	message.Header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	message.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(UpgradeMessageKeyHeader, record.StatusID)
	return message, nil
}

func decodeUpgradeStatusReservationMessage(message *nats.RawStreamMsg, nodeID string,
	record UpgradeStatusRecord,
) error {
	if message == nil || message.Sequence == 0 || !canonicalUpgradeUUID(nodeID) || record.NodeID != nodeID ||
		message.Subject != upgradeStatusIdentitySubject(nodeID, record.StatusID) {
		return fmt.Errorf("upgrade status reservation wire identity is invalid")
	}
	var wire upgradeStatusReservationWire
	if decodeCanonicalUpgradeJSON(message.Data, &wire) != nil {
		return fmt.Errorf("upgrade status reservation wire is invalid")
	}
	if wire.Schema != upgradeStatusReservationSchema || wire.NodeID != nodeID || wire.StatusID != record.StatusID ||
		wire.StatusRevision != record.StatusRevision || wire.CommandID != record.CommandID || wire.PlanID != record.PlanID ||
		wire.PlanRevision != record.PlanRevision || wire.InstallationID != record.InstallationID ||
		wire.StatusSHA256 != hex.EncodeToString(record.SHA256[:]) || !bytes.Equal(wire.Status, record.Encoded) {
		return fmt.Errorf("%w: requested status differs", errUpgradeStatusIdentityConflict)
	}
	payloadDigest := sha256.Sum256(message.Data)
	if !exactUpgradeHeaders(message.Header, map[string]string{
		nats.MsgIdHdr:          upgradeStatusReservationIDPrefix + hex.EncodeToString(payloadDigest[:]),
		nats.ExpectedStreamHdr: UpgradeStatusStream, nats.ExpectedLastSubjSeqHdr: "0",
		UpgradePayloadSHA256Header: hex.EncodeToString(payloadDigest[:]), UpgradeMessageKeyHeader: record.StatusID,
	}) {
		return fmt.Errorf("upgrade status reservation headers are invalid")
	}
	return nil
}

func decodeUpgradeStatusIdentityMessage(message *nats.RawStreamMsg, nodeID string,
	record UpgradeStatusRecord,
) (upgradeStatusIdentityState, error) {
	if message == nil || message.Sequence == 0 || !canonicalUpgradeUUID(nodeID) || record.NodeID != nodeID ||
		message.Subject != upgradeStatusIdentitySubject(nodeID, record.StatusID) {
		return upgradeStatusIdentityState{}, fmt.Errorf("upgrade status identity wire identity is invalid")
	}
	var wire upgradeStatusIdentityWire
	if decodeCanonicalUpgradeJSON(message.Data, &wire) != nil {
		return upgradeStatusIdentityState{}, fmt.Errorf("upgrade status identity wire is invalid")
	}
	if (wire.Schema != upgradeStatusIdentitySchema && wire.Schema != legacyUpgradeStatusIdentitySchema) ||
		wire.NodeID != nodeID || wire.StatusID != record.StatusID || wire.StatusRevision != record.StatusRevision ||
		wire.CommandID != record.CommandID || wire.PlanID != record.PlanID || wire.PlanRevision != record.PlanRevision ||
		wire.InstallationID != record.InstallationID || wire.StatusSHA256 != hex.EncodeToString(record.SHA256[:]) ||
		wire.PublishedStream != UpgradeStatusStream || wire.PublishedSequence == 0 ||
		!bytes.Equal(wire.Status, record.Encoded) {
		return upgradeStatusIdentityState{}, fmt.Errorf("%w: requested status differs", errUpgradeStatusIdentityConflict)
	}
	expectedPrevious := uint64(0)
	messageIDPrefix := upgradeStatusIdentityMessageIDPrefix
	if wire.Schema == upgradeStatusIdentitySchema {
		validOrdering := wire.ReservationSequence < wire.PublishedSequence && wire.PublishedSequence < message.Sequence
		if wire.LegacyMigration {
			validOrdering = wire.PublishedSequence < wire.ReservationSequence && wire.ReservationSequence < message.Sequence
		}
		if wire.ReservationSequence == 0 || !validOrdering {
			return upgradeStatusIdentityState{}, fmt.Errorf("upgrade status identity reservation is invalid")
		}
		expectedPrevious = wire.ReservationSequence
	} else {
		if wire.ReservationSequence != 0 || wire.LegacyMigration || wire.PublishedSequence >= message.Sequence {
			return upgradeStatusIdentityState{}, fmt.Errorf("upgrade status identity legacy reservation is invalid")
		}
		messageIDPrefix = "gateway-upgrade-status-identity-v1-"
	}
	payloadDigest := sha256.Sum256(message.Data)
	if !exactUpgradeHeaders(message.Header, map[string]string{
		nats.MsgIdHdr:               messageIDPrefix + hex.EncodeToString(payloadDigest[:]),
		nats.ExpectedStreamHdr:      UpgradeStatusStream,
		nats.ExpectedLastSubjSeqHdr: strconv.FormatUint(expectedPrevious, 10),
		UpgradePayloadSHA256Header:  hex.EncodeToString(payloadDigest[:]), UpgradeMessageKeyHeader: record.StatusID,
	}) {
		return upgradeStatusIdentityState{}, fmt.Errorf("upgrade status identity headers are invalid")
	}
	return upgradeStatusIdentityState{ReservationSequence: wire.ReservationSequence,
		Publication: UpgradeStatusPublication{Stream: wire.PublishedStream, Sequence: wire.PublishedSequence}}, nil
}

func (b *NATSUpgradeCommandBus) loadUpgradeStatusIdentityState(ctx context.Context, nodeID string,
	record UpgradeStatusRecord,
) (upgradeStatusIdentityState, bool, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || !canonicalUpgradeUUID(nodeID) ||
		record.NodeID != nodeID || !canonicalUpgradeUUID(record.StatusID) {
		return upgradeStatusIdentityState{}, false, fmt.Errorf("upgrade status identity lookup is invalid")
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	message, err := b.js.GetLastMsg(UpgradeStatusStream, upgradeStatusIdentitySubject(nodeID, record.StatusID), nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return upgradeStatusIdentityState{}, false, nil
	}
	if err != nil {
		return upgradeStatusIdentityState{}, false, fmt.Errorf("load upgrade status identity: %w", err)
	}
	var envelope struct {
		Schema string `json:"schema"`
	}
	if json.Unmarshal(message.Data, &envelope) != nil {
		return upgradeStatusIdentityState{}, false, fmt.Errorf("upgrade status identity wire is invalid")
	}
	if envelope.Schema == upgradeStatusReservationSchema {
		if err := decodeUpgradeStatusReservationMessage(message, nodeID, record); err != nil {
			return upgradeStatusIdentityState{}, false, err
		}
		return upgradeStatusIdentityState{ReservationSequence: message.Sequence}, true, nil
	}
	state, err := decodeUpgradeStatusIdentityMessage(message, nodeID, record)
	if err != nil {
		return upgradeStatusIdentityState{}, false, err
	}
	if state.ReservationSequence != 0 {
		operationCtx, cancel = context.WithTimeout(ctx, b.operationTimeout)
		reservation, reservationErr := b.js.GetMsg(UpgradeStatusStream, state.ReservationSequence, nats.Context(operationCtx))
		cancel()
		if reservationErr != nil || reservation == nil || reservation.Sequence != state.ReservationSequence ||
			decodeUpgradeStatusReservationMessage(reservation, nodeID, record) != nil {
			return upgradeStatusIdentityState{}, false, fmt.Errorf("upgrade status identity reservation source is invalid")
		}
	}
	return state, true, nil
}

func (b *NATSUpgradeCommandBus) loadUpgradeStatusIdentity(ctx context.Context, nodeID string,
	record UpgradeStatusRecord,
) (UpgradeStatusPublication, bool, error) {
	state, found, err := b.loadUpgradeStatusIdentityState(ctx, nodeID, record)
	if err != nil || !found || state.Publication.Sequence == 0 {
		return UpgradeStatusPublication{}, false, err
	}
	if _, err := b.loadUpgradeStatusPublicationAtSequence(ctx, nodeID, record, state.Publication.Sequence); err != nil {
		return UpgradeStatusPublication{}, false, fmt.Errorf("load identity source status: %w", err)
	}
	return state.Publication, true, nil
}

func (b *NATSUpgradeCommandBus) reserveUpgradeStatusIdentity(ctx context.Context,
	record UpgradeStatusRecord,
) (upgradeStatusIdentityState, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) {
		return upgradeStatusIdentityState{}, fmt.Errorf("upgrade status reservation publication is invalid")
	}
	message, err := upgradeStatusReservationMessage(record)
	if err != nil {
		return upgradeStatusIdentityState{}, err
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	ack, publishErr := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(UpgradeStatusStream),
		nats.ExpectLastSequencePerSubject(0))
	cancel()
	state, found, loadErr := b.loadUpgradeStatusIdentityState(ctx, record.NodeID, record)
	if loadErr != nil {
		if errors.Is(loadErr, errUpgradeStatusIdentityConflict) {
			return upgradeStatusIdentityState{}, loadErr
		}
		if publishErr != nil {
			return upgradeStatusIdentityState{}, fmt.Errorf("reserve upgrade status identity: %w", publishErr)
		}
		return upgradeStatusIdentityState{}, loadErr
	}
	if !found || (state.ReservationSequence == 0 && state.Publication.Sequence == 0) {
		if publishErr != nil {
			return upgradeStatusIdentityState{}, fmt.Errorf("reserve upgrade status identity: %w", publishErr)
		}
		return upgradeStatusIdentityState{}, fmt.Errorf("upgrade status reservation persistence returned inconsistent state")
	}
	if publishErr == nil {
		if err := b.validateUpgradeProofPublication(ctx, ack, message); err != nil {
			return upgradeStatusIdentityState{}, fmt.Errorf("upgrade status reservation returned an invalid PubAck: %w", err)
		}
	}
	return state, nil
}

func (b *NATSUpgradeCommandBus) publishUpgradeStatusIdentity(ctx context.Context, record UpgradeStatusRecord,
	reservationSequence uint64, publication UpgradeStatusPublication,
) error {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || reservationSequence == 0 {
		return fmt.Errorf("upgrade status identity publication is invalid")
	}
	message, err := upgradeStatusIdentityMessage(record, reservationSequence, publication)
	if err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	ack, publishErr := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(UpgradeStatusStream),
		nats.ExpectLastSequencePerSubject(reservationSequence))
	cancel()
	persisted, found, loadErr := b.loadUpgradeStatusIdentity(ctx, record.NodeID, record)
	if loadErr != nil {
		if errors.Is(loadErr, errUpgradeStatusIdentityConflict) {
			return loadErr
		}
		if publishErr != nil {
			return fmt.Errorf("publish upgrade status identity: %w", publishErr)
		}
		return loadErr
	}
	if !found || persisted != publication {
		if publishErr != nil {
			return fmt.Errorf("publish upgrade status identity: %w", publishErr)
		}
		return fmt.Errorf("upgrade status identity persistence returned inconsistent state")
	}
	if publishErr == nil {
		if err := b.validateUpgradeProofPublication(ctx, ack, message); err != nil {
			return fmt.Errorf("upgrade status identity returned an invalid PubAck: %w", err)
		}
	}
	return nil
}

func (b *NATSUpgradeCommandBus) publishLegacyUpgradeStatusIdentity(ctx context.Context, record UpgradeStatusRecord,
	publication UpgradeStatusPublication,
) error {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) {
		return fmt.Errorf("legacy upgrade status identity publication is invalid")
	}
	message, err := legacyUpgradeStatusIdentityMessage(record, publication)
	if err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	ack, publishErr := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(UpgradeStatusStream),
		nats.ExpectLastSequencePerSubject(0))
	cancel()
	persisted, found, loadErr := b.loadUpgradeStatusIdentity(ctx, record.NodeID, record)
	if loadErr != nil {
		if errors.Is(loadErr, errUpgradeStatusIdentityConflict) {
			return loadErr
		}
		if publishErr != nil {
			return fmt.Errorf("publish legacy upgrade status identity: %w", publishErr)
		}
		return loadErr
	}
	if !found || persisted != publication {
		if publishErr != nil {
			return fmt.Errorf("publish legacy upgrade status identity: %w", publishErr)
		}
		return fmt.Errorf("legacy upgrade status identity persistence returned inconsistent state")
	}
	if publishErr == nil {
		if err := b.validateUpgradeProofPublication(ctx, ack, message); err != nil {
			return fmt.Errorf("legacy upgrade status identity returned an invalid PubAck: %w", err)
		}
	}
	return nil
}

func (b *NATSUpgradeCommandBus) listUpgradeStatusAcks(ctx context.Context, nodeID string, limit int) ([]upgradeStatusAckRecord, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) {
		return nil, fmt.Errorf("upgrade status acknowledgement list is invalid")
	}
	records, _, err := b.loadUpgradeStatusAckLedger(ctx, nodeID, limit)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if _, err := b.ensureUpgradeCommandCompletion(ctx, record); err != nil {
			return nil, err
		}
	}
	return records, err
}

func (b *NATSUpgradeCommandBus) hasCompletedUpgradeCommand(ctx context.Context, command UpgradeCommandRecord,
	limit int,
) (bool, error) {
	decoded, err := decodeUpgradeCommandRecord(command.Encoded)
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || limit <= 0 || err != nil ||
		decoded.SHA256 != command.SHA256 || decoded.NodeID != command.NodeID ||
		decoded.InstallationID != command.InstallationID || decoded.CommandID != command.CommandID ||
		decoded.PlanID != command.PlanID || decoded.PlanRevision != command.PlanRevision || decoded.BatchID != command.BatchID {
		return false, fmt.Errorf("upgrade command completion lookup is invalid")
	}
	_, status, found, err := b.loadUpgradeCommandCompletion(ctx, command.NodeID, command.InstallationID, command.CommandID)
	if err != nil {
		return false, err
	}
	if found {
		if !upgradeStatusCompletesCommand(status, command) {
			return false, errUpgradeStatusAckConflict
		}
		return true, nil
	}
	records, _, err := b.loadUpgradeStatusAckLedger(ctx, command.NodeID, limit)
	if err != nil {
		return false, err
	}
	for _, record := range records {
		status, loadErr := b.loadUpgradeStatusForAck(ctx, record)
		if loadErr != nil {
			return false, loadErr
		}
		if status.State != "accepted" || status.CommandID != command.CommandID ||
			record.InstallationID != command.InstallationID {
			continue
		}
		if !upgradeStatusCompletesCommand(status, command) {
			return false, errUpgradeStatusAckConflict
		}
		completed, ensureErr := b.ensureUpgradeCommandCompletion(ctx, record)
		if ensureErr != nil {
			return false, ensureErr
		}
		if !completed {
			return false, errUpgradeStatusAckConflict
		}
		return true, nil
	}
	return false, nil
}

func (b *NATSUpgradeCommandBus) saveUpgradeStatusAck(ctx context.Context, candidate upgradeStatusAckRecord,
	limit int,
) (upgradeStatusAckRecord, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || limit <= 0 || validateUpgradeStatusAckRecord(candidate) != nil {
		return upgradeStatusAckRecord{}, fmt.Errorf("upgrade status acknowledgement persistence input is invalid")
	}
	records, sequence, err := b.loadUpgradeStatusAckLedger(ctx, candidate.NodeID, limit)
	if err != nil {
		return upgradeStatusAckRecord{}, err
	}
	for _, record := range records {
		if sameUpgradeStatusAckBinding(record, candidate) {
			if _, err := b.ensureUpgradeCommandCompletion(ctx, record); err != nil {
				return upgradeStatusAckRecord{}, err
			}
			return cloneUpgradeStatusAckRecord(record), nil
		}
		if record.Ack.GetStatusEventId() == candidate.Ack.GetStatusEventId() {
			return upgradeStatusAckRecord{}, errUpgradeStatusAckConflict
		}
	}
	if len(records) >= limit {
		return upgradeStatusAckRecord{}, errUpgradeStatusAckLimit
	}
	records = append(records, cloneUpgradeStatusAckRecord(candidate))
	persisted, err := b.publishUpgradeStatusAckLedger(ctx, candidate.NodeID, records, sequence, limit)
	if err != nil {
		return upgradeStatusAckRecord{}, err
	}
	for _, record := range persisted {
		if sameUpgradeStatusAckBinding(record, candidate) {
			if _, err := b.ensureUpgradeCommandCompletion(ctx, record); err != nil {
				return upgradeStatusAckRecord{}, err
			}
			return cloneUpgradeStatusAckRecord(record), nil
		}
	}
	return upgradeStatusAckRecord{}, fmt.Errorf("upgrade status acknowledgement persistence returned inconsistent state")
}

// saveUpgradeStatusAckHorizon retains a bounded replay horizon for agents that
// negotiated PubAck metadata but not acknowledgement receipts. Those agents do
// not confirm pending records, so the oldest completed identity is evicted when
// the horizon reaches its per-node limit. The immutable command-completion proof
// remains available for audit and redelivery checks.
func (b *NATSUpgradeCommandBus) saveUpgradeStatusAckHorizon(ctx context.Context, candidate upgradeStatusAckRecord,
	limit int,
) (upgradeStatusAckRecord, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || limit <= 0 || validateUpgradeStatusAckRecord(candidate) != nil {
		return upgradeStatusAckRecord{}, fmt.Errorf("upgrade status acknowledgement horizon input is invalid")
	}
	records, sequence, err := b.loadUpgradeStatusAckLedger(ctx, candidate.NodeID, limit)
	if err != nil {
		return upgradeStatusAckRecord{}, err
	}
	for _, record := range records {
		if sameUpgradeStatusAckBinding(record, candidate) {
			if _, err := b.ensureUpgradeCommandCompletion(ctx, record); err != nil {
				return upgradeStatusAckRecord{}, err
			}
			return cloneUpgradeStatusAckRecord(record), nil
		}
		if record.Ack.GetStatusEventId() == candidate.Ack.GetStatusEventId() {
			return upgradeStatusAckRecord{}, errUpgradeStatusAckConflict
		}
		if _, err := b.ensureUpgradeCommandCompletion(ctx, record); err != nil {
			return upgradeStatusAckRecord{}, err
		}
	}
	records = append(records, cloneUpgradeStatusAckRecord(candidate))
	sortUpgradeStatusAckRecords(records)
	if len(records) > limit {
		records = records[len(records)-limit:]
	}
	persisted, err := b.publishUpgradeStatusAckLedger(ctx, candidate.NodeID, records, sequence, limit)
	if err != nil {
		return upgradeStatusAckRecord{}, err
	}
	for _, record := range persisted {
		if sameUpgradeStatusAckBinding(record, candidate) {
			if _, err := b.ensureUpgradeCommandCompletion(ctx, record); err != nil {
				return upgradeStatusAckRecord{}, err
			}
			return cloneUpgradeStatusAckRecord(record), nil
		}
	}
	return upgradeStatusAckRecord{}, fmt.Errorf("upgrade status acknowledgement horizon returned inconsistent state")
}

func (b *NATSUpgradeCommandBus) confirmUpgradeStatusAck(ctx context.Context, nodeID string,
	receipt *agentv1.UpgradeStatusAckReceipt, limit int,
) (*agentv1.UpgradeStatusAckReceipt, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || !canonicalUpgradeUUID(nodeID) || limit <= 0 ||
		validateUpgradeStatusAckReceiptShape(receipt) != nil {
		return nil, fmt.Errorf("upgrade status acknowledgement confirmation input is invalid")
	}
	var digest [sha256.Size]byte
	copy(digest[:], receipt.GetAckSha256())
	confirmedRecord, confirmedReceipt, found, err := b.loadUpgradeStatusAckConfirmation(ctx, nodeID, digest)
	if err != nil {
		return nil, err
	}
	if found {
		if validateUpgradeStatusAckReceipt(confirmedRecord, receipt) != nil || !proto.Equal(confirmedReceipt, receipt) {
			return nil, errUpgradeStatusAckConflict
		}
	} else {
		records, _, loadErr := b.loadUpgradeStatusAckLedger(ctx, nodeID, limit)
		if loadErr != nil {
			return nil, loadErr
		}
		for _, record := range records {
			recordDigest, digestErr := upgradeStatusAckSHA256(record.Ack)
			if digestErr != nil {
				return nil, errUpgradeStatusAckConflict
			}
			if recordDigest != digest {
				continue
			}
			if validateUpgradeStatusAckReceipt(record, receipt) != nil {
				return nil, errUpgradeStatusAckConflict
			}
			confirmedRecord = cloneUpgradeStatusAckRecord(record)
			break
		}
		if confirmedRecord.Ack == nil {
			return nil, errUpgradeStatusAckNotFound
		}
		confirmedRecord, confirmedReceipt, err = b.publishUpgradeStatusAckConfirmation(ctx, confirmedRecord, receipt, digest)
		if err != nil {
			return nil, err
		}
	}
	if _, err := b.ensureUpgradeCommandCompletion(ctx, confirmedRecord); err != nil {
		return nil, err
	}

	records, sequence, err := b.loadUpgradeStatusAckLedger(ctx, nodeID, limit)
	if err != nil {
		return nil, err
	}
	remaining := make([]upgradeStatusAckRecord, 0, len(records))
	removed := false
	for _, record := range records {
		recordDigest, digestErr := upgradeStatusAckSHA256(record.Ack)
		if digestErr != nil {
			return nil, errUpgradeStatusAckConflict
		}
		if recordDigest == digest {
			if !sameUpgradeStatusAckRecord(record, confirmedRecord) {
				return nil, errUpgradeStatusAckConflict
			}
			removed = true
			continue
		}
		remaining = append(remaining, record)
	}
	if removed {
		if _, err := b.publishUpgradeStatusAckLedger(ctx, nodeID, remaining, sequence, limit); err != nil {
			return nil, err
		}
	}
	return proto.Clone(confirmedReceipt).(*agentv1.UpgradeStatusAckReceipt), nil
}

func (b *NATSUpgradeCommandBus) loadUpgradeStatusAckLedger(ctx context.Context, nodeID string,
	limit int,
) ([]upgradeStatusAckRecord, uint64, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || !canonicalUpgradeUUID(nodeID) || limit <= 0 {
		return nil, 0, fmt.Errorf("upgrade status acknowledgement ledger lookup is invalid")
	}
	subject := upgradeStatusAckLedgerSubject(nodeID)
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	message, err := b.js.GetLastMsg(UpgradeStatusStream, subject, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("load upgrade status acknowledgement ledger: %w", err)
	}
	records, err := decodeUpgradeStatusAckLedgerMessage(message, nodeID, limit)
	if err != nil {
		return nil, 0, err
	}
	return records, message.Sequence, nil
}

func decodeUpgradeStatusAckLedgerMessage(message *nats.RawStreamMsg, nodeID string,
	limit int,
) ([]upgradeStatusAckRecord, error) {
	if message == nil || message.Subject != upgradeStatusAckLedgerSubject(nodeID) || message.Sequence == 0 {
		return nil, fmt.Errorf("upgrade status acknowledgement ledger identity is invalid")
	}
	var wire upgradeStatusAckLedgerWire
	if decodeCanonicalUpgradeJSON(message.Data, &wire) != nil || wire.Schema != upgradeStatusAckLedgerSchema ||
		wire.NodeID != nodeID || wire.PreviousSequence >= message.Sequence || len(wire.Pending) > limit {
		return nil, fmt.Errorf("upgrade status acknowledgement ledger payload is invalid")
	}
	payloadDigest := sha256.Sum256(message.Data)
	if !exactUpgradeHeaders(message.Header, map[string]string{
		nats.MsgIdHdr:               upgradeStatusAckLedgerMessageIDPrefix + hex.EncodeToString(payloadDigest[:]),
		nats.ExpectedStreamHdr:      UpgradeStatusStream,
		nats.ExpectedLastSubjSeqHdr: strconv.FormatUint(wire.PreviousSequence, 10),
		UpgradePayloadSHA256Header:  hex.EncodeToString(payloadDigest[:]), UpgradeMessageKeyHeader: nodeID,
	}) {
		return nil, fmt.Errorf("upgrade status acknowledgement ledger headers are invalid")
	}
	records := make([]upgradeStatusAckRecord, 0, len(wire.Pending))
	seenEvents := make(map[string]struct{}, len(wire.Pending))
	var previousStatusSequence uint64
	for _, entry := range wire.Pending {
		record, err := decodeUpgradeStatusAckRecordWire(nodeID, entry)
		if err != nil || record.Ack.GetPublishedSequence() <= previousStatusSequence {
			return nil, fmt.Errorf("upgrade status acknowledgement ledger entry is invalid")
		}
		if _, exists := seenEvents[record.Ack.GetStatusEventId()]; exists {
			return nil, fmt.Errorf("upgrade status acknowledgement ledger entry is duplicated")
		}
		seenEvents[record.Ack.GetStatusEventId()] = struct{}{}
		previousStatusSequence = record.Ack.GetPublishedSequence()
		records = append(records, record)
	}
	return records, nil
}

func decodeUpgradeStatusAckRecordWire(nodeID string, wire upgradeStatusAckRecordWire) (upgradeStatusAckRecord, error) {
	ack := &agentv1.UpgradeStatusAck{}
	if len(wire.Ack) == 0 || proto.Unmarshal(wire.Ack, ack) != nil || cacheControlMessageHasUnknown(ack.ProtoReflect()) {
		return upgradeStatusAckRecord{}, fmt.Errorf("upgrade status acknowledgement wire is invalid")
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(ack)
	digest, digestErr := upgradeStatusAckSHA256(ack)
	record := upgradeStatusAckRecord{NodeID: nodeID, InstallationID: wire.InstallationID, Ack: ack}
	if err != nil || digestErr != nil || !bytes.Equal(canonical, wire.Ack) ||
		wire.AckSHA256 != hex.EncodeToString(digest[:]) || validateUpgradeStatusAckRecord(record) != nil {
		return upgradeStatusAckRecord{}, fmt.Errorf("upgrade status acknowledgement wire is invalid")
	}
	return record, nil
}

func encodeUpgradeStatusAckRecordWire(record upgradeStatusAckRecord) (upgradeStatusAckRecordWire, error) {
	if validateUpgradeStatusAckRecord(record) != nil {
		return upgradeStatusAckRecordWire{}, fmt.Errorf("upgrade status acknowledgement record is invalid")
	}
	ack, err := proto.MarshalOptions{Deterministic: true}.Marshal(record.Ack)
	if err != nil {
		return upgradeStatusAckRecordWire{}, fmt.Errorf("encode upgrade status acknowledgement: %w", err)
	}
	digest, err := upgradeStatusAckSHA256(record.Ack)
	if err != nil {
		return upgradeStatusAckRecordWire{}, fmt.Errorf("digest upgrade status acknowledgement: %w", err)
	}
	return upgradeStatusAckRecordWire{InstallationID: record.InstallationID, Ack: ack,
		AckSHA256: hex.EncodeToString(digest[:])}, nil
}

func (b *NATSUpgradeCommandBus) loadUpgradeStatusForAck(ctx context.Context,
	record upgradeStatusAckRecord,
) (UpgradeStatusRecord, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || validateUpgradeStatusAckRecord(record) != nil {
		return UpgradeStatusRecord{}, fmt.Errorf("upgrade status acknowledgement lookup is invalid")
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	message, err := b.js.GetMsg(UpgradeStatusStream, record.Ack.GetPublishedSequence(), nats.Context(operationCtx))
	cancel()
	if err != nil {
		return UpgradeStatusRecord{}, fmt.Errorf("load acknowledged upgrade status: %w", err)
	}
	legacySubject := UpgradeStatusSubjectPrefix + "." + record.NodeID
	v2Subject := upgradeStatusV2Subject(record.Ack.GetStatusEventId())
	if message == nil || message.Sequence != record.Ack.GetPublishedSequence() ||
		(message.Subject != legacySubject && message.Subject != v2Subject) {
		return UpgradeStatusRecord{}, fmt.Errorf("acknowledged upgrade status identity is invalid")
	}
	status, err := decodeUpgradeStatusRecord(message.Data)
	if err != nil || status.NodeID != record.NodeID || status.InstallationID != record.InstallationID ||
		status.StatusID != record.Ack.GetStatusEventId() || status.CommandID != record.Ack.GetCommandId() ||
		status.StatusRevision != record.Ack.GetStatusRevision() || !bytes.Equal(status.SHA256[:], record.Ack.GetStatusSha256()) {
		return UpgradeStatusRecord{}, fmt.Errorf("acknowledged upgrade status wire is invalid")
	}
	expectedHeaders := map[string]string{
		nats.MsgIdHdr: status.StatusID, nats.ExpectedStreamHdr: UpgradeStatusStream,
		UpgradePayloadSHA256Header: hex.EncodeToString(status.SHA256[:]), UpgradeMessageKeyHeader: status.StatusID,
	}
	if message.Subject == v2Subject {
		expectedHeaders[nats.MsgIdHdr] = upgradeStatusV2MessageIDPrefix + status.StatusID
		expectedHeaders[nats.ExpectedLastSubjSeqHdr] = "0"
	}
	if !exactUpgradeHeaders(message.Header, expectedHeaders) {
		return UpgradeStatusRecord{}, fmt.Errorf("acknowledged upgrade status wire is invalid")
	}
	return status, nil
}

func upgradeStatusCompletesCommand(status UpgradeStatusRecord, command UpgradeCommandRecord) bool {
	return status.State == "accepted" && status.NodeID == command.NodeID &&
		status.InstallationID == command.InstallationID && status.CommandID == command.CommandID &&
		status.PlanID == command.PlanID && status.PlanRevision == command.PlanRevision &&
		commandStatusDigest(status.Encoded) == hex.EncodeToString(command.SHA256[:])
}

func (b *NATSUpgradeCommandBus) ensureUpgradeCommandCompletion(ctx context.Context,
	record upgradeStatusAckRecord,
) (bool, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) {
		return false, fmt.Errorf("upgrade command completion input is invalid")
	}
	status, err := b.loadUpgradeStatusForAck(ctx, record)
	if err != nil {
		return false, err
	}
	if status.State != "accepted" {
		return false, nil
	}
	persistedRecord, persistedStatus, found, err := b.loadUpgradeCommandCompletion(
		ctx, record.NodeID, record.InstallationID, record.Ack.GetCommandId(),
	)
	if err != nil {
		return false, err
	}
	if found {
		if !sameUpgradeStatusAckRecord(persistedRecord, record) || persistedStatus.SHA256 != status.SHA256 ||
			!bytes.Equal(persistedStatus.Encoded, status.Encoded) {
			return false, errUpgradeStatusAckConflict
		}
		return true, nil
	}
	recordWire, err := encodeUpgradeStatusAckRecordWire(record)
	if err != nil {
		return false, err
	}
	wire := upgradeCommandCompletionWire{
		Schema: upgradeCommandCompletionSchema, NodeID: record.NodeID,
		CommandSHA256: commandStatusDigest(status.Encoded), Status: append([]byte(nil), status.Encoded...), Record: recordWire,
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maxUpgradeWireBytes {
		return false, fmt.Errorf("upgrade command completion proof exceeds its size limit")
	}
	payloadDigest := sha256.Sum256(encoded)
	subject := upgradeCommandCompletionSubject(record.NodeID, record.InstallationID, record.Ack.GetCommandId())
	message := nats.NewMsg(subject)
	message.Data = encoded
	message.Header.Set(nats.MsgIdHdr, upgradeCommandCompletionIDPrefix+hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	message.Header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	message.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(UpgradeMessageKeyHeader, record.Ack.GetCommandId())
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	ack, publishErr := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(UpgradeStatusStream),
		nats.ExpectLastSequencePerSubject(0))
	cancel()
	persistedRecord, persistedStatus, found, loadErr := b.loadUpgradeCommandCompletion(
		ctx, record.NodeID, record.InstallationID, record.Ack.GetCommandId(),
	)
	if loadErr != nil || !found || !sameUpgradeStatusAckRecord(persistedRecord, record) ||
		persistedStatus.SHA256 != status.SHA256 || !bytes.Equal(persistedStatus.Encoded, status.Encoded) {
		if publishErr != nil {
			return false, fmt.Errorf("publish upgrade command completion proof: %w", publishErr)
		}
		return false, fmt.Errorf("upgrade command completion proof persistence returned inconsistent state")
	}
	if publishErr == nil {
		if err := b.validateUpgradeProofPublication(ctx, ack, message); err != nil {
			return false, fmt.Errorf("upgrade command completion proof returned an invalid PubAck: %w", err)
		}
	}
	return true, nil
}

func (b *NATSUpgradeCommandBus) loadUpgradeCommandCompletion(ctx context.Context, nodeID, installationID,
	commandID string,
) (upgradeStatusAckRecord, UpgradeStatusRecord, bool, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || !canonicalUpgradeUUID(nodeID) ||
		!canonicalUpgradeUUID(installationID) || !canonicalUpgradeUUID(commandID) {
		return upgradeStatusAckRecord{}, UpgradeStatusRecord{}, false,
			fmt.Errorf("upgrade command completion proof lookup is invalid")
	}
	subject := upgradeCommandCompletionSubject(nodeID, installationID, commandID)
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	message, err := b.js.GetLastMsg(UpgradeStatusStream, subject, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return upgradeStatusAckRecord{}, UpgradeStatusRecord{}, false, nil
	}
	if err != nil {
		return upgradeStatusAckRecord{}, UpgradeStatusRecord{}, false,
			fmt.Errorf("load upgrade command completion proof: %w", err)
	}
	if message == nil || message.Subject != subject || message.Sequence == 0 {
		return upgradeStatusAckRecord{}, UpgradeStatusRecord{}, false,
			fmt.Errorf("upgrade command completion proof identity is invalid")
	}
	var wire upgradeCommandCompletionWire
	if decodeCanonicalUpgradeJSON(message.Data, &wire) != nil || wire.Schema != upgradeCommandCompletionSchema ||
		wire.NodeID != nodeID || len(wire.CommandSHA256) != sha256.Size*2 {
		return upgradeStatusAckRecord{}, UpgradeStatusRecord{}, false,
			fmt.Errorf("upgrade command completion proof payload is invalid")
	}
	payloadDigest := sha256.Sum256(message.Data)
	if !exactUpgradeHeaders(message.Header, map[string]string{
		nats.MsgIdHdr:          upgradeCommandCompletionIDPrefix + hex.EncodeToString(payloadDigest[:]),
		nats.ExpectedStreamHdr: UpgradeStatusStream, nats.ExpectedLastSubjSeqHdr: "0",
		UpgradePayloadSHA256Header: hex.EncodeToString(payloadDigest[:]), UpgradeMessageKeyHeader: commandID,
	}) {
		return upgradeStatusAckRecord{}, UpgradeStatusRecord{}, false,
			fmt.Errorf("upgrade command completion proof headers are invalid")
	}
	record, err := decodeUpgradeStatusAckRecordWire(nodeID, wire.Record)
	status, statusErr := decodeUpgradeStatusRecord(wire.Status)
	if err != nil || statusErr != nil || record.InstallationID != installationID ||
		record.Ack.GetCommandId() != commandID || status.NodeID != nodeID || status.InstallationID != installationID ||
		status.CommandID != commandID || status.State != "accepted" || wire.CommandSHA256 != commandStatusDigest(status.Encoded) ||
		status.StatusID != record.Ack.GetStatusEventId() || status.StatusRevision != record.Ack.GetStatusRevision() ||
		!bytes.Equal(status.SHA256[:], record.Ack.GetStatusSha256()) {
		return upgradeStatusAckRecord{}, UpgradeStatusRecord{}, false,
			fmt.Errorf("upgrade command completion proof binding is invalid")
	}
	persistedStatus, err := b.loadUpgradeStatusForAck(ctx, record)
	if err != nil || persistedStatus.SHA256 != status.SHA256 || !bytes.Equal(persistedStatus.Encoded, status.Encoded) {
		return upgradeStatusAckRecord{}, UpgradeStatusRecord{}, false,
			fmt.Errorf("upgrade command completion proof source status is invalid")
	}
	return record, status, true, nil
}

func (b *NATSUpgradeCommandBus) publishUpgradeStatusAckLedger(ctx context.Context, nodeID string,
	records []upgradeStatusAckRecord, previousSequence uint64, limit int,
) ([]upgradeStatusAckRecord, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || !canonicalUpgradeUUID(nodeID) || limit <= 0 {
		return nil, fmt.Errorf("upgrade status acknowledgement ledger publication is invalid")
	}
	if len(records) > limit {
		return nil, errUpgradeStatusAckLimit
	}
	stable := make([]upgradeStatusAckRecord, len(records))
	for index, record := range records {
		if validateUpgradeStatusAckRecord(record) != nil || record.NodeID != nodeID {
			return nil, fmt.Errorf("upgrade status acknowledgement ledger candidate is invalid")
		}
		stable[index] = cloneUpgradeStatusAckRecord(record)
	}
	sortUpgradeStatusAckRecords(stable)
	wire := upgradeStatusAckLedgerWire{Schema: upgradeStatusAckLedgerSchema, NodeID: nodeID,
		PreviousSequence: previousSequence, Pending: make([]upgradeStatusAckRecordWire, 0, len(stable))}
	for _, record := range stable {
		ackWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(record.Ack)
		if err != nil {
			return nil, fmt.Errorf("encode upgrade status acknowledgement ledger: %w", err)
		}
		digest, digestErr := upgradeStatusAckSHA256(record.Ack)
		if digestErr != nil {
			return nil, fmt.Errorf("digest upgrade status acknowledgement ledger: %w", digestErr)
		}
		wire.Pending = append(wire.Pending, upgradeStatusAckRecordWire{InstallationID: record.InstallationID,
			Ack: ackWire, AckSHA256: hex.EncodeToString(digest[:])})
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maxUpgradeWireBytes {
		return nil, fmt.Errorf("upgrade status acknowledgement ledger exceeds its size limit")
	}
	payloadDigest := sha256.Sum256(encoded)
	subject := upgradeStatusAckLedgerSubject(nodeID)
	message := nats.NewMsg(subject)
	message.Data = encoded
	message.Header.Set(nats.MsgIdHdr, upgradeStatusAckLedgerMessageIDPrefix+hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	message.Header.Set(nats.ExpectedLastSubjSeqHdr, strconv.FormatUint(previousSequence, 10))
	message.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(UpgradeMessageKeyHeader, nodeID)
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	ack, publishErr := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(UpgradeStatusStream),
		nats.ExpectLastSequencePerSubject(previousSequence))
	cancel()
	persisted, sequence, loadErr := b.loadUpgradeStatusAckLedger(ctx, nodeID, limit)
	if loadErr != nil || !sameUpgradeStatusAckRecords(persisted, stable) || sequence <= previousSequence {
		if publishErr != nil {
			return nil, fmt.Errorf("publish upgrade status acknowledgement ledger: %w", publishErr)
		}
		return nil, fmt.Errorf("upgrade status acknowledgement ledger persistence returned inconsistent state")
	}
	if publishErr == nil && (ack == nil || ack.Stream != UpgradeStatusStream || ack.Sequence != sequence) {
		return nil, fmt.Errorf("upgrade status acknowledgement ledger returned an invalid PubAck")
	}
	return persisted, nil
}

func sameUpgradeStatusAckRecords(left, right []upgradeStatusAckRecord) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !sameUpgradeStatusAckRecord(left[index], right[index]) {
			return false
		}
	}
	return true
}

func (b *NATSUpgradeCommandBus) loadUpgradeStatusAckConfirmation(ctx context.Context, nodeID string,
	digest [sha256.Size]byte,
) (upgradeStatusAckRecord, *agentv1.UpgradeStatusAckReceipt, bool, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || !canonicalUpgradeUUID(nodeID) {
		return upgradeStatusAckRecord{}, nil, false,
			fmt.Errorf("upgrade status acknowledgement confirmation lookup is invalid")
	}
	subject := upgradeStatusAckConfirmationSubject(nodeID, digest)
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	message, err := b.js.GetLastMsg(UpgradeStatusStream, subject, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return upgradeStatusAckRecord{}, nil, false, nil
	}
	if err != nil {
		return upgradeStatusAckRecord{}, nil, false, fmt.Errorf("load upgrade status acknowledgement confirmation: %w", err)
	}
	if message == nil || message.Subject != subject || message.Sequence == 0 {
		return upgradeStatusAckRecord{}, nil, false, fmt.Errorf("upgrade status acknowledgement confirmation identity is invalid")
	}
	var wire upgradeStatusAckConfirmationWire
	if decodeCanonicalUpgradeJSON(message.Data, &wire) != nil || wire.Schema != upgradeStatusAckConfirmationSchema ||
		wire.NodeID != nodeID || wire.AckSHA256 != hex.EncodeToString(digest[:]) {
		return upgradeStatusAckRecord{}, nil, false, fmt.Errorf("upgrade status acknowledgement confirmation payload is invalid")
	}
	payloadDigest := sha256.Sum256(message.Data)
	if !exactUpgradeHeaders(message.Header, map[string]string{
		nats.MsgIdHdr:          upgradeStatusAckProofMessageIDPrefix + hex.EncodeToString(payloadDigest[:]),
		nats.ExpectedStreamHdr: UpgradeStatusStream, nats.ExpectedLastSubjSeqHdr: "0",
		UpgradePayloadSHA256Header: hex.EncodeToString(payloadDigest[:]), UpgradeMessageKeyHeader: hex.EncodeToString(digest[:]),
	}) {
		return upgradeStatusAckRecord{}, nil, false, fmt.Errorf("upgrade status acknowledgement confirmation headers are invalid")
	}
	record, err := decodeUpgradeStatusAckRecordWire(nodeID, upgradeStatusAckRecordWire{
		InstallationID: wire.InstallationID, Ack: wire.Ack, AckSHA256: wire.AckSHA256,
	})
	if err != nil {
		return upgradeStatusAckRecord{}, nil, false, err
	}
	receipt := &agentv1.UpgradeStatusAckReceipt{}
	if len(wire.Receipt) == 0 || proto.Unmarshal(wire.Receipt, receipt) != nil ||
		cacheControlMessageHasUnknown(receipt.ProtoReflect()) || validateUpgradeStatusAckReceipt(record, receipt) != nil ||
		!bytes.Equal(receipt.GetAckSha256(), digest[:]) {
		return upgradeStatusAckRecord{}, nil, false, fmt.Errorf("upgrade status acknowledgement confirmation receipt is invalid")
	}
	canonicalReceipt, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil || !bytes.Equal(canonicalReceipt, wire.Receipt) {
		return upgradeStatusAckRecord{}, nil, false, fmt.Errorf("upgrade status acknowledgement confirmation receipt is noncanonical")
	}
	return record, receipt, true, nil
}

func (b *NATSUpgradeCommandBus) publishUpgradeStatusAckConfirmation(ctx context.Context,
	record upgradeStatusAckRecord, receipt *agentv1.UpgradeStatusAckReceipt, digest [sha256.Size]byte,
) (upgradeStatusAckRecord, *agentv1.UpgradeStatusAckReceipt, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) {
		return upgradeStatusAckRecord{}, nil,
			fmt.Errorf("upgrade status acknowledgement confirmation publication is invalid")
	}
	ackWire, ackErr := proto.MarshalOptions{Deterministic: true}.Marshal(record.Ack)
	receiptWire, receiptErr := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if ackErr != nil || receiptErr != nil || validateUpgradeStatusAckReceipt(record, receipt) != nil {
		return upgradeStatusAckRecord{}, nil, fmt.Errorf("upgrade status acknowledgement confirmation candidate is invalid")
	}
	wire := upgradeStatusAckConfirmationWire{Schema: upgradeStatusAckConfirmationSchema, NodeID: record.NodeID,
		InstallationID: record.InstallationID, Ack: ackWire, AckSHA256: hex.EncodeToString(digest[:]), Receipt: receiptWire}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maxUpgradeWireBytes {
		return upgradeStatusAckRecord{}, nil, fmt.Errorf("upgrade status acknowledgement confirmation exceeds its size limit")
	}
	payloadDigest := sha256.Sum256(encoded)
	subject := upgradeStatusAckConfirmationSubject(record.NodeID, digest)
	message := nats.NewMsg(subject)
	message.Data = encoded
	message.Header.Set(nats.MsgIdHdr, upgradeStatusAckProofMessageIDPrefix+hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	message.Header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	message.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(UpgradeMessageKeyHeader, hex.EncodeToString(digest[:]))
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	ack, publishErr := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(UpgradeStatusStream),
		nats.ExpectLastSequencePerSubject(0))
	cancel()
	persistedRecord, persistedReceipt, found, loadErr := b.loadUpgradeStatusAckConfirmation(ctx, record.NodeID, digest)
	if loadErr != nil || !found || !sameUpgradeStatusAckRecord(persistedRecord, record) || !proto.Equal(persistedReceipt, receipt) {
		if publishErr != nil {
			return upgradeStatusAckRecord{}, nil, fmt.Errorf("publish upgrade status acknowledgement confirmation: %w", publishErr)
		}
		return upgradeStatusAckRecord{}, nil, fmt.Errorf("upgrade status acknowledgement confirmation persistence returned inconsistent state")
	}
	if publishErr == nil {
		if err := b.validateUpgradeProofPublication(ctx, ack, message); err != nil {
			return upgradeStatusAckRecord{}, nil,
				fmt.Errorf("upgrade status acknowledgement confirmation returned an invalid PubAck: %w", err)
		}
	}
	return persistedRecord, persistedReceipt, nil
}

func (b *NATSUpgradeCommandBus) validateUpgradeProofPublication(ctx context.Context, ack *nats.PubAck,
	expected *nats.Msg,
) error {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || ack == nil || ack.Stream != UpgradeStatusStream ||
		ack.Sequence == 0 || expected == nil {
		return fmt.Errorf("proof publication acknowledgement is invalid")
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	message, err := b.js.GetMsg(UpgradeStatusStream, ack.Sequence, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return fmt.Errorf("load acknowledged proof publication: %w", err)
	}
	expectedHeaders := make(map[string]string, len(expected.Header))
	for name, values := range expected.Header {
		if len(values) != 1 {
			return fmt.Errorf("proof publication headers are invalid")
		}
		expectedHeaders[name] = values[0]
	}
	if message == nil || message.Sequence != ack.Sequence || message.Subject != expected.Subject ||
		!bytes.Equal(message.Data, expected.Data) || !exactUpgradeHeaders(message.Header, expectedHeaders) {
		return fmt.Errorf("acknowledged proof publication wire is invalid")
	}
	return nil
}

var _ upgradeStatusAckStore = (*NATSUpgradeCommandBus)(nil)
