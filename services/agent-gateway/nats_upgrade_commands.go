package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

type NATSUpgradeCommandBus struct {
	js               nats.JetStreamContext
	ackWait          time.Duration
	maxWaiting       int
	maxAckPending    int
	operationTimeout time.Duration
}

const (
	maxUpgradeStatusScanSequences = 4096
	maxUpgradeStatusScanBytes     = 8 << 20
	maxUpgradeStatusScanDuration  = 2 * time.Second
)

func NewNATSUpgradeCommandBus(connection *nats.Conn, config NATSCommandBusConfig) (*NATSUpgradeCommandBus, error) {
	if connection == nil || connection.IsClosed() {
		return nil, fmt.Errorf("an active NATS connection is required")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create upgrade JetStream context: %w", err)
	}
	return &NATSUpgradeCommandBus{js: js, ackWait: config.AckWait, maxWaiting: config.MaxWaiting,
		maxAckPending: config.MaxAckPending, operationTimeout: config.OperationTimeout}, nil
}

func upgradeConsumerConfig(nodeID string, ackWait time.Duration, maxWaiting, maxAckPending int, operationTimeout time.Duration) *nats.ConsumerConfig {
	durable := "node_upgrade_" + strings.ReplaceAll(nodeID, "-", "_")
	return &nats.ConsumerConfig{
		Name: durable, Durable: durable, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: ackWait, MaxDeliver: -1,
		FilterSubject: UpgradeCommandSubjectPrefix + "." + nodeID, ReplayPolicy: nats.ReplayInstantPolicy,
		MaxWaiting: maxWaiting, MaxAckPending: maxAckPending, MaxRequestBatch: 1,
		MaxRequestExpires: operationTimeout, MaxRequestMaxBytes: maxUpgradeWireBytes,
	}
}

func (b *NATSUpgradeCommandBus) SubscribeUpgrade(ctx context.Context, nodeID string) (UpgradeCommandSubscription, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || !canonicalUpgradeUUID(nodeID) {
		return nil, fmt.Errorf("node ID must be a canonical UUID")
	}
	expected := upgradeConsumerConfig(nodeID, b.ackWait, b.maxWaiting, b.maxAckPending, b.operationTimeout)
	// The Gateway owns per-node durables (like the generic command consumer):
	// create the exact expected one on first use. JetStream treats an
	// identical create as idempotent and refuses to change an existing
	// durable, so a drifted consumer is never repaired here and still fails
	// the exact verification below.
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	_, _ = b.js.AddConsumer(UpgradeCommandStream, expected, nats.Context(operationCtx))
	cancel()
	operationCtx, cancel = context.WithTimeout(ctx, b.operationTimeout)
	info, infoErr := b.js.ConsumerInfo(UpgradeCommandStream, expected.Durable, nats.Context(operationCtx))
	cancel()
	if infoErr != nil || !sameUpgradeConsumerConfig(info, expected) {
		if infoErr != nil {
			return nil, fmt.Errorf("verify durable node upgrade consumer: %w", infoErr)
		}
		return nil, fmt.Errorf("durable node upgrade consumer configuration does not match")
	}
	subscription, err := b.js.PullSubscribe(expected.FilterSubject, expected.Durable, nats.Bind(UpgradeCommandStream, expected.Durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to durable node upgrade commands: %w", err)
	}
	operationCtx, cancel = context.WithTimeout(ctx, b.operationTimeout)
	info, infoErr = b.js.ConsumerInfo(UpgradeCommandStream, expected.Durable, nats.Context(operationCtx))
	cancel()
	if infoErr != nil || !sameUpgradeConsumerConfig(info, expected) {
		_ = subscription.Unsubscribe()
		return nil, fmt.Errorf("post-bind durable node upgrade consumer configuration does not match")
	}
	return &natsUpgradeCommandSubscription{subscription: subscription, nodeID: nodeID, fetchTimeout: b.operationTimeout}, nil
}

func (b *NATSUpgradeCommandBus) PublishUpgradeStatus(ctx context.Context, nodeID string, encoded []byte) (UpgradeStatusPublication, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || !canonicalUpgradeUUID(nodeID) {
		return UpgradeStatusPublication{}, fmt.Errorf("node ID must be a canonical UUID")
	}
	record, err := decodeUpgradeStatusRecord(encoded)
	if err != nil || record.NodeID != nodeID {
		return UpgradeStatusPublication{}, fmt.Errorf("upgrade status is invalid")
	}
	if publication, found, loadErr := b.loadUpgradeStatusV2Publication(ctx, record); loadErr != nil {
		return UpgradeStatusPublication{}, loadErr
	} else if found {
		return publication, nil
	}
	migrated, migrationErr := b.ensureUpgradeStatusLegacyMigration(ctx)
	if migrationErr != nil {
		return UpgradeStatusPublication{}, migrationErr
	}
	if !migrated {
		return UpgradeStatusPublication{}, errUpgradeStatusMigrationInProgress
	}
	if publication, found, loadErr := b.loadUpgradeStatusV2Publication(ctx, record); loadErr != nil {
		return UpgradeStatusPublication{}, loadErr
	} else if found {
		return publication, nil
	}
	identity, identityFound, identityErr := b.loadUpgradeStatusIdentityState(ctx, nodeID, record)
	if identityErr != nil {
		return UpgradeStatusPublication{}, identityErr
	}
	if !identityFound {
		identity, err = b.reserveUpgradeStatusIdentity(ctx, record)
		if err != nil {
			return UpgradeStatusPublication{}, err
		}
	}
	message := nats.NewMsg(upgradeStatusV2Subject(record.StatusID))
	message.Data = append([]byte(nil), encoded...)
	message.Header.Set(nats.MsgIdHdr, upgradeStatusV2MessageIDPrefix+record.StatusID)
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	message.Header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	message.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(record.SHA256[:]))
	message.Header.Set(UpgradeMessageKeyHeader, record.StatusID)
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	ack, publishErr := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(UpgradeStatusStream),
		nats.ExpectLastSequencePerSubject(0))
	cancel()
	publication, found, loadErr := b.loadUpgradeStatusV2Publication(ctx, record)
	if loadErr != nil {
		return UpgradeStatusPublication{}, loadErr
	}
	if !found {
		if publishErr != nil {
			return UpgradeStatusPublication{}, fmt.Errorf("publish upgrade status: %w", publishErr)
		}
		return UpgradeStatusPublication{}, fmt.Errorf("upgrade status publication returned inconsistent state")
	}
	if publishErr == nil && (ack == nil || ack.Stream != publication.Stream || ack.Sequence != publication.Sequence) {
		return UpgradeStatusPublication{}, fmt.Errorf("publish upgrade status returned an invalid acknowledgement")
	}
	if identity.Publication.Sequence == 0 {
		if err := b.publishUpgradeStatusIdentity(ctx, record, identity.ReservationSequence, publication); err != nil {
			return UpgradeStatusPublication{}, err
		}
	}
	return publication, nil
}

func (b *NATSUpgradeCommandBus) loadUpgradeStatusV2Publication(ctx context.Context,
	record UpgradeStatusRecord,
) (UpgradeStatusPublication, bool, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || !canonicalUpgradeUUID(record.StatusID) {
		return UpgradeStatusPublication{}, false, fmt.Errorf("upgrade status v2 lookup is invalid")
	}
	subject := upgradeStatusV2Subject(record.StatusID)
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	message, err := b.js.GetLastMsg(UpgradeStatusStream, subject, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return UpgradeStatusPublication{}, false, nil
	}
	if err != nil {
		return UpgradeStatusPublication{}, false, fmt.Errorf("load upgrade status v2: %w", err)
	}
	if message == nil || message.Subject != subject || message.Sequence == 0 {
		return UpgradeStatusPublication{}, false, fmt.Errorf("upgrade status v2 identity is invalid")
	}
	stored, err := decodeUpgradeStatusRecord(message.Data)
	if err != nil || stored.NodeID != record.NodeID || stored.StatusID != record.StatusID ||
		stored.CommandID != record.CommandID || stored.StatusRevision != record.StatusRevision ||
		stored.InstallationID != record.InstallationID || stored.PlanID != record.PlanID ||
		stored.PlanRevision != record.PlanRevision || stored.SHA256 != record.SHA256 ||
		!bytes.Equal(stored.Encoded, record.Encoded) {
		return UpgradeStatusPublication{}, false, fmt.Errorf("%w: requested status differs", errUpgradeStatusIdentityConflict)
	}
	if !exactUpgradeHeaders(message.Header, map[string]string{
		nats.MsgIdHdr: upgradeStatusV2MessageIDPrefix + record.StatusID, nats.ExpectedStreamHdr: UpgradeStatusStream,
		nats.ExpectedLastSubjSeqHdr: "0", UpgradePayloadSHA256Header: hex.EncodeToString(record.SHA256[:]),
		UpgradeMessageKeyHeader: record.StatusID,
	}) {
		return UpgradeStatusPublication{}, false, fmt.Errorf("upgrade status v2 headers are invalid")
	}
	return UpgradeStatusPublication{Stream: UpgradeStatusStream, Sequence: message.Sequence}, true, nil
}

func (b *NATSUpgradeCommandBus) loadLatestUpgradeStatusPublication(ctx context.Context, nodeID string,
	record UpgradeStatusRecord,
) (UpgradeStatusPublication, bool, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || !canonicalUpgradeUUID(nodeID) || record.NodeID != nodeID {
		return UpgradeStatusPublication{}, false, fmt.Errorf("latest upgrade status lookup is invalid")
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	message, err := b.js.GetLastMsg(UpgradeStatusStream, UpgradeStatusSubjectPrefix+"."+nodeID, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return UpgradeStatusPublication{}, false, nil
	}
	if err != nil {
		return UpgradeStatusPublication{}, false, fmt.Errorf("load latest upgrade status: %w", err)
	}
	stored, err := decodeUpgradeStatusWire(message, nodeID)
	if err != nil {
		return UpgradeStatusPublication{}, false, err
	}
	if stored.StatusID != record.StatusID {
		return UpgradeStatusPublication{}, false, nil
	}
	publication, err := b.loadUpgradeStatusPublicationAtSequence(ctx, nodeID, record, message.Sequence)
	if err != nil {
		return UpgradeStatusPublication{}, false, err
	}
	return publication, true, nil
}

func (b *NATSUpgradeCommandBus) loadUpgradeStatusPublicationAtSequence(ctx context.Context, nodeID string,
	record UpgradeStatusRecord, sequence uint64,
) (UpgradeStatusPublication, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) || !canonicalUpgradeUUID(nodeID) || record.NodeID != nodeID || sequence == 0 {
		return UpgradeStatusPublication{}, fmt.Errorf("upgrade status publication lookup is invalid")
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
	message, err := b.js.GetMsg(UpgradeStatusStream, sequence, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return UpgradeStatusPublication{}, fmt.Errorf("load published upgrade status: %w", err)
	}
	legacySubject := UpgradeStatusSubjectPrefix + "." + nodeID
	v2Subject := upgradeStatusV2Subject(record.StatusID)
	if message == nil || message.Sequence != sequence ||
		(message.Subject != legacySubject && message.Subject != v2Subject) {
		return UpgradeStatusPublication{}, fmt.Errorf("published upgrade status wire identity is invalid")
	}
	stored, err := decodeUpgradeStatusRecord(message.Data)
	if err != nil || stored.NodeID != nodeID || stored.StatusID != record.StatusID ||
		stored.CommandID != record.CommandID || stored.StatusRevision != record.StatusRevision ||
		stored.InstallationID != record.InstallationID || stored.PlanID != record.PlanID ||
		stored.PlanRevision != record.PlanRevision || stored.SHA256 != record.SHA256 ||
		!bytes.Equal(stored.Encoded, record.Encoded) {
		return UpgradeStatusPublication{}, fmt.Errorf("published upgrade status wire conflicts with the requested identity")
	}
	expectedHeaders := map[string]string{
		nats.MsgIdHdr: stored.StatusID, nats.ExpectedStreamHdr: UpgradeStatusStream,
		UpgradePayloadSHA256Header: hex.EncodeToString(stored.SHA256[:]), UpgradeMessageKeyHeader: stored.StatusID,
	}
	if message.Subject == v2Subject {
		expectedHeaders[nats.MsgIdHdr] = upgradeStatusV2MessageIDPrefix + stored.StatusID
		expectedHeaders[nats.ExpectedLastSubjSeqHdr] = "0"
	}
	if !exactUpgradeHeaders(message.Header, expectedHeaders) {
		return UpgradeStatusPublication{}, fmt.Errorf("published upgrade status wire conflicts with the requested identity")
	}
	return UpgradeStatusPublication{Stream: UpgradeStatusStream, Sequence: sequence}, nil
}

func (b *NATSUpgradeCommandBus) ensureUpgradeStatusLegacyMigration(ctx context.Context) (bool, error) {
	if b == nil || isNilInterface(b.js) || isNilInterface(ctx) {
		return false, fmt.Errorf("upgrade status legacy migration is invalid")
	}
	state, found, err := b.loadUpgradeStatusMigrationState(ctx)
	if err != nil {
		return false, err
	}
	emptyAtInitialization := false
	if !found {
		operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
		info, infoErr := b.js.StreamInfo(UpgradeStatusStream, nats.Context(operationCtx))
		cancel()
		if infoErr != nil {
			return false, fmt.Errorf("load upgrade status migration horizon: %w", infoErr)
		}
		if info == nil || (info.Config.Name != "" && info.Config.Name != UpgradeStatusStream) {
			return false, fmt.Errorf("upgrade status migration stream identity is invalid")
		}
		state = upgradeStatusMigrationState{ProgressSequence: 0}
		if info.State.Msgs == 0 {
			emptyAtInitialization = true
			state.NextSequence = 1
			state.Complete = true
		} else {
			if info.State.FirstSeq == 0 || info.State.LastSeq < info.State.FirstSeq {
				return false, fmt.Errorf("upgrade status migration stream state is invalid")
			}
			state.HorizonSequence = info.State.LastSeq
			state.NextSequence = info.State.FirstSeq
		}
		state, err = b.persistUpgradeStatusMigrationState(ctx, state, 0)
		if err != nil {
			return false, err
		}
		if emptyAtInitialization && state.HorizonSequence == 0 && state.Complete {
			return true, nil
		}
	}
	if state.Complete {
		operationCtx, cancel := context.WithTimeout(ctx, b.operationTimeout)
		info, infoErr := b.js.StreamInfo(UpgradeStatusStream, nats.Context(operationCtx))
		cancel()
		if infoErr != nil {
			return false, fmt.Errorf("load completed upgrade status migration horizon: %w", infoErr)
		}
		if info == nil || (info.Config.Name != "" && info.Config.Name != UpgradeStatusStream) ||
			info.State.LastSeq < state.HorizonSequence {
			return false, fmt.Errorf("completed upgrade status migration stream identity is invalid")
		}
		if info.State.LastSeq < state.NextSequence {
			return true, nil
		}
		state.HorizonSequence = info.State.LastSeq
		state.Complete = false
		state, err = b.persistUpgradeStatusMigrationState(ctx, state, state.ProgressSequence)
		if err != nil {
			return false, err
		}
	}
	return b.advanceUpgradeStatusLegacyMigration(ctx, state)
}

func (b *NATSUpgradeCommandBus) advanceUpgradeStatusLegacyMigration(ctx context.Context,
	state upgradeStatusMigrationState,
) (bool, error) {
	if !validUpgradeStatusMigrationState(state) || state.Complete {
		return false, fmt.Errorf("upgrade status migration progress is invalid")
	}
	scanDuration := b.operationTimeout
	if scanDuration <= 0 || scanDuration > maxUpgradeStatusScanDuration {
		scanDuration = maxUpgradeStatusScanDuration
	}
	scanCtx, cancel := context.WithTimeout(ctx, scanDuration)
	defer cancel()
	next := state.NextSequence
	var scannedSequences uint64
	var scannedBytes int
	for next <= state.HorizonSequence && scannedSequences < maxUpgradeStatusScanSequences {
		message, err := b.js.GetMsg(UpgradeStatusStream, next, nats.Context(scanCtx))
		if errors.Is(err, nats.ErrMsgNotFound) {
			next++
			scannedSequences++
			continue
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
				break
			}
			return false, fmt.Errorf("scan upgrade status migration horizon: %w", err)
		}
		if message == nil || message.Sequence != next {
			return false, fmt.Errorf("upgrade status migration message identity is invalid")
		}
		if len(message.Data) > maxUpgradeStatusScanBytes-scannedBytes {
			break
		}
		scannedBytes += len(message.Data)
		if err := b.migrateUpgradeStatusMessage(scanCtx, message); err != nil {
			return false, err
		}
		next++
		scannedSequences++
	}
	if next == state.NextSequence {
		return false, fmt.Errorf("upgrade status migration could not advance within its budget")
	}
	candidate := upgradeStatusMigrationState{
		HorizonSequence: state.HorizonSequence, NextSequence: next,
		ProgressSequence: state.ProgressSequence, Complete: next == state.HorizonSequence+1,
	}
	persisted, err := b.persistUpgradeStatusMigrationState(ctx, candidate, state.ProgressSequence)
	if err != nil {
		return false, err
	}
	return persisted.Complete, nil
}

func (b *NATSUpgradeCommandBus) migrateUpgradeStatusMessage(ctx context.Context, message *nats.RawStreamMsg) error {
	prefix := UpgradeStatusSubjectPrefix + "."
	if message == nil || !strings.HasPrefix(message.Subject, prefix) {
		return nil
	}
	nodeID := strings.TrimPrefix(message.Subject, prefix)
	if strings.Contains(nodeID, ".") || !canonicalUpgradeUUID(nodeID) {
		return fmt.Errorf("legacy upgrade status subject is invalid")
	}
	record, err := decodeUpgradeStatusWire(message, nodeID)
	if err != nil {
		return err
	}
	identity, found, err := b.loadUpgradeStatusIdentityState(ctx, nodeID, record)
	if err != nil {
		return err
	}
	publication := UpgradeStatusPublication{Stream: UpgradeStatusStream, Sequence: message.Sequence}
	if found {
		if identity.Publication.Sequence != 0 {
			_, err := b.loadUpgradeStatusPublicationAtSequence(ctx, nodeID, record, identity.Publication.Sequence)
			return err
		}
		if identity.ReservationSequence == 0 {
			return fmt.Errorf("legacy upgrade status identity state is incomplete")
		}
		return b.publishUpgradeStatusIdentity(ctx, record, identity.ReservationSequence, publication)
	}
	return b.publishLegacyUpgradeStatusIdentity(ctx, record, publication)
}

func decodeUpgradeStatusWire(message *nats.RawStreamMsg, nodeID string) (UpgradeStatusRecord, error) {
	if message == nil || message.Sequence == 0 || message.Subject != UpgradeStatusSubjectPrefix+"."+nodeID {
		return UpgradeStatusRecord{}, fmt.Errorf("upgrade status stream message identity is invalid")
	}
	stored, err := decodeUpgradeStatusRecord(message.Data)
	if err != nil || stored.NodeID != nodeID || !exactUpgradeHeaders(message.Header, map[string]string{
		nats.MsgIdHdr: stored.StatusID, nats.ExpectedStreamHdr: UpgradeStatusStream,
		UpgradePayloadSHA256Header: hex.EncodeToString(stored.SHA256[:]), UpgradeMessageKeyHeader: stored.StatusID,
	}) {
		return UpgradeStatusRecord{}, fmt.Errorf("upgrade status stream message wire is invalid")
	}
	return stored, nil
}

type natsUpgradeCommandSubscription struct {
	subscription *nats.Subscription
	nodeID       string
	fetchTimeout time.Duration
}

func (s *natsUpgradeCommandSubscription) Next(ctx context.Context) (UpgradeCommandDelivery, error) {
	if s == nil || s.subscription == nil || isNilInterface(ctx) {
		return nil, fmt.Errorf("upgrade subscription is invalid")
	}
	var messages []*nats.Msg
	for {
		fetchCtx, cancel := context.WithTimeout(ctx, s.fetchTimeout)
		var err error
		messages, err = s.subscription.Fetch(1, nats.Context(fetchCtx))
		cancel()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
			continue
		}
		return nil, err
	}
	if len(messages) != 1 {
		return nil, fmt.Errorf("pull consumer returned an unexpected upgrade command batch")
	}
	message := messages[0]
	record, decodeErr := validateUpgradeCommandMessage(message, s.nodeID)
	if decodeErr != nil {
		_ = message.Nak()
		return nil, fmt.Errorf("durable upgrade command is invalid")
	}
	return &natsUpgradeCommandDelivery{message: message, command: record}, nil
}

func validateUpgradeCommandMessage(message *nats.Msg, nodeID string) (UpgradeCommandRecord, error) {
	if message == nil || !canonicalUpgradeUUID(nodeID) || message.Subject != UpgradeCommandSubjectPrefix+"."+nodeID {
		return UpgradeCommandRecord{}, errors.New("invalid upgrade command message")
	}
	record, err := decodeUpgradeCommandRecord(message.Data)
	if err != nil || record.NodeID != nodeID {
		return UpgradeCommandRecord{}, errors.New("invalid upgrade command message")
	}
	digest := sha256.Sum256(message.Data)
	hexDigest := hex.EncodeToString(digest[:])
	if !exactUpgradeHeaders(message.Header, map[string]string{
		nats.MsgIdHdr:              controlUpgradeMessageID(message.Data),
		nats.ExpectedStreamHdr:     UpgradeCommandStream,
		UpgradePayloadSHA256Header: hexDigest,
		UpgradeMessageKeyHeader:    record.CommandID,
	}) {
		return UpgradeCommandRecord{}, errors.New("invalid upgrade command headers")
	}
	return record, nil
}

func exactUpgradeHeaders(actual nats.Header, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for name, value := range expected {
		values := actual.Values(name)
		if len(values) != 1 || !bytes.Equal([]byte(values[0]), []byte(value)) {
			return false
		}
	}
	return true
}

func (s *natsUpgradeCommandSubscription) Close() error {
	if s == nil || s.subscription == nil {
		return fmt.Errorf("upgrade subscription is invalid")
	}
	return s.subscription.Unsubscribe()
}

type natsUpgradeCommandDelivery struct {
	message *nats.Msg
	command UpgradeCommandRecord
}

func (d *natsUpgradeCommandDelivery) Command() UpgradeCommandRecord {
	if d == nil {
		return UpgradeCommandRecord{}
	}
	return d.command
}
func (d *natsUpgradeCommandDelivery) Ack(ctx context.Context) error {
	if d == nil || d.message == nil || isNilInterface(ctx) {
		return fmt.Errorf("upgrade command delivery is invalid")
	}
	if err := d.message.AckSync(nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return err
	}
	return nil
}
func (d *natsUpgradeCommandDelivery) Nak(ctx context.Context) error {
	if d == nil || d.message == nil || isNilInterface(ctx) {
		return fmt.Errorf("upgrade command delivery is invalid")
	}
	if err := d.message.Nak(nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return err
	}
	return nil
}

func sameUpgradeConsumerConfig(info *nats.ConsumerInfo, expected *nats.ConsumerConfig) bool {
	if info == nil || expected == nil {
		return false
	}
	a := info.Config
	return a.Name == expected.Name && a.Durable == expected.Durable && a.Description == expected.Description &&
		upgradeSameMetadata(a.Metadata, expected.Metadata) && a.DeliverPolicy == expected.DeliverPolicy &&
		a.OptStartSeq == expected.OptStartSeq && reflect.DeepEqual(a.OptStartTime, expected.OptStartTime) &&
		a.AckPolicy == expected.AckPolicy && a.AckWait == expected.AckWait && a.MaxDeliver == expected.MaxDeliver &&
		reflect.DeepEqual(a.BackOff, expected.BackOff) && a.FilterSubject == expected.FilterSubject &&
		reflect.DeepEqual(a.FilterSubjects, expected.FilterSubjects) && a.ReplayPolicy == expected.ReplayPolicy &&
		a.RateLimit == expected.RateLimit && a.SampleFrequency == expected.SampleFrequency &&
		a.MaxAckPending == expected.MaxAckPending && a.MaxWaiting == expected.MaxWaiting &&
		a.MaxRequestBatch == expected.MaxRequestBatch && a.MaxRequestExpires == expected.MaxRequestExpires &&
		a.MaxRequestMaxBytes == expected.MaxRequestMaxBytes && a.FlowControl == expected.FlowControl &&
		a.Heartbeat == expected.Heartbeat && a.DeliverSubject == expected.DeliverSubject &&
		a.DeliverGroup == expected.DeliverGroup && a.InactiveThreshold == expected.InactiveThreshold &&
		a.Replicas == expected.Replicas && a.MemoryStorage == expected.MemoryStorage && a.HeadersOnly == expected.HeadersOnly
}

var upgradeNATSServerAPILevels = map[string]string{"2.11.4": "1", "2.12.15-cdnca.1": "3"}

func upgradeSameMetadata(actual, expected map[string]string) bool {
	filtered := func(source map[string]string) (map[string]string, bool) {
		result := make(map[string]string, len(source))
		serverKeys := 0
		for key, value := range source {
			if !strings.HasPrefix(key, "_nats.") {
				result[key] = value
				continue
			}
			serverKeys++
			switch key {
			case "_nats.req.level":
				if value != "0" {
					return nil, false
				}
			case "_nats.level", "_nats.ver":
			default:
				return nil, false
			}
		}
		if serverKeys == 0 {
			return result, true
		}
		// Each pinned server reports its own JetStream API level: 2.11.4 is the e2e
		// pin, 2.12.15-cdnca.1 the signed native profile server.
		level, ok := upgradeNATSServerAPILevels[source["_nats.ver"]]
		if serverKeys != 3 || !ok || source["_nats.level"] != level {
			return nil, false
		}
		return result, true
	}
	actualUser, actualOK := filtered(actual)
	expectedUser, expectedOK := filtered(expected)
	return actualOK && expectedOK && reflect.DeepEqual(actualUser, expectedUser)
}
