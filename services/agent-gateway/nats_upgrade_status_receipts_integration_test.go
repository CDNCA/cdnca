//go:build integration

package gateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNATSUpgradeStatusAckProofSurvivesRestartAndConfirmsInOrder(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	firstConnection := connectIntegrationNATS(t, natsURL)
	firstJS, err := firstConnection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	cleanupStreams := ensureUpgradeReceiptIntegrationStreams(t, firstJS)
	cleanupJS := firstJS
	cleanupConnection := firstConnection
	t.Cleanup(func() {
		cleanupStreams(cleanupJS)
		cleanupConnection.Close()
	})
	config := DefaultNATSCommandBusConfig()
	config.OperationTimeout = time.Second
	firstBus, err := NewNATSUpgradeCommandBus(firstConnection, config)
	if err != nil {
		t.Fatal(err)
	}
	command := integrationUpgradeCommand(t)
	statusRecord := integrationUpgradeStatus(t, command)
	publication, err := firstBus.PublishUpgradeStatus(t.Context(), command.NodeID, statusRecord.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	record := upgradeStatusAckRecord{NodeID: command.NodeID, InstallationID: command.InstallationID, Ack: &agentv1.UpgradeStatusAck{
		StatusEventId: statusRecord.StatusID, CommandId: statusRecord.CommandID, StatusRevision: statusRecord.StatusRevision,
		StatusSha256: append([]byte(nil), statusRecord.SHA256[:]...), PersistedTime: timestamppb.New(time.Unix(123, 456).UTC()),
		PublishedStream: publication.Stream, PublishedSequence: publication.Sequence,
	}}
	stored, err := firstBus.saveUpgradeStatusAck(t.Context(), record, defaultMaxPendingCommands)
	if err != nil {
		t.Fatal(err)
	}
	statusMessage, err := firstJS.GetLastMsg(UpgradeStatusStream,
		UpgradeStatusV2SubjectPrefix+"."+statusRecord.StatusID)
	if err != nil || statusMessage.Sequence != publication.Sequence || !bytes.Equal(statusMessage.Data, statusRecord.Encoded) {
		t.Fatalf("status message=(%+v,%v)", statusMessage, err)
	}
	ledgerMessage, err := firstJS.GetLastMsg(UpgradeStatusStream, upgradeStatusAckLedgerSubject(command.NodeID))
	if err != nil || ledgerMessage.Sequence <= statusMessage.Sequence {
		t.Fatalf("pending ledger=(%+v,%v)", ledgerMessage, err)
	}
	secondConnection := connectIntegrationNATS(t, natsURL)
	secondJS, err := secondConnection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	cleanupJS = secondJS
	cleanupConnection = secondConnection
	firstConnection.Close()
	secondBus, err := NewNATSUpgradeCommandBus(secondConnection, config)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := secondBus.listUpgradeStatusAcks(t.Context(), command.NodeID, defaultMaxPendingCommands)
	if err != nil || len(recovered) != 1 || !sameUpgradeStatusAckRecord(recovered[0], stored) {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	replayedPublication, err := secondBus.PublishUpgradeStatus(t.Context(), command.NodeID, statusRecord.Encoded)
	if err != nil || replayedPublication != publication {
		t.Fatalf("replayed publication=(%+v,%v), want %+v", replayedPublication, err, publication)
	}
	replayedMessage, err := secondJS.GetLastMsg(UpgradeStatusStream,
		UpgradeStatusV2SubjectPrefix+"."+statusRecord.StatusID)
	if err != nil || replayedMessage.Sequence != statusMessage.Sequence {
		t.Fatalf("status was republished: message=(%+v,%v)", replayedMessage, err)
	}

	receipt := receiptTestUpgradeStatusAckReceipt(t, stored)
	wrong := proto.Clone(receipt).(*agentv1.UpgradeStatusAckReceipt)
	wrong.StatusSha256[0] ^= 0xff
	if _, err := secondBus.confirmUpgradeStatusAck(t.Context(), command.NodeID, wrong, defaultMaxPendingCommands); err == nil {
		t.Fatal("wrong status digest confirmed")
	}
	confirmed, err := secondBus.confirmUpgradeStatusAck(t.Context(), command.NodeID, receipt, defaultMaxPendingCommands)
	if err != nil || !proto.Equal(confirmed, receipt) {
		t.Fatalf("confirmed=(%+v,%v)", confirmed, err)
	}
	digest, err := upgradeStatusAckSHA256(stored.Ack)
	if err != nil {
		t.Fatal(err)
	}
	proofMessage, err := secondJS.GetLastMsg(UpgradeStatusStream, upgradeStatusAckConfirmationSubject(command.NodeID, digest))
	if err != nil {
		t.Fatal(err)
	}
	clearedLedger, err := secondJS.GetLastMsg(UpgradeStatusStream, upgradeStatusAckLedgerSubject(command.NodeID))
	if err != nil || !(statusMessage.Sequence < ledgerMessage.Sequence && ledgerMessage.Sequence < proofMessage.Sequence && proofMessage.Sequence < clearedLedger.Sequence) {
		t.Fatalf("durability order status=%d pending=%d proof=%d cleared=%d err=%v",
			statusMessage.Sequence, ledgerMessage.Sequence, proofMessage.Sequence, clearedLedger.Sequence, err)
	}
	remaining, err := secondBus.listUpgradeStatusAcks(t.Context(), command.NodeID, defaultMaxPendingCommands)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("remaining=%+v err=%v", remaining, err)
	}

	reconfirmed, err := secondBus.confirmUpgradeStatusAck(t.Context(), command.NodeID, receipt, defaultMaxPendingCommands)
	if err != nil || !proto.Equal(reconfirmed, receipt) {
		t.Fatalf("response-loss reconfirmation=(%+v,%v)", reconfirmed, err)
	}
	proofAfterReplay, err := secondJS.GetLastMsg(UpgradeStatusStream, upgradeStatusAckConfirmationSubject(command.NodeID, digest))
	if err != nil || proofAfterReplay.Sequence != proofMessage.Sequence {
		t.Fatalf("confirmation proof was duplicated: before=%d after=%+v err=%v", proofMessage.Sequence, proofAfterReplay, err)
	}
}

func TestNATSUpgradeStatusReservationSurvivesFinalProofCrashPastDedupeWindow(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection := connectIntegrationNATS(t, natsURL)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	cleanupStreams := ensureUpgradeReceiptIntegrationStreams(t, js)
	t.Cleanup(func() {
		cleanupStreams(js)
		connection.Close()
	})
	config := DefaultNATSCommandBusConfig()
	config.OperationTimeout = time.Second
	bus, err := NewNATSUpgradeCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	command := integrationUpgradeCommand(t)
	status := integrationUpgradeStatus(t, command)
	identity, err := bus.reserveUpgradeStatusIdentity(t.Context(), status)
	if err != nil || identity.ReservationSequence == 0 || identity.Publication.Sequence != 0 {
		t.Fatalf("reservation=(%+v,%v)", identity, err)
	}
	message := nats.NewMsg(UpgradeStatusSubjectPrefix + "." + command.NodeID)
	message.Data = append([]byte(nil), status.Encoded...)
	message.Header.Set(nats.MsgIdHdr, status.StatusID)
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	message.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(status.SHA256[:]))
	message.Header.Set(UpgradeMessageKeyHeader, status.StatusID)
	ack, err := js.PublishMsg(message, nats.ExpectStream(UpgradeStatusStream))
	if err != nil || ack.Sequence <= identity.ReservationSequence {
		t.Fatalf("orphaned status PubAck=(%+v,%v)", ack, err)
	}
	time.Sleep(200 * time.Millisecond)

	conflict := statusWithSameIDDifferentPayload(t, status)
	if _, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, conflict.Encoded); err == nil {
		t.Fatal("conflicting payload was accepted after broker deduplication expired")
	}
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil || publication.Sequence <= ack.Sequence {
		t.Fatalf("exact crash recovery=(%+v,%v), legacy sequence %d", publication, err, ack.Sequence)
	}
	stored, err := js.GetLastMsg(UpgradeStatusStream, upgradeStatusV2Subject(status.StatusID))
	if err != nil || stored.Sequence != publication.Sequence || !bytes.Equal(stored.Data, status.Encoded) {
		t.Fatalf("canonical v2 status=(%+v,%v)", stored, err)
	}
	legacy, err := js.GetLastMsg(UpgradeStatusStream, message.Subject)
	if err != nil || legacy.Sequence != ack.Sequence {
		t.Fatalf("legacy status changed: message=(%+v,%v)", legacy, err)
	}
	proof, err := js.GetLastMsg(UpgradeStatusStream, upgradeStatusIdentitySubject(command.NodeID, status.StatusID))
	state, decodeErr := decodeUpgradeStatusIdentityMessage(proof, command.NodeID, status)
	if err != nil || decodeErr != nil || state.ReservationSequence != identity.ReservationSequence ||
		state.Publication != (UpgradeStatusPublication{Stream: UpgradeStatusStream, Sequence: ack.Sequence}) {
		t.Fatalf("final proof=(%+v,state=%+v,get=%v,decode=%v)", proof, state, err, decodeErr)
	}
	replayed, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil || replayed != publication {
		t.Fatalf("canonical v2 replay=(%+v,%v), want %+v", replayed, err, publication)
	}
}

func TestNATSUpgradeCommandNextWaitsThroughIdleFetchAndHonorsCancel(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection := connectIntegrationNATS(t, natsURL)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	cleanupStreams := ensureUpgradeReceiptIntegrationStreams(t, js)
	t.Cleanup(func() {
		cleanupStreams(js)
		connection.Close()
	})
	config := DefaultNATSCommandBusConfig()
	config.OperationTimeout = 50 * time.Millisecond
	bus, err := NewNATSUpgradeCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.NewString()
	consumer := upgradeConsumerConfig(nodeID, config.AckWait, config.MaxWaiting, config.MaxAckPending, config.OperationTimeout)
	if _, err := js.AddConsumer(UpgradeCommandStream, consumer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := js.DeleteConsumer(UpgradeCommandStream, consumer.Durable); err != nil {
			t.Errorf("delete upgrade receipt integration consumer %s: %v", consumer.Durable, err)
		}
	})
	subscription, err := bus.SubscribeUpgrade(t.Context(), nodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := subscription.Close(); err != nil {
			t.Errorf("close upgrade receipt integration subscription: %v", err)
		}
	})
	idleContext, idleCancel := context.WithTimeout(context.Background(), 3*config.OperationTimeout)
	defer idleCancel()
	if delivery, err := subscription.Next(idleContext); delivery != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("idle fetch result delivery=%v error=%v", delivery, err)
	}
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	if delivery, err := subscription.Next(canceledContext); delivery != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled fetch result delivery=%v error=%v", delivery, err)
	}
}

func TestNATSUpgradeStatusAckCASConcurrentNoLostRecords(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection := connectIntegrationNATS(t, natsURL)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	cleanupStreams := ensureUpgradeReceiptIntegrationStreams(t, js)
	t.Cleanup(func() {
		cleanupStreams(js)
		connection.Close()
	})
	config := DefaultNATSCommandBusConfig()
	config.OperationTimeout = 2 * time.Second
	bus, err := NewNATSUpgradeCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}

	base := integrationUpgradeCommand(t)
	firstCommand := distinctIntegrationUpgradeCommand(t, base, base.InstallationID)
	secondCommand := distinctIntegrationUpgradeCommand(t, base, base.InstallationID)
	thirdCommand := distinctIntegrationUpgradeCommand(t, base, base.InstallationID)
	first := integrationUpgradeAckRecord(t, bus, firstCommand)
	second := integrationUpgradeAckRecord(t, bus, secondCommand)
	third := integrationUpgradeAckRecord(t, bus, thirdCommand)
	appendBarrier := newUpgradePublishBarrier(2, func(message *nats.Msg) bool {
		return message.Subject == upgradeStatusAckLedgerSubject(first.NodeID)
	})
	appendBus := upgradeIntegrationBarrierBus(bus, appendBarrier.wait)

	start := make(chan struct{})
	type saveResult struct {
		attempts int
		err      error
	}
	appendResults := make([]saveResult, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	for index, record := range []upgradeStatusAckRecord{first, second} {
		go func(index int, record upgradeStatusAckRecord) {
			defer wait.Done()
			<-start
			appendResults[index].attempts, appendResults[index].err = retryIntegrationUpgradeAckSave(t.Context(), appendBus, record, 4)
		}(index, record)
	}
	close(start)
	wait.Wait()
	for index, result := range appendResults {
		if result.err != nil {
			t.Fatalf("double append %d attempts=%d err=%v", index, result.attempts, result.err)
		}
	}
	records, err := bus.listUpgradeStatusAcks(t.Context(), base.NodeID, 4)
	if err != nil || len(records) != 2 {
		t.Fatalf("double append records=%d err=%v", len(records), err)
	}

	firstReceipt := receiptTestUpgradeStatusAckReceipt(t, first)
	confirmAppendBarrier := newUpgradePublishBarrier(2, func(message *nats.Msg) bool {
		return message.Subject == upgradeStatusAckLedgerSubject(first.NodeID)
	})
	confirmAppendBus := upgradeIntegrationBarrierBus(bus, confirmAppendBarrier.wait)
	start = make(chan struct{})
	var confirmErr, appendErr error
	var confirmAttempts, appendAttempts int
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		confirmAttempts, confirmErr = retryIntegrationUpgradeAckConfirm(t.Context(), confirmAppendBus, first.NodeID, firstReceipt, 4)
	}()
	go func() {
		defer wait.Done()
		<-start
		appendAttempts, appendErr = retryIntegrationUpgradeAckSave(t.Context(), confirmAppendBus, third, 4)
	}()
	close(start)
	wait.Wait()
	if confirmErr != nil || appendErr != nil {
		t.Fatalf("confirm-vs-append confirm=(%d,%v) append=(%d,%v)", confirmAttempts, confirmErr, appendAttempts, appendErr)
	}
	records, err = bus.listUpgradeStatusAcks(t.Context(), base.NodeID, 4)
	if err != nil || len(records) != 2 || !containsUpgradeStatusAck(records, second) || !containsUpgradeStatusAck(records, third) {
		t.Fatalf("confirm-vs-append records=%+v err=%v", records, err)
	}

	secondReceipt := receiptTestUpgradeStatusAckReceipt(t, second)
	secondDigest := mustUpgradeStatusAckDigest(t, second.Ack)
	doubleConfirmBarrier := newUpgradePublishBarrier(2, func(message *nats.Msg) bool {
		return message.Subject == upgradeStatusAckConfirmationSubject(second.NodeID, secondDigest)
	})
	doubleConfirmBus := upgradeIntegrationBarrierBus(bus, doubleConfirmBarrier.wait)
	start = make(chan struct{})
	confirmResults := make([]saveResult, 2)
	wait.Add(2)
	for index := range confirmResults {
		go func(index int) {
			defer wait.Done()
			<-start
			confirmResults[index].attempts, confirmResults[index].err = retryIntegrationUpgradeAckConfirm(
				t.Context(), doubleConfirmBus, second.NodeID, secondReceipt, 4,
			)
		}(index)
	}
	close(start)
	wait.Wait()
	for index, result := range confirmResults {
		if result.err != nil {
			t.Fatalf("double confirm %d attempts=%d err=%v", index, result.attempts, result.err)
		}
	}
	records, err = bus.listUpgradeStatusAcks(t.Context(), base.NodeID, 4)
	if err != nil || len(records) != 1 || !containsUpgradeStatusAck(records, third) {
		t.Fatalf("double confirm records=%+v err=%v", records, err)
	}

	crossCommand := distinctIntegrationUpgradeCommand(t, base, "00000000-0000-4000-8000-000000000099")
	cross := integrationUpgradeAckRecord(t, bus, crossCommand)
	if _, err := bus.saveUpgradeStatusAck(t.Context(), cross, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := bus.confirmUpgradeStatusAck(t.Context(), third.NodeID, receiptTestUpgradeStatusAckReceipt(t, third), 4); err != nil {
		t.Fatal(err)
	}
	records, err = bus.listUpgradeStatusAcks(t.Context(), base.NodeID, 4)
	if err != nil || len(records) != 1 || !sameUpgradeStatusAckRecord(records[0], cross) {
		t.Fatalf("cross-installation record lost: records=%+v err=%v", records, err)
	}

	limitedBase := integrationUpgradeCommand(t)
	limitedFirst := integrationUpgradeAckRecord(t, bus, distinctIntegrationUpgradeCommand(t, limitedBase, limitedBase.InstallationID))
	limitedSecond := integrationUpgradeAckRecord(t, bus, distinctIntegrationUpgradeCommand(t, limitedBase, limitedBase.InstallationID))
	limitBarrier := newUpgradePublishBarrier(2, func(message *nats.Msg) bool {
		return message.Subject == upgradeStatusAckLedgerSubject(limitedFirst.NodeID)
	})
	limitBus := upgradeIntegrationBarrierBus(bus, limitBarrier.wait)
	start = make(chan struct{})
	limitResults := make([]saveResult, 2)
	wait.Add(2)
	for index, record := range []upgradeStatusAckRecord{limitedFirst, limitedSecond} {
		go func(index int, record upgradeStatusAckRecord) {
			defer wait.Done()
			<-start
			limitResults[index].attempts, limitResults[index].err = retryIntegrationUpgradeAckSave(t.Context(), limitBus, record, 1)
		}(index, record)
	}
	close(start)
	wait.Wait()
	successes := 0
	limits := 0
	for _, result := range limitResults {
		switch {
		case result.err == nil:
			successes++
		case errors.Is(result.err, errUpgradeStatusAckLimit):
			limits++
		default:
			t.Fatalf("limit race attempts=%d err=%v", result.attempts, result.err)
		}
	}
	limitedRecords, err := bus.listUpgradeStatusAcks(t.Context(), limitedBase.NodeID, 1)
	if err != nil || successes != 1 || limits != 1 || len(limitedRecords) != 1 {
		t.Fatalf("limit race success=%d limit=%d records=%d err=%v", successes, limits, len(limitedRecords), err)
	}
	if appendResults[0].attempts == 1 && appendResults[1].attempts == 1 &&
		confirmAttempts == 1 && appendAttempts == 1 && confirmResults[0].attempts == 1 && confirmResults[1].attempts == 1 {
		t.Fatal("concurrent CAS scenarios did not exercise a loser retry")
	}
}

type upgradeIntegrationBarrierJetStream struct {
	nats.JetStreamContext
	beforePublish func(*nats.Msg)
}

func (s *upgradeIntegrationBarrierJetStream) PublishMsg(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
	s.beforePublish(message)
	return s.JetStreamContext.PublishMsg(message, options...)
}

func upgradeIntegrationBarrierBus(bus *NATSUpgradeCommandBus, beforePublish func(*nats.Msg)) *NATSUpgradeCommandBus {
	result := *bus
	result.js = &upgradeIntegrationBarrierJetStream{JetStreamContext: bus.js, beforePublish: beforePublish}
	return &result
}

func distinctIntegrationUpgradeCommand(t *testing.T, base UpgradeCommandRecord, installationID string) UpgradeCommandRecord {
	t.Helper()
	var wire upgradeCommandWire
	if err := json.Unmarshal(base.Encoded, &wire); err != nil {
		t.Fatal(err)
	}
	wire.CommandID = uuid.NewString()
	wire.InstallationID = installationID
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	command, err := decodeUpgradeCommandRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func integrationUpgradeAckRecord(t *testing.T, bus *NATSUpgradeCommandBus, command UpgradeCommandRecord) upgradeStatusAckRecord {
	t.Helper()
	statusRecord := integrationUpgradeStatus(t, command)
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, statusRecord.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	return upgradeStatusAckRecord{NodeID: command.NodeID, InstallationID: command.InstallationID, Ack: &agentv1.UpgradeStatusAck{
		StatusEventId: statusRecord.StatusID, CommandId: statusRecord.CommandID, StatusRevision: statusRecord.StatusRevision,
		StatusSha256: append([]byte(nil), statusRecord.SHA256[:]...), PersistedTime: timestamppb.Now(),
		PublishedStream: publication.Stream, PublishedSequence: publication.Sequence,
	}}
}

func retryIntegrationUpgradeAckSave(ctx context.Context, bus *NATSUpgradeCommandBus, record upgradeStatusAckRecord,
	limit int,
) (int, error) {
	var err error
	for attempt := 1; attempt <= 8; attempt++ {
		if _, err = bus.saveUpgradeStatusAck(ctx, record, limit); err == nil || errors.Is(err, errUpgradeStatusAckLimit) ||
			errors.Is(err, errUpgradeStatusAckConflict) {
			return attempt, err
		}
	}
	return 8, err
}

func retryIntegrationUpgradeAckConfirm(ctx context.Context, bus *NATSUpgradeCommandBus, nodeID string,
	receipt *agentv1.UpgradeStatusAckReceipt, limit int,
) (int, error) {
	var err error
	for attempt := 1; attempt <= 8; attempt++ {
		if _, err = bus.confirmUpgradeStatusAck(ctx, nodeID, receipt, limit); err == nil ||
			errors.Is(err, errUpgradeStatusAckConflict) || errors.Is(err, errUpgradeStatusAckNotFound) {
			return attempt, err
		}
	}
	return 8, err
}

func ensureUpgradeReceiptIntegrationStreams(t *testing.T, js nats.JetStreamContext) func(nats.JetStreamContext) {
	t.Helper()
	created := make([]string, 0, 2)
	ensure := func(config *nats.StreamConfig) {
		info, err := js.StreamInfo(config.Name)
		if err == nil {
			t.Fatalf("task-owned NATS already contains stream %s; refusing to mutate or reuse it", config.Name)
		}
		if !errors.Is(err, nats.ErrStreamNotFound) {
			t.Fatal(err)
		}
		if _, err := js.AddStream(config); err != nil {
			t.Fatal(err)
		}
		created = append(created, config.Name)
		info, err = js.StreamInfo(config.Name)
		if err != nil {
			t.Fatal(err)
		}
		if info == nil || info.Config.Name != config.Name || !sameUpgradeReceiptSubjects(info.Config.Subjects, config.Subjects) ||
			info.Config.Storage != nats.FileStorage || info.Config.Replicas < 1 || info.Config.Duplicates <= 0 {
			t.Fatalf("existing stream %s does not match its exact durable fixture", config.Name)
		}
		if config.Name == UpgradeStatusStream {
			streamConfig := info.Config
			if streamConfig.Retention != nats.LimitsPolicy || streamConfig.MaxAge != 0 ||
				streamConfig.MaxMsgs != -1 || streamConfig.MaxBytes != -1 || streamConfig.MaxMsgsPerSubject != -1 ||
				streamConfig.Discard != nats.DiscardOld || streamConfig.DiscardNewPerSubject ||
				streamConfig.AllowRollup || streamConfig.AllowMsgTTL {
				t.Fatalf("existing stream %s is not immutable: retention=%v max_age=%s max_msgs=%d max_bytes=%d max_msgs_per_subject=%d discard=%v discard_new_per_subject=%v rollup=%v msg_ttl=%v",
					config.Name, streamConfig.Retention, streamConfig.MaxAge, streamConfig.MaxMsgs, streamConfig.MaxBytes,
					streamConfig.MaxMsgsPerSubject, streamConfig.Discard, streamConfig.DiscardNewPerSubject,
					streamConfig.AllowRollup, streamConfig.AllowMsgTTL)
			}
		} else if info.Config.Retention != nats.WorkQueuePolicy {
			t.Fatalf("existing stream %s does not use work-queue retention", config.Name)
		}
	}
	ensure(&nats.StreamConfig{
		Name: UpgradeCommandStream, Subjects: []string{UpgradeCommandSubjectPrefix + ".*"},
		Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage, Replicas: 1, Duplicates: 100 * time.Millisecond,
	})
	ensure(&nats.StreamConfig{
		Name: UpgradeStatusStream, Subjects: []string{
			UpgradeStatusSubjectPrefix + ".*",
			UpgradeStatusV2SubjectPrefix + ".*",
			UpgradeStatusProofSubjectPrefix + ".pending.*",
			UpgradeStatusProofSubjectPrefix + ".confirmed.*.*",
			UpgradeStatusProofSubjectPrefix + ".completed.*.*.*",
			UpgradeStatusProofSubjectPrefix + ".status.*.*",
		},
		Retention: nats.LimitsPolicy, Storage: nats.FileStorage, Duplicates: 100 * time.Millisecond,
		Replicas: 1,
		Discard:  nats.DiscardOld, MaxAge: 0, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
	})
	return func(cleanupJS nats.JetStreamContext) {
		t.Helper()
		for index := len(created) - 1; index >= 0; index-- {
			if err := cleanupJS.DeleteStream(created[index]); err != nil {
				t.Errorf("delete upgrade receipt integration stream %s: %v", created[index], err)
			}
		}
	}
}

func sameUpgradeReceiptSubjects(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	remaining := make(map[string]int, len(expected))
	for _, subject := range expected {
		remaining[subject]++
	}
	for _, subject := range actual {
		if remaining[subject] == 0 {
			return false
		}
		remaining[subject]--
	}
	return true
}
