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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	testUpgradeStatusScanMaxSequences = 4096
	testUpgradeStatusScanMaxBytes     = 8 << 20
)

type upgradeProofJetStream struct {
	nats.JetStreamContext
	mu              sync.Mutex
	nextSequence    uint64
	firstSequence   uint64
	last            map[string]*nats.RawStreamMsg
	history         map[uint64]*nats.RawStreamMsg
	messageIDs      map[string]uint64
	getMsgCalls     int
	streamInfoCalls int
	published       []*nats.Msg
	ackOverride     *nats.PubAck
	publishErr      error
	storeOnError    bool
	corruptAckWire  bool
	beforePublish   func(*nats.Msg)
	rejectPublish   func(*nats.Msg) error
}

func (s *upgradeProofJetStream) GetLastMsg(stream, subject string, _ ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stream != UpgradeStatusStream {
		return nil, errors.New("wrong stream")
	}
	message := s.last[subject]
	if message == nil {
		return nil, nats.ErrMsgNotFound
	}
	return cloneUpgradeRawMessage(message), nil
}

func (s *upgradeProofJetStream) GetMsg(stream string, sequence uint64, _ ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getMsgCalls++
	if stream != UpgradeStatusStream {
		return nil, errors.New("wrong stream")
	}
	message := s.history[sequence]
	if message == nil {
		return nil, nats.ErrMsgNotFound
	}
	return cloneUpgradeRawMessage(message), nil
}

func (s *upgradeProofJetStream) StreamInfo(stream string, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamInfoCalls++
	if stream != UpgradeStatusStream {
		return nil, errors.New("wrong stream")
	}
	state := nats.StreamState{Msgs: uint64(len(s.history)), LastSeq: s.nextSequence}
	if s.firstSequence != 0 {
		state.FirstSeq = s.firstSequence
		return &nats.StreamInfo{Config: nats.StreamConfig{Name: stream}, State: state}, nil
	}
	for sequence := uint64(1); sequence <= s.nextSequence; sequence++ {
		if s.history[sequence] != nil {
			state.FirstSeq = sequence
			break
		}
	}
	return &nats.StreamInfo{Config: nats.StreamConfig{Name: stream}, State: state}, nil
}

func upgradeStatusBusinessPublishCount(messages []*nats.Msg) int {
	count := 0
	for _, message := range messages {
		if message != nil && (strings.HasPrefix(message.Subject, UpgradeStatusSubjectPrefix+".") ||
			strings.HasPrefix(message.Subject, UpgradeStatusV2SubjectPrefix+".")) {
			count++
		}
	}
	return count
}

func requireUpgradeStatusV2Publication(t *testing.T, jetstream *upgradeProofJetStream,
	record UpgradeStatusRecord, publication UpgradeStatusPublication,
) {
	t.Helper()
	message := jetstream.last[upgradeStatusV2Subject(record.StatusID)]
	if publication.Stream != UpgradeStatusStream || publication.Sequence == 0 || message == nil ||
		message.Sequence != publication.Sequence || !bytes.Equal(message.Data, record.Encoded) {
		t.Fatalf("upgrade status v2 publication=(%+v,message=%+v)", publication, message)
	}
}

func TestUpgradeStatusLegacyMigrationResumesThenNewStatusesAreO1(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	legacy := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{nextSequence: testUpgradeStatusScanMaxSequences + 904, firstSequence: 1,
		last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	for sequence := uint64(1); sequence <= jetstream.nextSequence; sequence++ {
		seedUpgradeStatusRawMessage(t, jetstream, sequence, legacy)
	}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	firstNew := distinctUpgradeStatusRecord(t, legacy, 2)

	if publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, firstNew.Encoded); publication != (UpgradeStatusPublication{}) ||
		!errors.Is(err, errUpgradeStatusMigrationInProgress) {
		t.Fatalf("first migration chunk=(%+v,%v)", publication, err)
	}
	progress, found, err := bus.loadUpgradeStatusMigrationState(t.Context())
	if err != nil || !found || progress.HorizonSequence != testUpgradeStatusScanMaxSequences+904 ||
		progress.NextSequence != testUpgradeStatusScanMaxSequences+1 || progress.Complete {
		t.Fatalf("first migration progress=(%+v,found=%t,err=%v)", progress, found, err)
	}
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, firstNew.Encoded)
	if err != nil || publication.Sequence == 0 {
		t.Fatalf("resumed migration publication=(%+v,%v)", publication, err)
	}
	progress, found, err = bus.loadUpgradeStatusMigrationState(t.Context())
	if err != nil || !found || !progress.Complete || progress.NextSequence != progress.HorizonSequence+1 {
		t.Fatalf("completed migration progress=(%+v,found=%t,err=%v)", progress, found, err)
	}

	streamInfoCalls := jetstream.streamInfoCalls
	secondNew := distinctUpgradeStatusRecord(t, firstNew, 3)
	if next, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, secondNew.Encoded); err != nil || next.Sequence <= publication.Sequence {
		t.Fatalf("post-migration publication=(%+v,%v)", next, err)
	}
	if jetstream.streamInfoCalls != streamInfoCalls+1 {
		t.Fatalf("post-migration incremental horizon checks: before=%d after=%d", streamInfoCalls, jetstream.streamInfoCalls)
	}
}

func TestUpgradeStatusMigrationInitializationAdoptsConcurrentWinnerHorizon(t *testing.T) {
	winner := upgradeStatusMigrationState{HorizonSequence: 1, NextSequence: 2, Complete: true}
	winnerMessage, err := upgradeStatusMigrationMessage(winner, 0)
	if err != nil {
		t.Fatal(err)
	}
	winner.ProgressSequence = 2
	jetstream := &upgradeProofJetStream{
		nextSequence: 2,
		last: map[string]*nats.RawStreamMsg{upgradeStatusMigrationSubject: {
			Subject: upgradeStatusMigrationSubject, Sequence: 2,
			Header: cloneUpgradeHeader(winnerMessage.Header), Data: append([]byte(nil), winnerMessage.Data...),
		}},
		history: map[uint64]*nats.RawStreamMsg{},
	}
	jetstream.history[2] = cloneUpgradeRawMessage(jetstream.last[upgradeStatusMigrationSubject])
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	loser := upgradeStatusMigrationState{HorizonSequence: 2, NextSequence: 1}

	persisted, err := bus.persistUpgradeStatusMigrationState(t.Context(), loser, 0)
	if err != nil || persisted != winner {
		t.Fatalf("concurrent initialization winner=(%+v,%v), want %+v", persisted, err, winner)
	}
}

func TestUpgradeStatusMigrationCASLoserAdoptsValidShorterWinner(t *testing.T) {
	winner := upgradeStatusMigrationState{HorizonSequence: 10, NextSequence: 4, ProgressSequence: 3}
	winnerMessage, err := upgradeStatusMigrationMessage(winner, 3)
	if err != nil {
		t.Fatal(err)
	}
	winner.ProgressSequence = 11
	jetstream := &upgradeProofJetStream{
		nextSequence: 11,
		last: map[string]*nats.RawStreamMsg{upgradeStatusMigrationSubject: {
			Subject: upgradeStatusMigrationSubject, Sequence: 11,
			Header: cloneUpgradeHeader(winnerMessage.Header), Data: append([]byte(nil), winnerMessage.Data...),
		}},
		history: map[uint64]*nats.RawStreamMsg{},
	}
	jetstream.history[11] = cloneUpgradeRawMessage(jetstream.last[upgradeStatusMigrationSubject])
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	candidate := upgradeStatusMigrationState{HorizonSequence: 10, NextSequence: 5, ProgressSequence: 3}

	persisted, err := bus.persistUpgradeStatusMigrationState(t.Context(), candidate, 3)
	if err != nil || persisted != winner {
		t.Fatalf("concurrent shorter winner=(%+v,%v), want %+v", persisted, err, winner)
	}
}

func (s *upgradeProofJetStream) PublishMsg(message *nats.Msg, _ ...nats.PubOpt) (*nats.PubAck, error) {
	if s.beforePublish != nil {
		s.beforePublish(message)
	}
	if s.rejectPublish != nil {
		if err := s.rejectPublish(message); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if messageID := message.Header.Get(nats.MsgIdHdr); messageID != "" {
		if sequence := s.messageIDs[messageID]; sequence != 0 {
			return &nats.PubAck{Stream: UpgradeStatusStream, Sequence: sequence, Duplicate: true}, nil
		}
	}
	if expected := message.Header.Get(nats.ExpectedLastSubjSeqHdr); expected != "" {
		want, err := strconv.ParseUint(expected, 10, 64)
		if err != nil {
			return nil, errors.New("invalid expected sequence")
		}
		var current uint64
		if previous := s.last[message.Subject]; previous != nil {
			current = previous.Sequence
		}
		if current != want {
			return nil, errors.New("subject CAS mismatch")
		}
	}
	if s.publishErr != nil && !s.storeOnError {
		return nil, s.publishErr
	}
	copyMessage := nats.NewMsg(message.Subject)
	copyMessage.Data = append([]byte(nil), message.Data...)
	copyMessage.Header = cloneUpgradeHeader(message.Header)
	if !strings.HasPrefix(message.Subject, UpgradeStatusIdentitySubjectPrefix+".") {
		s.published = append(s.published, copyMessage)
	}
	s.nextSequence++
	if s.last == nil {
		s.last = make(map[string]*nats.RawStreamMsg)
	}
	if s.history == nil {
		s.history = make(map[uint64]*nats.RawStreamMsg)
	}
	if s.messageIDs == nil {
		s.messageIDs = make(map[string]uint64)
	}
	stored := &nats.RawStreamMsg{
		Subject: message.Subject, Sequence: s.nextSequence, Header: cloneUpgradeHeader(message.Header),
		Data: append([]byte(nil), message.Data...), Time: time.Unix(int64(s.nextSequence), 0).UTC(),
	}
	if s.corruptAckWire {
		stored.Data = []byte("corrupt acknowledged wire")
	}
	s.last[message.Subject] = stored
	s.history[s.nextSequence] = stored
	if messageID := message.Header.Get(nats.MsgIdHdr); messageID != "" {
		s.messageIDs[messageID] = s.nextSequence
	}
	if s.publishErr != nil {
		return nil, s.publishErr
	}
	if s.ackOverride != nil {
		return s.ackOverride, nil
	}
	return &nats.PubAck{Stream: UpgradeStatusStream, Sequence: s.nextSequence}, nil
}

func TestUpgradeStatusPublishRecoversExactSequenceWithoutRepublish(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}

	first, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, statusRecord.Encoded)
	if err != nil || first.Stream != UpgradeStatusStream || first.Sequence == 0 {
		t.Fatalf("first publish=(%+v,%v)", first, err)
	}
	if count := upgradeStatusBusinessPublishCount(jetstream.published); count != 1 {
		t.Fatalf("first business publish count=%d", count)
	}
	wire := jetstream.last[upgradeStatusV2Subject(statusRecord.StatusID)]
	if wire.Subject != UpgradeStatusV2SubjectPrefix+"."+statusRecord.StatusID ||
		!bytes.Equal(wire.Data, statusRecord.Encoded) ||
		!exactUpgradeHeaders(wire.Header, map[string]string{
			nats.MsgIdHdr: upgradeStatusV2MessageIDPrefix + statusRecord.StatusID, nats.ExpectedStreamHdr: UpgradeStatusStream,
			nats.ExpectedLastSubjSeqHdr: "0", UpgradePayloadSHA256Header: hex.EncodeToString(statusRecord.SHA256[:]),
			UpgradeMessageKeyHeader: statusRecord.StatusID,
		}) {
		t.Fatalf("status wire=%+v", wire)
	}

	replayed, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, statusRecord.Encoded)
	if count := upgradeStatusBusinessPublishCount(jetstream.published); err != nil || replayed != first || count != 1 {
		t.Fatalf("exact replay=(%+v,%v) business publishes=%d", replayed, err, count)
	}

	next := distinctUpgradeStatusRecord(t, statusRecord, 2)
	jetstream.publishErr = errors.New("response lost")
	jetstream.storeOnError = true
	recovered, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, next.Encoded)
	if err != nil || recovered.Stream != UpgradeStatusStream || recovered.Sequence <= first.Sequence {
		t.Fatalf("read-after-write recovery=(%+v,%v)", recovered, err)
	}
}

func TestUpgradeStatusV2CASInterleavingReturnsOneCanonicalSequence(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	firstStatus := validUpgradeStatusRecord(t, command)
	secondStatus := distinctUpgradeStatusRecord(t, firstStatus, 2)
	jetstream := &upgradeProofJetStream{}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}

	first, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, firstStatus.Encoded)
	if err != nil || first.Sequence == 0 {
		t.Fatalf("first publication=(%+v,%v)", first, err)
	}
	second, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, secondStatus.Encoded)
	if err != nil || second.Sequence == 0 || second.Sequence == first.Sequence {
		t.Fatalf("second publication=(%+v,%v)", second, err)
	}
	jetstream.messageIDs = make(map[string]uint64)
	replayed, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, firstStatus.Encoded)
	if err != nil || replayed != first {
		t.Fatalf("expired-dedupe replay=(%+v,%v), want %+v", replayed, err, first)
	}
	firstSubject := UpgradeStatusV2SubjectPrefix + "." + firstStatus.StatusID
	secondSubject := UpgradeStatusV2SubjectPrefix + "." + secondStatus.StatusID
	if jetstream.last[firstSubject] == nil || jetstream.last[firstSubject].Sequence != first.Sequence ||
		jetstream.last[secondSubject] == nil || jetstream.last[secondSubject].Sequence != second.Sequence {
		t.Fatalf("per-status subjects do not preserve canonical publications: first=%+v second=%+v",
			jetstream.last[firstSubject], jetstream.last[secondSubject])
	}
	statusPublishes := 0
	for _, message := range jetstream.published {
		if message.Subject == firstSubject || message.Subject == secondSubject {
			statusPublishes++
		}
	}
	if statusPublishes != 2 {
		t.Fatalf("business status publishes=%d, want one per StatusID", statusPublishes)
	}
}

func TestUpgradeStatusCompletedMigrationClaimsLateLegacyStatus(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	first := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	if _, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, first.Encoded); err != nil {
		t.Fatal(err)
	}

	late := distinctUpgradeStatusRecord(t, first, 2)
	jetstream.mu.Lock()
	lateSequence := jetstream.nextSequence + 1
	seedUpgradeStatusRawMessage(t, jetstream, lateSequence, late)
	jetstream.nextSequence = lateSequence
	jetstream.mu.Unlock()
	next := distinctUpgradeStatusRecord(t, late, 3)
	for attempt := 0; attempt < 4; attempt++ {
		if _, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, next.Encoded); err != nil &&
			!errors.Is(err, errUpgradeStatusMigrationInProgress) {
			t.Fatalf("incremental migration attempt %d: %v", attempt, err)
		}
		if jetstream.last[upgradeStatusIdentitySubject(command.NodeID, late.StatusID)] != nil {
			break
		}
	}
	if jetstream.last[upgradeStatusIdentitySubject(command.NodeID, late.StatusID)] == nil {
		t.Fatal("late legacy status was never claimed by incremental migration")
	}
	canonical, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, late.Encoded)
	if err != nil || canonical.Sequence <= lateSequence {
		t.Fatalf("late legacy canonical publication=(%+v,%v), legacy sequence %d", canonical, err, lateSequence)
	}
	requireUpgradeStatusV2Publication(t, jetstream, late, canonical)
	publishedCount := upgradeStatusBusinessPublishCount(jetstream.published)
	replayed, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, late.Encoded)
	if err != nil || replayed != canonical || upgradeStatusBusinessPublishCount(jetstream.published) != publishedCount {
		t.Fatalf("late legacy replay=(%+v,%v) business publishes=%d", replayed, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
}

func TestUpgradeStatusReservationSurvivesCrashBeforeStatusAppend(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{}
	jetstream.rejectPublish = func(message *nats.Msg) error {
		if message.Subject == upgradeStatusV2Subject(status.StatusID) {
			return errors.New("crash before status append")
		}
		return nil
	}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}

	if publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded); err == nil ||
		publication != (UpgradeStatusPublication{}) {
		t.Fatalf("crash-window publish=(%+v,%v)", publication, err)
	}
	identitySubject := upgradeStatusIdentitySubject(command.NodeID, status.StatusID)
	if jetstream.last[identitySubject] == nil {
		t.Fatal("status identity was not reserved before the append attempt")
	}
	jetstream.rejectPublish = nil
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if count := upgradeStatusBusinessPublishCount(jetstream.published); err != nil || publication.Sequence == 0 || count != 1 {
		t.Fatalf("crash-window retry=(%+v,%v) business publishes=%d", publication, err, count)
	}
}

func TestUpgradeStatusReservationRejectsConflictAfterFinalProofCrashAndDedupeExpiry(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{}
	jetstream.rejectPublish = func(message *nats.Msg) error {
		if message.Subject != upgradeStatusIdentitySubject(command.NodeID, status.StatusID) {
			return nil
		}
		var wire struct {
			PublishedSequence uint64 `json:"published_sequence"`
		}
		if json.Unmarshal(message.Data, &wire) == nil && wire.PublishedSequence != 0 {
			return errors.New("crash before final proof")
		}
		return nil
	}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	if _, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded); err == nil {
		t.Fatal("final-proof crash was accepted")
	}

	jetstream.rejectPublish = nil
	jetstream.messageIDs = make(map[string]uint64)
	conflict := statusWithSameIDDifferentPayload(t, status)
	if _, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, conflict.Encoded); err == nil {
		t.Fatal("different payload was accepted after deduplication expiry")
	}
	replayed, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if count := upgradeStatusBusinessPublishCount(jetstream.published); err != nil || replayed.Sequence == 0 || count != 1 {
		t.Fatalf("exact crash recovery=(%+v,%v) business publishes=%d", replayed, err, count)
	}
}

func TestUpgradeStatusLegacyHistoryMigratesWithoutDedupe(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{nextSequence: 1, firstSequence: 1,
		last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	seedUpgradeStatusRawMessage(t, jetstream, 1, status)
	jetstream.messageIDs = make(map[string]uint64)
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}

	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil || publication.Sequence <= 1 || upgradeStatusBusinessPublishCount(jetstream.published) != 1 {
		t.Fatalf("legacy migration=(%+v,%v) business publishes=%d", publication, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
	requireUpgradeStatusV2Publication(t, jetstream, status, publication)
	if jetstream.last[upgradeStatusIdentitySubject(command.NodeID, status.StatusID)] == nil {
		t.Fatal("legacy migration did not persist an identity proof")
	}
	publishedCount := upgradeStatusBusinessPublishCount(jetstream.published)
	replayed, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil || replayed != publication || upgradeStatusBusinessPublishCount(jetstream.published) != publishedCount {
		t.Fatalf("migrated legacy replay=(%+v,%v) business publishes=%d", replayed, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
}

func TestUpgradeStatusPublishRejectsInvalidPubAckAndConflictingLastIdentity(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	for _, ack := range []*nats.PubAck{{Stream: "OTHER", Sequence: 1}, {Stream: UpgradeStatusStream}} {
		jetstream := &upgradeProofJetStream{ackOverride: ack}
		bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
		if publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, statusRecord.Encoded); err == nil || publication != (UpgradeStatusPublication{}) {
			t.Fatalf("invalid PubAck accepted: ack=%+v publication=%+v err=%v", ack, publication, err)
		}
	}

	jetstream := &upgradeProofJetStream{last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}, nextSequence: 7}
	subject := UpgradeStatusSubjectPrefix + "." + command.NodeID
	invalid := &nats.RawStreamMsg{Subject: subject, Sequence: 7, Header: make(nats.Header), Data: []byte("not-json")}
	jetstream.last[subject] = invalid
	jetstream.history[7] = invalid
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, statusRecord.Encoded)
	if err == nil || publication != (UpgradeStatusPublication{}) || upgradeStatusBusinessPublishCount(jetstream.published) != 0 {
		t.Fatalf("corrupt legacy history was accepted: publication=%+v err=%v business publishes=%d", publication, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
}

func TestUpgradeStatusPublishFindsHistoricalExactSequence(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	firstStatus := validUpgradeStatusRecord(t, command)
	secondStatus := distinctUpgradeStatusRecord(t, firstStatus, 2)
	jetstream := &upgradeProofJetStream{nextSequence: 9}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}

	first, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, firstStatus.Encoded)
	if err != nil || first.Sequence == 0 {
		t.Fatalf("first publication=(%+v,%v)", first, err)
	}
	requireUpgradeStatusV2Publication(t, jetstream, firstStatus, first)
	second, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, secondStatus.Encoded)
	if err != nil || second.Sequence <= first.Sequence {
		t.Fatalf("second publication=(%+v,%v)", second, err)
	}
	requireUpgradeStatusV2Publication(t, jetstream, secondStatus, second)
	publishedCount := upgradeStatusBusinessPublishCount(jetstream.published)
	lastSequence := jetstream.nextSequence
	replayed, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, firstStatus.Encoded)
	if err != nil || replayed != first || upgradeStatusBusinessPublishCount(jetstream.published) != publishedCount ||
		jetstream.nextSequence != lastSequence {
		t.Fatalf("historical replay=(%+v,%v) business publishes=%d last=%d", replayed, err,
			upgradeStatusBusinessPublishCount(jetstream.published), jetstream.nextSequence)
	}
}

func TestUpgradeStatusPublishFailsClosedOnScanSequenceBudget(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{nextSequence: testUpgradeStatusScanMaxSequences + 1,
		firstSequence: 1, last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	for sequence := uint64(1); sequence <= jetstream.nextSequence; sequence++ {
		seedUpgradeStatusRawMessage(t, jetstream, sequence, status)
	}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	replayed := distinctUpgradeStatusRecord(t, status, 2)
	before := upgradeStatusBusinessPublishCount(jetstream.published)
	if publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, replayed.Encoded); publication != (UpgradeStatusPublication{}) ||
		!errors.Is(err, errUpgradeStatusMigrationInProgress) || upgradeStatusBusinessPublishCount(jetstream.published) != before {
		t.Fatalf("sequence-budget migration=(%+v,%v) business publishes=%d", publication, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
	progress, found, err := bus.loadUpgradeStatusMigrationState(t.Context())
	if err != nil || !found || progress.Complete || progress.NextSequence != testUpgradeStatusScanMaxSequences+1 {
		t.Fatalf("sequence-budget progress=(%+v,found=%t,err=%v)", progress, found, err)
	}
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, replayed.Encoded)
	if err != nil || publication.Sequence == 0 || upgradeStatusBusinessPublishCount(jetstream.published) != before+1 {
		t.Fatalf("sequence-budget resume=(%+v,%v) business publishes=%d", publication, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
}

func TestUpgradeStatusPublishScanHandlesSparseFirstSequenceGap(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{nextSequence: 100, last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	seedUpgradeStatusRawMessage(t, jetstream, 100, status)
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	next := distinctUpgradeStatusRecord(t, status, 2)
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, next.Encoded)
	if err != nil || publication.Sequence <= 100 {
		t.Fatalf("sparse first sequence scan=(%+v,%v) last=%d", publication, err, jetstream.nextSequence)
	}
	requireUpgradeStatusV2Publication(t, jetstream, next, publication)
}

func TestUpgradeStatusPublishSkipsInternalHistoryGap(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{nextSequence: 3, firstSequence: 1,
		last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	seedUpgradeStatusRawMessage(t, jetstream, 1, distinctUpgradeStatusRecord(t, status, 1))
	seedUpgradeStatusRawMessage(t, jetstream, 3, status)
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil || publication.Sequence <= 3 || upgradeStatusBusinessPublishCount(jetstream.published) != 1 {
		t.Fatalf("internal history gap replay=(%+v,%v) business publishes=%d", publication, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
	requireUpgradeStatusV2Publication(t, jetstream, status, publication)
}

func TestUpgradeStatusPublishSkipsEvictedFirstSequence(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{nextSequence: 2, firstSequence: 1,
		last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	seedUpgradeStatusRawMessage(t, jetstream, 2, status)
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil || publication.Sequence <= 2 || upgradeStatusBusinessPublishCount(jetstream.published) != 1 {
		t.Fatalf("evicted first sequence replay=(%+v,%v) business publishes=%d", publication, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
	requireUpgradeStatusV2Publication(t, jetstream, status, publication)
}

func TestUpgradeStatusPublishFailsClosedOnScanByteBudget(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	var wire upgradeStatusWire
	if err := json.Unmarshal(status.Encoded, &wire); err != nil {
		t.Fatal(err)
	}
	wire.CurrentVersion = strings.Repeat("v", 120<<10)
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	status, err = decodeUpgradeStatusRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	jetstream := &upgradeProofJetStream{nextSequence: 70, firstSequence: 1,
		last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	for sequence := uint64(1); sequence <= jetstream.nextSequence; sequence++ {
		seedUpgradeStatusRawMessage(t, jetstream, sequence, status)
	}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	replayed := distinctUpgradeStatusRecord(t, status, 2)
	before := upgradeStatusBusinessPublishCount(jetstream.published)
	if publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, replayed.Encoded); publication != (UpgradeStatusPublication{}) ||
		!errors.Is(err, errUpgradeStatusMigrationInProgress) || upgradeStatusBusinessPublishCount(jetstream.published) != before {
		t.Fatalf("byte-budget migration=(%+v,%v) business publishes=%d", publication, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
	progress, found, err := bus.loadUpgradeStatusMigrationState(t.Context())
	if err != nil || !found || progress.Complete || progress.NextSequence <= 1 ||
		progress.NextSequence > progress.HorizonSequence {
		t.Fatalf("byte-budget progress=(%+v,found=%t,err=%v)", progress, found, err)
	}
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, replayed.Encoded)
	if err != nil || publication.Sequence == 0 || upgradeStatusBusinessPublishCount(jetstream.published) != before+1 {
		t.Fatalf("byte-budget resume=(%+v,%v) business publishes=%d", publication, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
}

func TestUpgradeStatusPublishValidatesConcurrentSameMessageIDConflicts(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	conflict := statusWithSameIDDifferentPayload(t, status)
	jetstream := &upgradeProofJetStream{}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, candidate := range []UpgradeStatusRecord{status, conflict} {
		candidate := candidate
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, candidate.Encoded)
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var successes, failures int
	for err := range results {
		if err == nil {
			successes++
		} else {
			failures++
		}
	}
	if published := upgradeStatusBusinessPublishCount(jetstream.published); successes != 1 || failures != 1 || published != 1 {
		t.Fatalf("same message ID conflict results successes=%d failures=%d business publishes=%d", successes, failures, published)
	}
}

func TestUpgradeStatusPublishRejectsCorruptAcknowledgedWire(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{corruptAckWire: true}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	if publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded); err == nil || publication != (UpgradeStatusPublication{}) {
		t.Fatalf("corrupt acknowledged wire accepted: publication=%+v err=%v", publication, err)
	}
}

func TestUpgradeStatusLegacyMigrationDoesNotIgnoreConflictBeyondSequenceBudget(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{nextSequence: testUpgradeStatusScanMaxSequences + 1, firstSequence: 1,
		last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	seedUpgradeStatusRawMessage(t, jetstream, 1, status)
	for sequence := uint64(2); sequence < jetstream.nextSequence; sequence++ {
		seedUpgradeStatusRawMessage(t, jetstream, sequence, distinctUpgradeStatusRecord(t, status, 2))
	}
	seedUpgradeStatusRawMessage(t, jetstream, jetstream.nextSequence, statusWithSameIDDifferentPayload(t, status))
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	requested := distinctUpgradeStatusRecord(t, status, 3)
	if publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, requested.Encoded); publication != (UpgradeStatusPublication{}) ||
		!errors.Is(err, errUpgradeStatusMigrationInProgress) {
		t.Fatalf("first conflict migration chunk=(%+v,%v)", publication, err)
	}
	before := upgradeStatusBusinessPublishCount(jetstream.published)
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, requested.Encoded)
	if err == nil || publication != (UpgradeStatusPublication{}) || upgradeStatusBusinessPublishCount(jetstream.published) != before {
		t.Fatalf("over-budget conflict=(%+v,err=%v,business publishes=%d)", publication, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
	progress, found, progressErr := bus.loadUpgradeStatusMigrationState(t.Context())
	if progressErr != nil || !found || progress.Complete || progress.NextSequence != testUpgradeStatusScanMaxSequences+1 {
		t.Fatalf("conflict progress=(%+v,found=%v,err=%v)", progress, found, progressErr)
	}
}

func TestUpgradeStatusPublishFailsClosedBeyondLegacyScanBudget(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{nextSequence: 5000, firstSequence: 1,
		last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	for sequence := uint64(1); sequence <= jetstream.nextSequence; sequence++ {
		seedUpgradeStatusRawMessage(t, jetstream, sequence, status)
	}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	next := distinctUpgradeStatusRecord(t, status, 2)
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, next.Encoded)
	if !errors.Is(err, errUpgradeStatusMigrationInProgress) || publication != (UpgradeStatusPublication{}) {
		t.Fatalf("large-history publish=(%+v,%v) last=%d", publication, err, jetstream.nextSequence)
	}
	progress, found, err := bus.loadUpgradeStatusMigrationState(t.Context())
	if err != nil || !found || progress.Complete || progress.HorizonSequence != 5000 ||
		progress.NextSequence != testUpgradeStatusScanMaxSequences+1 {
		t.Fatalf("large-history progress=(%+v,found=%t,err=%v)", progress, found, err)
	}
	publication, err = bus.PublishUpgradeStatus(t.Context(), command.NodeID, next.Encoded)
	if err != nil || publication.Sequence == 0 {
		t.Fatalf("large-history resume=(%+v,%v)", publication, err)
	}
}

func TestUpgradeStatusPublishResponseLossCannotBypassLegacyScanBudget(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{nextSequence: 5000, firstSequence: 1,
		last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{},
		publishErr: errors.New("response lost"), storeOnError: true}
	for sequence := uint64(1); sequence <= jetstream.nextSequence; sequence++ {
		seedUpgradeStatusRawMessage(t, jetstream, sequence, status)
	}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	next := distinctUpgradeStatusRecord(t, status, 2)
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, next.Encoded)
	if !errors.Is(err, errUpgradeStatusMigrationInProgress) || publication != (UpgradeStatusPublication{}) {
		t.Fatalf("response-loss legacy scan=(%+v,%v) last=%d", publication, err, jetstream.nextSequence)
	}
	progress, found, err := bus.loadUpgradeStatusMigrationState(t.Context())
	if err != nil || !found || progress.Complete || progress.NextSequence != testUpgradeStatusScanMaxSequences+1 {
		t.Fatalf("response-loss progress=(%+v,found=%t,err=%v)", progress, found, err)
	}
	publication, err = bus.PublishUpgradeStatus(t.Context(), command.NodeID, next.Encoded)
	if err != nil || publication.Sequence == 0 || upgradeStatusBusinessPublishCount(jetstream.published) != 1 {
		t.Fatalf("response-loss resume=(%+v,%v) business publishes=%d", publication, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
	replayed, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, next.Encoded)
	if err != nil || replayed != publication || upgradeStatusBusinessPublishCount(jetstream.published) != 1 {
		t.Fatalf("response-loss replay=(%+v,%v) business publishes=%d", replayed, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
}

func TestUpgradeStatusPublishRejectsHistoricalDuplicateStatusIDConflict(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	conflict := statusWithSameIDDifferentPayload(t, status)
	jetstream := &upgradeProofJetStream{nextSequence: 2, firstSequence: 1,
		last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	seedUpgradeStatusRawMessage(t, jetstream, 1, status)
	seedUpgradeStatusRawMessage(t, jetstream, 2, conflict)
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	requested := distinctUpgradeStatusRecord(t, status, 2)
	if publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, requested.Encoded); err == nil ||
		publication != (UpgradeStatusPublication{}) || upgradeStatusBusinessPublishCount(jetstream.published) != 0 {
		t.Fatalf("historical duplicate conflict accepted: publication=%+v err=%v", publication, err)
	}
}

func TestUpgradeStatusIdentityIndexMakesReplayO1AndRejectsConflict(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}

	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	identitySubject := upgradeStatusIdentitySubject(command.NodeID, status.StatusID)
	identity := jetstream.last[identitySubject]
	if identity == nil || identity.Sequence <= publication.Sequence {
		t.Fatalf("identity index=%+v publication=%+v", identity, publication)
	}
	state, err := decodeUpgradeStatusIdentityMessage(identity, command.NodeID, status)
	if err != nil || state.Publication != publication || state.ReservationSequence == 0 ||
		state.ReservationSequence >= publication.Sequence || publication.Sequence >= identity.Sequence {
		t.Fatalf("identity index is invalid: %v", err)
	}
	if err := decodeUpgradeStatusReservationMessage(jetstream.history[state.ReservationSequence], command.NodeID, status); err != nil {
		t.Fatalf("identity reservation is invalid: %v", err)
	}

	publishedCount := len(jetstream.published)
	replayed, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil || replayed != publication || len(jetstream.published) != publishedCount {
		t.Fatalf("identity replay=(%+v,%v) publishes=%d want=%+v/%d", replayed, err, len(jetstream.published), publication, publishedCount)
	}

	conflict := statusWithSameIDDifferentPayload(t, status)
	if _, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, conflict.Encoded); err == nil {
		t.Fatal("same StatusID with a different payload was accepted")
	}
}

func TestUpgradeStatusLegacyV1IdentityProofRemainsReadable(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{nextSequence: 2, firstSequence: 1,
		last: map[string]*nats.RawStreamMsg{}, history: map[uint64]*nats.RawStreamMsg{}}
	seedUpgradeStatusRawMessage(t, jetstream, 1, status)
	wire := upgradeStatusIdentityWire{
		Schema: legacyUpgradeStatusIdentitySchema, NodeID: command.NodeID, StatusID: status.StatusID,
		StatusRevision: status.StatusRevision, CommandID: status.CommandID, PlanID: status.PlanID,
		PlanRevision: status.PlanRevision, InstallationID: status.InstallationID,
		StatusSHA256: hex.EncodeToString(status.SHA256[:]), PublishedStream: UpgradeStatusStream,
		PublishedSequence: 1, Status: append([]byte(nil), status.Encoded...),
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	subject := upgradeStatusIdentitySubject(command.NodeID, status.StatusID)
	header := make(nats.Header)
	header.Set(nats.MsgIdHdr, "gateway-upgrade-status-identity-v1-"+hex.EncodeToString(digest[:]))
	header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(digest[:]))
	header.Set(UpgradeMessageKeyHeader, status.StatusID)
	identity := &nats.RawStreamMsg{Subject: subject, Sequence: 2, Header: header, Data: encoded}
	jetstream.last[subject] = identity
	jetstream.history[2] = identity
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}

	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil || publication.Sequence <= 2 || upgradeStatusBusinessPublishCount(jetstream.published) != 1 {
		t.Fatalf("legacy v1 identity replay=(%+v,%v) business publishes=%d", publication, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
	requireUpgradeStatusV2Publication(t, jetstream, status, publication)
	publishedCount := upgradeStatusBusinessPublishCount(jetstream.published)
	replayed, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil || replayed != publication || upgradeStatusBusinessPublishCount(jetstream.published) != publishedCount {
		t.Fatalf("legacy v1 canonical replay=(%+v,%v) business publishes=%d", replayed, err,
			upgradeStatusBusinessPublishCount(jetstream.published))
	}
}

func TestUpgradeStatusReceiptHelpersTypedNilDependenciesFailClosed(t *testing.T) {
	record := receiptTestUpgradeStatusAckRecord(t)
	receipt := receiptTestUpgradeStatusAckReceipt(t, record)
	digest, err := upgradeStatusAckSHA256(record.Ack)
	if err != nil {
		t.Fatal(err)
	}
	assertErrorWithoutPanic := func(name string, call func() error) {
		t.Helper()
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("%s panicked: %v", name, recovered)
			}
		}()
		if err := call(); err == nil {
			t.Fatalf("%s accepted a nil dependency", name)
		}
	}
	testBus := func(name string, bus *NATSUpgradeCommandBus, ctx context.Context) {
		t.Helper()
		assertErrorWithoutPanic(name+" list", func() error {
			_, err := bus.listUpgradeStatusAcks(ctx, record.NodeID, 1)
			return err
		})
		assertErrorWithoutPanic(name+" completion", func() error {
			_, err := bus.ensureUpgradeCommandCompletion(ctx, record)
			return err
		})
		assertErrorWithoutPanic(name+" ledger publish", func() error {
			_, err := bus.publishUpgradeStatusAckLedger(ctx, record.NodeID, nil, 0, 1)
			return err
		})
		assertErrorWithoutPanic(name+" confirmation load", func() error {
			_, _, _, err := bus.loadUpgradeStatusAckConfirmation(ctx, record.NodeID, digest)
			return err
		})
		assertErrorWithoutPanic(name+" confirmation publish", func() error {
			_, _, err := bus.publishUpgradeStatusAckConfirmation(ctx, record, receipt, digest)
			return err
		})
	}

	testBus("nil receiver", nil, context.Background())
	var nilJetStream *upgradeProofJetStream
	testBus("typed-nil JetStream", &NATSUpgradeCommandBus{js: nilJetStream, operationTimeout: time.Second}, context.Background())
	testBus("typed-nil context", &NATSUpgradeCommandBus{js: &upgradeProofJetStream{}, operationTimeout: time.Second}, typedNilUpgradeContext())
}

func seedUpgradeStatusRawMessage(t *testing.T, jetstream *upgradeProofJetStream, sequence uint64, status UpgradeStatusRecord) {
	t.Helper()
	message := nats.NewMsg(UpgradeStatusSubjectPrefix + "." + status.NodeID)
	message.Data = append([]byte(nil), status.Encoded...)
	message.Header.Set(nats.MsgIdHdr, status.StatusID)
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	message.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(status.SHA256[:]))
	message.Header.Set(UpgradeMessageKeyHeader, status.StatusID)
	raw := &nats.RawStreamMsg{Subject: message.Subject, Sequence: sequence, Header: cloneUpgradeHeader(message.Header),
		Data: append([]byte(nil), message.Data...)}
	jetstream.last[message.Subject] = raw
	jetstream.history[sequence] = raw
	if jetstream.messageIDs == nil {
		jetstream.messageIDs = make(map[string]uint64)
	}
	jetstream.messageIDs[status.StatusID] = sequence
}

func statusWithSameIDDifferentPayload(t *testing.T, base UpgradeStatusRecord) UpgradeStatusRecord {
	t.Helper()
	var wire upgradeStatusWire
	if err := json.Unmarshal(base.Encoded, &wire); err != nil {
		t.Fatal(err)
	}
	wire.CurrentVersion += "-conflict"
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeUpgradeStatusRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestUpgradeStatusAckLedgerAndConfirmationUseImmutableExactWire(t *testing.T) {
	jetstream := &upgradeProofJetStream{}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	record := publishedNonterminalUpgradeStatusAckRecord(t, bus, validUpgradeCommandRecord(t), 1, "")
	jetstream.published = nil

	stored, err := bus.saveUpgradeStatusAck(t.Context(), record, 2)
	if err != nil || !sameUpgradeStatusAckRecord(stored, record) {
		t.Fatalf("save=(%+v,%v)", stored, err)
	}
	ledgerSubject := upgradeStatusAckLedgerSubject(record.NodeID)
	ledger := jetstream.last[ledgerSubject]
	if ledger == nil || ledger.Subject != "cdnca.agent.deployment-status.upgrade-proof.pending."+record.NodeID {
		t.Fatalf("ledger subject=%+v", ledger)
	}
	payloadDigest := sha256.Sum256(ledger.Data)
	if !exactUpgradeHeaders(ledger.Header, map[string]string{
		nats.MsgIdHdr:          "gateway-upgrade-status-ack-ledger-v1-" + hex.EncodeToString(payloadDigest[:]),
		nats.ExpectedStreamHdr: UpgradeStatusStream, nats.ExpectedLastSubjSeqHdr: "0",
		UpgradePayloadSHA256Header: hex.EncodeToString(payloadDigest[:]), UpgradeMessageKeyHeader: record.NodeID,
	}) {
		t.Fatalf("ledger headers=%v", ledger.Header)
	}

	changedTime := cloneUpgradeStatusAckRecord(record)
	changedTime.Ack.PersistedTime.Seconds++
	replayed, err := bus.saveUpgradeStatusAck(t.Context(), changedTime, 2)
	if err != nil || !sameUpgradeStatusAckRecord(replayed, stored) || len(jetstream.published) != 1 {
		t.Fatalf("ledger replay=(%+v,%v) publishes=%d", replayed, err, len(jetstream.published))
	}

	receipt := receiptTestUpgradeStatusAckReceipt(t, record)
	confirmed, err := bus.confirmUpgradeStatusAck(t.Context(), record.NodeID, receipt, 2)
	if err != nil || !proto.Equal(confirmed, receipt) {
		t.Fatalf("confirmation=(%+v,%v)", confirmed, err)
	}
	digest, err := upgradeStatusAckSHA256(record.Ack)
	if err != nil {
		t.Fatal(err)
	}
	confirmationSubject := upgradeStatusAckConfirmationSubject(record.NodeID, digest)
	proof := jetstream.last[confirmationSubject]
	if proof == nil || proof.Subject != "cdnca.agent.deployment-status.upgrade-proof.confirmed."+record.NodeID+"."+hex.EncodeToString(digest[:]) {
		t.Fatalf("confirmation proof=%+v", proof)
	}
	if len(jetstream.published) != 3 || jetstream.published[1].Subject != confirmationSubject || jetstream.published[2].Subject != ledgerSubject {
		t.Fatalf("confirmation order=%v", upgradePublishedSubjects(jetstream.published))
	}
	pending, err := bus.listUpgradeStatusAcks(t.Context(), record.NodeID, 2)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after confirmation=%+v err=%v", pending, err)
	}

	before := len(jetstream.published)
	reconfirmed, err := bus.confirmUpgradeStatusAck(t.Context(), record.NodeID, receipt, 2)
	if err != nil || !proto.Equal(reconfirmed, receipt) || len(jetstream.published) != before {
		t.Fatalf("reconfirmation=(%+v,%v) publishes=%d want=%d", reconfirmed, err, len(jetstream.published), before)
	}
}

func TestUpgradeProofPublicationBindsPubAckSequenceToExactWire(t *testing.T) {
	jetstream := &upgradeProofJetStream{}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	message := nats.NewMsg(UpgradeStatusProofSubjectPrefix + ".pending.00000000-0000-4000-8000-000000000014")
	message.Data = []byte(`{"schema":"proof"}`)
	message.Header.Set(nats.MsgIdHdr, "proof-message")
	message.Header.Set(nats.ExpectedStreamHdr, UpgradeStatusStream)
	ack, err := jetstream.PublishMsg(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := bus.validateUpgradeProofPublication(t.Context(), ack, message); err != nil {
		t.Fatalf("exact proof PubAck rejected: %v", err)
	}
	wrongSequence := *ack
	wrongSequence.Sequence++
	if err := bus.validateUpgradeProofPublication(t.Context(), &wrongSequence, message); err == nil {
		t.Fatal("wrong proof PubAck sequence was accepted")
	}
	jetstream.history[ack.Sequence].Data = []byte("conflict")
	if err := bus.validateUpgradeProofPublication(t.Context(), ack, message); err == nil {
		t.Fatal("conflicting proof PubAck wire was accepted")
	}
}

func TestUpgradeStatusAckConfirmationMismatchCannotDiscardPending(t *testing.T) {
	jetstream := &upgradeProofJetStream{}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	record := publishedNonterminalUpgradeStatusAckRecord(t, bus, validUpgradeCommandRecord(t), 1, "")
	if _, err := bus.saveUpgradeStatusAck(t.Context(), record, 1); err != nil {
		t.Fatal(err)
	}
	before := len(jetstream.published)
	receipt := receiptTestUpgradeStatusAckReceipt(t, record)
	receipt.StatusRevision++
	if _, err := bus.confirmUpgradeStatusAck(t.Context(), record.NodeID, receipt, 1); err == nil {
		t.Fatal("mismatched receipt was confirmed")
	}
	pending, err := bus.listUpgradeStatusAcks(t.Context(), record.NodeID, 1)
	if err != nil || len(pending) != 1 || len(jetstream.published) != before {
		t.Fatalf("mismatch changed durable state: pending=%d publishes=%d err=%v", len(pending), len(jetstream.published), err)
	}
}

func TestUpgradeStatusAckProofRecoversAfterPublishResponseLoss(t *testing.T) {
	jetstream := &upgradeProofJetStream{}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	record := publishedNonterminalUpgradeStatusAckRecord(t, bus, validUpgradeCommandRecord(t), 1, "")
	if _, err := bus.saveUpgradeStatusAck(t.Context(), record, 1); err != nil {
		t.Fatal(err)
	}

	jetstream.publishErr = errors.New("response lost")
	jetstream.storeOnError = true
	receipt := receiptTestUpgradeStatusAckReceipt(t, record)
	confirmed, err := bus.confirmUpgradeStatusAck(t.Context(), record.NodeID, receipt, 1)
	if err != nil || !proto.Equal(confirmed, receipt) {
		t.Fatalf("response-loss confirmation=(%+v,%v)", confirmed, err)
	}
	pending, err := bus.listUpgradeStatusAcks(t.Context(), record.NodeID, 1)
	if err != nil || len(pending) != 0 {
		t.Fatalf("response-loss pending=%+v err=%v", pending, err)
	}
}

func TestUpgradeCommandCompletionProofSurvivesAckConfirmation(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, statusRecord.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	jetstream.nextSequence = testUpgradeStatusScanMaxSequences + 100
	record := upgradeStatusAckRecord{NodeID: command.NodeID, InstallationID: command.InstallationID, Ack: &agentv1.UpgradeStatusAck{
		StatusEventId: statusRecord.StatusID, CommandId: statusRecord.CommandID, StatusRevision: statusRecord.StatusRevision,
		StatusSha256: append([]byte(nil), statusRecord.SHA256[:]...), PersistedTime: timestamppb.Now(),
		PublishedStream: publication.Stream, PublishedSequence: publication.Sequence,
	}}
	stored, err := bus.saveUpgradeStatusAck(t.Context(), record, 2)
	if err != nil {
		t.Fatal(err)
	}
	lookup, ok := any(bus).(interface {
		hasCompletedUpgradeCommand(context.Context, UpgradeCommandRecord, int) (bool, error)
	})
	if !ok {
		t.Fatal("upgrade command completion lookup is unavailable")
	}
	completed, err := lookup.hasCompletedUpgradeCommand(t.Context(), command, 2)
	if err != nil || !completed {
		t.Fatalf("pending completion=(%t,%v)", completed, err)
	}
	receipt := receiptTestUpgradeStatusAckReceipt(t, stored)
	if _, err := bus.confirmUpgradeStatusAck(t.Context(), command.NodeID, receipt, 2); err != nil {
		t.Fatal(err)
	}
	completed, err = lookup.hasCompletedUpgradeCommand(t.Context(), command, 2)
	if err != nil || !completed {
		t.Fatalf("confirmed completion=(%t,%v)", completed, err)
	}
	var crossWire upgradeCommandWire
	if err := json.Unmarshal(command.Encoded, &crossWire); err != nil {
		t.Fatal(err)
	}
	crossWire.InstallationID = "00000000-0000-4000-8000-000000000099"
	crossEncoded, err := json.Marshal(crossWire)
	if err != nil {
		t.Fatal(err)
	}
	crossCommand, err := decodeUpgradeCommandRecord(crossEncoded)
	if err != nil {
		t.Fatal(err)
	}
	completed, err = lookup.hasCompletedUpgradeCommand(t.Context(), crossCommand, 2)
	if err != nil || completed {
		t.Fatalf("cross-installation completion=(%t,%v)", completed, err)
	}
	completionSubject := UpgradeStatusProofSubjectPrefix + ".completed." + command.NodeID + "." +
		command.InstallationID + "." + command.CommandID
	if len(jetstream.published) != 5 || jetstream.published[2].Subject != completionSubject ||
		jetstream.published[3].Subject != upgradeStatusAckConfirmationSubject(
			command.NodeID, mustUpgradeStatusAckDigest(t, stored.Ack),
		) {
		t.Fatalf("completion durability order=%v", upgradePublishedSubjects(jetstream.published))
	}
}

func TestUpgradeStatusAckRecoveryRepairsCompletionBeforeReplay(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	jetstream := &upgradeProofJetStream{}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, statusRecord.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	record := upgradeStatusAckRecord{NodeID: command.NodeID, InstallationID: command.InstallationID, Ack: &agentv1.UpgradeStatusAck{
		StatusEventId: statusRecord.StatusID, CommandId: statusRecord.CommandID, StatusRevision: statusRecord.StatusRevision,
		StatusSha256: append([]byte(nil), statusRecord.SHA256[:]...), PersistedTime: timestamppb.Now(),
		PublishedStream: publication.Stream, PublishedSequence: publication.Sequence,
	}}
	if _, err := bus.publishUpgradeStatusAckLedger(t.Context(), command.NodeID, []upgradeStatusAckRecord{record}, 0, 2); err != nil {
		t.Fatal(err)
	}
	completionSubject := upgradeCommandCompletionSubject(command.NodeID, command.InstallationID, command.CommandID)
	if jetstream.last[completionSubject] != nil {
		t.Fatal("ledger-only crash fixture already has a completion proof")
	}
	recovered, err := bus.listUpgradeStatusAcks(t.Context(), command.NodeID, 2)
	if err != nil || len(recovered) != 1 || !sameUpgradeStatusAckRecord(recovered[0], record) ||
		jetstream.last[completionSubject] == nil {
		t.Fatalf("recovery records=%+v completion=%+v err=%v", recovered, jetstream.last[completionSubject], err)
	}
}

func TestUpgradeStatusAckCASConcurrencyPreservesRecords(t *testing.T) {
	jetstream := &upgradeProofJetStream{}
	bus := &NATSUpgradeCommandBus{js: jetstream, operationTimeout: time.Second}
	command := validUpgradeCommandRecord(t)
	first := publishedNonterminalUpgradeStatusAckRecord(t, bus, command, 1, "")
	second := publishedNonterminalUpgradeStatusAckRecord(t, bus, command, 2, "")

	results := concurrentlySaveUpgradeStatusAcks(t, jetstream, bus, 4, first, second)
	for index, result := range results {
		if result != nil {
			candidate := []upgradeStatusAckRecord{first, second}[index]
			if _, err := bus.saveUpgradeStatusAck(t.Context(), candidate, 4); err != nil {
				t.Fatalf("CAS loser retry %d: %v", index, err)
			}
		}
	}
	records, err := bus.listUpgradeStatusAcks(t.Context(), first.NodeID, 4)
	if err != nil || len(records) != 2 {
		t.Fatalf("double append records=%d err=%v", len(records), err)
	}

	third := publishedNonterminalUpgradeStatusAckRecord(t, bus, command, 3, "")
	firstReceipt := receiptTestUpgradeStatusAckReceipt(t, first)
	barrier := newUpgradePublishBarrier(2, func(message *nats.Msg) bool {
		return message.Subject == upgradeStatusAckLedgerSubject(first.NodeID)
	})
	jetstream.beforePublish = barrier.wait
	var confirmErr, appendErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, confirmErr = bus.confirmUpgradeStatusAck(t.Context(), first.NodeID, firstReceipt, 4)
	}()
	go func() {
		defer wait.Done()
		_, appendErr = bus.saveUpgradeStatusAck(t.Context(), third, 4)
	}()
	wait.Wait()
	jetstream.beforePublish = nil
	if confirmErr != nil {
		if _, err := bus.confirmUpgradeStatusAck(t.Context(), first.NodeID, firstReceipt, 4); err != nil {
			t.Fatalf("confirm-vs-append confirm retry: %v", err)
		}
	}
	if appendErr != nil {
		if _, err := bus.saveUpgradeStatusAck(t.Context(), third, 4); err != nil {
			t.Fatalf("confirm-vs-append append retry: %v", err)
		}
	}
	records, err = bus.listUpgradeStatusAcks(t.Context(), first.NodeID, 4)
	if err != nil || len(records) != 2 || !containsUpgradeStatusAck(records, second) || !containsUpgradeStatusAck(records, third) {
		t.Fatalf("confirm-vs-append records=%+v err=%v", records, err)
	}

	secondReceipt := receiptTestUpgradeStatusAckReceipt(t, second)
	barrier = newUpgradePublishBarrier(2, func(message *nats.Msg) bool {
		return message.Subject == upgradeStatusAckConfirmationSubject(first.NodeID, mustUpgradeStatusAckDigest(t, second.Ack))
	})
	jetstream.beforePublish = barrier.wait
	confirmResults := make([]error, 2)
	wait.Add(2)
	for index := range confirmResults {
		go func(index int) {
			defer wait.Done()
			_, confirmResults[index] = bus.confirmUpgradeStatusAck(t.Context(), first.NodeID, secondReceipt, 4)
		}(index)
	}
	wait.Wait()
	jetstream.beforePublish = nil
	for index, result := range confirmResults {
		if result != nil {
			if _, err := bus.confirmUpgradeStatusAck(t.Context(), first.NodeID, secondReceipt, 4); err != nil {
				t.Fatalf("double confirm retry %d: %v", index, err)
			}
		}
	}
	records, err = bus.listUpgradeStatusAcks(t.Context(), first.NodeID, 4)
	if err != nil || len(records) != 1 || !containsUpgradeStatusAck(records, third) {
		t.Fatalf("double confirm records=%+v err=%v", records, err)
	}

	crossInstallation := publishedNonterminalUpgradeStatusAckRecord(
		t, bus, command, 4, "00000000-0000-4000-8000-000000000099",
	)
	if _, err := bus.saveUpgradeStatusAck(t.Context(), crossInstallation, 4); err != nil {
		t.Fatal(err)
	}
	thirdReceipt := receiptTestUpgradeStatusAckReceipt(t, third)
	if _, err := bus.confirmUpgradeStatusAck(t.Context(), first.NodeID, thirdReceipt, 4); err != nil {
		t.Fatal(err)
	}
	records, err = bus.listUpgradeStatusAcks(t.Context(), first.NodeID, 4)
	if err != nil || len(records) != 1 || !sameUpgradeStatusAckRecord(records[0], crossInstallation) {
		t.Fatalf("cross-installation record lost: records=%+v err=%v", records, err)
	}

	limitedJetStream := &upgradeProofJetStream{}
	limitedBus := &NATSUpgradeCommandBus{js: limitedJetStream, operationTimeout: time.Second}
	limitedFirst := publishedNonterminalUpgradeStatusAckRecord(t, limitedBus, command, 5, "")
	limitedSecond := publishedNonterminalUpgradeStatusAckRecord(t, limitedBus, command, 6, "")
	limitResults := concurrentlySaveUpgradeStatusAcks(t, limitedJetStream, limitedBus, 1, limitedFirst, limitedSecond)
	successes := 0
	for index, result := range limitResults {
		if result == nil {
			successes++
			continue
		}
		candidate := []upgradeStatusAckRecord{limitedFirst, limitedSecond}[index]
		_, retryErr := limitedBus.saveUpgradeStatusAck(t.Context(), candidate, 1)
		if !errors.Is(retryErr, errUpgradeStatusAckLimit) {
			t.Fatalf("limit loser retry %d: %v", index, retryErr)
		}
	}
	limitedRecords, err := limitedBus.listUpgradeStatusAcks(t.Context(), first.NodeID, 1)
	if err != nil || successes != 1 || len(limitedRecords) != 1 {
		t.Fatalf("limit competition successes=%d records=%d err=%v", successes, len(limitedRecords), err)
	}
}

type upgradePublishBarrier struct {
	remaining atomic.Int32
	released  chan struct{}
	match     func(*nats.Msg) bool
}

func newUpgradePublishBarrier(count int32, match func(*nats.Msg) bool) *upgradePublishBarrier {
	barrier := &upgradePublishBarrier{released: make(chan struct{}), match: match}
	barrier.remaining.Store(count)
	return barrier
}

func (b *upgradePublishBarrier) wait(message *nats.Msg) {
	if !b.match(message) {
		return
	}
	if b.remaining.Add(-1) == 0 {
		close(b.released)
	}
	<-b.released
}

func concurrentlySaveUpgradeStatusAcks(t *testing.T, jetstream *upgradeProofJetStream, bus *NATSUpgradeCommandBus,
	limit int, records ...upgradeStatusAckRecord,
) []error {
	t.Helper()
	barrier := newUpgradePublishBarrier(int32(len(records)), func(message *nats.Msg) bool {
		return message.Subject == upgradeStatusAckLedgerSubject(records[0].NodeID)
	})
	jetstream.beforePublish = barrier.wait
	results := make([]error, len(records))
	var wait sync.WaitGroup
	wait.Add(len(records))
	for index, record := range records {
		go func(index int, record upgradeStatusAckRecord) {
			defer wait.Done()
			_, results[index] = bus.saveUpgradeStatusAck(t.Context(), record, limit)
		}(index, record)
	}
	wait.Wait()
	jetstream.beforePublish = nil
	return results
}

func publishedNonterminalUpgradeStatusAckRecord(t *testing.T, bus *NATSUpgradeCommandBus,
	command UpgradeCommandRecord, revision uint64, installationID string,
) upgradeStatusAckRecord {
	t.Helper()
	status := validUpgradeStatusRecord(t, command)
	var wire upgradeStatusWire
	if err := json.Unmarshal(status.Encoded, &wire); err != nil {
		t.Fatal(err)
	}
	wire.StatusID = fmt.Sprintf("00000000-0000-4000-8000-%012d", 200+revision)
	wire.StatusRevision = revision
	wire.State = "installing"
	if installationID != "" {
		wire.InstallationID = installationID
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	status, err = decodeUpgradeStatusRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := bus.PublishUpgradeStatus(t.Context(), command.NodeID, status.Encoded)
	if err != nil {
		t.Fatal(err)
	}
	return upgradeStatusAckRecord{NodeID: command.NodeID, InstallationID: status.InstallationID, Ack: &agentv1.UpgradeStatusAck{
		StatusEventId: status.StatusID, CommandId: status.CommandID, StatusRevision: status.StatusRevision,
		StatusSha256: append([]byte(nil), status.SHA256[:]...), PersistedTime: timestamppb.Now(),
		PublishedStream: publication.Stream, PublishedSequence: publication.Sequence,
	}}
}

func containsUpgradeStatusAck(records []upgradeStatusAckRecord, candidate upgradeStatusAckRecord) bool {
	for _, record := range records {
		if sameUpgradeStatusAckRecord(record, candidate) {
			return true
		}
	}
	return false
}

func mustUpgradeStatusAckDigest(t *testing.T, ack *agentv1.UpgradeStatusAck) [sha256.Size]byte {
	t.Helper()
	digest, err := upgradeStatusAckSHA256(ack)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func distinctUpgradeStatusRecord(t *testing.T, base UpgradeStatusRecord, revision uint64) UpgradeStatusRecord {
	t.Helper()
	var wire upgradeStatusWire
	if err := json.Unmarshal(base.Encoded, &wire); err != nil {
		t.Fatal(err)
	}
	wire.StatusID = "00000000-0000-4000-8000-0000000000" + strconv.FormatUint(21+revision, 10)
	wire.StatusRevision = revision
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeUpgradeStatusRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func cloneUpgradeHeader(source nats.Header) nats.Header {
	result := make(nats.Header, len(source))
	for name, values := range source {
		result[name] = append([]string(nil), values...)
	}
	return result
}

func cloneUpgradeRawMessage(source *nats.RawStreamMsg) *nats.RawStreamMsg {
	if source == nil {
		return nil
	}
	return &nats.RawStreamMsg{Subject: source.Subject, Sequence: source.Sequence, Header: cloneUpgradeHeader(source.Header),
		Data: append([]byte(nil), source.Data...), Time: source.Time}
}

func upgradePublishedSubjects(messages []*nats.Msg) []string {
	result := make([]string, 0, len(messages))
	for _, message := range messages {
		result = append(result, message.Subject)
	}
	return result
}
