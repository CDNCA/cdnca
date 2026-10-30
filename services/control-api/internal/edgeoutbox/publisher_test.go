package edgeoutbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var errInjected = errors.New("injected failure")

type failedRecord struct {
	id         uuid.UUID
	claimToken time.Time
	failure    failure
	backoff    time.Duration
	textLimit  int
}

type fakeStore struct {
	mu               sync.Mutex
	commands         []claimedCommand
	onClaim          func()
	claimErr         error
	markPublishedErr error
	markFailedErr    error
	published        []uuid.UUID
	failed           []failedRecord
	superseded       []uuid.UUID
}

func (s *fakeStore) markSuperseded(_ context.Context, id uuid.UUID, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.superseded = append(s.superseded, id)
	return nil
}

func (s *fakeStore) claim(context.Context, int, time.Duration) ([]claimedCommand, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.onClaim != nil {
		s.onClaim()
	}
	if s.claimErr != nil {
		return nil, s.claimErr
	}
	commands := append([]claimedCommand(nil), s.commands...)
	s.commands = nil
	return commands, nil
}

func (s *fakeStore) markPublished(_ context.Context, id uuid.UUID, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.markPublishedErr != nil {
		return s.markPublishedErr
	}
	s.published = append(s.published, id)
	return nil
}

func (s *fakeStore) markFailed(_ context.Context, id uuid.UUID, token time.Time, failed failure, backoff time.Duration, limit int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.markFailedErr != nil {
		return s.markFailedErr
	}
	s.failed = append(s.failed, failedRecord{id: id, claimToken: token, failure: failed, backoff: backoff, textLimit: limit})
	return nil
}

type publishCall struct {
	subject        string
	payload        []byte
	messageID      string
	expectedStream string
}

type fakeMessages struct {
	ack   publishAck
	err   error
	calls []publishCall
}

func (p *fakeMessages) publish(_ context.Context, subject string, payload []byte, messageID, expectedStream string) (publishAck, error) {
	p.calls = append(p.calls, publishCall{
		subject: subject, payload: bytes.Clone(payload), messageID: messageID, expectedStream: expectedStream,
	})
	return p.ack, p.err
}

func TestPublishBatchPublishesValidatedCommandAndAcceptsDuplicateAck(t *testing.T) {
	command := validClaim(t)
	store := &fakeStore{commands: []claimedCommand{command}}
	messages := &fakeMessages{ack: publishAck{stream: DefaultConfig().Stream, duplicate: true}}
	publisher := testPublisher(t, store, messages)
	result, err := publisher.PublishBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result != (BatchResult{Claimed: 1, Published: 1, Duplicates: 1}) {
		t.Fatalf("result = %+v", result)
	}
	if len(store.published) != 1 || store.published[0] != command.outboxID || len(store.failed) != 0 {
		t.Fatalf("published=%v failed=%v", store.published, store.failed)
	}
	if len(messages.calls) != 1 {
		t.Fatalf("publish calls = %d", len(messages.calls))
	}
	call := messages.calls[0]
	if call.subject != command.subject || call.messageID != command.commandEventID.String() ||
		call.expectedStream != DefaultConfig().Stream || !bytes.Equal(call.payload, command.payload) {
		t.Fatalf("unexpected publish call: %+v", call)
	}
}

func TestPublishBatchRejectsTamperedPayloadBeforeNATS(t *testing.T) {
	command := validClaim(t)
	command.payload = append(bytes.Clone(command.payload), 0)
	store := &fakeStore{commands: []claimedCommand{command}}
	messages := &fakeMessages{ack: publishAck{stream: DefaultConfig().Stream}}
	publisher := testPublisher(t, store, messages)
	result, err := publisher.PublishBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Claimed != 1 || result.PermanentFailures != 1 || len(messages.calls) != 0 || len(store.failed) != 1 {
		t.Fatalf("result=%+v calls=%d failures=%+v", result, len(messages.calls), store.failed)
	}
	if store.failed[0].failure.class != "integrity" || store.failed[0].failure.retryable {
		t.Fatalf("tamper disposition = %+v", store.failed[0].failure)
	}
}

func TestPublishBatchRejectsWrongPubAckStream(t *testing.T) {
	store := &fakeStore{commands: []claimedCommand{validClaim(t)}}
	messages := &fakeMessages{ack: publishAck{stream: "WRONG_STREAM"}}
	publisher := testPublisher(t, store, messages)
	result, err := publisher.PublishBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.PermanentFailures != 1 || len(store.published) != 0 || len(store.failed) != 1 {
		t.Fatalf("result=%+v published=%v failed=%+v", result, store.published, store.failed)
	}
	if got := store.failed[0].failure; got.class != "configuration" || got.code != "puback_stream_mismatch" || got.retryable {
		t.Fatalf("wrong-stream disposition = %+v", got)
	}
}

func TestPublishBatchPersistsRetryableFailureWithCappedBackoff(t *testing.T) {
	command := validClaim(t)
	command.publishAttempts = 100
	store := &fakeStore{commands: []claimedCommand{command}}
	messages := &fakeMessages{err: context.DeadlineExceeded}
	publisher := testPublisher(t, store, messages)
	result, err := publisher.PublishBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.RetryableFailures != 1 || len(store.failed) != 1 {
		t.Fatalf("result=%+v failures=%+v", result, store.failed)
	}
	if got := store.failed[0]; !got.failure.retryable || got.failure.code != "timeout" || got.backoff != DefaultConfig().MaxBackoff {
		t.Fatalf("retry disposition = %+v", got)
	}
}

func TestPublishBatchCancellationReleasesClaimWithoutPublishing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := &fakeStore{commands: []claimedCommand{validClaim(t)}, onClaim: cancel}
	messages := &fakeMessages{ack: publishAck{stream: DefaultConfig().Stream}}
	publisher := testPublisher(t, store, messages)
	result, err := publisher.PublishBatch(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if result.RetryableFailures != 1 || len(messages.calls) != 0 || len(store.failed) != 1 || !store.failed[0].failure.retryable {
		t.Fatalf("result=%+v calls=%d failed=%+v", result, len(messages.calls), store.failed)
	}
}

func TestPubAckDatabaseFailureLeavesClaimForStaleRecovery(t *testing.T) {
	store := &fakeStore{commands: []claimedCommand{validClaim(t)}, markPublishedErr: errInjected}
	messages := &fakeMessages{ack: publishAck{stream: DefaultConfig().Stream}}
	publisher := testPublisher(t, store, messages)
	result, err := publisher.PublishBatch(context.Background())
	if !errors.Is(err, errInjected) {
		t.Fatalf("error = %v, want injected failure", err)
	}
	if result.Claimed != 1 || result.Published != 0 || len(messages.calls) != 1 || len(store.failed) != 0 {
		t.Fatalf("result=%+v calls=%d failed=%+v", result, len(messages.calls), store.failed)
	}
}

func TestClassifyPublishErrorSeparatesConfigurationAndTransport(t *testing.T) {
	configuration := classifyPublishError(&nats.APIError{Code: 400, ErrorCode: 10060}, context.Background())
	if configuration.class != "configuration" || configuration.retryable {
		t.Fatalf("configuration failure = %+v", configuration)
	}
	transport := classifyPublishError(nats.ErrNoResponders, context.Background())
	if transport.class != "publish" || !transport.retryable {
		t.Fatalf("transport failure = %+v", transport)
	}
}

func TestValidateClaimRejectsFrozenIdentityMismatch(t *testing.T) {
	command := validClaim(t)
	decoded := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(command.payload, decoded); err != nil {
		t.Fatal(err)
	}
	decoded.DeploymentId = uuid.NewString()
	command.payload = deterministicCommand(t, decoded)
	digest := sha256.Sum256(command.payload)
	command.payloadSHA256 = digest[:]
	command.commandBytes = bytes.Clone(command.payload)
	command.commandSHA256 = bytes.Clone(digest[:])
	if _, failed := validateClaim(command, DefaultConfig().MaxPayloadBytes); failed.code != "deployment_command_identity_mismatch" {
		t.Fatalf("identity failure = %+v", failed)
	}
}

func testPublisher(t *testing.T, store outboxStore, messages messagePublisher) *Publisher {
	t.Helper()
	publisher, err := newPublisher(store, messages, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

func validClaim(t *testing.T) claimedCommand {
	t.Helper()
	outboxID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101")
	deploymentID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102")
	nodeID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103")
	eventID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7104")
	requestID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7105")
	correlationID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7106")
	rolloutID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7107")
	configVersionID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7108")
	traceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	taskID := "edge-rollout:018f47a2-5b9c-7d31-8a60-104c9c0b7107"
	command := &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{
			EventId: eventID.String(), RequestId: requestID.String(), Traceparent: traceparent,
			CorrelationId: correlationID.String(), TaskId: &taskID,
			OccurredTime: timestamppb.New(time.Unix(1_700_000_000, 0)),
		},
		DeploymentId: deploymentID.String(), Attempt: 1,
		RolloutId:       rolloutID.String(),
		ConfigVersionId: configVersionID.String(),
		Action:          agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		DeadlineTime:    timestamppb.New(time.Unix(1_800_000_000, 0)),
	}
	payload := deterministicCommand(t, command)
	digest := sha256.Sum256(payload)
	return claimedCommand{
		outboxID: outboxID, deploymentID: deploymentID, deploymentAttempt: 1,
		nodeID: nodeID, subject: CommandSubjectPrefix + "." + nodeID.String(),
		payload: bytes.Clone(payload), payloadSHA256: bytes.Clone(digest[:]), publishAttempts: 1,
		claimToken: time.Unix(1_700_000_001, 0).UTC(), commandEventID: eventID,
		deploymentNodeID: nodeID, rolloutID: rolloutID, configVersionID: configVersionID,
		commandBytes: bytes.Clone(payload), commandSHA256: bytes.Clone(digest[:]),
	}
}

func deterministicCommand(t *testing.T, command *agentv1.DeploymentCommand) []byte {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
