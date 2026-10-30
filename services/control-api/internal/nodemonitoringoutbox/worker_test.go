package nodemonitoringoutbox

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type workerStoreStub struct {
	commands  []Command
	published []Command
	released  []string
	failed    []string
}

func (stub *workerStoreStub) ClaimCommands(context.Context, uuid.UUID, int, time.Duration) ([]Command, error) {
	commands := stub.commands
	stub.commands = nil
	return commands, nil
}

func (stub *workerStoreStub) MarkPublished(_ context.Context, command Command, stream string, sequence uint64) error {
	if stream != CommandStream || sequence == 0 {
		return ErrConflict
	}
	stub.published = append(stub.published, command)
	return nil
}

func (stub *workerStoreStub) ReleaseCommand(_ context.Context, command Command, _ time.Time, errorCode string) error {
	stub.released = append(stub.released, errorCode)
	return nil
}

func (stub *workerStoreStub) FailCommand(_ context.Context, command Command, errorCode string) error {
	stub.failed = append(stub.failed, errorCode)
	return nil
}

type workerPublisherStub struct {
	ack publishAck
	err error
}

func (stub *workerPublisherStub) Publish(context.Context, Command) (publishAck, error) {
	return stub.ack, stub.err
}

func validWorkerCommand(t *testing.T) Command {
	t.Helper()
	nodeID := uuid.MustParse("01990000-0000-7000-8000-000000000001")
	eventID := uuid.MustParse("01990000-0000-7000-8000-000000000002")
	config := []byte(`{"schema_version":"cdnca.node-monitoring/v1","config_revision":7}`)
	configDigest := sha256.Sum256(config)
	artifact := &agentv1.NodeMonitoringArtifact{
		Event: &commonv1.EventMetadata{
			EventId: eventID.String(), RequestId: uuid.New().String(),
			OccurredTime: timestamppb.New(time.Unix(10, 0).UTC()),
		},
		Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1, NodeId: nodeID.String(),
		ConfigRevision: 7, PublicationSequence: 7, CanonicalConfigJson: config, ConfigSha256: configDigest[:],
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(payload)
	return Command{ID: eventID, NodeID: nodeID, ConfigRevision: 7,
		Subject: CommandSubjectBase + "." + nodeID.String(), MessageID: CommandMessagePrefix + eventID.String(),
		Payload: payload, PayloadSHA256: payloadDigest[:], ClaimToken: uuid.New(), AttemptCount: 1}
}

func workerConfig() Config {
	config := DefaultConfig()
	config.Clock = func() time.Time { return time.Unix(100, 0).UTC() }
	return config
}

func TestPublisherPublishesAndRecordsDuplicatePubAck(t *testing.T) {
	command := validWorkerCommand(t)
	store := &workerStoreStub{commands: []Command{command}}
	publisher, err := newPublisher(store, &workerPublisherStub{
		ack: publishAck{stream: CommandStream, sequence: 42, duplicate: true},
	}, workerConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.PublishBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Claimed != 1 || result.Published != 1 || result.Duplicates != 1 || len(store.published) != 1 {
		t.Fatalf("result=%#v published=%d", result, len(store.published))
	}
}

func TestPublisherFailsInvalidPayloadWithoutPublishing(t *testing.T) {
	command := validWorkerCommand(t)
	command.Payload[0] ^= 1
	store := &workerStoreStub{commands: []Command{command}}
	publisher, err := newPublisher(store, &workerPublisherStub{
		ack: publishAck{stream: CommandStream, sequence: 42},
	}, workerConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.PublishBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.PermanentFailures != 1 || len(store.failed) != 1 || len(store.published) != 0 {
		t.Fatalf("result=%#v failed=%v published=%d", result, store.failed, len(store.published))
	}
}

func TestPublisherCountsTerminalPublishFailureAsPermanent(t *testing.T) {
	command := validWorkerCommand(t)
	config := workerConfig()
	config.MaxAttempts = command.AttemptCount
	store := &workerStoreStub{commands: []Command{command}}
	publisher, err := newPublisher(store, &workerPublisherStub{err: context.DeadlineExceeded}, config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.PublishBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.PermanentFailures != 1 || result.RetryableFailures != 0 || len(store.failed) != 1 || len(store.released) != 0 {
		t.Fatalf("result=%#v failed=%v released=%v", result, store.failed, store.released)
	}
}

func TestValidateCommandRejectsEmptyOrMismatchedArtifactConfig(t *testing.T) {
	command := validWorkerCommand(t)
	artifact := &agentv1.NodeMonitoringArtifact{}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(command.Payload, artifact); err != nil {
		t.Fatal(err)
	}
	artifact.CanonicalConfigJson = nil
	artifact.ConfigSha256 = sha256.New().Sum(nil)
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	command.Payload = payload
	digest := sha256.Sum256(payload)
	command.PayloadSHA256 = digest[:]
	if err := validateCommand(command, 1<<20); err == nil {
		t.Fatal("empty artifact configuration was accepted")
	}

	command = validWorkerCommand(t)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(command.Payload, artifact); err != nil {
		t.Fatal(err)
	}
	artifact.CanonicalConfigJson = []byte(`{"schema_version":"cdnca.node-monitoring/v1","config_revision":8}`)
	digest = sha256.Sum256(artifact.CanonicalConfigJson)
	artifact.ConfigSha256 = digest[:]
	payload, err = (proto.MarshalOptions{Deterministic: true}).Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	command.Payload = payload
	digest = sha256.Sum256(payload)
	command.PayloadSHA256 = digest[:]
	if err := validateCommand(command, 1<<20); err == nil {
		t.Fatal("mismatched artifact configuration revision was accepted")
	}
}

func TestValidateCommandBindsMessageAndSubject(t *testing.T) {
	command := validWorkerCommand(t)
	if err := validateCommand(command, 1<<20); err != nil {
		t.Fatal(err)
	}
	command.Subject += ".other"
	if err := validateCommand(command, 1<<20); err == nil {
		t.Fatal("subject mismatch was accepted")
	}
}
