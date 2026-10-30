package gatewayclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

const correlationJournalTraceparent = "00-11111111111111111111111111111111-2222222222222222-01"

func TestDeploymentJournalPreservesCorrelationIdentityAcrossRestart(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command, _ := signedTestCommand(t, privateKey)
	taskID := "edge-activation-task"
	command.Event.Traceparent = correlationJournalTraceparent
	command.Event.TaskId = &taskID

	directory := filepath.Join(secureTempDir(t), "correlation-journal")
	store, err := newDurableStore(directory, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	record, created, err := store.putCommand(command, deliveredStatus(command))
	if err != nil || !created {
		t.Fatalf("putCommand() = (%+v, %t, %v)", record, created, err)
	}
	terminal := statusFor(command, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		time.Now().UTC(), false, "", "", time.Second)
	if err := store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{terminal}, true); err != nil {
		t.Fatal(err)
	}

	restarted, err := newDurableStore(directory, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	records, err := restarted.records()
	if err != nil || len(records) != 1 {
		t.Fatalf("restarted records = (%d, %v)", len(records), err)
	}
	persistedCommand := commandFromBytes(records[0].Command)
	statuses, err := statusesFromRecord(records[0])
	if err != nil || len(statuses) != 2 {
		t.Fatalf("restarted statuses = (%d, %v)", len(statuses), err)
	}
	if !proto.Equal(persistedCommand.Event, command.Event) {
		t.Fatalf("persisted command event = %+v, want %+v", persistedCommand.Event, command.Event)
	}
	for index, status := range statuses {
		if status.Event.RequestId != command.Event.RequestId || status.Event.Traceparent != command.Event.Traceparent ||
			status.Event.CorrelationId != command.Event.CorrelationId || status.Event.GetTaskId() != taskID {
			t.Fatalf("replayed status %d lost correlation identity: %+v", index, status.Event)
		}
	}
}
