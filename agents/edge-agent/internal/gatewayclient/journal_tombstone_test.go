package gatewayclient

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
)

// quarantineBadRecord stores a record whose STARTED follows its terminal status
// under a higher sequence (cannot be made consistent) and scans it into quarantine.
func quarantineBadRecord(t *testing.T, store *durableStore, command *agentv1.DeploymentCommand, first *agentv1.DeploymentStatus) *durableRecord {
	t.Helper()
	bad, _, err := store.putCommand(command, first)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []*agentv1.DeploymentStatus{
		failedStatus(command, 2, time.Now(), commonv1.ErrorCode_ERROR_CODE_INTERNAL, "x", false),
		statusFor(command, 5, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED, time.Now(), false, "", "", 0),
	} {
		encoded, err := marshalStatus(status, store.maxStatusBytes)
		if err != nil {
			t.Fatal(err)
		}
		bad.Statuses = append(bad.Statuses, encoded)
	}
	bad.ExecutionDone = true
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.saveLocked(bad); err != nil {
		t.Fatal(err)
	}
	if err := store.scanDeploymentRecordsLocked(func(*durableRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	return bad
}

func assertQuarantinedRedelivery(t *testing.T, store *durableStore, command *agentv1.DeploymentCommand, first *agentv1.DeploymentStatus) {
	t.Helper()
	record, created, err := store.putCommand(command, first)
	if err != nil || !created || !record.ExecutionDone {
		t.Fatalf("redelivery = (created %v, done %v, %v), want a finished record and no execution", created, record != nil && record.ExecutionDone, err)
	}
	statuses, err := statusesFromRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	last := statuses[len(statuses)-1]
	if last.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || !strings.HasPrefix(last.Error.GetMessage(), journalQuarantinedReason) {
		t.Fatalf("last status = %v %q, want FAILED with %s", last.State, last.Error.GetMessage(), journalQuarantinedReason)
	}
	if (command.ConfigurationScopeId != nil) != (last.ConfigurationScopeId != nil) {
		t.Fatalf("scope binding of the terminal status = %v", last.ConfigurationScopeId)
	}
	if err := validateRecordStatusOrder(record); err != nil {
		t.Fatalf("answered record must be self-consistent: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.tombstoneDirectory(), record.RecordKey+".json")); err == nil {
		t.Fatal("tombstone must be dropped once the finished record carries the identity")
	}
	again, created, err := store.putCommand(command, first)
	if err != nil || created || !again.ExecutionDone || len(again.Statuses) != len(record.Statuses) {
		t.Fatalf("second redelivery = (created %v, %v), want the same finished record", created, err)
	}
}

func TestJournalQuarantineKeepsTombstoneScoped(t *testing.T) {
	store := journalOrderStore(t)
	command := scopedTestCommand()
	first := withCommandScope(command, deliveredStatus(command))
	bad := quarantineBadRecord(t, store, command, first)
	if _, err := os.Stat(filepath.Join(store.tombstoneDirectory(), bad.RecordKey+".json")); err != nil {
		t.Fatalf("tombstone missing after quarantine: %v", err)
	}
	assertQuarantinedRedelivery(t, store, command, first)
}

func TestJournalQuarantineKeepsTombstoneUnscoped(t *testing.T) {
	store := journalOrderStore(t)
	command := scopedTestCommand()
	command.ConfigurationScopeId = nil
	quarantineBadRecord(t, store, command, deliveredStatus(command))
	assertQuarantinedRedelivery(t, store, command, deliveredStatus(command))
}

func TestJournalTombstoneRejectsChangedCommand(t *testing.T) {
	store := journalOrderStore(t)
	command := scopedTestCommand()
	command.ConfigurationScopeId = nil
	quarantineBadRecord(t, store, command, deliveredStatus(command))
	changed := proto.Clone(command).(*agentv1.DeploymentCommand)
	changed.ConfigVersionId = command.ConfigVersionId + "-other"
	if _, _, err := store.putCommand(changed, deliveredStatus(changed)); !errors.Is(err, ErrCommandConflict) && err == nil {
		t.Fatalf("changed command = %v, want a conflict or rejection", err)
	}
}

func TestJournalTombstoneExpires(t *testing.T) {
	store := journalOrderStore(t)
	command := scopedTestCommand()
	command.ConfigurationScopeId = nil
	quarantineBadRecord(t, store, command, deliveredStatus(command))
	defer func(previous func() time.Time) { journalTombstoneClock = previous }(journalTombstoneClock)
	journalTombstoneClock = func() time.Time { return time.Now().Add(journalTombstoneRetention + time.Hour) }
	record, created, err := store.putCommand(command, deliveredStatus(command))
	if err != nil || !created || record.ExecutionDone {
		t.Fatalf("expired tombstone must let the command run as new (created %v, %v)", created, err)
	}
}

func TestJournalTombstoneCountIsBounded(t *testing.T) {
	store := journalOrderStore(t)
	base := time.Now()
	defer func(previous func() time.Time) { journalTombstoneClock = previous }(journalTombstoneClock)
	for index := 0; index < journalTombstoneLimit+20; index++ {
		journalTombstoneClock = func() time.Time { return base.Add(time.Duration(index) * time.Second) }
		command := scopedTestCommand()
		record, _, err := store.putCommand(command, deliveredStatus(command))
		if err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		err = store.writeTombstoneLocked(record)
		store.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(store.tombstoneDirectory())
	if err != nil || len(entries) > journalTombstoneLimit {
		t.Fatalf("tombstones = %d (%v), want at most %d", len(entries), err, journalTombstoneLimit)
	}
}
