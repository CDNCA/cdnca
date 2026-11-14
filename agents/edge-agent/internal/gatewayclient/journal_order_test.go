package gatewayclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
)

type journalOrderSample struct {
	ExecutionDone bool `json:"execution_done"`
	Statuses      []struct {
		State    string `json:"state"`
		Sequence uint64 `json:"sequence"`
	} `json:"statuses"`
}

func journalOrderStore(t *testing.T) *durableStore {
	t.Helper()
	store, err := newDurableStore(filepath.Join(secureTempDir(t), "journal"), 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// recordFromFieldSample rebuilds the field record (testdata keeps only its
// structure) with its statuses in the order they were found in the file.
func recordFromFieldSample(t *testing.T, store *durableStore) *durableRecord {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "journal_order_field_sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sample journalOrderSample
	if err := json.Unmarshal(raw, &sample); err != nil {
		t.Fatal(err)
	}
	command := scopedTestCommand()
	record, _, err := store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	record.Statuses = nil
	for _, entry := range sample.Statuses {
		state := agentv1.NodeDeploymentState(agentv1.NodeDeploymentState_value["NODE_DEPLOYMENT_STATE_"+entry.State])
		status := statusFor(command, entry.Sequence, state, time.Now(), false, "", "", 0)
		encoded, err := marshalStatus(status, store.maxStatusBytes)
		if err != nil {
			t.Fatal(err)
		}
		record.Statuses = append(record.Statuses, encoded)
	}
	record.ExecutionDone = sample.ExecutionDone
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.saveLocked(record); err != nil {
		t.Fatal(err)
	}
	return record
}

// Reproduces the field failure: the terminal status was found before STARTED, so
// "the last status" was STARTED and replay failed with "terminal status is corrupt".
func TestJournalReplayOrdersStatusesBySequenceFieldSample(t *testing.T) {
	store := journalOrderStore(t)
	record := recordFromFieldSample(t, store)
	raw, err := statusesFromRecordFileOrder(record)
	if err != nil || terminalDeploymentState(raw[len(raw)-1].State) {
		t.Fatalf("sample must keep the broken file order (last=%v err=%v)", raw[len(raw)-1].State, err)
	}
	visited := 0
	store.mu.Lock()
	err = store.scanDeploymentRecordsLocked(func(r *durableRecord) error {
		visited++
		statuses, err := statusesFromRecord(r)
		if err != nil || !terminalDeploymentState(statuses[len(statuses)-1].State) {
			return os.ErrInvalid
		}
		for i, want := range []uint64{1, 2, 3, 4} {
			if statuses[i].TransitionSequence != want {
				t.Fatalf("status %d sequence = %d, want %d", i, statuses[i].TransitionSequence, want)
			}
		}
		if statuses[3].State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED {
			t.Fatalf("final state = %v, want the real FAILED terminal", statuses[3].State)
		}
		return nil
	})
	store.mu.Unlock()
	if err != nil || visited != 1 {
		t.Fatalf("scan = (visited %d, %v), want the record replayed", visited, err)
	}
	if _, err := os.Stat(filepath.Join(store.directory, journalQuarantineDirectory)); err == nil {
		t.Fatal("a repairable record must not be quarantined")
	}
}

func statusesFromRecordFileOrder(record *durableRecord) ([]*agentv1.DeploymentStatus, error) {
	out := make([]*agentv1.DeploymentStatus, 0, len(record.Statuses))
	for _, encoded := range record.Statuses {
		status := new(agentv1.DeploymentStatus)
		if err := proto.Unmarshal(encoded, status); err != nil {
			return nil, err
		}
		out = append(out, status)
	}
	return out, nil
}

func TestJournalWriterRefusesOutOfOrderNonTerminalStatus(t *testing.T) {
	store := journalOrderStore(t)
	command := scopedTestCommand()
	record, _, err := store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	appendOne := func(status *agentv1.DeploymentStatus, done bool) {
		t.Helper()
		if err := store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{status}, done); err != nil {
			t.Fatal(err)
		}
	}
	appendOne(scopedQueuedStatus(command, now), false)
	// The field race: the worker's terminal status lands first, STARTED comes late.
	appendOne(failedStatus(command, 2, now, commonv1.ErrorCode_ERROR_CODE_INTERNAL, "install timed out", false), true)
	appendOne(scopedStartedStatus(command, now), false)
	got, err := store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, _ := statusesFromRecord(got)
	if len(statuses) != 3 || !terminalDeploymentState(statuses[2].State) {
		t.Fatalf("statuses after late STARTED = %d, want 3 ending in the terminal status", len(statuses))
	}
	if err := validateRecordStatusOrder(got); err != nil {
		t.Fatal(err)
	}
}

func TestJournalWriterKeepsNormalSequence(t *testing.T) {
	store := journalOrderStore(t)
	command := scopedTestCommand()
	record, _, err := store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, status := range []*agentv1.DeploymentStatus{scopedQueuedStatus(command, now), scopedStartedStatus(command, now)} {
		if err := store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{status}, false); err != nil {
			t.Fatal(err)
		}
	}
	healthy := statusFor(command, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, now, false, "", "", time.Second)
	if err := store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{healthy}, true); err != nil {
		t.Fatal(err)
	}
	got, _ := store.record(record.RecordKey)
	statuses, _ := statusesFromRecord(got)
	if len(statuses) != 4 || validateRecordStatusOrder(got) != nil {
		t.Fatalf("normal sequence stored %d statuses, order error %v", len(statuses), validateRecordStatusOrder(got))
	}
}

// The worker records STARTED before executing, so a fast terminal status
// can never be written ahead of it.
func TestRecordScopedStartedPrecedesTerminal(t *testing.T) {
	store := journalOrderStore(t)
	client := &Client{store: store, now: time.Now}
	command := scopedTestCommand()
	record, _, err := store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{scopedQueuedStatus(command, time.Now())}, false); err != nil {
		t.Fatal(err)
	}
	if err := client.recordScopedStarted(record.RecordKey); err != nil {
		t.Fatal(err)
	}
	if err := client.recordScopedStarted(record.RecordKey); err != nil {
		t.Fatal(err)
	}
	failed := failedStatus(command, 2, time.Now(), commonv1.ErrorCode_ERROR_CODE_INTERNAL, "install timed out", false)
	if err := store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{failed}, true); err != nil {
		t.Fatal(err)
	}
	if err := client.recordScopedStarted(record.RecordKey); err != nil {
		t.Fatal(err)
	}
	got, _ := store.record(record.RecordKey)
	if len(got.Statuses) != 4 || validateRecordStatusOrder(got) != nil {
		t.Fatalf("statuses = %d (want DELIVERED, QUEUED, STARTED once, FAILED), order error %v", len(got.Statuses), validateRecordStatusOrder(got))
	}
}

// A record that no ordering can make consistent (a non-terminal status with a
// higher sequence than the terminal one) is moved aside, reported once, and the
// other records still replay.
func TestJournalReplayQuarantinesUnrecoverableRecord(t *testing.T) {
	store := journalOrderStore(t)
	healthyCommand := scopedTestCommand()
	healthy, _, err := store.putCommand(healthyCommand, deliveredStatus(healthyCommand))
	if err != nil {
		t.Fatal(err)
	}
	done := statusFor(healthyCommand, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, time.Now(), false, "", "", time.Second)
	if err := store.appendStatuses(healthy.RecordKey, []*agentv1.DeploymentStatus{done}, true); err != nil {
		t.Fatal(err)
	}

	badCommand := scopedTestCommand()
	bad, _, err := store.putCommand(badCommand, deliveredStatus(badCommand))
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []*agentv1.DeploymentStatus{
		failedStatus(badCommand, 2, time.Now(), commonv1.ErrorCode_ERROR_CODE_INTERNAL, "x", false),
		statusFor(badCommand, 5, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED, time.Now(), false, "", "", 0),
	} {
		encoded, err := marshalStatus(status, store.maxStatusBytes)
		if err != nil {
			t.Fatal(err)
		}
		bad.Statuses = append(bad.Statuses, encoded)
	}
	bad.ExecutionDone = true
	store.mu.Lock()
	if err := store.saveLocked(bad); err != nil {
		t.Fatal(err)
	}
	visited := map[string]bool{}
	for pass := 0; pass < 2; pass++ {
		if err := store.scanDeploymentRecordsLocked(func(r *durableRecord) error {
			visited[r.RecordKey] = true
			return nil
		}); err != nil {
			t.Fatalf("scan pass %d: %v", pass, err)
		}
	}
	store.mu.Unlock()
	if !visited[healthy.RecordKey] || visited[bad.RecordKey] {
		t.Fatalf("visited = %v, want only the consistent record", visited)
	}
	if _, err := os.Stat(filepath.Join(store.directory, bad.RecordKey+".json")); err == nil {
		t.Fatal("corrupt record still in the journal root")
	}
	entries, err := os.ReadDir(filepath.Join(store.directory, journalQuarantineDirectory))
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), bad.RecordKey) {
		t.Fatalf("quarantine = (%v, %v), want the corrupt record kept", entries, err)
	}
}
