package gatewayclient

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachetask"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CACHEFLOW-E05 (fix-cacheflow3 P2-14): a purge whose running state was
// persisted but whose terminal status was not may already have deleted the
// objects, and objects filled since are new. Resuming must not purge them
// again: the targets end failed with cache_outcome_unknown and the user
// decides on a retry (a new attempt).
func TestCacheControlResumedPurgeEndsOutcomeUnknownWithoutRunningAgain(t *testing.T) {
	fixed := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for name, persistRunning := range map[string]bool{"running persisted": true, "delivered only": false} {
		t.Run(name, func(t *testing.T) {
			command := testCacheControlCommandWithTwoTargets()
			command.Action = agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_EXACT
			command.DeadlineTime = timestamppb.New(fixed.Add(time.Hour))
			store, err := newCacheControlDurableStore(filepath.Join(secureTempDir(t), "cache-control"), 1<<20, 256<<10)
			if err != nil {
				t.Fatal(err)
			}
			record, _, err := store.putCommand(command, cacheControlDeliveredStatus(command, fixed))
			if err != nil {
				t.Fatal(err)
			}
			if persistRunning {
				if err := store.appendStatuses(record.RecordKey, []*agentv1.CacheControlStatus{cacheControlRunningStatus(command, fixed)}, false); err != nil {
					t.Fatal(err)
				}
			}
			manager := &fakeCacheTaskManager{execute: func(task cachetask.Task) (cachetask.Result, error) {
				result := successfulCacheTaskResult(task, command.Targets[0], fixed.Add(time.Second))
				second := result.Items[0]
				second.Index, second.Target = 1, command.Targets[1].CanonicalUrl
				second.TargetDigest = hex.EncodeToString(command.Targets[1].Sha256)
				result.Items = append(result.Items, second)
				for index := range result.Items {
					result.Items[index].Code = cachetask.CodePurged
				}
				return result, nil
			}}
			client := &Client{cacheStore: store, cacheTasks: manager, now: func() time.Time { return fixed }}
			if err := client.executeCacheControlRecord(context.Background(), record.RecordKey); err != nil {
				t.Fatal(err)
			}
			persisted, err := store.record(record.RecordKey)
			if err != nil || !persisted.ExecutionDone {
				t.Fatalf("persisted=%+v err=%v", persisted, err)
			}
			statuses, err := cacheControlStatusesFromRecord(persisted)
			if err != nil {
				t.Fatal(err)
			}
			terminal := statuses[len(statuses)-1]
			if !persistRunning {
				// Never started before: it runs once as usual.
				if manager.calls != 1 || terminal.State != agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED {
					t.Fatalf("calls=%d terminal=%v code=%s", manager.calls, terminal.State, terminal.ErrorCode)
				}
				return
			}
			if manager.calls != 0 {
				t.Fatalf("resumed purge ran again: calls=%d", manager.calls)
			}
			if terminal.State != agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED || terminal.ErrorCode != cacheOutcomeUnknownCode ||
				len(terminal.Results) != 2 {
				t.Fatalf("terminal=%+v", terminal)
			}
			for _, result := range terminal.Results {
				if result.State != agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED || result.CauseCode != cacheOutcomeUnknownCode {
					t.Fatalf("target result=%+v", result)
				}
			}
		})
	}
}
