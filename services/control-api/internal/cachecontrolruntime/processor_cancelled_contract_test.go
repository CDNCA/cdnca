package cachecontrolruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"google.golang.org/protobuf/proto"
)

func TestProcessorMapsCancelledStatusToCancelledReportFacts(t *testing.T) {
	config := DefaultConfig()
	config.Clock = func() time.Time { return runtimeTestNow }
	claim := testClaim(cachecontrol.ActionPrewarm, cachecontrol.TargetExactURL)
	command, err := buildCommand(claim)
	if err != nil {
		t.Fatal(err)
	}
	status := testStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED,
		agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED)
	status.ErrorCode = "worker_stopped"
	status.Results[0].CauseCode = "shutdown"
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	control := &fakeControl{open: []cachecontrol.Claim{claim}}
	source := &fakeDelivery{
		subject: config.StatusSubjectPrefix + "." + claim.NodeID.String(), data: payload, delivered: 1,
	}
	runtime := testRuntime(config, control, source)
	disposition, err := runtime.ProcessStatusOnce(context.Background())
	if err != nil || disposition != DispositionAck || source.acks != 1 || len(control.reports) != 1 {
		t.Fatalf("disposition=%q err=%v delivery=%+v reports=%+v", disposition, err, source, control.reports)
	}
	result := control.reports[0].Results
	if len(result) != 1 || result[0].State != cachecontrol.ItemCancelled ||
		result[0].ErrorCode != "cancelled" {
		t.Fatalf("cancelled report results=%+v", result)
	}

	status.Results[0].State = agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS
	if _, err := terminalResults(command, status); !errors.Is(err, cachecontrol.ErrInvalidInput) {
		t.Fatalf("cancelled status with success result err=%v, want ErrInvalidInput", err)
	}
}

// CACHE-ADD-07 (R03): a node that finished one target and was cancelled
// before the other reports CANCELLED with one success and one cancelled
// target (agent dynroute CacheTasks); the success stays a success.
func TestTerminalResultsAcceptsSuccessThenCancelled(t *testing.T) {
	claim := testClaim(cachecontrol.ActionPrewarm, cachecontrol.TargetExactURL)
	second := claim.Targets[0]
	second.Ordinal, second.CanonicalURL, second.CanonicalPath = 2, "https://cache.example/assets/b.css", "/assets/b.css"
	claim.Targets = append(claim.Targets, second)
	command, err := buildCommand(claim)
	if err != nil {
		t.Fatal(err)
	}
	status := testStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED,
		agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS)
	cancelled := proto.Clone(status.Results[0]).(*agentv1.CacheControlTargetResult)
	cancelled.Index, cancelled.TargetOrdinal = 1, command.Targets[1].TargetOrdinal
	cancelled.Sha256 = append([]byte(nil), command.Targets[1].Sha256...)
	cancelled.State, cancelled.ResultCode = agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED, "task_cancelled"
	status.Results = append(status.Results, cancelled)
	results, err := terminalResults(command, status)
	if err != nil || len(results) != 2 || results[0].State != cachecontrol.ItemSucceeded ||
		results[1].State != cachecontrol.ItemCancelled || results[1].ErrorCode != "cancelled" {
		t.Fatalf("results=%+v err=%v", results, err)
	}
}
