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

func TestCACHE05StatusSnapshotDistinguishesTerminalRetryAndDLQWithoutReplayDoubleCount(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.Clock = func() time.Time { return runtimeTestNow }
	claim := testClaim(cachecontrol.ActionPrewarm, cachecontrol.TargetExactURL)
	command, err := buildCommand(claim)
	if err != nil {
		t.Fatal(err)
	}
	status := testStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_SUCCEEDED,
		agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS)
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	control := &cache05VisibilityControl{
		fakeControl: fakeControl{open: []cachecontrol.Claim{claim}},
		result:      cachecontrol.ReportResult{Applied: true},
	}
	bus := &cache05VisibilityBus{}
	runtime := cache05VisibilityRuntime(config, control, bus)

	disposition, err := cache05ProcessPayload(runtime, claim, payload, 1)
	if err != nil || disposition != DispositionAck {
		t.Fatalf("applied disposition=%s err=%v", disposition, err)
	}
	control.result = cachecontrol.ReportResult{Replayed: true}
	disposition, err = cache05ProcessPayload(runtime, claim, payload, 2)
	if err != nil || disposition != DispositionAck {
		t.Fatalf("replay disposition=%s err=%v", disposition, err)
	}
	control.open = nil
	disposition, err = cache05ProcessPayload(runtime, claim, payload, 3)
	if err != nil || disposition != DispositionTerm {
		t.Fatalf("stale disposition=%s err=%v", disposition, err)
	}

	control.open = []cachecontrol.Claim{claim}
	control.result = cachecontrol.ReportResult{}
	control.err = errors.New("temporary report outage")
	disposition, err = cache05ProcessPayload(runtime, claim, payload, 2)
	if err == nil || disposition != DispositionNak {
		t.Fatalf("requeued disposition=%s err=%v", disposition, err)
	}
	disposition, err = cache05ProcessPayload(runtime, claim, payload, uint64(config.MaxDeliver))
	if err == nil || disposition != DispositionTerm {
		t.Fatalf("exhausted disposition=%s err=%v", disposition, err)
	}

	control.err = nil
	poison := append(append([]byte(nil), payload...), 0xa0, 0x06, 0x01)
	disposition, err = cache05ProcessPayload(runtime, claim, poison, 1)
	if err != nil || disposition != DispositionTerm {
		t.Fatalf("quarantined disposition=%s err=%v", disposition, err)
	}

	snapshot := runtime.StatusSnapshot()
	if snapshot.Terminal.Succeeded != 1 || snapshot.Terminal.PartialFailed != 0 ||
		snapshot.Terminal.Failed != 0 || snapshot.Terminal.Cancelled != 0 ||
		snapshot.Retry.Requeued != 1 || snapshot.Retry.RetryExhaustedDLQ != 1 ||
		snapshot.Retry.QuarantinedDLQ != 1 {
		t.Fatalf("status snapshot=%+v", snapshot)
	}
	if len(bus.reasons) != 2 || bus.reasons[0] != StatusReasonRetryExhausted ||
		bus.reasons[1] != "protobuf_invalid" || StatusReasonRetryExhausted != "retry_exhausted" {
		t.Fatalf("DLQ reasons=%v", bus.reasons)
	}
}

func cache05ProcessPayload(runtime *Runtime, claim cachecontrol.Claim, payload []byte, delivered uint64) (string, error) {
	runtime.consumer = &fakeConsumer{delivery: &fakeDelivery{
		subject: runtime.config.StatusSubjectPrefix + "." + claim.NodeID.String(),
		data:    payload, delivered: delivered,
	}}
	return runtime.ProcessStatusOnce(context.Background())
}

func cache05VisibilityRuntime(config Config, control controlStore, bus messageBus) *Runtime {
	return &Runtime{
		config: config, control: control, repository: &fakeRepository{}, leases: &fakeLeases{},
		bus: bus, consumer: &fakeConsumer{err: ErrNoMessage},
	}
}

type cache05VisibilityControl struct {
	fakeControl
	result cachecontrol.ReportResult
	err    error
}

func (control *cache05VisibilityControl) Report(_ context.Context,
	request cachecontrol.ReportRequest,
) (cachecontrol.ReportResult, error) {
	control.reports = append(control.reports, request)
	return control.result, control.err
}

type cache05VisibilityBus struct {
	reasons []string
}

func (*cache05VisibilityBus) PublishCommand(context.Context, string, *agentv1.CacheControlCommand) (bool, error) {
	return false, nil
}

func (bus *cache05VisibilityBus) PublishCancel(context.Context, string, *agentv1.CacheControlCancel) error {
	return nil
}

func (bus *cache05VisibilityBus) PublishDLQ(_ context.Context, _ delivery, reason string) error {
	bus.reasons = append(bus.reasons, reason)
	return nil
}
