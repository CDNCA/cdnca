package l4runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type listenerFailure struct {
	id     string
	reason string
}

func (e listenerFailure) Error() string      { return e.reason }
func (e listenerFailure) ListenerID() string { return e.id }
func (e listenerFailure) ReasonCode() string { return e.reason }

type listenerLifecycleRuntime struct {
	precheckErr error
}

func (r *listenerLifecycleRuntime) Precheck(context.Context, string) error {
	err := r.precheckErr
	r.precheckErr = nil
	return err
}

func (*listenerLifecycleRuntime) Activate(context.Context, string) error { return nil }
func (*listenerLifecycleRuntime) Healthy(context.Context, Config) error  { return nil }
func (*listenerLifecycleRuntime) Stop(context.Context, string) error     { return nil }

func TestManagerReportsDeterministicListenerLifecycleForApplyAndRollback(t *testing.T) {
	runtime := &listenerLifecycleRuntime{}
	manager, _ := testManager(t, runtime)
	initial := listenerLifecycleConfig("l4-lifecycle-v1", false)
	first, err := manager.Apply(context.Background(), initial)
	if err != nil {
		t.Fatal(err)
	}
	assertListenerResults(t, first.ListenerResults, []ListenerResult{
		{ID: "delete", Operation: ListenerOperationCreate, ReasonCode: ListenerReasonCreated},
		{ID: "disable", Operation: ListenerOperationCreate, ReasonCode: ListenerReasonCreated},
		{ID: "edit", Operation: ListenerOperationCreate, ReasonCode: ListenerReasonCreated},
		{ID: "enable", Operation: ListenerOperationCreate, ReasonCode: ListenerReasonCreated},
	})

	candidate := listenerLifecycleConfig("l4-lifecycle-v2", true)
	second, err := manager.Apply(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	wantApply := []ListenerResult{
		{ID: "create", Operation: ListenerOperationCreate, ReasonCode: ListenerReasonCreated},
		{ID: "delete", Operation: ListenerOperationDelete, ReasonCode: ListenerReasonDeleted},
		{ID: "disable", Operation: ListenerOperationDisable, ReasonCode: ListenerReasonDisabled},
		{ID: "edit", Operation: ListenerOperationEdit, ReasonCode: ListenerReasonEdited},
		{ID: "enable", Operation: ListenerOperationEnable, ReasonCode: ListenerReasonEnabled},
	}
	assertListenerResults(t, second.ListenerResults, wantApply)

	rolledBack, err := manager.Rollback(context.Background(), first.VersionID, first.Digest)
	if err != nil {
		t.Fatal(err)
	}
	assertListenerResults(t, rolledBack.ListenerResults, []ListenerResult{
		{ID: "create", Operation: ListenerOperationDelete, ReasonCode: ListenerReasonDeleted},
		{ID: "delete", Operation: ListenerOperationCreate, ReasonCode: ListenerReasonCreated},
		{ID: "disable", Operation: ListenerOperationEnable, ReasonCode: ListenerReasonEnabled},
		{ID: "edit", Operation: ListenerOperationEdit, ReasonCode: ListenerReasonEdited},
		{ID: "enable", Operation: ListenerOperationDisable, ReasonCode: ListenerReasonDisabled},
	})
}

func TestManagerListenerFailurePreservesLKGAndReportsOneStableRootCause(t *testing.T) {
	runtime := &listenerLifecycleRuntime{}
	manager, root := testManager(t, runtime)
	first, err := manager.Apply(context.Background(), listenerLifecycleConfig("l4-lifecycle-v1", false))
	if err != nil {
		t.Fatal(err)
	}
	currentBefore, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}

	runtime.precheckErr = listenerFailure{id: "edit", reason: "LISTENER_PORT_CONFLICT"}
	failed, err := manager.Apply(context.Background(), listenerLifecycleConfig("l4-lifecycle-v2", true))
	if !errors.Is(err, ErrPrecheck) {
		t.Fatalf("Apply() error = %v, want ErrPrecheck", err)
	}
	want := []ListenerResult{
		{ID: "create", Operation: ListenerOperationCreate, ReasonCode: ListenerReasonApplyAborted},
		{ID: "delete", Operation: ListenerOperationDelete, ReasonCode: ListenerReasonApplyAborted},
		{ID: "disable", Operation: ListenerOperationDisable, ReasonCode: ListenerReasonApplyAborted},
		{ID: "edit", Operation: ListenerOperationEdit, ReasonCode: "LISTENER_PORT_CONFLICT"},
		{ID: "enable", Operation: ListenerOperationEnable, ReasonCode: ListenerReasonApplyAborted},
	}
	assertListenerResults(t, failed.ListenerResults, want)
	if !failed.RunningVersionUnchanged || failed.ActiveVersionID != first.VersionID || failed.ActiveDigest != first.Digest {
		t.Fatalf("failed result = %+v", failed)
	}
	currentAfter, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || currentAfter != currentBefore {
		t.Fatalf("current changed from %q to %q: %v", currentBefore, currentAfter, err)
	}
	status, err := manager.Status()
	if err != nil || status.VersionID != first.VersionID || status.Digest != first.Digest {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
}

func listenerLifecycleConfig(version string, changed bool) Config {
	config := validConfig(version)
	listeners := []Listener{
		{ID: "delete", Protocol: ProtocolUDP, Address: "0.0.0.0", Port: 5301, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 500, IdleTimeoutMS: 5_000, MaxConnectionsPerClient: 20},
		{ID: "disable", Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 443, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 500, IdleTimeoutMS: 5_000, MaxConnectionsPerClient: 20},
		{ID: "edit", Protocol: ProtocolUDP, Address: "0.0.0.0", Port: 5302, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 500, IdleTimeoutMS: 5_000, MaxConnectionsPerClient: 20},
		{ID: "enable", Disabled: true, Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 8443, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 500, IdleTimeoutMS: 5_000, MaxConnectionsPerClient: 20},
	}
	if changed {
		listeners = []Listener{
			{ID: "create", Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 9443, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 500, IdleTimeoutMS: 5_000, MaxConnectionsPerClient: 20},
			{ID: "disable", Disabled: true, Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 443, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 500, IdleTimeoutMS: 5_000, MaxConnectionsPerClient: 20},
			{ID: "edit", Protocol: ProtocolUDP, Address: "0.0.0.0", Port: 5303, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 500, IdleTimeoutMS: 5_000, MaxConnectionsPerClient: 20},
			{ID: "enable", Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 8443, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 500, IdleTimeoutMS: 5_000, MaxConnectionsPerClient: 20},
		}
	}
	config.Listeners = listeners
	return config
}

func assertListenerResults(t *testing.T, got, want []ListenerResult) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("listener results = %#v, want %#v", got, want)
	}
}
