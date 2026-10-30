package gatewayclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type transitionStateStore struct {
	active  GatewayEndpointState
	staged  []GatewayEndpointState
	commits int
}

func (s *transitionStateStore) Recover() error { return nil }
func (s *transitionStateStore) RecordFailure(value GatewayEndpointState) error {
	s.active = value
	return nil
}

func (s *transitionStateStore) Active() GatewayEndpointState { return s.active }
func (s *transitionStateStore) Stage(value GatewayEndpointState) error {
	s.staged = append(s.staged, value)
	return nil
}
func (s *transitionStateStore) Activate(value GatewayEndpointState) error {
	s.active = value
	s.commits++
	return nil
}
func (s *transitionStateStore) Finalize(value GatewayEndpointState) error {
	s.active = value
	return nil
}
func (s *transitionStateStore) Rollback(value GatewayEndpointState) error {
	s.active = value
	return nil
}

type candidateDialer struct {
	identity string
	err      error
	proof    GatewayEndpointState
}

func (d *candidateDialer) Probe(_ context.Context, state GatewayEndpointState, identity string) error {
	d.proof = state
	if identity != d.identity {
		return ErrPortTransitionIdentityMismatch
	}
	return d.err
}

func TestAgentPortTransitionStagesBeforeDialAndKeepsIdentity(t *testing.T) {
	old := GatewayEndpointState{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", Revision: 2}
	store := &transitionStateStore{active: old}
	dialer := &candidateDialer{identity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	runtime := NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now)
	status, err := runtime.Apply(context.Background(), validAgentTransitionCommand())
	if err != nil {
		t.Fatal(err)
	}
	if len(store.staged) != 1 || dialer.proof.Revision != 3 || store.commits != 1 || store.active.Address != "gateway.example.com:8443" {
		t.Fatalf("candidate was not staged, proved, and activated in order: store=%+v dial=%+v", store, dialer)
	}
	if status.GetState() != agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_SWITCHED || status.GetCertificateSha256() != dialer.identity {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestFileGatewayEndpointStateStoreInitializesMissingActiveState(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "gateway-endpoint")
	initial := GatewayEndpointState{Address: "gateway.example.com:7443", ServerName: "gateway.example.com"}
	store, err := NewFileGatewayEndpointStateStore(directory, initial)
	if err != nil {
		t.Fatalf("NewFileGatewayEndpointStateStore() error = %v", err)
	}
	if store.Active() != initial {
		t.Fatalf("active state = %+v, want %+v", store.Active(), initial)
	}
	if _, err := os.Stat(filepath.Join(directory, gatewayEndpointActiveFile)); err != nil {
		t.Fatalf("active state file was not created: %v", err)
	}
}

func TestAgentPortTransitionDialFailurePreservesOldEndpoint(t *testing.T) {
	old := GatewayEndpointState{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", Revision: 2}
	store := &transitionStateStore{active: old}
	dialer := &candidateDialer{identity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", err: errors.New("dial failed")}
	runtime := NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now)
	status, err := runtime.Apply(context.Background(), validAgentTransitionCommand())
	if err == nil || store.commits != 0 || store.active.Address != old.Address || store.active.ServerName != old.ServerName {
		t.Fatalf("dial failure changed the active endpoint: status=%+v err=%v store=%+v", status, err, store)
	}
	if status.GetState() != agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FAILED || status.GetErrorCode() != "candidate_dial_failed" {
		t.Fatalf("unexpected failure status: %+v", status)
	}
}

func TestAgentPortTransitionTerminalStatusSurvivesRestartAndReplay(t *testing.T) {
	for _, action := range []agentv1.GatewayPortTransitionAction{
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE,
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK,
	} {
		t.Run(action.String(), func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			initial := GatewayEndpointState{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", Revision: 2}
			dialer := &candidateDialer{identity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
			open := func() (*PortTransitionRuntime, *FileGatewayEndpointStateStore) {
				t.Helper()
				store, err := NewFileGatewayEndpointStateStore(filepath.Join(root, "endpoint"), initial)
				if err != nil {
					t.Fatal(err)
				}
				return NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now), store
			}
			runtime, _ := open()
			switchCommand := validAgentTransitionCommand()
			switched, err := runtime.Apply(context.Background(), switchCommand)
			if err != nil {
				t.Fatal(err)
			}
			terminalCommand := proto.Clone(switchCommand).(*agentv1.GatewayPortTransitionCommand)
			terminalCommand.Action = action
			terminalCommand.Event.EventId = "55555555-5555-4555-8555-555555555555"
			runtime, _ = open()
			terminal, err := runtime.Apply(context.Background(), terminalCommand)
			if err != nil {
				t.Fatal(err)
			}
			if terminal.StatusRevision <= switched.StatusRevision {
				t.Fatalf("terminal revision %d does not advance switch revision %d", terminal.StatusRevision, switched.StatusRevision)
			}
			runtime, store := open()
			before := store.Active()
			replayed, err := runtime.Apply(context.Background(), terminalCommand)
			if err != nil || !proto.Equal(replayed, terminal) || store.Active() != before {
				t.Fatalf("terminal replay changed durable outcome: status=%v error=%v", replayed, err)
			}
			changed := proto.Clone(terminalCommand).(*agentv1.GatewayPortTransitionCommand)
			changed.Event.EventId = "66666666-6666-4666-8666-666666666666"
			if _, err := runtime.Apply(context.Background(), changed); err == nil {
				t.Fatal("different command reused a completed operation")
			}
		})
	}
}

func TestAgentPortTransitionSwitchReplayDoesNotProbeAgain(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initial := GatewayEndpointState{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", Revision: 2}
	directory := filepath.Join(root, "endpoint")
	store, err := NewFileGatewayEndpointStateStore(directory, initial)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &candidateDialer{identity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	command := validAgentTransitionCommand()
	status, err := NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now).Apply(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	store, err = NewFileGatewayEndpointStateStore(directory, initial)
	if err != nil {
		t.Fatal(err)
	}
	dialer.err = errors.New("a replay must not probe")
	replayed, err := NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now).Apply(context.Background(), command)
	if err != nil || !proto.Equal(status, replayed) {
		t.Fatalf("switch replay lost original status: status=%v error=%v", replayed, err)
	}
}

func TestAgentPortTransitionReceiptRejectsCorruptionAndIdentityDrift(t *testing.T) {
	for _, scenario := range []string{"corrupt receipt", "missing digest", "identity drift", "endpoint mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			store := &transitionStateStore{active: GatewayEndpointState{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", Revision: 2}}
			dialer := &candidateDialer{identity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
			command := validAgentTransitionCommand()
			if _, err := NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now).Apply(context.Background(), command); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "corrupt receipt":
				store.active.LastStatus = "invalid"
			case "missing digest":
				store.active.LastCommandSHA256 = ""
			case "identity drift":
				dialer.identity = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			case "endpoint mismatch":
				store.active.Address = "gateway.example.com:9443"
			}
			before := store.active
			if status, err := NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now).Apply(context.Background(), command); err == nil || status != nil || store.active != before || store.commits != 1 {
				t.Fatalf("invalid receipt changed state: status=%v error=%v", status, err)
			}
		})
	}
}

func TestAgentPortTransitionLegacySwitchedStateCanFinalize(t *testing.T) {
	command := validAgentTransitionCommand()
	command.Action = agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE
	store := &transitionStateStore{active: GatewayEndpointState{TransitionID: command.TransitionId, Address: command.NewEndpoint.Address, ServerName: command.NewEndpoint.ServerName, Revision: command.Revision}}
	dialer := &candidateDialer{identity: command.CertificateSha256}
	status, err := NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now).Apply(context.Background(), command)
	if err != nil || status.GetStatusRevision() != 2 || store.active.LastStatus == "" {
		t.Fatalf("legacy switched state did not advance revision 1: status=%v error=%v", status, err)
	}
}

func validAgentTransitionCommand() *agentv1.GatewayPortTransitionCommand {
	now := time.Now().UTC()
	return &agentv1.GatewayPortTransitionCommand{
		Event: &commonv1.EventMetadata{EventId: "33333333-3333-4333-8333-333333333333", RequestId: "44444444-4444-4444-8444-444444444444",
			OccurredTime: timestamppb.New(now), CorrelationId: "11111111-1111-4111-8111-111111111111"},
		Schema:       agentv1.GatewayPortTransitionSchema_GATEWAY_PORT_TRANSITION_SCHEMA_V1,
		TransitionId: "11111111-1111-4111-8111-111111111111",
		NodeId:       "22222222-2222-4222-8222-222222222222", Revision: 3, ExpectedNodeRevision: 9,
		OldEndpoint:           &agentv1.GatewayEndpoint{Address: "gateway.example.com:7443", ServerName: "gateway.example.com"},
		NewEndpoint:           &agentv1.GatewayEndpoint{Address: "gateway.example.com:8443", ServerName: "gateway.example.com"},
		CompatibilityDeadline: timestamppb.New(now.Add(30 * time.Minute)), RollbackDeadline: timestamppb.New(now.Add(time.Hour)),
		CertificateSha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Action:            agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH,
	}
}

func TestAgentPortTransitionFailedReceiptSurvivesRestart(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initial := GatewayEndpointState{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", Revision: 2}
	directory := filepath.Join(root, "endpoint")
	store, err := NewFileGatewayEndpointStateStore(directory, initial)
	if err != nil {
		t.Fatal(err)
	}
	command := validAgentTransitionCommand()
	dialer := &candidateDialer{identity: command.CertificateSha256, err: errors.New("probe unavailable")}
	runtime := NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now)
	failed, err := runtime.Apply(t.Context(), command)
	if err == nil || failed.GetState() != agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FAILED {
		t.Fatalf("expected durable failure: %v %v", failed, err)
	}
	store, err = NewFileGatewayEndpointStateStore(directory, initial)
	if err != nil {
		t.Fatal(err)
	}
	dialer.err = nil
	dialer.proof = GatewayEndpointState{}
	runtime = NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now)
	replayed, err := runtime.Apply(t.Context(), command)
	if err == nil || !proto.Equal(failed, replayed) || dialer.proof.Revision != 0 || store.Active().Address != initial.Address || runtime.Proof() != nil {
		t.Fatalf("failed replay retried mutation: %v %v active=%+v", replayed, err, store.Active())
	}
	rollback := proto.Clone(command).(*agentv1.GatewayPortTransitionCommand)
	rollback.Action = agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK
	terminal, err := runtime.Apply(t.Context(), rollback)
	if err != nil || terminal.GetStatusRevision() != 2 || terminal.GetState() != agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_ROLLED_BACK || store.Active().Address != initial.Address {
		t.Fatalf("rollback after failed probe: %v %v", terminal, err)
	}
}

type uncertainActivationStore struct {
	*FileGatewayEndpointStateStore
	failures int
}

func (s *uncertainActivationStore) Activate(value GatewayEndpointState) error {
	if err := s.FileGatewayEndpointStateStore.Activate(value); err != nil {
		return err
	}
	s.failures++
	return ErrPortTransitionPersistenceUnknown
}

func TestAgentPortTransitionUnknownWriteRecoversDurableReceipt(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initial := GatewayEndpointState{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", Revision: 2}
	fileStore, err := NewFileGatewayEndpointStateStore(filepath.Join(root, "endpoint"), initial)
	if err != nil {
		t.Fatal(err)
	}
	store := &uncertainActivationStore{FileGatewayEndpointStateStore: fileStore}
	command := validAgentTransitionCommand()
	dialer := &candidateDialer{identity: command.CertificateSha256}
	runtime := NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now)
	status, err := runtime.Apply(t.Context(), command)
	if !errors.Is(err, ErrPortTransitionPersistenceUnknown) || status != nil {
		t.Fatalf("uncertain activation fabricated outcome: %v %v", status, err)
	}
	dialer.err = errors.New("must recover receipt without probing")
	status, err = runtime.Apply(t.Context(), command)
	if err != nil || status.GetState() != agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_SWITCHED || store.failures != 1 {
		t.Fatalf("could not recover committed receipt: %v %v", status, err)
	}
}

type failedReceiptStore struct{ transitionStateStore }

func (s *failedReceiptStore) RecordFailure(GatewayEndpointState) error {
	return errors.New("disk unavailable")
}
func TestAgentPortTransitionDoesNotReportUnpersistedFailure(t *testing.T) {
	command := validAgentTransitionCommand()
	old := GatewayEndpointState{Address: command.OldEndpoint.Address, ServerName: command.OldEndpoint.ServerName, Revision: 2}
	store := &failedReceiptStore{transitionStateStore{active: old}}
	dialer := &candidateDialer{identity: command.CertificateSha256, err: errors.New("probe failed")}
	status, err := NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now).Apply(t.Context(), command)
	if err == nil || status != nil || store.active != old {
		t.Fatalf("unpersisted failure was reported: %v %v", status, err)
	}
}

func TestFileGatewayEndpointStateStoreCandidateCleanupCannotUndoCommit(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	command := validAgentTransitionCommand()
	initial := GatewayEndpointState{Address: command.OldEndpoint.Address, ServerName: command.OldEndpoint.ServerName, Revision: 2}
	directory := filepath.Join(root, "endpoint")
	store, err := NewFileGatewayEndpointStateStore(directory, initial)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &candidateDialer{identity: command.CertificateSha256}
	runtime := NewPortTransitionRuntime(store, dialer, dialer.identity, time.Now)
	if _, err := runtime.Apply(t.Context(), command); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(directory, gatewayEndpointCandidateFile)
	if err := os.Mkdir(candidate, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "blocked"), []byte("cleanup failure fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	command.Action = agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE
	status, err := runtime.Apply(t.Context(), command)
	if err != nil || status.GetState() != agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FINALIZED {
		t.Fatalf("cleanup reversed committed result: %v %v", status, err)
	}
	reopened, err := NewFileGatewayEndpointStateStore(directory, initial)
	if err != nil || reopened.Active() != store.Active() {
		t.Fatalf("disk and memory disagree after cleanup failure: %v", err)
	}
}
