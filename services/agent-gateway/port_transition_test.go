package gateway

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type transitionListener struct {
	address string
	closed  bool
}

func (l *transitionListener) Accept() (net.Conn, error) { return nil, errors.New("unused") }
func (l *transitionListener) Close() error              { l.closed = true; return nil }
func (l *transitionListener) Addr() net.Addr            { return transitionAddress(l.address) }

type transitionAddress string

func (a transitionAddress) Network() string { return "tcp" }
func (a transitionAddress) String() string  { return string(a) }

func TestPortTransitionPreparesListenerBeforeCommandAndRetainsOld(t *testing.T) {
	oldListener := &transitionListener{address: "0.0.0.0:7443"}
	var opened *transitionListener
	manager := NewPortTransitionManager(oldListener, "gateway.example.com:7443", func(_ context.Context, address string) (net.Listener, error) {
		opened = &transitionListener{address: address}
		return opened, nil
	}, time.Now)
	if err := manager.ConfigureServe(func(net.Listener) error { return nil }); err != nil {
		t.Fatal(err)
	}
	command := validPortTransitionCommand()
	prepared, err := manager.Prepare(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if opened == nil || opened.address != "0.0.0.0:8443" || prepared.GetTransitionId() != command.GetTransitionId() {
		t.Fatalf("new listener was not prepared before delivery: opened=%+v prepared=%+v", opened, prepared)
	}
	if oldListener.closed {
		t.Fatal("old listener closed before the compatibility window completed")
	}
}

func TestPortTransitionRequiresSameCertificateAndAllNodesBeforeFinalize(t *testing.T) {
	oldListener := &transitionListener{address: "0.0.0.0:7443"}
	manager := NewPortTransitionManager(oldListener, "gateway.example.com:7443", func(_ context.Context, address string) (net.Listener, error) {
		return &transitionListener{address: address}, nil
	}, time.Now)
	if err := manager.ConfigureServe(func(net.Listener) error { return nil }); err != nil {
		t.Fatal(err)
	}
	command := validPortTransitionCommand()
	if _, err := manager.Prepare(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	second := validPortTransitionCommand()
	second.NodeId = "55555555-5555-4555-8555-555555555555"
	if _, err := manager.Prepare(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if err := manager.RecordConnection(command.GetTransitionId(), command.GetRevision(), command.GetNodeId(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); !errors.Is(err, ErrPortTransitionIdentityMismatch) {
		t.Fatalf("certificate drift got %v", err)
	}
	if err := manager.Finalize(command.GetTransitionId(), []string{command.GetNodeId(), "55555555-5555-4555-8555-555555555555"}); !errors.Is(err, ErrPortTransitionIncomplete) {
		t.Fatalf("incomplete cohort got %v", err)
	}
	if oldListener.closed {
		t.Fatal("old listener closed with an incomplete cohort")
	}
	if err := manager.RecordConnection(command.GetTransitionId(), command.GetRevision(), command.GetNodeId(), command.GetCertificateSha256()); err != nil {
		t.Fatal(err)
	}
	if err := manager.RecordConnection(command.GetTransitionId(), command.GetRevision(), "55555555-5555-4555-8555-555555555555", command.GetCertificateSha256()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Finalize(command.GetTransitionId(), []string{command.GetNodeId(), "55555555-5555-4555-8555-555555555555"}); err != nil {
		t.Fatal(err)
	}
	if !oldListener.closed {
		t.Fatal("old listener remained open after every required node proved the new endpoint")
	}
}

func validPortTransitionCommand() *agentv1.GatewayPortTransitionCommand {
	now := time.Now().UTC()
	return &agentv1.GatewayPortTransitionCommand{
		Event: &commonv1.EventMetadata{EventId: "33333333-3333-4333-8333-333333333333", RequestId: "44444444-4444-4444-8444-444444444444",
			OccurredTime: timestamppb.New(now), CorrelationId: "11111111-1111-4111-8111-111111111111"},
		Schema:       agentv1.GatewayPortTransitionSchema_GATEWAY_PORT_TRANSITION_SCHEMA_V1,
		TransitionId: "11111111-1111-4111-8111-111111111111",
		NodeId:       "22222222-2222-4222-8222-222222222222", Revision: 3, ExpectedNodeRevision: 9,
		OldEndpoint:           &agentv1.GatewayEndpoint{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:7443"},
		NewEndpoint:           &agentv1.GatewayEndpoint{Address: "gateway.example.com:8443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:8443"},
		CompatibilityDeadline: timestamppb.New(now.Add(30 * time.Minute)), RollbackDeadline: timestamppb.New(now.Add(time.Hour)),
		CertificateSha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Action:            agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH,
	}
}
