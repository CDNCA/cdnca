package gateway

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPortTransitionTerminalPublicationRetry(t *testing.T) {
	for _, action := range []agentv1.GatewayPortTransitionAction{
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE,
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK,
	} {
		t.Run(action.String(), func(t *testing.T) {
			now := time.Date(2026, time.September, 29, 0, 0, 0, 0, time.UTC)
			old := &countedPortListener{transitionListener: transitionListener{address: "0.0.0.0:7443"}}
			candidate := &countedPortListener{transitionListener: transitionListener{address: "0.0.0.0:8443"}}
			opened := 0
			manager := NewPortTransitionManager(old, "gateway.example.com:7443", func(context.Context, string) (net.Listener, error) {
				opened++
				if opened > 1 {
					return &transitionListener{address: "0.0.0.0:9443"}, nil
				}
				return candidate, nil
			}, func() time.Time { return now })
			if err := manager.ConfigureServe(func(net.Listener) error { return nil }); err != nil {
				t.Fatal(err)
			}
			command := validPortTransitionCommand()
			command.Event.OccurredTime = timestamppb.New(now)
			command.CompatibilityDeadline = timestamppb.New(now.Add(30 * time.Minute))
			command.RollbackDeadline = timestamppb.New(now.Add(time.Hour))
			if _, err := manager.Prepare(t.Context(), command); err != nil {
				t.Fatal(err)
			}
			if err := manager.RecordConnection(command.TransitionId, command.Revision, command.NodeId, command.CertificateSha256); err != nil {
				t.Fatal(err)
			}
			command.Action = action
			for name, change := range map[string]func(*agentv1.GatewayPortTransitionCommand){
				"node": func(c *agentv1.GatewayPortTransitionCommand) { c.NodeId = "66666666-6666-4666-8666-666666666666" },
				"certificate": func(c *agentv1.GatewayPortTransitionCommand) {
					c.CertificateSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
				},
				"listener": func(c *agentv1.GatewayPortTransitionCommand) { c.NewEndpoint.ListenAddress = "0.0.0.0:9443" },
			} {
				changed := proto.Clone(command).(*agentv1.GatewayPortTransitionCommand)
				change(changed)
				if _, err := manager.ValidateAction(changed); err == nil {
					t.Fatalf("accepted %s drift before completion", name)
				}
			}
			admitted, err := manager.ValidateAction(command)
			if err != nil {
				t.Fatal(err)
			}
			original := proto.Clone(command).(*agentv1.GatewayPortTransitionCommand)
			command.Event.EventId = "77777777-7777-4777-8777-777777777777"
			command.NewEndpoint.Address = "gateway.example.com:9443"
			admitted.CertificateSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			admitted.NewEndpoint.ListenAddress = "0.0.0.0:9443"
			command = original
			if replayed, err := manager.ValidateAction(command); err != nil || !proto.Equal(replayed, command) {
				t.Fatalf("input or returned command mutated admitted state: %v", err)
			}
			for name, change := range terminalCommandDrifts() {
				changed := proto.Clone(command).(*agentv1.GatewayPortTransitionCommand)
				change(changed)
				if _, err := manager.ValidateAction(changed); err == nil {
					t.Errorf("accepted %s drift after admission", name)
				}
			}
			bus := &terminalStatusBus{}
			service := &Gateway{config: DefaultConfig(), portTransitions: bus, portManager: manager}
			delivery := &lostTerminalAck{command: command}
			pending := pendingPortTransitionSet{command.TransitionId: {command: command, deliveries: []PortTransitionCommandDelivery{delivery}}}
			value := terminalStatus(command)
			if err := service.persistPortTransitionStatus(t.Context(), command.NodeId, command.CertificateSha256, value, pending); err == nil {
				t.Fatal("lost first broker acknowledgement was reported as success")
			}
			if bus.calls != 1 || old.closes+candidate.closes != 1 {
				t.Fatal("status must publish before exactly one terminal listener mutation")
			}
			for _, expired := range []bool{false, true} {
				if expired {
					now = command.RollbackDeadline.AsTime().Add(time.Second)
				}
				prepared, err := manager.ValidateAction(command)
				if err != nil || !proto.Equal(prepared, command) {
					t.Fatalf("exact redelivery could not reach Agent (expired=%v): %v", expired, err)
				}
				prepared.Event.RequestId = "77777777-7777-4777-8777-777777777777"
				prepared.OldEndpoint.ServerName = "changed.example.com"
				if _, err := manager.ValidateAction(nil); err == nil {
					t.Fatal("nil terminal command admitted")
				}
				for name, change := range terminalCommandDrifts() {
					changed := proto.Clone(command).(*agentv1.GatewayPortTransitionCommand)
					change(changed)
					if _, err := manager.ValidateAction(changed); err == nil {
						t.Errorf("accepted %s drift after completion (expired=%v)", name, expired)
					}
				}
				if replayed, err := manager.ValidateAction(command); err != nil || !proto.Equal(replayed, command) {
					t.Fatalf("returned command or drift attempt mutated completed state: %v", err)
				}
			}
			if err := service.persistPortTransitionStatus(t.Context(), command.NodeId, command.CertificateSha256, value, pending); err != nil {
				t.Fatal(err)
			}
			if bus.calls != 2 || delivery.acks != 2 || len(pending) != 0 || old.closes+candidate.closes != 1 {
				t.Fatalf("terminal replay republished different state or repeated mutation: publications=%d acks=%d closes=%d pending=%d", bus.calls, delivery.acks, old.closes+candidate.closes, len(pending))
			}
			if opened != 1 {
				t.Fatal("terminal replay opened another listener")
			}
			if _, err := manager.Prepare(t.Context(), validPortTransitionCommand()); err == nil {
				t.Fatal("obsolete switch reopened terminal transition")
			}
			next := proto.Clone(command).(*agentv1.GatewayPortTransitionCommand)
			next.Action = agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH
			next.TransitionId = "99999999-9999-4999-8999-999999999999"
			next.Revision++
			next.Event.EventId = "77777777-7777-4777-8777-777777777777"
			next.Event.CorrelationId = next.TransitionId
			next.Event.OccurredTime = timestamppb.New(now)
			next.CompatibilityDeadline = timestamppb.New(now.Add(30 * time.Minute))
			next.RollbackDeadline = timestamppb.New(now.Add(time.Hour))
			if action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE {
				next.OldEndpoint = proto.Clone(command.NewEndpoint).(*agentv1.GatewayEndpoint)
			}
			next.NewEndpoint = &agentv1.GatewayEndpoint{Address: "gateway.example.com:9443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:9443"}
			if _, err := manager.Prepare(t.Context(), next); err != nil {
				t.Fatal(err)
			}
			// Removing the expiry rejection must not revive an obsolete operation.
			now = command.RollbackDeadline.AsTime()
			if _, err := manager.ValidateAction(command); !errors.Is(err, ErrPortTransitionConflict) {
				t.Fatalf("obsolete completed command survived the next operation: %v", err)
			}
			if err := manager.Finalize(command.TransitionId, []string{command.NodeId}); err == nil {
				t.Fatal("obsolete finalize mutated the next operation")
			}
			if err := manager.Rollback(command.TransitionId); err == nil {
				t.Fatal("obsolete rollback mutated the next operation")
			}
			if opened != 2 || old.closes+candidate.closes != 1 {
				t.Fatal("obsolete terminal replay mutated a listener")
			}
		})
	}
}

func terminalCommandDrifts() map[string]func(*agentv1.GatewayPortTransitionCommand) {
	otherID := "77777777-7777-4777-8777-777777777777"
	return map[string]func(*agentv1.GatewayPortTransitionCommand){
		"schema": func(c *agentv1.GatewayPortTransitionCommand) { c.Schema++ },
		"action": func(c *agentv1.GatewayPortTransitionCommand) {
			if c.Action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE {
				c.Action = agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK
			} else {
				c.Action = agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE
			}
		},
		"switch": func(c *agentv1.GatewayPortTransitionCommand) {
			c.Action = agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH
		},
		"transition":             func(c *agentv1.GatewayPortTransitionCommand) { c.TransitionId = otherID },
		"node":                   func(c *agentv1.GatewayPortTransitionCommand) { c.NodeId = otherID },
		"revision":               func(c *agentv1.GatewayPortTransitionCommand) { c.Revision++ },
		"expected node revision": func(c *agentv1.GatewayPortTransitionCommand) { c.ExpectedNodeRevision++ },
		"certificate": func(c *agentv1.GatewayPortTransitionCommand) {
			c.CertificateSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		"old address":            func(c *agentv1.GatewayPortTransitionCommand) { c.OldEndpoint.Address = "gateway.example.com:6443" },
		"old server name":        func(c *agentv1.GatewayPortTransitionCommand) { c.OldEndpoint.ServerName = "changed.example.com" },
		"old listener":           func(c *agentv1.GatewayPortTransitionCommand) { c.OldEndpoint.ListenAddress = "0.0.0.0:6443" },
		"new address":            func(c *agentv1.GatewayPortTransitionCommand) { c.NewEndpoint.Address = "gateway.example.com:9443" },
		"new server name":        func(c *agentv1.GatewayPortTransitionCommand) { c.NewEndpoint.ServerName = "changed.example.com" },
		"new listener":           func(c *agentv1.GatewayPortTransitionCommand) { c.NewEndpoint.ListenAddress = "0.0.0.0:9443" },
		"compatibility deadline": func(c *agentv1.GatewayPortTransitionCommand) { c.CompatibilityDeadline.Seconds++ },
		"rollback deadline":      func(c *agentv1.GatewayPortTransitionCommand) { c.RollbackDeadline.Seconds++ },
		"event":                  func(c *agentv1.GatewayPortTransitionCommand) { c.Event = nil },
		"event ID":               func(c *agentv1.GatewayPortTransitionCommand) { c.Event.EventId = otherID },
		"request ID":             func(c *agentv1.GatewayPortTransitionCommand) { c.Event.RequestId = otherID },
		"causation ID":           func(c *agentv1.GatewayPortTransitionCommand) { c.Event.CausationId = &otherID },
		"correlation ID":         func(c *agentv1.GatewayPortTransitionCommand) { c.Event.CorrelationId = otherID },
		"task ID":                func(c *agentv1.GatewayPortTransitionCommand) { c.Event.TaskId = &otherID },
		"trace":                  func(c *agentv1.GatewayPortTransitionCommand) { c.Event.Traceparent = "different-trace" },
		"event time":             func(c *agentv1.GatewayPortTransitionCommand) { c.Event.OccurredTime.Seconds++ },
		"unknown field":          func(c *agentv1.GatewayPortTransitionCommand) { c.ProtoReflect().SetUnknown([]byte{0xf8, 0x7f, 0x01}) },
		"nested unknown field": func(c *agentv1.GatewayPortTransitionCommand) {
			c.Event.ProtoReflect().SetUnknown([]byte{0xf8, 0x7f, 0x01})
		},
	}
}

func TestPortTransitionUnfinishedTerminalExpires(t *testing.T) {
	for _, action := range []agentv1.GatewayPortTransitionAction{
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE,
		agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK,
	} {
		for _, stage := range []string{"not admitted", "admitted", "listener close failed"} {
			t.Run(action.String()+"/"+stage, func(t *testing.T) {
				now := time.Date(2026, time.September, 29, 0, 0, 0, 0, time.UTC)
				old := &failedTerminalListener{transitionListener{address: "0.0.0.0:7443"}}
				manager := NewPortTransitionManager(old, "gateway.example.com:7443", func(context.Context, string) (net.Listener, error) {
					return &failedTerminalListener{transitionListener{address: "0.0.0.0:8443"}}, nil
				}, func() time.Time { return now })
				if err := manager.ConfigureServe(func(net.Listener) error { return nil }); err != nil {
					t.Fatal(err)
				}
				command := validPortTransitionCommand()
				command.Event.OccurredTime = timestamppb.New(now)
				command.CompatibilityDeadline = timestamppb.New(now.Add(30 * time.Minute))
				command.RollbackDeadline = timestamppb.New(now.Add(time.Hour))
				if _, err := manager.Prepare(t.Context(), command); err != nil {
					t.Fatal(err)
				}
				if err := manager.RecordConnection(command.TransitionId, command.Revision, command.NodeId, command.CertificateSha256); err != nil {
					t.Fatal(err)
				}
				command.Action = action
				if stage != "not admitted" {
					if _, err := manager.ValidateAction(command); err != nil {
						t.Fatal(err)
					}
				}
				if stage == "listener close failed" {
					var err error
					if action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE {
						err = manager.Finalize(command.TransitionId, []string{command.NodeId})
					} else {
						err = manager.Rollback(command.TransitionId)
					}
					if err == nil {
						t.Fatal("listener close failure was ignored")
					}
				}
				now = command.RollbackDeadline.AsTime().Add(time.Second)
				if _, err := manager.ValidateAction(command); !errors.Is(err, ErrPortTransitionInvalid) {
					t.Fatalf("unfinished operation bypassed execution deadline: %v", err)
				}
				if manager.completed != nil {
					t.Fatal("unfinished listener operation was retained as completed")
				}
			})
		}
	}
}

type failedTerminalListener struct{ transitionListener }

func (l *failedTerminalListener) Close() error { return errors.New("terminal listener close failed") }

type countedPortListener struct {
	transitionListener
	closes int
}

func (l *countedPortListener) Close() error {
	l.closes++
	if l.closes > 1 {
		return errors.New("listener closed twice")
	}
	return l.transitionListener.Close()
}

type lostTerminalAck struct {
	command *agentv1.GatewayPortTransitionCommand
	acks    int
}

func (d *lostTerminalAck) Command() *agentv1.GatewayPortTransitionCommand { return d.command }
func (d *lostTerminalAck) Retry(context.Context, time.Duration) error     { return nil }
func (d *lostTerminalAck) Ack(context.Context) error {
	d.acks++
	if d.acks == 1 {
		return errors.New("broker acknowledgement lost after listener mutation")
	}
	return nil
}

type terminalStatusBus struct {
	value *agentv1.GatewayPortTransitionStatus
	calls int
}

func (b *terminalStatusBus) SubscribePortTransitions(context.Context, string) (PortTransitionCommandSubscription, error) {
	return nil, errors.New("not used by status boundary test")
}

func (b *terminalStatusBus) PublishPortTransitionStatus(_ context.Context, _ string, value *agentv1.GatewayPortTransitionStatus) (PortTransitionStatusPublication, error) {
	b.calls++
	if b.value != nil && !proto.Equal(b.value, value) {
		return PortTransitionStatusPublication{}, errors.New("status identity changed")
	}
	b.value = proto.Clone(value).(*agentv1.GatewayPortTransitionStatus)
	return PortTransitionStatusPublication{Stream: "unit-status", Sequence: 1, Replayed: b.calls > 1}, nil
}

func terminalStatus(command *agentv1.GatewayPortTransitionCommand) *agentv1.GatewayPortTransitionStatus {
	value := &agentv1.GatewayPortTransitionStatus{Event: &commonv1.EventMetadata{
		EventId: "88888888-8888-4888-8888-888888888888", RequestId: command.Event.RequestId,
		CausationId: &command.Event.EventId, CorrelationId: command.TransitionId, OccurredTime: timestamppb.Now()},
		Schema: command.Schema, TransitionId: command.TransitionId, NodeId: command.NodeId,
		Revision: command.Revision, StatusRevision: 2, CertificateSha256: command.CertificateSha256,
		State:          agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FINALIZED,
		ActiveEndpoint: proto.Clone(command.NewEndpoint).(*agentv1.GatewayEndpoint)}
	if command.Action == agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK {
		value.State = agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_ROLLED_BACK
		value.ActiveEndpoint = proto.Clone(command.OldEndpoint).(*agentv1.GatewayEndpoint)
		value.ErrorCode = "operator_rollback"
	}
	value.ActiveEndpoint.ListenAddress = ""
	return value
}
