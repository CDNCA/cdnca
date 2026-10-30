package gatewayclient

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNodeMonitoringBridgeAcknowledgementReplayIsExactAndBounded(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	newBridge := func(t *testing.T) *NodeMonitoringBridge {
		t.Helper()
		bridge, err := NewNodeMonitoringBridge(t.TempDir(), nodeID)
		if err != nil {
			t.Fatal(err)
		}
		return bridge
	}
	enqueue := func(t *testing.T, bridge *NodeMonitoringBridge) *agentv1.NodeMonitoringAck {
		t.Helper()
		if err := bridge.ReportNodeMonitoring(t.Context(), nodemonitoring.MetricReport{
			SchemaVersion: 1, NodeID: nodeID, ConfigRevision: 7, ObservedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
		pending := bridge.Pending()
		record := pending[len(pending)-1]
		return &agentv1.NodeMonitoringAck{
			EventId: record.Event.EventId, NodeId: record.NodeId, ConfigRevision: record.ConfigRevision,
			PublicationSequence: record.PublicationSequence, PublishedStream: nodeMonitoringStatusStream,
			PublishedSequence: record.PublicationSequence + 100, AcceptedTime: timestamppb.Now(),
		}
	}
	t.Run("exact replay leaves next pending intact", func(t *testing.T) {
		bridge := newBridge(t)
		ack := enqueue(t, bridge)
		next := enqueue(t, bridge)
		canonical := proto.Clone(ack).(*agentv1.NodeMonitoringAck)
		if err := bridge.Acknowledge(next); !errors.Is(err, ErrInvalidMessage) || len(bridge.Pending()) != 2 {
			t.Fatalf("unconfirmed non-head acknowledgement accepted: %v", err)
		}
		if err := bridge.Acknowledge(ack); err != nil {
			t.Fatal(err)
		}
		if err := bridge.Acknowledge(canonical); err != nil {
			t.Fatalf("exact persisted acknowledgement replay rejected: %v", err)
		}
		// Cache entries must not retain mutable protobuf pointers from callers.
		ack.Replayed = true
		if err := bridge.Acknowledge(ack); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("mutated caller acknowledgement accepted: %v", err)
		}
		mutations := map[string]func(*agentv1.NodeMonitoringAck){
			"foreign node":         func(value *agentv1.NodeMonitoringAck) { value.NodeId = "01990000-0000-7000-8000-000000000008" },
			"event":                func(value *agentv1.NodeMonitoringAck) { value.EventId = next.EventId },
			"revision":             func(value *agentv1.NodeMonitoringAck) { value.ConfigRevision++ },
			"publication sequence": func(value *agentv1.NodeMonitoringAck) { value.PublicationSequence++ },
			"stream":               func(value *agentv1.NodeMonitoringAck) { value.PublishedStream = "FORGED" },
			"stream sequence":      func(value *agentv1.NodeMonitoringAck) { value.PublishedSequence++ },
			"replayed":             func(value *agentv1.NodeMonitoringAck) { value.Replayed = !value.Replayed },
			"accepted time":        func(value *agentv1.NodeMonitoringAck) { value.AcceptedTime.Seconds++ },
			"missing time":         func(value *agentv1.NodeMonitoringAck) { value.AcceptedTime = nil },
			"invalid time":         func(value *agentv1.NodeMonitoringAck) { value.AcceptedTime.Nanos = 1_000_000_000 },
			"unknown field":        func(value *agentv1.NodeMonitoringAck) { value.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01}) },
			"nested unknown field": func(value *agentv1.NodeMonitoringAck) {
				value.AcceptedTime.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01})
			},
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				candidate := proto.Clone(canonical).(*agentv1.NodeMonitoringAck)
				mutate(candidate)
				if err := bridge.Acknowledge(candidate); !errors.Is(err, ErrInvalidMessage) {
					t.Fatalf("altered acknowledgement accepted: %v", err)
				}
				if pending := bridge.Pending(); len(pending) != 1 || pending[0].Event.EventId != next.EventId {
					t.Fatal("replay removed or reordered the next pending report")
				}
			})
		}
		if err := bridge.Acknowledge(canonical); err != nil {
			t.Fatalf("caller mutation changed the remembered acknowledgement: %v", err)
		}
		if err := bridge.Acknowledge(next); err != nil {
			t.Fatal(err)
		}
		if err := bridge.Acknowledge(next); err != nil || len(bridge.Pending()) != 0 {
			t.Fatalf("empty-outbox exact replay failed: %v", err)
		}
		restarted, err := NewNodeMonitoringBridge(filepath.Dir(bridge.stateDir), nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if err := restarted.Acknowledge(next); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("new Bridge invented prior-session acknowledgement history: %v", err)
		}
	})
	t.Run("concurrent duplicates remove the head only once", func(t *testing.T) {
		bridge := newBridge(t)
		ack := enqueue(t, bridge)
		next := enqueue(t, bridge)
		results := make(chan error, 16)
		for index := 0; index < cap(results); index++ {
			go func() { results <- bridge.Acknowledge(ack) }()
		}
		for index := 0; index < cap(results); index++ {
			if err := <-results; err != nil {
				t.Fatalf("concurrent exact acknowledgement rejected: %v", err)
			}
		}
		if pending := bridge.Pending(); len(pending) != 1 || pending[0].Event.EventId != next.EventId {
			t.Fatal("concurrent acknowledgements removed the next pending report")
		}
	})
	t.Run("unknown fields rejected before first persistence", func(t *testing.T) {
		for _, nested := range []bool{false, true} {
			bridge := newBridge(t)
			ack := enqueue(t, bridge)
			if nested {
				ack.AcceptedTime.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01})
			} else {
				ack.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01})
			}
			if err := bridge.Acknowledge(ack); !errors.Is(err, ErrInvalidMessage) || len(bridge.Pending()) != 1 {
				t.Fatalf("unknown fields changed the outbox: %v", err)
			}
		}
	})
	t.Run("replay history is bounded", func(t *testing.T) {
		bridge := newBridge(t)
		acks := make([]*agentv1.NodeMonitoringAck, 0, maxNodeMonitoringOutbox+1)
		for index := 0; index <= maxNodeMonitoringOutbox; index++ {
			ack := enqueue(t, bridge)
			if err := bridge.Acknowledge(ack); err != nil {
				t.Fatal(err)
			}
			acks = append(acks, ack)
		}
		next := enqueue(t, bridge)
		if err := bridge.Acknowledge(acks[0]); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("expired acknowledgement replay accepted: %v", err)
		}
		for _, ack := range acks[1:] {
			if err := bridge.Acknowledge(ack); err != nil {
				t.Fatalf("in-window acknowledgement replay rejected: %v", err)
			}
		}
		if pending := bridge.Pending(); len(pending) != 1 || pending[0].Event.EventId != next.EventId {
			t.Fatal("bounded replay changed the pending report")
		}
	})
}

func TestNodeMonitoringBridgeDoesNotRememberFailedAcknowledgement(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	bridge, err := NewNodeMonitoringBridge(t.TempDir(), nodeID)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		if err := bridge.ReportNodeMonitoring(t.Context(), nodemonitoring.MetricReport{
			SchemaVersion: 1, NodeID: nodeID, ConfigRevision: 7, ObservedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	pending := bridge.Pending()
	ack := &agentv1.NodeMonitoringAck{
		EventId: pending[0].Event.EventId, NodeId: nodeID, ConfigRevision: 7,
		PublicationSequence: 1, PublishedStream: nodeMonitoringStatusStream,
		PublishedSequence: 100, AcceptedTime: timestamppb.Now(),
	}
	path := filepath.Join(bridge.stateDir, nodeMonitoringOutboxFile)
	backup := path + ".test-backup"
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	// A directory at the destination forces rename failure even when run as root.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := bridge.Acknowledge(ack); err == nil {
			t.Fatal("failed persistence was treated as an acknowledged replay")
		}
		remaining := bridge.Pending()
		if len(remaining) != 2 || !proto.Equal(remaining[0], pending[0]) || !proto.Equal(remaining[1], pending[1]) {
			t.Fatal("persistence failure changed pending order")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, path); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Acknowledge(ack); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Acknowledge(ack); err != nil {
		t.Fatalf("successfully retried acknowledgement was not remembered: %v", err)
	}
	if remaining := bridge.Pending(); len(remaining) != 1 || !proto.Equal(remaining[0], pending[1]) {
		t.Fatal("acknowledgement retry removed the next pending report")
	}
}
