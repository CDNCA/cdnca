package l4live

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type requesterFunc func(nodeID string, command *agentv1.L4LiveConnectionsCommand) ([]byte, error)

func (function requesterFunc) Request(_ context.Context, nodeID string, payload []byte) ([]byte, error) {
	var command agentv1.L4LiveConnectionsCommand
	if err := proto.Unmarshal(payload, &command); err != nil {
		return nil, err
	}
	return function(nodeID, &command)
}

func TestListReportsEveryNodeAndClosesOnCapableNodes(t *testing.T) {
	scope, stream := uuid.New(), uuid.New()
	listing, viewer, legacy, offline := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	started := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	received := uint64(10)
	var lastClose *agentv1.L4LiveConnectionsCommand
	service := &Service{now: time.Now, nodes: func(_ context.Context, got uuid.UUID) ([]target, error) {
		if got != scope {
			t.Fatalf("scope %s", got)
		}
		return []target{{id: legacy, name: "c", version: 0}, {id: offline, name: "d", version: 2},
			{id: viewer, name: "b", version: 1}, {id: listing, name: "a", version: 2}}, nil
	}, requester: requesterFunc(func(nodeID string, command *agentv1.L4LiveConnectionsCommand) ([]byte, error) {
		if command.StreamId != stream.String() || command.NodeId != nodeID || !command.ExpireTime.AsTime().After(time.Now()) {
			t.Fatalf("command %+v", command)
		}
		if nodeID == offline.String() {
			return nil, ErrOffline
		}
		result := &agentv1.L4LiveConnectionsResult{NodeId: nodeID, CommandEventId: command.Event.EventId}
		if len(command.CloseSessionKeys) != 0 {
			lastClose = command
			for _, key := range command.CloseSessionKeys {
				result.Closed = append(result.Closed, &agentv1.L4LiveConnectionClose{SessionKey: key})
			}
		} else if nodeID == listing.String() {
			if command.ClientIp != "203.0.113.0/24" || command.Limit != 50 {
				t.Fatalf("filter %+v", command)
			}
			result.Matched = 1
			result.Connections = []*agentv1.L4LiveConnection{{SessionKey: "k", ClientIp: "203.0.113.10", PeerIp: "192.0.2.9",
				StartedAt: timestamppb.New(started), BytesReceived: &received}}
		} else {
			result.ErrorCode = "busy"
		}
		return proto.Marshal(result)
	})}
	response, err := service.List(t.Context(), scope, stream, "203.0.113.0/24", 50)
	if err != nil {
		t.Fatal(err)
	}
	states := map[uuid.UUID]NodeResult{}
	for _, node := range response.Nodes {
		states[uuid.MustParse(node.NodeID)] = node
	}
	if response.Nodes[0].NodeID != listing.String() || states[listing].State != "ok" || !states[listing].CanClose ||
		len(states[listing].Connections) != 1 || !states[listing].Connections[0].StartedAt.Equal(started) ||
		states[listing].Connections[0].PeerIP != "192.0.2.9" || *states[listing].Connections[0].BytesReceived != 10 {
		t.Fatalf("listing node %+v", states[listing])
	}
	if states[viewer].State != "error" || states[viewer].ErrorCode != "busy" || states[viewer].CanClose ||
		states[legacy].State != "unsupported" || states[offline].State != "offline" {
		t.Fatalf("states %+v", states)
	}
	closed, err := service.Close(t.Context(), scope, stream, listing, []string{"k"})
	if err != nil || closed.State != "ok" || len(closed.Results) != 1 || lastClose == nil {
		t.Fatalf("close %+v %v", closed, err)
	}
	if closed, err := service.Close(t.Context(), scope, stream, viewer, []string{"k"}); err != nil || closed.State != "unsupported" {
		t.Fatalf("close on a list-only node %+v %v", closed, err)
	}
	if _, err := service.Close(t.Context(), scope, stream, uuid.New(), []string{"k"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("close on a node outside the scope: %v", err)
	}
	if _, err := service.List(t.Context(), scope, stream, "nope", 50); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("bad client accepted")
	}
}
