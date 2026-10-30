package l4live

import (
	"context"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Opened without a forward, 实时连接 asks every reachable forward on its
// scope's nodes and merges the connections newest first.
func TestListAllMergesForwardsNewestFirst(t *testing.T) {
	scopeA, scopeB := uuid.New(), uuid.New()
	streamA, streamB := uuid.New(), uuid.New()
	nodeA, nodeB, offline := uuid.New(), uuid.New(), uuid.New()
	base := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	var gotFilter AllFilter
	service := &Service{now: time.Now,
		streams: func(_ context.Context, filter AllFilter) ([]streamRef, error) {
			gotFilter = filter
			return []streamRef{{id: streamA, scopeID: scopeA, name: "a"}, {id: streamB, scopeID: scopeB, name: "b"}}, nil
		},
		nodes: func(_ context.Context, scope uuid.UUID) ([]target, error) {
			if scope == scopeA {
				return []target{{id: nodeA, name: "node-a", version: 2}, {id: offline, name: "node-off", version: 2}}, nil
			}
			return []target{{id: nodeB, name: "node-b", version: 1}}, nil
		},
		requester: requesterFunc(func(nodeID string, command *agentv1.L4LiveConnectionsCommand) ([]byte, error) {
			if nodeID == offline.String() {
				return nil, ErrOffline
			}
			result := &agentv1.L4LiveConnectionsResult{NodeId: nodeID, CommandEventId: command.Event.EventId, Matched: 2}
			offset := time.Minute
			if command.StreamId == streamB.String() {
				offset = 2 * time.Minute
			}
			result.Connections = []*agentv1.L4LiveConnection{
				{SessionKey: command.StreamId + "-old", ListenPort: 9000, ClientIp: "203.0.113.1", StartedAt: timestamppb.New(base)},
				{SessionKey: command.StreamId + "-new", ListenPort: 9000, ClientIp: "203.0.113.2", StartedAt: timestamppb.New(base.Add(offset))},
			}
			return proto.Marshal(result)
		}),
	}
	got, err := service.ListAll(t.Context(), AllFilter{Platform: true, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if !gotFilter.Platform || gotFilter.TenantID != uuid.Nil {
		t.Fatalf("stream filter = %+v", gotFilter)
	}
	keys := []string{}
	for _, item := range got.Connections {
		keys = append(keys, item.SessionKey)
	}
	want := []string{streamB.String() + "-new", streamA.String() + "-new", streamA.String() + "-old", streamB.String() + "-old"}
	if got.Streams != 2 || len(keys) != 4 || keys[0] != want[0] || keys[1] != want[1] || keys[3] != want[3] {
		t.Fatalf("order = %v, want %v", keys, want)
	}
	if got.Connections[0].StreamName != "b" || got.Connections[0].NodeName != "node-b" || got.Connections[0].CanClose ||
		!got.Connections[1].CanClose {
		t.Fatalf("connection attribution = %+v", got.Connections[:2])
	}
	if len(got.Problems) != 1 || got.Problems[0].State != "offline" || got.Problems[0].NodeName != "node-off" {
		t.Fatalf("problems = %+v", got.Problems)
	}
}

func TestListAllNarrowsNodeAndPortAndBoundsForwards(t *testing.T) {
	scope, node, other := uuid.New(), uuid.New(), uuid.New()
	asked := map[string]int{}
	var mu sync.Mutex
	streams := make([]streamRef, MaxAllStreams+1)
	for index := range streams {
		streams[index] = streamRef{id: uuid.New(), scopeID: scope, name: "s"}
	}
	service := &Service{now: time.Now,
		streams: func(context.Context, AllFilter) ([]streamRef, error) { return streams, nil },
		nodes: func(context.Context, uuid.UUID) ([]target, error) {
			return []target{{id: node, name: "n", version: 2}, {id: other, name: "o", version: 2}}, nil
		},
		requester: requesterFunc(func(nodeID string, command *agentv1.L4LiveConnectionsCommand) ([]byte, error) {
			mu.Lock()
			asked[nodeID]++
			mu.Unlock()
			return proto.Marshal(&agentv1.L4LiveConnectionsResult{NodeId: nodeID, CommandEventId: command.Event.EventId, Matched: 2,
				Connections: []*agentv1.L4LiveConnection{{SessionKey: "a", ListenPort: 80}, {SessionKey: "b", ListenPort: 81}}})
		}),
	}
	got, err := service.ListAll(t.Context(), AllFilter{Platform: true, NodeID: node, ListenPort: 81, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if asked[other.String()] != 0 || asked[node.String()] != MaxAllStreams || !got.StreamsTruncated || got.Streams != MaxAllStreams {
		t.Fatalf("asked=%v response=%+v", asked, got)
	}
	for _, item := range got.Connections {
		if item.ListenPort != 81 {
			t.Fatalf("port filter kept %+v", item)
		}
	}
}

// A tenant session is pinned to its own forwards and cannot name a tenant.
func TestListAllRejectsMixedScopes(t *testing.T) {
	service := &Service{now: time.Now}
	for _, filter := range []AllFilter{
		{Limit: 10}, // neither platform nor owner
		{Platform: true, OwnerScopeID: uuid.New(), OwnerUserID: uuid.New(), Limit: 10},
		{OwnerScopeID: uuid.New(), Limit: 10},
		{OwnerScopeID: uuid.New(), OwnerUserID: uuid.New(), TenantID: uuid.New(), Limit: 10},
		{Platform: true, Limit: 0},
		{Platform: true, Limit: 10, ClientIP: "nope"},
	} {
		if _, err := service.ListAll(t.Context(), filter); err != ErrInvalidInput {
			t.Fatalf("filter %+v err=%v", filter, err)
		}
	}
}
