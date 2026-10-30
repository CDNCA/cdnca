package l4live

import (
	"context"
	"sort"
	"sync"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/l4live"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Bounds of the 实时连接 page opened without a forward: the newest TCP
// forwards in reach are asked (each on the nodes of its scope), and at most
// MaxAllConnections connections are returned, newest first.
const (
	MaxAllStreams     = 20
	MaxAllConnections = 1000
	streamParallelism = 4
)

// AllFilter selects the forwards of ListAll. Platform callers see every
// forward (TenantID narrows to one tenant, tenants.id); tenant callers only
// their own (OwnerScopeID + OwnerUserID, the rule of l4forward Get).
type AllFilter struct {
	Platform     bool
	TenantID     uuid.UUID
	OwnerScopeID uuid.UUID
	OwnerUserID  uuid.UUID
	StreamID     uuid.UUID
	NodeID       uuid.UUID
	ListenPort   uint16
	ClientIP     string
	Limit        uint32 // per node and stream
}

type AllConnection struct {
	Connection
	StreamID   string `json:"stream_id"`
	StreamName string `json:"stream_name"`
	NodeName   string `json:"node_name"`
	CanClose   bool   `json:"can_close"`
}

// AllNode is a node that did not answer for some forward (state as in
// NodeResult); nodes that answered are not listed.
type AllNode struct {
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name"`
	State     string `json:"state"`
	ErrorCode string `json:"error_code,omitempty"`
}

type AllResponse struct {
	Streams          int             `json:"streams"`
	StreamsTruncated bool            `json:"streams_truncated"`
	Truncated        bool            `json:"truncated"`
	Problems         []AllNode       `json:"problems"`
	Connections      []AllConnection `json:"connections"`
}

type streamRef struct {
	id, scopeID uuid.UUID
	name        string
}

type streamSource func(ctx context.Context, filter AllFilter) ([]streamRef, error)

func (service *Service) loadStreams(ctx context.Context, filter AllFilter) ([]streamRef, error) {
	query := `SELECT f.id, f.scope_id, f.name FROM l4_forwards f
		JOIN access_scopes scope ON scope.id = f.scope_id
		WHERE f.deleted_at IS NULL AND f.enabled AND f.protocol = 'tcp'
		  AND ($1::uuid IS NULL OR scope.tenant_id = $1)
		  AND ($2::uuid IS NULL OR (f.scope_id = $2 AND f.owner_user_id = $3))
		  AND ($4::uuid IS NULL OR f.id = $4)
		  AND ($5::integer IS NULL OR $5 BETWEEN f.listen_port AND GREATEST(f.listen_port, COALESCE(f.listen_port_end, 0))
		       OR EXISTS (SELECT 1 FROM l4_forward_listeners listener WHERE listener.stream_id = f.id
		                  AND listener.retired_at IS NULL AND listener.protocol = 'tcp' AND listener.port = $5))
		ORDER BY f.created_at DESC, f.id DESC LIMIT $6`
	optional := func(value uuid.UUID) any {
		if value == uuid.Nil {
			return nil
		}
		return value
	}
	var port any
	if filter.ListenPort != 0 {
		port = int(filter.ListenPort)
	}
	rows, err := service.pool.Query(ctx, query, optional(filter.TenantID), optional(filter.OwnerScopeID), optional(filter.OwnerUserID),
		optional(filter.StreamID), port, MaxAllStreams+1)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (streamRef, error) {
		var item streamRef
		return item, row.Scan(&item.id, &item.scopeID, &item.name)
	})
}

// ListAll asks for the live sessions of every forward the caller reaches
// (bounded), merged newest first; a filter that is not set does not narrow.
func (service *Service) ListAll(ctx context.Context, filter AllFilter) (AllResponse, error) {
	if filter.Limit < 1 || filter.Limit > contract.MaxConnections || !validClient(filter.ClientIP) ||
		filter.Platform == (filter.OwnerScopeID != uuid.Nil) || (!filter.Platform && (filter.OwnerUserID == uuid.Nil || filter.TenantID != uuid.Nil)) {
		return AllResponse{}, ErrInvalidInput
	}
	streams, err := service.streams(ctx, filter)
	if err != nil {
		return AllResponse{}, err
	}
	response := AllResponse{Problems: []AllNode{}, Connections: []AllConnection{}}
	if len(streams) > MaxAllStreams {
		streams, response.StreamsTruncated = streams[:MaxAllStreams], true
	}
	response.Streams = len(streams)
	results := make([]ListResponse, len(streams))
	errs := make([]error, len(streams))
	var group sync.WaitGroup
	slots := make(chan struct{}, streamParallelism)
	for index, stream := range streams {
		group.Add(1)
		go func() {
			defer group.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			results[index], errs[index] = service.list(ctx, stream.scopeID, stream.id, filter.NodeID, filter.ClientIP, filter.Limit)
		}()
	}
	group.Wait()
	problems := map[string]AllNode{}
	for index, result := range results {
		if errs[index] != nil {
			return AllResponse{}, errs[index]
		}
		for _, node := range result.Nodes {
			if node.State != "ok" {
				if _, seen := problems[node.NodeID]; !seen {
					problems[node.NodeID] = AllNode{NodeID: node.NodeID, NodeName: node.NodeName, State: node.State, ErrorCode: node.ErrorCode}
				}
				continue
			}
			if node.Matched > uint32(len(node.Connections)) {
				response.Truncated = true
			}
			for _, connection := range node.Connections {
				if filter.ListenPort != 0 && connection.ListenPort != uint32(filter.ListenPort) {
					continue
				}
				response.Connections = append(response.Connections, AllConnection{Connection: connection,
					StreamID: streams[index].id.String(), StreamName: streams[index].name, NodeName: node.NodeName, CanClose: node.CanClose})
			}
		}
	}
	// Newest first; connections without a registered start (session log off)
	// last, in a stable order.
	sort.SliceStable(response.Connections, func(i, j int) bool {
		left, right := response.Connections[i].StartedAt, response.Connections[j].StartedAt
		if left == nil || right == nil {
			return left != nil && right == nil
		}
		return left.After(*right)
	})
	if len(response.Connections) > MaxAllConnections {
		response.Connections, response.Truncated = response.Connections[:MaxAllConnections], true
	}
	for _, node := range problems {
		response.Problems = append(response.Problems, node)
	}
	sort.Slice(response.Problems, func(i, j int) bool { return response.Problems[i].NodeName < response.Problems[j].NodeName })
	return response, nil
}
