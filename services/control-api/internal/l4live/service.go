// Package l4live serves the 实时连接 page: it asks every node that holds a
// stream's scope configuration for the stream's live TCP sessions (or to
// close some) through the gateway relay (libs/edgeconfig/l4live), and reports
// per node: nodes whose agent lacks CAPABILITY_NAME_L4_LIVE_CONNECTIONS are
// listed as unsupported, and recover as soon as their session declares it.
package l4live

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/l4live"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrInvalidInput = errors.New("invalid L4 live connections request")
	ErrOffline      = errors.New("node has no live gateway session")
)

const (
	maxNodes     = 64
	parallelism  = 8
	nodeDeadline = 5 * time.Second
)

// Requester sends one encoded command to a node's gateway session and
// returns the encoded result (empty when the gateway refused).
type Requester interface {
	Request(ctx context.Context, nodeID string, command []byte) ([]byte, error)
}

type NATSRequester struct{ connection *nats.Conn }

func NewNATSRequester(connection *nats.Conn) (*NATSRequester, error) {
	if connection == nil || connection.IsClosed() {
		return nil, errors.New("L4 live requester requires an active edge NATS connection")
	}
	return &NATSRequester{connection: connection}, nil
}

func (requester *NATSRequester) Request(ctx context.Context, nodeID string, command []byte) ([]byte, error) {
	reply, err := requester.connection.RequestWithContext(ctx, contract.Subject(nodeID), command)
	if errors.Is(err, nats.ErrNoResponders) {
		return nil, ErrOffline
	}
	if err != nil {
		return nil, err
	}
	if len(reply.Data) > contract.MaxCarrierBytes {
		return nil, errors.New("L4 live reply is too large")
	}
	return reply.Data, nil
}

type Connection struct {
	NodeID        string     `json:"node_id"`
	SessionKey    string     `json:"session_key"`
	ListenerID    string     `json:"listener_id"`
	ListenPort    uint32     `json:"listen_port"`
	ClientIP      string     `json:"client_ip"`
	ClientPort    uint32     `json:"client_port"`
	PeerIP        string     `json:"peer_ip,omitempty"`
	Upstream      string     `json:"upstream"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	BytesReceived *uint64    `json:"bytes_received,omitempty"`
	BytesSent     *uint64    `json:"bytes_sent,omitempty"`
}

// NodeResult: state is ok, unsupported (agent lacks the capability),
// offline (no gateway session) or error (error_code from the agent:
// unavailable, busy, expired; or "timeout", "refused").
type NodeResult struct {
	NodeID      string       `json:"node_id"`
	NodeName    string       `json:"node_name"`
	State       string       `json:"state"`
	ErrorCode   string       `json:"error_code,omitempty"`
	CanClose    bool         `json:"can_close"`
	Matched     uint32       `json:"matched"`
	Untracked   uint32       `json:"untracked"`
	Connections []Connection `json:"connections"`
}

type ListResponse struct {
	StreamID string       `json:"stream_id"`
	Nodes    []NodeResult `json:"nodes"`
}

type CloseResult struct {
	SessionKey string `json:"session_key"`
	ErrorCode  string `json:"error_code,omitempty"`
}

type CloseResponse struct {
	NodeID    string        `json:"node_id"`
	State     string        `json:"state"`
	ErrorCode string        `json:"error_code,omitempty"`
	Results   []CloseResult `json:"results"`
}

type Service struct {
	pool      *pgxpool.Pool
	nodes     nodeSource
	streams   streamSource
	requester Requester
	now       func() time.Time
}

type target struct {
	id      uuid.UUID
	name    string
	version uint32 // 0: unsupported
}

type nodeSource func(ctx context.Context, scopeID uuid.UUID) ([]target, error)

func New(pool *pgxpool.Pool, requester Requester) (*Service, error) {
	if pool == nil || requester == nil {
		return nil, ErrInvalidInput
	}
	service := &Service{pool: pool, requester: requester, now: time.Now}
	service.nodes = service.loadTargets
	service.streams = service.loadStreams
	return service, nil
}

// loadTargets: active nodes holding the scope's configuration, with the
// L4_LIVE_CONNECTIONS version their latest session declared.
func (service *Service) loadTargets(ctx context.Context, scopeID uuid.UUID) ([]target, error) {
	rows, err := service.pool.Query(ctx, `SELECT node.id, node.name,
			(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts WHERE facts.node_id=node.id
			 ORDER BY facts.session_epoch DESC LIMIT 1)
		FROM node_config_state state JOIN nodes node ON node.id=state.node_id AND node.admin_state='active'
		WHERE state.configuration_scope_id=$1 AND state.current_config_version_id IS NOT NULL
		ORDER BY node.name, node.id LIMIT $2`, scopeID, maxNodes)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (target, error) {
		var item target
		var snapshot []byte
		if err := row.Scan(&item.id, &item.name, &snapshot); err != nil {
			return target{}, err
		}
		var capabilities agentv1.AgentCapabilities
		if len(snapshot) != 0 && proto.Unmarshal(snapshot, &capabilities) == nil {
			for _, capability := range capabilities.Features {
				if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS {
					item.version = capability.GetApiVersion()
				}
			}
		}
		return item, nil
	})
}

func validClient(value string) bool {
	if value == "" {
		return true
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return true
	}
	address, err := netip.ParseAddr(value)
	return err == nil && address.Zone() == ""
}

func (service *Service) command(nodeID, streamID uuid.UUID, clientIP string, limit uint32, keys []string) []byte {
	now := service.now()
	command := &agentv1.L4LiveConnectionsCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(now)},
		NodeId: nodeID.String(), StreamId: streamID.String(), ClientIp: clientIP, Limit: limit, CloseSessionKeys: keys,
		ExpireTime: timestamppb.New(now.Add(nodeDeadline)),
	}
	payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	return payload
}

func (service *Service) exchange(ctx context.Context, item target, payload []byte) (*agentv1.L4LiveConnectionsResult, string, string) {
	requestCtx, cancel := context.WithTimeout(ctx, nodeDeadline)
	defer cancel()
	reply, err := service.requester.Request(requestCtx, item.id.String(), payload)
	switch {
	case errors.Is(err, ErrOffline):
		return nil, "offline", ""
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout):
		return nil, "error", "timeout"
	case err != nil:
		return nil, "error", "request_failed"
	case len(reply) == 0:
		return nil, "error", "refused"
	}
	var result agentv1.L4LiveConnectionsResult
	if proto.Unmarshal(reply, &result) != nil || result.GetNodeId() != item.id.String() {
		return nil, "error", "invalid_reply"
	}
	if result.GetErrorCode() != "" {
		return &result, "error", result.GetErrorCode()
	}
	return &result, "ok", ""
}

// List asks every node of the stream's scope for its live sessions.
func (service *Service) List(ctx context.Context, scopeID, streamID uuid.UUID, clientIP string, limit uint32) (ListResponse, error) {
	if limit < 1 || limit > contract.MaxConnections || !validClient(clientIP) {
		return ListResponse{}, ErrInvalidInput
	}
	return service.list(ctx, scopeID, streamID, uuid.Nil, clientIP, limit)
}

// list asks the scope's nodes (only nodeID when set) for streamID's sessions.
func (service *Service) list(ctx context.Context, scopeID, streamID, nodeID uuid.UUID, clientIP string, limit uint32) (ListResponse, error) {
	targets, err := service.nodes(ctx, scopeID)
	if err != nil {
		return ListResponse{}, err
	}
	if nodeID != uuid.Nil {
		kept := targets[:0:0]
		for _, item := range targets {
			if item.id == nodeID {
				kept = append(kept, item)
			}
		}
		targets = kept
	}
	response := ListResponse{StreamID: streamID.String(), Nodes: make([]NodeResult, len(targets))}
	var group sync.WaitGroup
	slots := make(chan struct{}, parallelism)
	for index, item := range targets {
		node := &response.Nodes[index]
		node.NodeID, node.NodeName, node.CanClose, node.Connections = item.id.String(), item.name, item.version >= 2, []Connection{}
		if item.version == 0 {
			node.State = "unsupported"
			continue
		}
		group.Add(1)
		go func() {
			defer group.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			result, state, code := service.exchange(ctx, item, service.command(item.id, streamID, clientIP, limit, nil))
			node.State, node.ErrorCode = state, code
			if result == nil || state != "ok" {
				return
			}
			node.Matched, node.Untracked = result.GetMatched(), result.GetUntracked()
			for _, connection := range result.GetConnections() {
				value := Connection{NodeID: node.NodeID, SessionKey: connection.GetSessionKey(), ListenerID: connection.GetListenerId(),
					ListenPort: connection.GetListenPort(), ClientIP: connection.GetClientIp(), ClientPort: connection.GetClientPort(),
					PeerIP: connection.GetPeerIp(), Upstream: connection.GetUpstream(),
					BytesReceived: connection.BytesReceived, BytesSent: connection.BytesSent}
				if connection.GetStartedAt() != nil {
					started := connection.GetStartedAt().AsTime().UTC()
					value.StartedAt = &started
				}
				node.Connections = append(node.Connections, value)
			}
		}()
	}
	group.Wait()
	sort.SliceStable(response.Nodes, func(i, j int) bool { return response.Nodes[i].State == "ok" && response.Nodes[j].State != "ok" })
	return response, nil
}

// Close asks one node of the stream's scope to close sessions.
func (service *Service) Close(ctx context.Context, scopeID, streamID, nodeID uuid.UUID, keys []string) (CloseResponse, error) {
	if len(keys) == 0 || len(keys) > contract.MaxCloseKeys {
		return CloseResponse{}, ErrInvalidInput
	}
	for _, key := range keys {
		if len(key) == 0 || len(key) > 160 {
			return CloseResponse{}, ErrInvalidInput
		}
	}
	targets, err := service.nodes(ctx, scopeID)
	if err != nil {
		return CloseResponse{}, err
	}
	for _, item := range targets {
		if item.id != nodeID {
			continue
		}
		response := CloseResponse{NodeID: nodeID.String(), Results: []CloseResult{}}
		if item.version < 2 {
			response.State = "unsupported"
			return response, nil
		}
		result, state, code := service.exchange(ctx, item, service.command(item.id, streamID, "", 1, keys))
		response.State, response.ErrorCode = state, code
		if result != nil {
			for _, closed := range result.GetClosed() {
				response.Results = append(response.Results, CloseResult{SessionKey: closed.GetSessionKey(), ErrorCode: closed.GetErrorCode()})
			}
		}
		return response, nil
	}
	return CloseResponse{}, ErrInvalidInput
}
