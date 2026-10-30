// Package nodegatewayaddr is 维护升级 → 节点设置「更换主控连接地址」
// (fix-nodegw, migration 573).
//
// An administrator names a new Gateway address (HOST:PORT) and an optional
// SNI name (default: the host) for all nodes, one region or selected nodes.
// For each node the control plane signs cdnca.gateway-address-change/v1
// (libs/edgeconfig/gatewayaddr, edge publication key, per node revision) and
// publishes it to the Gateway's command stream. The node probes the new
// address with mTLS and an authenticated hello and switches only on success;
// it answers probing, then switched (on the new address) or failed. Failed
// nodes can be retried (a new revision). The old address must stay reachable
// until every node has switched (the page says so).
package nodegatewayaddr

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/gatewayaddr"
	"github.com/google/uuid"
)

const (
	TargetAll    = "all"
	TargetRegion = "region"
	TargetNodes  = "nodes"

	StatePending    = "pending"
	StateDelivered  = "delivered"
	StateProbing    = gatewayaddr.StateProbing
	StateSwitched   = gatewayaddr.StateSwitched
	StateFailed     = gatewayaddr.StateFailed
	StateSuperseded = "superseded"

	// ErrorUndelivered: the document expired before the node answered (offline
	// for the whole lifetime); retry republishes it.
	ErrorUndelivered = "undelivered"

	// MaxNodes bounds one change (selected nodes and the resolved scope).
	MaxNodes = 10000
	// DocumentLifetime is the signed document's validity.
	DocumentLifetime = 24 * time.Hour

	// StepUpAudience / StepUpAction: the platform MFA proof bound to one change request.
	StepUpAudience = "node-gateway-address"
	StepUpAction   = "node.gateway_address.change"

	AuditCreate = "node.gateway_address.change"
	AuditRetry  = "node.gateway_address.retry"
	AuditReport = "node.gateway_address.report"
)

var (
	ErrInvalidInput      = errors.New("gateway address change input is invalid")
	ErrNoNodes           = errors.New("gateway address change matched no node")
	ErrTooManyNodes      = errors.New("gateway address change matched too many nodes")
	ErrNotFound          = errors.New("gateway address change not found")
	ErrNothingToRetry    = errors.New("gateway address change has no failed node to retry")
	ErrStepUpRequired    = errors.New("gateway address change needs an MFA step-up")
	ErrSignerUnavailable = errors.New("the edge publication signer or edge messaging is not configured")
)

type Actor struct {
	ScopeID   uuid.UUID
	UserID    uuid.UUID
	SessionID uuid.UUID
	RequestID string
	SourceIP  string
}

// CreateRequest is what the page submits.
type CreateRequest struct {
	Address     string
	ServerName  string // empty: the address host
	TargetKind  string
	Region      string
	NodeIDs     []uuid.UUID
	StepUpToken string
}

// Normalize validates the request and fills the default server name.
func (request CreateRequest) Normalize() (CreateRequest, error) {
	request.Address = strings.TrimSpace(request.Address)
	request.ServerName = strings.TrimSpace(request.ServerName)
	request.Region = strings.TrimSpace(request.Region)
	if !gatewayaddr.ValidAddress(request.Address) {
		return request, ErrInvalidInput
	}
	if request.ServerName == "" {
		host, _, _ := net.SplitHostPort(request.Address)
		request.ServerName = host
	}
	if !gatewayaddr.ValidServerName(request.ServerName) {
		return request, ErrInvalidInput
	}
	switch request.TargetKind {
	case TargetAll:
		if request.Region != "" || len(request.NodeIDs) != 0 {
			return request, ErrInvalidInput
		}
	case TargetRegion:
		if request.Region == "" || len(request.Region) > 64 || len(request.NodeIDs) != 0 {
			return request, ErrInvalidInput
		}
	case TargetNodes:
		if request.Region != "" || len(request.NodeIDs) == 0 || len(request.NodeIDs) > MaxNodes {
			return request, ErrInvalidInput
		}
		seen := map[uuid.UUID]bool{}
		for _, id := range request.NodeIDs {
			if id == uuid.Nil || seen[id] {
				return request, ErrInvalidInput
			}
			seen[id] = true
		}
	default:
		return request, ErrInvalidInput
	}
	return request, nil
}

// Change is one submitted change with its per node states.
type Change struct {
	ID         uuid.UUID    `json:"id"`
	Address    string       `json:"address"`
	ServerName string       `json:"server_name"`
	TargetKind string       `json:"target_kind"`
	Region     string       `json:"region,omitempty"`
	NodeCount  int          `json:"node_count"`
	Counts     StateCounts  `json:"counts"`
	CreatedAt  time.Time    `json:"created_at"`
	CreatedBy  uuid.UUID    `json:"created_by_user_id"`
	Nodes      []NodeStatus `json:"nodes,omitempty"`
}

type StateCounts struct {
	Pending    int `json:"pending"`
	Probing    int `json:"probing"`
	Switched   int `json:"switched"`
	Failed     int `json:"failed"`
	Superseded int `json:"superseded"`
}

// Complete: every node that is still part of the change has switched.
func (counts StateCounts) Complete() bool {
	return counts.Pending == 0 && counts.Probing == 0 && counts.Failed == 0
}

type NodeStatus struct {
	NodeID        uuid.UUID  `json:"node_id"`
	DisplayID     string     `json:"display_id"`
	Name          string     `json:"name"`
	Region        string     `json:"region"`
	State         string     `json:"state"`
	ErrorCode     string     `json:"error_code,omitempty"`
	Attempts      int        `json:"attempts"`
	ActiveAddress string     `json:"active_address,omitempty"`
	ReportedAt    *time.Time `json:"reported_at,omitempty"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// Count buckets a state for the page: delivered shows as pending (待下发 →
// waiting for the node), probing as probing.
func (counts *StateCounts) Count(state string) {
	switch state {
	case StatePending, StateDelivered:
		counts.Pending++
	case StateProbing:
		counts.Probing++
	case StateSwitched:
		counts.Switched++
	case StateFailed:
		counts.Failed++
	case StateSuperseded:
		counts.Superseded++
	}
}

// nextState applies a node receipt to the stored state. ok=false: the
// receipt is stale for this row (ignored). A final state never moves back.
func nextState(current, reported, code string) (state, errorCode string, ok bool) {
	switch current {
	case StatePending, StateDelivered, StateProbing:
	default:
		return current, "", false
	}
	switch reported {
	case StateProbing:
		if current == StateProbing {
			return current, "", false
		}
		return StateProbing, "", true
	case StateSwitched:
		return StateSwitched, "", true
	case StateFailed:
		if !validErrorCode(code) || code == "" {
			return current, "", false
		}
		return StateFailed, code, true
	}
	return current, "", false
}

func validErrorCode(value string) bool {
	if len(value) > 64 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || index > 0 && (character >= '0' && character <= '9' || character == '_') {
			continue
		}
		return false
	}
	return true
}
