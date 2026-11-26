package gatewayregistry

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// LocalGatewayFresh: the co-located Gateway polls its settings every minute
// (agent-gateway DefaultSettingsPollInterval) and forwards every node call,
// so nothing seen for this long means it is not reaching the control plane.
const LocalGatewayFresh = 3 * time.Minute

// nodeFreshness matches the admin dashboard (dashboard.NodeFreshnessCutoff):
// a node counts as connected while its presence is online and this recent.
const nodeFreshness = 45 * time.Second

// LocalGateway is the co-located Gateway as the management page shows it.
// It has no row: the facts are what it last presented to ControlInternal in
// this control-api process (nil until it has called since start).
type LocalGateway struct {
	// Address / ServerName: the node endpoint it is published as (empty: not
	// published, CDNCA_GATEWAY_LOCAL_* unset).
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
	// Status: online (called within LocalGatewayFresh), offline, or
	// not_reported (no call since this control-api started).
	Status               string     `json:"status"`
	InstanceID           string     `json:"instance_id"`
	Version              string     `json:"version"`
	ReadyAt              *time.Time `json:"ready_at"`
	LastSeenAt           *time.Time `json:"last_seen_at"`
	CertificateExpiresAt *time.Time `json:"certificate_expires_at"`
	NodesOnline          int        `json:"nodes_online"`
}

type localGatewayState struct {
	mu                                    sync.Mutex
	instanceID, version                   string
	readyAt, lastSeenAt, certificateUntil time.Time
}

// ObserveLocalGateway records a call of the co-located Gateway
// (controlinternal.LocalGatewayObserver). Empty or zero values keep what was
// recorded before: only ReportGatewayReady carries the version.
func (s *Service) ObserveLocalGateway(instanceID, version string, certificateNotAfter time.Time) {
	if s == nil {
		return
	}
	now := s.config.Now().UTC()
	state := &s.local
	state.mu.Lock()
	defer state.mu.Unlock()
	if instanceID != "" {
		state.instanceID = instanceID
	}
	if version != "" {
		state.version, state.readyAt = version, now
	}
	if !certificateNotAfter.IsZero() {
		state.certificateUntil = certificateNotAfter.UTC()
	}
	state.lastSeenAt = now
}

func (s *Service) localGateway(nodes int) LocalGateway {
	state := &s.local
	state.mu.Lock()
	defer state.mu.Unlock()
	out := LocalGateway{Address: s.config.LocalGateway.Address, ServerName: s.config.LocalGateway.ServerName,
		Status: "not_reported", InstanceID: state.instanceID, Version: state.version, NodesOnline: nodes,
		ReadyAt: optionalTime(state.readyAt), LastSeenAt: optionalTime(state.lastSeenAt), CertificateExpiresAt: optionalTime(state.certificateUntil)}
	if !state.lastSeenAt.IsZero() {
		out.Status = "offline"
		if s.config.Now().Sub(state.lastSeenAt) <= LocalGatewayFresh {
			out.Status = "online"
		}
	}
	return out
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

// nodesOnlineByGateway counts connected nodes by the gateway_instance_id of
// their current session: a standalone Gateway sends its gateway_id, so what
// is left over came through the co-located Gateway.
func (s *Service) nodesOnlineByGateway(ctx context.Context) (map[string]int, error) {
	rows, err := s.config.Pool.Query(ctx, `SELECT session.gateway_instance_id, count(*)
  FROM node_presence presence
  JOIN nodes node ON node.id=presence.node_id AND node.admin_state<>'retired'
  JOIN node_session_capabilities session ON session.node_id=presence.node_id AND session.session_epoch=presence.session_epoch
  WHERE presence.status='online' AND presence.last_seen_at >= $1
  GROUP BY session.gateway_instance_id`, s.config.Now().Add(-nodeFreshness))
	if err != nil {
		return nil, fmt.Errorf("count nodes by gateway: %w", err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var instance string
		var count int
		if err := rows.Scan(&instance, &count); err != nil {
			return nil, fmt.Errorf("scan node count: %w", err)
		}
		counts[instance] = count
	}
	return counts, rows.Err()
}

// Overview is the management page list: the standalone Gateways with their
// connected nodes, and the co-located Gateway with the rest.
func (s *Service) Overview(ctx context.Context) ([]Gateway, LocalGateway, error) {
	gateways, err := s.List(ctx)
	if err != nil {
		return nil, LocalGateway{}, err
	}
	counts, err := s.nodesOnlineByGateway(ctx)
	if err != nil {
		return nil, LocalGateway{}, err
	}
	for index := range gateways {
		id := gateways[index].ID.String()
		gateways[index].NodesOnline = counts[id]
		delete(counts, id)
	}
	local := 0
	for _, count := range counts {
		local += count
	}
	return gateways, s.localGateway(local), nil
}
