package marketprobe

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Node-market role assignment. A seller putting a line
// group in an offer (own_pool) consents to its nodes joining the node
// market: each inventory round assigns JOIN_MARKET to the nodes of every
// active pool that declare MARKET_ROLE, and PROBE_ONLY to nodes the
// controller joined earlier that no active pool holds any more. The node
// decides within its local settings (market_probe.enabled, leave_market,
// join_market) and answers the role in effect; that answer, not a database
// field, is what the pool report goes by.

// roleTimeout bounds one role assignment (the node may reload nginx).
const roleTimeout = 30 * time.Second

// heartbeatGrace: a heartbeat still showing another role this long after the
// node's answer means the node restarted or was reinstalled; ask again.
const heartbeatGrace = 2 * time.Minute

// Role sources a node answers (MarketProbeResult.role_source).
const (
	RoleSourceAssigned   = "assigned"
	RoleSourceLocalJoin  = "local_join"
	RoleSourceLocalLeave = "local_leave"
)

// roleAnswer is a node's last answer to an assignment.
type roleAnswer struct {
	Desired agentv1.MarketProbeRole // what was assigned
	Role    agentv1.MarketProbeRole // in effect
	Source  string
	At      time.Time
}

// roleTarget is a node an assignment may go to.
type roleTarget struct {
	NodeID   uuid.UUID
	Member   bool    // in a current revision of an active pool
	Presence *string // node_presence.market_probe_role
	Snapshot []byte  // latest session capabilities
}

func marketRoleCapable(snapshot []byte) bool {
	return HasCapability(snapshot, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_ROLE, 1)
}

// loadRoleTargets reads the nodes of the active pools' current revisions
// (enabled endpoints, active nodes), and the nodes reporting join_market
// outside them.
func (s *Service) loadRoleTargets(ctx context.Context, pools []uuid.UUID) ([]roleTarget, error) {
	rows, err := s.pool.Query(ctx, `WITH members AS (
			SELECT DISTINCT endpoint.node_id FROM node_line_groups line_group
			JOIN access_scopes scope ON scope.id=line_group.tenant_scope_id AND scope.kind='platform'
			JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
			  AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision AND endpoint.enabled
			JOIN nodes node ON node.id=endpoint.node_id AND node.admin_state='active'
			WHERE line_group.id=ANY($1::uuid[]) AND line_group.deleted_at IS NULL),
		candidates AS (
			SELECT node_id, true AS member FROM members
			UNION ALL
			SELECT presence.node_id, false FROM node_presence presence
			WHERE presence.market_probe_role='join_market' AND presence.node_id NOT IN (SELECT node_id FROM members))
		SELECT candidate.node_id, candidate.member,
			(SELECT presence.market_probe_role FROM node_presence presence WHERE presence.node_id=candidate.node_id),
			(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts WHERE facts.node_id=candidate.node_id
			 ORDER BY facts.session_epoch DESC LIMIT 1)
		FROM candidates candidate ORDER BY candidate.node_id`, pools)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (roleTarget, error) {
		var target roleTarget
		return target, row.Scan(&target.NodeID, &target.Member, &target.Presence, &target.Snapshot)
	})
}

// assignmentDue: no answer for this assignment yet, or the heartbeat still
// does not show what the node answered heartbeatGrace later (restart,
// reinstall).
func assignmentDue(previous roleAnswer, known bool, desired agentv1.MarketProbeRole, presence *string, now time.Time) bool {
	if !known || previous.Desired != desired {
		return true
	}
	return presence != nil && *presence != roleName(previous.Role) && now.Sub(previous.At) >= heartbeatGrace
}

func roleName(role agentv1.MarketProbeRole) string {
	switch role {
	case agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET:
		return roleJoinMarket
	case agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY:
		return "probe_only"
	case agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED:
		return "disabled"
	}
	return ""
}

// AssignRoles sends the assignments that are due for pools (the active ones
// of this round) and returns the answers by node ID. A node that is offline
// or does not answer keeps its previous answer and is asked next round.
func (s *Service) AssignRoles(ctx context.Context, pools []string) (map[string]roleAnswer, error) {
	if s.pool == nil || s.nodes == nil {
		return nil, nil // no database or no node relay: nothing to assign
	}
	ids := make([]uuid.UUID, 0, len(pools))
	for _, ref := range pools {
		if id, err := uuid.Parse(ref); err == nil {
			ids = append(ids, id)
		}
	}
	targets, err := s.loadRoleTargets(ctx, ids)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	previous := s.roles
	s.mu.Unlock()
	answers := make(map[string]roleAnswer, len(targets))
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		slots = make(chan struct{}, s.cfg.Concurrency)
	)
	for _, target := range targets {
		node := target.NodeID.String()
		desired := agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY
		if target.Member {
			desired = agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET
		}
		last, known := previous[node]
		if !marketRoleCapable(target.Snapshot) {
			continue // older Agent: its local setting decides (node_not_join_market)
		}
		if !target.Member && known && last.Source != RoleSourceAssigned {
			answers[node] = last // joined locally: not ours to withdraw
			continue
		}
		if !assignmentDue(last, known, desired, target.Presence, s.cfg.Now()) {
			answers[node] = last
			continue
		}
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			answer, err := s.assign(ctx, node, desired)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				answers[node] = answer
			case known:
				answers[node] = last
			}
			if err != nil && !errors.Is(err, ErrOffline) && !errors.Is(err, context.DeadlineExceeded) {
				s.skip(node, "role_assignment_failed", "err", err.Error())
			}
		}()
	}
	wg.Wait()
	s.mu.Lock()
	s.roles = answers
	s.mu.Unlock()
	return answers, nil
}

// assign sends one assignment and reads the node's answer.
func (s *Service) assign(ctx context.Context, nodeID string, role agentv1.MarketProbeRole) (roleAnswer, error) {
	now := s.cfg.Now()
	command := &agentv1.MarketProbeCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(now)},
		NodeId: nodeID, ExpireTime: timestamppb.New(now.Add(roleTimeout)), AssignedRole: role,
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return roleAnswer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, roleTimeout)
	defer cancel()
	reply, err := s.nodes.Request(ctx, nodeID, payload)
	if err != nil {
		return roleAnswer{}, err
	}
	var result agentv1.MarketProbeResult
	if len(reply) == 0 || proto.Unmarshal(reply, &result) != nil || result.NodeId != nodeID ||
		result.CommandEventId != command.Event.EventId || len(result.Results) != 0 ||
		!slices.Contains([]string{RoleSourceAssigned, RoleSourceLocalJoin, RoleSourceLocalLeave}, result.RoleSource) ||
		(result.EffectiveRole != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET &&
			result.EffectiveRole != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY) {
		return roleAnswer{}, errors.New("market role answer refused or invalid")
	}
	return roleAnswer{Desired: role, Role: result.EffectiveRole, Source: result.RoleSource, At: now}, nil
}

// RoleAnswer is a node's last answer to an assignment (pool report).
func (s *Service) RoleAnswer(nodeID string) (role, source string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	answer, ok := s.roles[nodeID]
	return roleName(answer.Role), answer.Source, ok
}
