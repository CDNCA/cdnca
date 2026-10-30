package marketsubscribe

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Node delivery after a leaf applied (fix-mktsiteconf7 §1, migration 577). A
// saved "applied" receipt only says the leaf took the revision; its nodes
// get it afterwards. The receipt reconciler's worker therefore also asks
// every applied leaf still delivering (supply.site_status, "nodes" in the
// reply, marketsupply node_delivery.go) and saves what it says: delivering →
// effective, or failed with the reason. Not settled yet backs off like a
// receipt (ReconcilePolicy); not settled within MaxAttempts is failed with
// node_delivery_timeout. A failure is audited and notifies the platform
// members holding marketplace.purchase; nothing is retried by itself, a new
// rollout starts the check over.

// Node delivery states (site_supply_leaf_sites.node_state).
const (
	NodeDelivering = "delivering"
	NodeEffective  = "effective"
	NodeFailed     = "failed"
)

// Subscriber-side node delivery reasons (the leaf's own come as sent).
const (
	NodeReasonTimeout           = "node_delivery_timeout"
	NodeReasonStatusUnavailable = "status_unavailable"
	NodeReasonUnknown           = "node_reason_unknown"
)

const (
	// NodeDeliveryFailedEvent is the notification of a leaf whose nodes did
	// not take the revision (migration 577).
	NodeDeliveryFailedEvent = "market.supply.node_delivery_failed"
	// Audit actions (internal/audit catalog_plugin.go).
	AuditNodeDeliveryConfirmed = "plugin.market_supply.node_delivery_confirmed"
	AuditNodeDeliveryFailed    = "plugin.market_supply.node_delivery_failed"

	nodeDeliveryTemplateVersion = 1
	nodeCheckActor              = "job:market-node-delivery-check"
)

var nodeReasonPattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// nodeCheck is one applied leaf whose nodes are still being checked.
type nodeCheck struct {
	siteID   uuid.UUID
	domain   string
	supplyID uuid.UUID
	supply   string
	leaf     Leaf
	leafSite uuid.UUID
	revision int64
	attempts int
}

// nodeCheckOutcome is what to save for one nodeCheck.
type nodeCheckOutcome struct {
	state    string
	reason   string
	detail   string
	attempts int
	next     time.Time // zero once settled
	notify   bool
}

// nodeCheckDecision turns one supply.site_status reply into what to save.
func nodeCheckDecision(c nodeCheck, reply siteconf.Reply, err error, now time.Time, policy ReconcilePolicy) nodeCheckOutcome {
	reason, detail := NodeReasonStatusUnavailable, ""
	switch {
	case err != nil:
		detail = err.Error()
	case !reply.OK:
		detail = reply.Error
	default:
		var status struct {
			Nodes *struct {
				State  string `json:"state"`
				Reason string `json:"reason"`
				Detail string `json:"detail"`
			} `json:"nodes"`
		}
		if json.Unmarshal(reply.Status, &status) == nil && status.Nodes != nil {
			leafReason := status.Nodes.Reason
			if leafReason != "" && !nodeReasonPattern.MatchString(leafReason) {
				leafReason = NodeReasonUnknown
			}
			switch status.Nodes.State {
			case NodeEffective:
				return nodeCheckOutcome{state: NodeEffective}
			case NodeFailed:
				if leafReason == "" {
					leafReason = NodeReasonUnknown
				}
				return nodeCheckOutcome{state: NodeFailed, reason: leafReason, detail: bounded(status.Nodes.Detail),
					attempts: c.attempts, notify: true}
			case NodeDelivering:
				reason, detail = leafReason, status.Nodes.Detail
			}
		}
	}
	detail = bounded(detail)
	attempts := c.attempts + 1
	if attempts >= policy.MaxAttempts {
		// Never settled: failed as a timeout, with what it last waited on.
		last := reason
		if detail != "" {
			last += ":" + detail
		}
		if reason == NodeReasonStatusUnavailable {
			return nodeCheckOutcome{state: NodeFailed, reason: reason, detail: detail, attempts: attempts, notify: true}
		}
		return nodeCheckOutcome{state: NodeFailed, reason: NodeReasonTimeout, detail: bounded(last), attempts: attempts, notify: true}
	}
	return nodeCheckOutcome{state: NodeDelivering, reason: reason, detail: detail, attempts: attempts,
		next: now.Add(policy.backoff(attempts))}
}

func bounded(text string) string {
	if len(text) > 500 {
		return text[:500]
	}
	return text
}

// backoff is the wait after the attempts-th unsettled try: Backoff·2^(n-1),
// at most MaxBackoff (as reconcileDecision).
func (p ReconcilePolicy) backoff(attempts int) time.Duration {
	wait := p.Backoff
	for i := 1; i < attempts && wait < p.MaxBackoff; i++ {
		wait *= 2
	}
	return min(wait, p.MaxBackoff)
}

// CheckNodeDelivery runs one pass: every applied leaf still delivering and
// due now is asked once. It returns how many settled (effective or failed).
func (s *Service) CheckNodeDelivery(ctx context.Context) (int, error) {
	policy := s.reconcilePolicy()
	if err := policy.validate(); err != nil {
		return 0, err
	}
	now := s.now().UTC()
	due, err := s.dueNodeChecks(ctx, now, policy.BatchSize)
	if err != nil {
		return 0, err
	}
	settled := 0
	for _, c := range due {
		// A fresh relay message per attempt; supply.site_status changes nothing.
		key := fmt.Sprintf("nodes-%s-%d-%s-%s-%d", c.siteID, c.revision, c.leaf.LeafMemberID, c.leaf.NodePoolRef, c.attempts+1)
		reply, callErr := s.caller.Call(ctx, c.leaf, siteconf.OpStatus, nil, key,
			siteconf.SiteRef{SiteID: c.siteID, LeafSiteID: c.leafSite})
		if ctx.Err() != nil {
			return settled, ctx.Err()
		}
		done, err := s.saveNodeCheck(ctx, c, nodeCheckDecision(c, reply, callErr, now, policy), now)
		if err != nil {
			return settled, err
		}
		if done {
			settled++
		}
	}
	return settled, nil
}

// dueNodeChecks lists applied leaves still delivering, due at now, oldest first.
func (s *Service) dueNodeChecks(ctx context.Context, now time.Time, limit int) ([]nodeCheck, error) {
	rows, err := s.pool.Query(ctx, `SELECT leaf.site_id, site.domain, leaf.supply_id, supply.name,
			leaf.leaf_member_id, leaf.node_pool_ref, leaf.leaf_site_id, leaf.applied_revision, leaf.node_check_attempts,
			supply.leaves
		FROM site_supply_leaf_sites leaf
		JOIN site_supplies supply ON supply.id=leaf.supply_id
		JOIN sites site ON site.id=leaf.site_id AND site.deleted_at IS NULL
		WHERE leaf.state='applied' AND leaf.node_state='delivering' AND leaf.next_node_check_at <= $1
		  AND leaf.leaf_site_id IS NOT NULL
		ORDER BY leaf.next_node_check_at, leaf.site_id LIMIT $2`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list node delivery checks: %w", err)
	}
	defer rows.Close()
	var out []nodeCheck
	for rows.Next() {
		var c nodeCheck
		var raw []byte
		if err := rows.Scan(&c.siteID, &c.domain, &c.supplyID, &c.supply, &c.leaf.LeafMemberID, &c.leaf.NodePoolRef,
			&c.leafSite, &c.revision, &c.attempts, &raw); err != nil {
			return nil, fmt.Errorf("scan node delivery check: %w", err)
		}
		var leaves []Leaf
		if err := json.Unmarshal(raw, &leaves); err != nil {
			return nil, fmt.Errorf("decode supply leaves: %w", err)
		}
		for _, l := range leaves {
			if l.LeafMemberID == c.leaf.LeafMemberID && l.NodePoolRef == c.leaf.NodePoolRef {
				c.leaf.GrantID = l.GrantID
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// saveNodeCheck writes outcome back only while the leaf still runs the
// revision this pass read and is still delivering (a new rollout owns it
// otherwise), audits a settled one and notifies a failure.
func (s *Service) saveNodeCheck(ctx context.Context, c nodeCheck, outcome nodeCheckOutcome, now time.Time) (bool, error) {
	settled := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var next *time.Time
		if outcome.state == NodeDelivering {
			next = &outcome.next
		}
		tag, err := tx.Exec(ctx, `UPDATE site_supply_leaf_sites SET node_state=$6, node_reason=$7, node_detail=$8,
				node_check_attempts=$9, node_checked_at=$10, next_node_check_at=$11
			WHERE site_id=$1 AND supply_id=$2 AND leaf_member_id=$3 AND node_pool_ref=$4 AND state='applied'
			  AND applied_revision=$5 AND node_state='delivering'`,
			c.siteID, c.supplyID, c.leaf.LeafMemberID, c.leaf.NodePoolRef, c.revision,
			outcome.state, outcome.reason, outcome.detail, outcome.attempts, now, next)
		if err != nil {
			return fmt.Errorf("save node delivery check: %w", err)
		}
		if tag.RowsAffected() != 1 || outcome.state == NodeDelivering {
			return nil
		}
		settled = true
		return s.auditNodeCheck(ctx, tx, c, outcome, now)
	})
	return settled, err
}

func (s *Service) auditNodeCheck(ctx context.Context, tx pgx.Tx, c nodeCheck, outcome nodeCheckOutcome, now time.Time) error {
	scope, err := platformScope(ctx, tx)
	if err != nil {
		return err
	}
	action, result, reason := AuditNodeDeliveryConfirmed, "success", ""
	if outcome.state == NodeFailed {
		action, result, reason = AuditNodeDeliveryFailed, "failure", outcome.reason
	}
	source := fmt.Sprintf("market-nodes/%s/%s/%s/%s/%d", c.siteID, c.supplyID, c.leaf.LeafMemberID, c.leaf.NodePoolRef, c.revision)
	if err := audit.NewWithClock(s.pool, s.now).Append(ctx, tx, audit.Event{ScopeID: scope, Action: action,
		ResourceType: "site", ResourceID: c.siteID.String(), RequestID: source, Result: result, ReasonCode: reason,
		ActorKind: audit.ActorSystem, ActorRef: nodeCheckActor, OccurredAt: now,
		Payload: map[string]any{"site_domain": c.domain, "supply_id": c.supplyID.String(), "supply": c.supply,
			"leaf_member_id": c.leaf.LeafMemberID.String(), "node_pool_ref": c.leaf.NodePoolRef,
			"revision": c.revision, "attempts": outcome.attempts, "reason": outcome.reason, "detail": outcome.detail},
		Changes: []audit.Change{{Field: "node_state", Before: NodeDelivering, After: outcome.state}},
	}); err != nil {
		return fmt.Errorf("audit node delivery check: %w", err)
	}
	if !outcome.notify || s.notices == nil {
		return nil
	}
	reasonText := outcome.reason
	if outcome.detail != "" {
		reasonText += "（" + outcome.detail + "）"
	}
	return s.notifyPurchasers(ctx, tx, scope, source, NodeDeliveryFailedEvent, nodeDeliveryTemplateVersion, c.siteID,
		notification.TemplateContext{"domain": notification.PublicValue(c.domain),
			"supply": notification.PublicValue(c.supply), "revision": notification.PublicValue(strconv.FormatInt(c.revision, 10)),
			"reason": notification.PublicValue(reasonText)})
}

// LeafNodeDelivery is a leaf's node delivery as saved (state ” = untracked).
type LeafNodeDelivery struct {
	State     string     `json:"state"`
	Reason    string     `json:"reason,omitempty"`
	Detail    string     `json:"detail,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	NextAt    *time.Time `json:"next_check_at,omitempty"`
}

// LeafStatus is one leaf's saved receipt and node delivery for the page.
type LeafStatus struct {
	SupplyID  uuid.UUID        `json:"supply_id"`
	Leaf      Leaf             `json:"leaf"`
	State     string           `json:"state"`
	Revision  int64            `json:"revision"`
	Error     string           `json:"error,omitempty"`
	Node      LeafNodeDelivery `json:"node"`
	UpdatedAt time.Time        `json:"updated_at"`
}

// SiteLeaves lists the saved receipts of the site's leaves on its bound
// market supplies, with their node delivery (the page polls it after an
// apply). Leaves of a supply no longer bound are not listed.
func (s *Service) SiteLeaves(ctx context.Context, siteID uuid.UUID) ([]LeafStatus, error) {
	rows, err := s.pool.Query(ctx, `SELECT leaf.supply_id, leaf.leaf_member_id, leaf.node_pool_ref, leaf.state,
			leaf.applied_revision, leaf.last_error, leaf.node_state, leaf.node_reason, leaf.node_detail,
			leaf.node_checked_at, leaf.next_node_check_at, leaf.updated_at
		FROM site_supply_leaf_sites leaf
		JOIN site_supply_bindings binding ON binding.site_id=leaf.site_id AND binding.supply_id=leaf.supply_id AND binding.line_scope=''
		WHERE leaf.site_id=$1
		ORDER BY binding.priority, leaf.supply_id, leaf.leaf_member_id, leaf.node_pool_ref`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LeafStatus{}
	for rows.Next() {
		var l LeafStatus
		if err := rows.Scan(&l.SupplyID, &l.Leaf.LeafMemberID, &l.Leaf.NodePoolRef, &l.State, &l.Revision, &l.Error,
			&l.Node.State, &l.Node.Reason, &l.Node.Detail, &l.Node.CheckedAt, &l.Node.NextAt, &l.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
