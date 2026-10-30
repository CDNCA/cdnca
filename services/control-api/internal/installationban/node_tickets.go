package installationban

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Node ticket states the console shows.
const (
	NodeTicketValid    = "valid"     // the node holds a ticket that has not ended
	NodeTicketExpired  = "expired"   // its last ticket ended: the node is frozen (keeps serving, no new sites/scaling/upgrades; user 10-28)
	NodeTicketNone     = "no_ticket" // never got its first ticket: the node does not serve yet
	NodeTicketUnknown  = "unknown"   // no receipt yet (node offline since, or an old agent)
	MaxNodeTicketBatch = 300
)

// NodeTicket is one node's last reported ServiceTicket.
type NodeTicket struct {
	NodeID     string     `json:"node_id"`
	State      string     `json:"state"`
	NodeStatus string     `json:"node_status,omitempty"` // what the node enforces (installation_ban_node_state.status)
	IssuedAt   *time.Time `json:"issued_at"`
	NotAfter   *time.Time `json:"not_after"`
	DaysLeft   *int       `json:"days_left"` // whole days until not_after, rounded down (0 on the last day)
	ReportedAt *time.Time `json:"reported_at"`
	// Delivery is set while the node's latest answered revision is not applied
	// (it refused the documents): why, and when they are sent again.
	Delivery *NodeTicketDelivery `json:"delivery,omitempty"`
}

// NodeTicketDelivery is a refused revision on the node page.
type NodeTicketDelivery struct {
	Revision        uint64     `json:"revision"`
	AppliedRevision uint64     `json:"applied_revision"`
	FailureClass    string     `json:"failure_class"` // FailureRetryable or FailurePermanent
	Reason          string     `json:"reason"`
	FailedAttempts  int        `json:"failed_attempts"`
	NextRetryAt     *time.Time `json:"next_retry_at"` // nil for a permanent refusal
}

// NodeTicketRow is the stored receipt of one node (nil = none yet).
type NodeTicketRow struct {
	Status     string
	IssuedAt   *time.Time
	NotAfter   *time.Time
	ReportedAt time.Time
	Delivery   NodeDelivery
}

// EvaluateNodeTicket derives the console view of one node at now.
func EvaluateNodeTicket(nodeID string, row *NodeTicketRow, now time.Time) NodeTicket {
	view := NodeTicket{NodeID: nodeID, State: NodeTicketUnknown}
	if row == nil {
		return view
	}
	reported := row.ReportedAt.UTC()
	view.ReportedAt, view.NodeStatus = &reported, row.Status
	if delivery := row.Delivery; delivery.FailureClass != FailureNone {
		view.Delivery = &NodeTicketDelivery{Revision: delivery.Revision, AppliedRevision: delivery.AppliedRevision,
			FailureClass: delivery.FailureClass, Reason: delivery.Reason, FailedAttempts: delivery.FailedAttempts}
		if delivery.NextRetryAt != nil {
			retry := delivery.NextRetryAt.UTC()
			view.Delivery.NextRetryAt = &retry
		}
	}
	if row.IssuedAt == nil || row.NotAfter == nil {
		view.State = NodeTicketNone
		return view
	}
	issued, notAfter := row.IssuedAt.UTC(), row.NotAfter.UTC()
	view.IssuedAt, view.NotAfter = &issued, &notAfter
	left := notAfter.Sub(now)
	if left <= 0 {
		view.State = NodeTicketExpired
		zero := 0
		view.DaysLeft = &zero
		return view
	}
	view.State = NodeTicketValid
	days := int(math.Floor(left.Hours() / 24))
	view.DaysLeft = &days
	return view
}

// NodeTicketReader reads the stored receipts of the given nodes.
type NodeTicketReader struct{ Pool *pgxpool.Pool }

// NodeTickets answers one view per requested node of the scope, in the
// requested order (a node of another scope reads as unknown).
func (reader NodeTicketReader) NodeTickets(ctx context.Context, scopeID uuid.UUID, nodeIDs []uuid.UUID,
	now time.Time,
) ([]NodeTicket, error) {
	rows := map[uuid.UUID]*NodeTicketRow{}
	if len(nodeIDs) > 0 {
		result, err := reader.Pool.Query(ctx, `SELECT state.node_id, state.status, state.ticket_issued_at,
				state.ticket_not_after, state.updated_at, state.revision, state.applied_revision, state.reason,
				state.failure_class, state.failed_attempts, state.next_retry_at
			FROM installation_ban_node_state state JOIN nodes node ON node.id = state.node_id
			WHERE state.node_id = ANY($1) AND node.scope_id = $2`, nodeIDs, scopeID)
		if err != nil {
			return nil, err
		}
		defer result.Close()
		for result.Next() {
			var id uuid.UUID
			var revision, applied int64
			row := &NodeTicketRow{}
			if err := result.Scan(&id, &row.Status, &row.IssuedAt, &row.NotAfter, &row.ReportedAt, &revision, &applied,
				&row.Delivery.Reason, &row.Delivery.FailureClass, &row.Delivery.FailedAttempts, &row.Delivery.NextRetryAt); err != nil {
				return nil, err
			}
			row.Delivery.Revision, row.Delivery.AppliedRevision, row.Delivery.Status = uint64(revision), uint64(applied), row.Status
			rows[id] = row
		}
		if err := result.Err(); err != nil {
			return nil, err
		}
	}
	views := make([]NodeTicket, len(nodeIDs))
	for index, id := range nodeIDs {
		views[index] = EvaluateNodeTicket(id.String(), rows[id], now)
	}
	return views, nil
}
