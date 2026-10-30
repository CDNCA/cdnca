package nodegatewayaddr

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the PostgreSQL side (tables of migration 573).
type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, auditor: audit.NewWithClock(pool, now), now: now}
}

func (s *Store) at() time.Time { return s.now().UTC().Truncate(time.Microsecond) }

func (s *Store) appendAudit(ctx context.Context, tx pgx.Tx, actor Actor, action, resourceID string, payload map[string]any) error {
	if actor.SourceIP != "" {
		payload["ip"] = actor.SourceIP
	}
	return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: action,
		ResourceType: "node_gateway_address_change", ResourceID: resourceID, RequestID: actor.RequestID,
		Result: "success", Payload: payload})
}

// targetNodes resolves the scope's nodes in use (not retired / pending).
const targetNodesSQL = `SELECT id FROM nodes
	WHERE scope_id=$1 AND admin_state IN ('active','draining','disabled')
	  AND ($2='all' OR ($2='region' AND region=$3) OR ($2='nodes' AND id = ANY($4)))
	ORDER BY id FOR UPDATE`

// Create records the change and one pending row per node (each with the
// node's next revision); an open row of an earlier change on the same node
// is superseded. Audited in the same transaction.
func (s *Store) Create(ctx context.Context, actor Actor, request CreateRequest) (Change, error) {
	now := s.at()
	change := Change{ID: uuid.New(), Address: request.Address, ServerName: request.ServerName, TargetKind: request.TargetKind,
		Region: request.Region, CreatedAt: now, CreatedBy: actor.UserID}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		ids := request.NodeIDs
		if ids == nil {
			ids = []uuid.UUID{}
		}
		rows, err := tx.Query(ctx, targetNodesSQL, actor.ScopeID, request.TargetKind, request.Region, ids)
		if err != nil {
			return err
		}
		nodes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		if len(nodes) == 0 || request.TargetKind == TargetNodes && len(nodes) != len(request.NodeIDs) {
			return ErrNoNodes
		}
		if len(nodes) > MaxNodes {
			return ErrTooManyNodes
		}
		change.NodeCount = len(nodes)
		if _, err := tx.Exec(ctx, `INSERT INTO node_gateway_address_changes(id,scope_id,address,server_name,target_kind,
			target_region,node_count,request_id,created_by_user_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			change.ID, actor.ScopeID, change.Address, change.ServerName, change.TargetKind, change.Region, change.NodeCount,
			actor.RequestID, actor.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE node_gateway_address_change_nodes SET state='superseded', updated_at=$2
			WHERE node_id = ANY($1) AND state IN ('pending','delivered','probing')`, nodes, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `WITH bumped AS (
				INSERT INTO node_gateway_address_node_revisions(node_id, revision)
				SELECT unnest($2::uuid[]), 1
				ON CONFLICT (node_id) DO UPDATE SET revision = node_gateway_address_node_revisions.revision + 1
				RETURNING node_id, revision)
			INSERT INTO node_gateway_address_change_nodes(change_id,node_id,revision,state,updated_at)
			SELECT $1, node_id, revision, 'pending', $3 FROM bumped`, change.ID, nodes, now); err != nil {
			return err
		}
		change.Counts.Pending = len(nodes)
		return s.appendAudit(ctx, tx, actor, AuditCreate, change.ID.String(), map[string]any{
			"address": change.Address, "server_name": change.ServerName, "target_kind": change.TargetKind,
			"region": change.Region, "node_count": change.NodeCount,
			"changes": map[string]any{"gateway_address": map[string]any{"to": change.Address}, "server_name": map[string]any{"to": change.ServerName}},
		})
	})
	if err != nil {
		return Change{}, err
	}
	return change, nil
}

// Retry moves the change's failed nodes back to pending with a new revision
// (all failed nodes when nodeIDs is empty).
func (s *Store) Retry(ctx context.Context, actor Actor, changeID uuid.UUID, nodeIDs []uuid.UUID) (int, error) {
	now := s.at()
	retried := 0
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT true FROM node_gateway_address_changes WHERE id=$1 AND scope_id=$2 FOR UPDATE`,
			changeID, actor.ScopeID).Scan(&exists); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		ids := nodeIDs
		if ids == nil {
			ids = []uuid.UUID{}
		}
		rows, err := tx.Query(ctx, `SELECT row.node_id FROM node_gateway_address_change_nodes row
			WHERE row.change_id=$1 AND row.state='failed' AND (cardinality($2::uuid[])=0 OR row.node_id = ANY($2))
			  -- only the node's newest document: a later change owns the node
			  AND NOT EXISTS (SELECT 1 FROM node_gateway_address_change_nodes other WHERE other.node_id=row.node_id
			      AND other.revision>row.revision)
			ORDER BY row.node_id FOR UPDATE`, changeID, ids)
		if err != nil {
			return err
		}
		nodes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		if len(nodes) == 0 {
			return ErrNothingToRetry
		}
		if _, err := tx.Exec(ctx, `WITH bumped AS (
				UPDATE node_gateway_address_node_revisions SET revision=revision+1 WHERE node_id = ANY($2)
				RETURNING node_id, revision)
			UPDATE node_gateway_address_change_nodes row SET revision=bumped.revision, state='pending', error_code='',
				document_sha256=NULL, published_at=NULL, updated_at=$3
			FROM bumped WHERE row.change_id=$1 AND row.node_id=bumped.node_id`, changeID, nodes, now); err != nil {
			return err
		}
		retried = len(nodes)
		return s.appendAudit(ctx, tx, actor, AuditRetry, changeID.String(), map[string]any{"node_count": retried})
	})
	return retried, err
}

// PendingDocument is one row to sign and publish.
type PendingDocument struct {
	ChangeID   uuid.UUID
	NodeID     uuid.UUID
	Revision   uint64
	Address    string
	ServerName string
	State      string
	Published  *time.Time
}

// Due lists rows to (re)publish: pending ones, and delivered ones last
// published before republishBefore (the gateway stream keeps the newest per
// node, so a republish only covers a lost stream). Published is the first
// publication time: the document's issued_at, so a republish signs the very
// same bytes (Ed25519 is deterministic) and a node that already handled it
// answers its stored outcome instead of "stale".
func (s *Store) Due(ctx context.Context, republishBefore time.Time, limit int) ([]PendingDocument, error) {
	rows, err := s.pool.Query(ctx, `SELECT row.change_id,row.node_id,row.revision,change.address,change.server_name,row.state,row.published_at
		FROM node_gateway_address_change_nodes row JOIN node_gateway_address_changes change ON change.id=row.change_id
		WHERE row.state='pending' OR (row.state='delivered' AND row.updated_at < $1)
		ORDER BY row.updated_at LIMIT $2`, republishBefore, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (PendingDocument, error) {
		var value PendingDocument
		var revision int64
		err := row.Scan(&value.ChangeID, &value.NodeID, &revision, &value.Address, &value.ServerName, &value.State, &value.Published)
		value.Revision = uint64(revision)
		return value, err
	})
}

// MarkPublished records the published document's digest (state delivered);
// published_at keeps the first publication.
func (s *Store) MarkPublished(ctx context.Context, document PendingDocument, digest []byte, issuedAt time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE node_gateway_address_change_nodes SET state='delivered', document_sha256=$4,
		published_at=coalesce(published_at,$6), attempts=attempts+1, updated_at=$5
		WHERE change_id=$1 AND node_id=$2 AND revision=$3 AND state IN ('pending','delivered')`,
		document.ChangeID, document.NodeID, int64(document.Revision), digest, s.at(), issuedAt)
	return err
}

// MarkExpired fails a delivered row whose document expired unanswered.
func (s *Store) MarkExpired(ctx context.Context, document PendingDocument) error {
	return s.applyLocked(ctx, document.NodeID, document.Revision, StateFailed, ErrorUndelivered)
}

// Report applies a node receipt (matched by node, revision and digest).
func (s *Store) Report(ctx context.Context, report Report) (bool, error) {
	applied := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var changeID uuid.UUID
		var scopeID uuid.UUID
		var current string
		err := tx.QueryRow(ctx, `SELECT row.change_id,change.scope_id,row.state FROM node_gateway_address_change_nodes row
			JOIN node_gateway_address_changes change ON change.id=row.change_id
			WHERE row.node_id=$1 AND row.revision=$2 AND row.document_sha256=$3 FOR UPDATE OF row`,
			report.NodeID, int64(report.Revision), report.DocumentSHA256).Scan(&changeID, &scopeID, &current)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // an answer to an older or unknown document
		}
		if err != nil {
			return err
		}
		state, code, ok := nextState(current, report.State, report.ErrorCode)
		if !ok {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE node_gateway_address_change_nodes SET state=$3, error_code=$4, active_address=$5,
			reported_at=$6, updated_at=$6 WHERE change_id=$1 AND node_id=$2`,
			changeID, report.NodeID, state, code, report.ActiveAddress, s.at()); err != nil {
			return err
		}
		applied = true
		if state == StateProbing {
			return nil // the intermediate state is not audited; the outcome is
		}
		result := "success"
		if state == StateFailed {
			result = "failure"
		}
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, Action: AuditReport, ActorKind: "node",
			ActorRef: "node:" + report.NodeID.String(), ResourceType: "node", ResourceID: report.NodeID.String(),
			RequestID: "ngw-report-" + changeID.String(), Result: result, ReasonCode: code,
			Payload: map[string]any{"change_id": changeID.String(), "state": state, "active_address": report.ActiveAddress}})
	})
	return applied, err
}

func (s *Store) applyLocked(ctx context.Context, nodeID uuid.UUID, revision uint64, state, code string) error {
	_, err := s.pool.Exec(ctx, `UPDATE node_gateway_address_change_nodes SET state=$3, error_code=$4, updated_at=$5
		WHERE node_id=$1 AND revision=$2 AND state IN ('pending','delivered','probing')`,
		nodeID, int64(revision), state, code, s.at())
	return err
}

// Report is one node receipt.
type Report struct {
	NodeID         uuid.UUID
	Revision       uint64
	DocumentSHA256 []byte
	State          string
	ErrorCode      string
	ActiveAddress  string
}

// List returns the scope's newest changes with counts.
func (s *Store) List(ctx context.Context, scopeID uuid.UUID, limit int) ([]Change, error) {
	rows, err := s.pool.Query(ctx, `SELECT change.id,change.address,change.server_name,change.target_kind,change.target_region,
			change.node_count,change.created_at,change.created_by_user_id,
			count(*) FILTER (WHERE row.state IN ('pending','delivered')),
			count(*) FILTER (WHERE row.state='probing'),
			count(*) FILTER (WHERE row.state='switched'),
			count(*) FILTER (WHERE row.state='failed'),
			count(*) FILTER (WHERE row.state='superseded')
		FROM node_gateway_address_changes change JOIN node_gateway_address_change_nodes row ON row.change_id=change.id
		WHERE change.scope_id=$1 GROUP BY change.id ORDER BY change.created_at DESC, change.id LIMIT $2`, scopeID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Change, error) {
		var change Change
		err := row.Scan(&change.ID, &change.Address, &change.ServerName, &change.TargetKind, &change.Region, &change.NodeCount,
			&change.CreatedAt, &change.CreatedBy, &change.Counts.Pending, &change.Counts.Probing, &change.Counts.Switched,
			&change.Counts.Failed, &change.Counts.Superseded)
		return change, err
	})
}

// Get returns one change with every node's state.
func (s *Store) Get(ctx context.Context, scopeID, changeID uuid.UUID) (Change, error) {
	changes, err := s.pool.Query(ctx, `SELECT id,address,server_name,target_kind,target_region,node_count,created_at,created_by_user_id
		FROM node_gateway_address_changes WHERE id=$1 AND scope_id=$2`, changeID, scopeID)
	if err != nil {
		return Change{}, err
	}
	change, err := pgx.CollectExactlyOneRow(changes, func(row pgx.CollectableRow) (Change, error) {
		var value Change
		err := row.Scan(&value.ID, &value.Address, &value.ServerName, &value.TargetKind, &value.Region, &value.NodeCount,
			&value.CreatedAt, &value.CreatedBy)
		return value, err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Change{}, ErrNotFound
	}
	if err != nil {
		return Change{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT row.node_id,node.display_id::text,node.name,node.region,row.state,row.error_code,
			row.attempts,row.active_address,row.reported_at,row.updated_at
		FROM node_gateway_address_change_nodes row JOIN nodes node ON node.id=row.node_id
		WHERE row.change_id=$1 ORDER BY node.display_id, row.node_id`, changeID)
	if err != nil {
		return Change{}, err
	}
	change.Nodes, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (NodeStatus, error) {
		var value NodeStatus
		err := row.Scan(&value.NodeID, &value.DisplayID, &value.Name, &value.Region, &value.State, &value.ErrorCode,
			&value.Attempts, &value.ActiveAddress, &value.ReportedAt, &value.UpdatedAt)
		return value, err
	})
	if err != nil {
		return Change{}, fmt.Errorf("read gateway address change nodes: %w", err)
	}
	for _, node := range change.Nodes {
		change.Counts.Count(node.State)
	}
	return change, nil
}
