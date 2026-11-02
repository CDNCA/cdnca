package nodescheduler

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AddressMove is one live line group whose current revision followed a node
// IP change: FromRevision -> ToRevision.
type AddressMove struct {
	GroupID       uuid.UUID `json:"line_group_id"`
	TenantScopeID uuid.UUID `json:"tenant_scope_id"`
	FromRevision  int64     `json:"from_revision"`
	ToRevision    int64     `json:"to_revision"`
	Endpoints     int       `json:"endpoints"`
}

// MoveNodeAddressTx rewrites, in a new revision of every live line group, the
// current endpoints of nodeID on oldAddress to newAddress. An administrator
// changing a node IP is authoritative, so its line groups follow instead of
// refusing the edit. An endpoint that would duplicate one already on
// newAddress (same carrier and port) is dropped. Each scope using a moved
// group is republished and the CNAME line workers follow current_revision.
// The caller holds the node row lock and writes the audit.
func MoveNodeAddressTx(
	ctx context.Context, tx pgx.Tx, publications PublicationTrigger,
	userID, nodeID uuid.UUID, oldAddress, newAddress, requestID string, now time.Time,
) ([]AddressMove, error) {
	from, err := netip.ParseAddr(oldAddress)
	if err != nil {
		return nil, ErrInvalidInput
	}
	to, err := netip.ParseAddr(newAddress)
	if err != nil || from.Is4() != to.Is4() || from == to {
		return nil, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT line_group.tenant_scope_id,line_group.id
		FROM node_line_endpoints endpoint
		JOIN node_line_groups line_group ON line_group.tenant_scope_id=endpoint.tenant_scope_id
		 AND line_group.id=endpoint.line_group_id AND line_group.current_revision=endpoint.config_revision
		 AND line_group.deleted_at IS NULL
		WHERE endpoint.node_id=$1 AND endpoint.address=$2::inet
		ORDER BY line_group.tenant_scope_id,line_group.id`, nodeID, from.String())
	if err != nil {
		return nil, fmt.Errorf("find line groups on node address: %w", err)
	}
	type groupKey struct{ scopeID, groupID uuid.UUID }
	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (groupKey, error) {
		var key groupKey
		return key, row.Scan(&key.scopeID, &key.groupID)
	})
	if err != nil {
		return nil, fmt.Errorf("find line groups on node address: %w", err)
	}
	moves := make([]AddressMove, 0, len(groups))
	for _, group := range groups {
		move, err := moveGroupAddress(ctx, tx, publications, userID, group.scopeID, group.groupID,
			nodeID, from.String(), to.String(), requestID, now)
		if err != nil {
			return nil, err
		}
		moves = append(moves, move)
	}
	return moves, nil
}

func moveGroupAddress(
	ctx context.Context, tx pgx.Tx, publications PublicationTrigger,
	userID, scopeID, groupID, nodeID uuid.UUID, from, to, requestID string, now time.Time,
) (AddressMove, error) {
	// Same lock order as a line group edit after the node lock (putGroup).
	if err := lockLineGroupReferences(ctx, tx, scopeID); err != nil {
		return AddressMove{}, err
	}
	usingScopes, err := lockLineGroupUsingScopes(ctx, tx, groupID)
	if err != nil {
		return AddressMove{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, groupID.String()); err != nil {
		return AddressMove{}, fmt.Errorf("lock node line group: %w", err)
	}
	var currentRevision int64
	var purpose string
	if err := tx.QueryRow(ctx, `SELECT current_revision,purpose FROM node_line_groups
		WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, scopeID, groupID).
		Scan(&currentRevision, &purpose); err != nil {
		return AddressMove{}, fmt.Errorf("lock node line group: %w", err)
	}
	current, err := loadRevisionOfPurpose(ctx, tx, scopeID, groupID, currentRevision, purpose)
	if err != nil {
		return AddressMove{}, err
	}
	taken := make(map[string]bool, len(current.Endpoints))
	for _, endpoint := range current.Endpoints {
		if endpoint.Address != from || endpoint.NodeID != nodeID {
			taken[addressMoveKey(endpoint, endpoint.Address)] = true
		}
	}
	endpoints := make([]Endpoint, 0, len(current.Endpoints))
	moved := 0
	for _, endpoint := range current.Endpoints {
		if endpoint.NodeID == nodeID && endpoint.Address == from {
			moved++
			key := addressMoveKey(endpoint, to)
			if taken[key] {
				continue // newAddress already listed on this carrier and port
			}
			taken[key] = true
			endpoint.Address = to
		}
		endpoints = append(endpoints, endpoint)
	}
	normalized, err := normalizePutRequest(PutGroupRequest{
		GroupID: groupID, ExpectedRevision: currentRevision, Name: current.Name, Region: current.Region,
		ResolvedValue: current.ResolvedValue, IPv4ResolvedValue: current.IPv4ResolvedValue,
		L2ConfigID: current.L2ConfigID, FailoverMode: current.FailoverMode, Note: current.Note,
		SortOrder: current.SortOrder, Policy: current.Policy, Endpoints: endpoints,
		IdempotencyKey: "node-address-move", RequestID: "node-address-move", Purpose: purpose,
	})
	if err != nil {
		return AddressMove{}, fmt.Errorf("move line group address: %w", err)
	}
	normalized.groupID = groupID
	if normalized, err = applyGroupDefaults(normalized); err != nil {
		return AddressMove{}, fmt.Errorf("move line group address: %w", err)
	}
	newRevision := currentRevision + 1
	writer := Actor{UserID: userID, ScopeID: scopeID}
	if err := insertRevision(ctx, tx, writer, normalized, newRevision, now); err != nil {
		return AddressMove{}, classifyWriteError(err)
	}
	command, err := tx.Exec(ctx, `UPDATE node_line_groups SET current_revision=$4,updated_by_user_id=$5,updated_at=$6
		WHERE tenant_scope_id=$1 AND id=$2 AND current_revision=$3`,
		scopeID, groupID, currentRevision, newRevision, userID, now)
	if err != nil {
		return AddressMove{}, classifyWriteError(err)
	}
	if command.RowsAffected() != 1 {
		return AddressMove{}, ErrRevisionConflict
	}
	// The published address changed even when the node set did not.
	republisher := &Service{publications: publications}
	if _, err := republisher.republishUsingScopes(ctx, tx, usingScopes, groupID, requestID); err != nil {
		return AddressMove{}, err
	}
	return AddressMove{GroupID: groupID, TenantScopeID: scopeID, FromRevision: currentRevision,
		ToRevision: newRevision, Endpoints: moved}, nil
}

func addressMoveKey(endpoint Endpoint, address string) string {
	return fmt.Sprintf("%s\x00%s\x00%d", endpoint.Carrier, address, endpoint.Port)
}
