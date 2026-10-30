package securitypolicy

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ResolvedIPLists are the published contents of the IP lists bound policies
// reference, keyed by list ID: what an ip_list condition
// expands to (edgeconfig.WAFIPList).
type ResolvedIPLists map[uuid.UUID]edgeconfig.WAFIPList

// Condition is the node condition of one ip_list rule condition; false when
// the list is not resolved (deleted or not usable by the scope).
func (lists ResolvedIPLists) Condition(condition Condition) (edgeconfig.WAFIPList, bool) {
	if condition.Field != "ip_list" || len(condition.Values) != 1 ||
		condition.Operator != "in_ip_list" && condition.Operator != "not_in_ip_list" {
		return edgeconfig.WAFIPList{}, false
	}
	id, err := uuid.Parse(condition.Values[0])
	if err != nil {
		return edgeconfig.WAFIPList{}, false
	}
	list, ok := lists[id]
	if !ok {
		return edgeconfig.WAFIPList{}, false
	}
	list.CIDRs = append([]string(nil), list.CIDRs...)
	list.Negate = condition.Operator == "not_in_ip_list"
	return list, true
}

// LoadIPListsTx resolves ids for the tenant scope scopeID: live lists the
// scope owns, or platform lists. A list that is not usable is absent.
func LoadIPListsTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, ids []uuid.UUID) (ResolvedIPLists, error) {
	result := ResolvedIPLists{}
	if len(ids) == 0 {
		return result, nil
	}
	rows, err := tx.Query(ctx, `SELECT list.id,list.revision,list.entries FROM security_ip_lists list
		JOIN access_scopes owner ON owner.id=list.owner_scope_id
		WHERE list.id=ANY($1::uuid[]) AND list.deleted_at IS NULL AND (list.owner_scope_id=$2 OR owner.kind='platform')`,
		ids, scopeID)
	if err != nil {
		return nil, fmt.Errorf("read IP lists: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var revision int64
		var entries []string
		if err := rows.Scan(&id, &revision, &entries); err != nil {
			return nil, fmt.Errorf("scan IP list: %w", err)
		}
		cidrs, err := edgeconfig.CanonicalIPListCIDRs(entries)
		if err != nil {
			return nil, fmt.Errorf("IP list %s entries: %w", id, err)
		}
		result[id] = edgeconfig.WAFIPList{ListID: id.String(), Revision: revision, CIDRs: cidrs}
	}
	return result, rows.Err()
}
