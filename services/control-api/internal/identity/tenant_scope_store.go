package identity

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

func (s *Store) ListTenantScopes(ctx context.Context, input ListTenantScopesInput) (TenantScopeList, error) {
	rows, err := s.pool.Query(ctx, `
		WITH filtered AS (
			SELECT scope.id AS scope_id, scope.tenant_id, tenant.display_id::text AS display_id,
			       tenant.display_name, tenant.status, tenant.created_at, tenant.parent_scope_id,
			       EXISTS (SELECT 1 FROM reseller_profiles profile WHERE profile.scope_id = scope.id) AS is_reseller
			FROM access_scopes AS scope
			JOIN tenants AS tenant ON tenant.id = scope.tenant_id
			WHERE scope.kind = 'tenant'
				  AND ($4 = '' OR ($4 = 'none' AND tenant.parent_scope_id IS NULL) OR
				      ($4 <> 'none' AND tenant.parent_scope_id::text = $4))
				  AND ($1 = '' OR CASE
				      WHEN $1 ~ '^[1-9][0-9]{0,18}$' THEN tenant.display_id::text = $1
				      ELSE position(lower($1) IN lower(concat_ws(' ', tenant.display_name,
				          scope.id::text, scope.tenant_id::text))) > 0
				  END)
		), paged AS (
			SELECT filtered.scope_id, filtered.tenant_id, filtered.display_id, filtered.display_name,
			       filtered.status, filtered.created_at, filtered.parent_scope_id, filtered.is_reseller
			FROM filtered
			ORDER BY filtered.created_at DESC, filtered.tenant_id DESC
			LIMIT $2 OFFSET $3
		), total AS (
			SELECT count(*)::bigint AS value FROM filtered
		)
		SELECT paged.scope_id, paged.tenant_id, paged.display_id, paged.display_name, paged.status,
		       paged.parent_scope_id, COALESCE(paged.is_reseller, false), total.value
		FROM total
		LEFT JOIN paged ON TRUE
		ORDER BY paged.created_at DESC, paged.tenant_id DESC`, input.Search, input.Limit, (input.Page-1)*input.Limit, input.Parent)
	if err != nil {
		return TenantScopeList{}, fmt.Errorf("list tenant scopes: %w", err)
	}
	defer rows.Close()
	result := TenantScopeList{Items: []TenantScope{}, Page: input.Page, Limit: input.Limit}
	for rows.Next() {
		var scopeID, tenantID, parentScopeID *uuid.UUID
		var displayID, tenantName, status *string
		var isReseller bool
		var total int64
		if err := rows.Scan(&scopeID, &tenantID, &displayID, &tenantName, &status, &parentScopeID, &isReseller,
			&total); err != nil {
			return TenantScopeList{}, fmt.Errorf("scan tenant scope: %w", err)
		}
		result.Total = total
		if scopeID == nil {
			// The LEFT JOIN emits one row with null item columns when the
			// requested page is empty, preserving total for out-of-range pages.
			continue
		}
		if tenantID == nil || displayID == nil || *displayID == "" || tenantName == nil || status == nil {
			return TenantScopeList{}, fmt.Errorf("scan tenant scope: incomplete row")
		}
		result.Items = append(result.Items, TenantScope{
			ScopeID: *scopeID, TenantID: *tenantID, DisplayID: *displayID, TenantName: *tenantName, Status: *status,
			ParentScopeID: parentScopeID, IsReseller: isReseller,
		})
	}
	if err := rows.Err(); err != nil {
		return TenantScopeList{}, fmt.Errorf("iterate tenant scopes: %w", err)
	}
	return result, nil
}
