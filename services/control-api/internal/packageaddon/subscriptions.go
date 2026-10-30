package packageaddon

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type SubscriptionOption struct {
	ID             uuid.UUID `json:"id"`
	TenantScopeID  uuid.UUID `json:"tenant_scope_id"`
	OwnerUserID    uuid.UUID `json:"owner_user_id"`
	OwnerDisplayID string    `json:"owner_display_id"`
	OwnerName      string    `json:"owner_name"`
	Name           string    `json:"name"`
	ProductID      uuid.UUID `json:"product_id"`
}

func (s *Store) Subscriptions(ctx context.Context, page, limit int, user string, addonID uuid.UUID) (Page[SubscriptionOption], error) {
	result := Page[SubscriptionOption]{Items: []SubscriptionOption{}, Page: page, Limit: limit}
	if s.Pool == nil || page < 1 || page > 100000 || limit < 1 || limit > 100 || len(user) > 128 {
		return result, ErrInvalid
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	from := ` FROM package_subscriptions s
 JOIN package_subscription_state_versions o ON o.subscription_id=s.id AND o.revision=s.revision AND o.tenant_scope_id=s.tenant_scope_id
 JOIN users u ON u.id=o.owner_user_id AND u.status='active'
 JOIN memberships m ON m.scope_id=s.tenant_scope_id AND m.user_id=u.id AND m.status='active'
 JOIN access_scopes sc ON sc.id=s.tenant_scope_id
 JOIN tenants t ON t.id=sc.tenant_id AND t.status='active'
 LEFT JOIN package_subscription_entitlement_versions e ON e.subscription_id=s.id AND e.revision=package_subscription_effective_entitlement_revision(s.id,$1)
 WHERE s.lifecycle_status='active' AND s.starts_at<=$1 AND s.ends_at>$1
 AND ($2='' OR u.id::text=$2 OR u.display_id::text=$2 OR u.username ILIKE '%'||$2||'%' OR lower(coalesce(u.email,'')) LIKE '%'||lower($2)||'%' OR u.phone LIKE '%'||$2||'%')
 AND ($3::uuid='00000000-0000-0000-0000-000000000000' OR EXISTS(
 SELECT 1 FROM package_addon_products p WHERE p.id=$3 AND p.deleted_at IS NULL AND p.enabled
 AND (cardinality(p.product_ids)=0 OR coalesce(e.product_id,s.product_id)=ANY(p.product_ids))
 AND NOT EXISTS(SELECT 1 FROM package_addon_assignments a WHERE a.subscription_id=s.id AND a.revoked_at IS NULL AND (a.addon_id=p.id OR p.kind='waf' AND a.kind='waf'))
 AND (p.kind<>'waf' OR NOT (package_addon_effective_base_limits(s.id,$1)->>'waf')::boolean)))`
	if err = tx.QueryRow(ctx, `SELECT count(*)`+from, now, user, addonID).Scan(&result.Total); err != nil {
		return result, err
	}
	rows, err := tx.Query(ctx, `SELECT s.id,s.tenant_scope_id,u.id,u.display_id::text,u.username,coalesce(e.product_snapshot->>'name',s.product_snapshot->>'name',''),coalesce(e.product_id,s.product_id)`+from+` ORDER BY s.created_at DESC,s.id LIMIT $4 OFFSET $5`, now, user, addonID, limit, (page-1)*limit)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item SubscriptionOption
		if err = rows.Scan(&item.ID, &item.TenantScopeID, &item.OwnerUserID, &item.OwnerDisplayID, &item.OwnerName, &item.Name, &item.ProductID); err != nil {
			rows.Close()
			return result, err
		}
		result.Items = append(result.Items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

// Bindings exposes only product identity needed for addon eligibility.
type BindingOption struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

func (s *Store) Bindings(ctx context.Context, page, limit int) (Page[BindingOption], error) {
	result := Page[BindingOption]{Items: []BindingOption{}, Page: page, Limit: limit}
	if s.Pool == nil || page < 1 || page > 100000 || limit < 1 || limit > 100 {
		return result, ErrInvalid
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM package_products WHERE deleted_at IS NULL`).Scan(&result.Total); err != nil {
		return result, err
	}
	rows, err := tx.Query(ctx, `SELECT id,name FROM package_products WHERE deleted_at IS NULL ORDER BY created_at DESC,id LIMIT $1 OFFSET $2`, limit, (page-1)*limit)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item BindingOption
		if err = rows.Scan(&item.ID, &item.Name); err != nil {
			rows.Close()
			return result, err
		}
		result.Items = append(result.Items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
