package packageaddon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	Pool *pgxpool.Pool
	Now  func() time.Time
}

var metadata = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

const productColumns = `id,display_id::text,name,remark,kind,quantity,monthly_price_minor,product_ids,enabled,revision,created_at,updated_at`

type scanner interface{ Scan(...any) error }

func scanProduct(row scanner) (Product, error) {
	var p Product
	err := row.Scan(&p.ID, &p.DisplayID, &p.Name, &p.Remark, &p.Kind, &p.Quantity, &p.MonthlyPriceMinor, &p.ProductIDs, &p.Enabled, &p.Revision, &p.CreatedAt, &p.UpdatedAt)
	if p.ProductIDs == nil {
		p.ProductIDs = []uuid.UUID{}
	}
	return p, err
}

func (s *Store) Products(ctx context.Context, page, limit int) (Page[Product], error) {
	result := Page[Product]{Items: []Product{}, Page: page, Limit: limit}
	if s.Pool == nil || page < 1 || page > 100000 || limit < 1 || limit > 100 {
		return result, ErrInvalid
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM package_addon_products WHERE deleted_at IS NULL`).Scan(&result.Total); err != nil {
		return result, err
	}
	rows, err := tx.Query(ctx, `SELECT `+productColumns+` FROM package_addon_products WHERE deleted_at IS NULL ORDER BY display_id DESC LIMIT $1 OFFSET $2`, limit, (page-1)*limit)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		item, e := scanProduct(rows)
		if e != nil {
			return result, e
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
func (s *Store) Assignments(ctx context.Context, page, limit int, user string, addonID uuid.UUID) (Page[Assignment], error) {
	result := Page[Assignment]{Items: []Assignment{}, Page: page, Limit: limit}
	if s.Pool == nil || page < 1 || page > 100000 || limit < 1 || limit > 100 || len(user) > 128 {
		return result, ErrInvalid
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	from := ` FROM package_addon_assignments a JOIN users u ON u.id=a.owner_user_id JOIN package_subscriptions s ON s.id=a.subscription_id WHERE a.revoked_at IS NULL AND ($1='' OR u.id::text=$1 OR u.display_id::text=$1 OR u.username ILIKE '%'||$1||'%' OR lower(coalesce(u.email,'')) LIKE '%'||lower($1)||'%' OR u.phone LIKE '%'||$1||'%') AND ($2::uuid='00000000-0000-0000-0000-000000000000' OR a.addon_id=$2)`
	if err = tx.QueryRow(ctx, `SELECT count(*)`+from, user, addonID).Scan(&result.Total); err != nil {
		return result, err
	}
	rows, err := tx.Query(ctx, `SELECT a.id,a.display_id::text,a.addon_id,a.tenant_scope_id,a.owner_user_id,u.display_id::text,u.username,a.subscription_id,s.product_snapshot->>'name',a.kind,a.amount,a.snapshot,a.charged_minor,a.revision,a.created_at,a.updated_at`+from+` ORDER BY a.display_id DESC LIMIT $3 OFFSET $4`, user, addonID, limit, (page-1)*limit)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var a Assignment
		var raw []byte
		if err = rows.Scan(&a.ID, &a.DisplayID, &a.AddonID, &a.TenantScopeID, &a.OwnerUserID, &a.OwnerDisplayID, &a.OwnerName, &a.SubscriptionID, &a.SubscriptionName, &a.Kind, &a.Amount, &raw, &a.ChargedMinor, &a.Revision, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return result, err
		}
		if json.Unmarshal(raw, &a.Snapshot) != nil {
			return result, ErrUnavailable
		}
		result.Items = append(result.Items, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func authorize(ctx context.Context, tx pgx.Tx, actor Actor, now time.Time, target uuid.UUID) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.SessionID == uuid.Nil {
		return ErrForbidden
	}
	if err := protocol.AcquireShared(ctx, tx); err != nil {
		return err
	}
	scopes := []uuid.UUID{actor.ScopeID}
	if target != uuid.Nil {
		scopes = append(scopes, target)
	}
	if _, err := protocol.AcquireScopes(ctx, tx, scopes); err != nil {
		return err
	}
	var ok bool
	err := tx.QueryRow(ctx, `SELECT s.revoked_at IS NULL AND s.expires_at>$4 AND u.status='active' AND m.status='active' AND scope.kind='platform' AND scope.tenant_id IS NULL
 AND EXISTS(SELECT 1 FROM role_assignments a JOIN role_permissions p ON p.role_id=a.role_id WHERE a.scope_id=$3 AND a.user_id=$2 AND p.permission_name IN ('billing.adjustments.manage','platform.admin'))
 FROM auth_sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON m.user_id=s.user_id AND m.scope_id=s.scope_id JOIN access_scopes scope ON scope.id=s.scope_id
 WHERE s.id=$1 AND s.user_id=$2 AND s.scope_id=$3 FOR SHARE OF s,u,m,scope`, actor.SessionID, actor.UserID, actor.ScopeID, now).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !ok {
		return ErrForbidden
	}
	return err
}

func (s *Store) Write(ctx context.Context, actor Actor, command Command, key, requestID string) (Result, error) {
	if s.Pool == nil || !Valid(command) || !metadata.MatchString(key) || !metadata.MatchString(requestID) {
		return Result{}, ErrInvalid
	}
	if command.Product != nil {
		fields := *command.Product
		fields.ProductIDs = append([]uuid.UUID{}, fields.ProductIDs...)
		command.Product = &fields
	}
	var result Result
	raw, _ := json.Marshal(command)
	digest := sha256.Sum256(raw)
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var target uuid.UUID
		if strings.HasPrefix(command.Action, "assignment.") {
			var err error
			if command.Action == "assignment.create" {
				err = tx.QueryRow(ctx, `SELECT tenant_scope_id FROM package_subscriptions WHERE id=$1`, command.SubscriptionID).Scan(&target)
			} else {
				err = tx.QueryRow(ctx, `SELECT tenant_scope_id FROM package_addon_assignments WHERE id=$1`, command.ID).Scan(&target)
			}
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if err := authorize(ctx, tx, actor, now, target); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,246))`, actor.ScopeID.String()+actor.UserID.String()+key); err != nil {
			return err
		}
		var previousDigest, previous []byte
		err := tx.QueryRow(ctx, `SELECT digest,response FROM package_addon_write_receipts WHERE actor_user_id=$1 AND actor_scope_id=$2 AND idempotency_key=$3`, actor.UserID, actor.ScopeID, key).Scan(&previousDigest, &previous)
		if err == nil {
			if !bytes.Equal(previousDigest, digest[:]) {
				return ErrConflict
			}
			return json.Unmarshal(previous, &result)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		switch {
		case strings.HasPrefix(command.Action, "product."):
			result, err = s.writeProduct(ctx, tx, command, now)
		default:
			result, err = s.writeAssignment(ctx, tx, command, now)
		}
		if err != nil {
			return err
		}
		action := "package.addon." + command.Action
		payload := map[string]any{"revision": result.Revision, "charged_minor": result.ChargedMinor, "command": command}
		err = audit.NewWithClock(s.Pool, func() time.Time { return now }).Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: action, ResourceType: "package_addon", ResourceID: result.ID.String(), RequestID: requestID, Result: "success", Payload: payload})
		if err != nil {
			return err
		}
		body, _ := json.Marshal(result)
		_, err = tx.Exec(ctx, `INSERT INTO package_addon_write_receipts(actor_user_id,actor_scope_id,idempotency_key,digest,response,created_at)VALUES($1,$2,$3,$4,$5,$6)`, actor.UserID, actor.ScopeID, key, digest[:], body, now)
		return err
	})
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && pgerr.Code == "23505" {
		err = ErrDuplicate
	}
	return result, err
}
func (s *Store) writeProduct(ctx context.Context, tx pgx.Tx, c Command, now time.Time) (Result, error) {
	if c.Product != nil && len(c.Product.ProductIDs) > 0 {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM package_products WHERE id=ANY($1) AND deleted_at IS NULL`, c.Product.ProductIDs).Scan(&count); err != nil {
			return Result{}, err
		}
		if count != len(c.Product.ProductIDs) {
			return Result{}, ErrInvalid
		}
	}
	if c.Action == "product.create" {
		id := uuid.New()
		f := c.Product
		if f.ProductIDs == nil {
			f.ProductIDs = []uuid.UUID{}
		}
		_, err := tx.Exec(ctx, `INSERT INTO package_addon_products(id,name,remark,kind,quantity,monthly_price_minor,product_ids,enabled,created_at,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, id, f.Name, f.Remark, f.Kind, f.Quantity, f.MonthlyPriceMinor, f.ProductIDs, f.Enabled, now)
		return Result{ID: id, Revision: 1}, err
	}
	p, err := scanProduct(tx.QueryRow(ctx, `SELECT `+productColumns+` FROM package_addon_products WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, c.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{}, ErrNotFound
	}
	if err != nil {
		return Result{}, err
	}
	if p.Revision != c.ExpectedRevision {
		return Result{}, ErrConflict
	}
	if c.Action == "product.delete" {
		_, err = tx.Exec(ctx, `UPDATE package_addon_products SET deleted_at=$2,updated_at=$2,revision=revision+1 WHERE id=$1`, c.ID, now)
	} else {
		f := c.Product
		if f.ProductIDs == nil {
			f.ProductIDs = []uuid.UUID{}
		}
		_, err = tx.Exec(ctx, `UPDATE package_addon_products SET name=$2,remark=$3,kind=$4,quantity=$5,monthly_price_minor=$6,product_ids=$7,enabled=$8,updated_at=$9,revision=revision+1 WHERE id=$1`, c.ID, f.Name, f.Remark, f.Kind, f.Quantity, f.MonthlyPriceMinor, f.ProductIDs, f.Enabled, now)
	}
	return Result{ID: c.ID, Revision: p.Revision + 1}, err
}
func (s *Store) writeAssignment(ctx context.Context, tx pgx.Tx, c Command, now time.Time) (Result, error) {
	var a Assignment
	var p Product
	if c.Action == "assignment.create" {
		var err error
		p, err = scanProduct(tx.QueryRow(ctx, `SELECT `+productColumns+` FROM package_addon_products WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, c.AddonID))
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, ErrNotFound
		}
		if err != nil {
			return Result{}, err
		}
		if !p.Enabled {
			return Result{}, ErrInvalid
		}
		a = Assignment{ID: uuid.New(), AddonID: c.AddonID, OwnerUserID: c.OwnerUserID, SubscriptionID: c.SubscriptionID, Kind: p.Kind, Amount: c.Amount, Revision: 1, Snapshot: p}
	} else {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT id,addon_id,tenant_scope_id,owner_user_id,subscription_id,kind,amount,snapshot,revision FROM package_addon_assignments WHERE id=$1 AND revoked_at IS NULL`, c.ID).Scan(&a.ID, &a.AddonID, &a.TenantScopeID, &a.OwnerUserID, &a.SubscriptionID, &a.Kind, &a.Amount, &raw, &a.Revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, ErrNotFound
		}
		if err != nil {
			return Result{}, err
		}
		if json.Unmarshal(raw, &p) != nil {
			return Result{}, ErrUnavailable
		}
		if a.Revision != c.ExpectedRevision {
			return Result{}, ErrConflict
		}
	}
	var baseProduct, owner, tenant uuid.UUID
	var lifecycle string
	var start, end time.Time
	var limits []byte
	err := tx.QueryRow(ctx, `SELECT coalesce(e.product_id,s.product_id),o.owner_user_id,s.tenant_scope_id,s.lifecycle_status,s.starts_at,s.ends_at,package_addon_effective_base_limits(s.id,$2) FROM package_subscriptions s JOIN package_subscription_state_versions o ON o.subscription_id=s.id AND o.revision=s.revision AND o.tenant_scope_id=s.tenant_scope_id LEFT JOIN package_subscription_entitlement_versions e ON e.subscription_id=s.id AND e.revision=package_subscription_effective_entitlement_revision(s.id,$2) WHERE s.id=$1 FOR UPDATE OF s`, a.SubscriptionID, now).Scan(&baseProduct, &owner, &tenant, &lifecycle, &start, &end, &limits)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{}, ErrNotFound
	}
	if err != nil {
		return Result{}, err
	}
	// The authoritative owner is the immutable owner projection.
	if owner != a.OwnerUserID {
		return Result{}, ErrInvalid
	}
	a.TenantScopeID = tenant
	var active bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_scopes sc JOIN tenants t ON t.id=sc.tenant_id JOIN memberships m ON m.scope_id=sc.id JOIN users u ON u.id=m.user_id WHERE sc.id=$1 AND m.user_id=$2 AND t.status='active' AND m.status='active' AND u.status='active')`, tenant, owner).Scan(&active); err != nil {
		return Result{}, err
	}
	if !active {
		return Result{}, ErrForbidden
	}
	if c.Action == "assignment.create" {
		if lifecycle != "active" || now.Before(start) || !now.Before(end) {
			return Result{}, ErrInvalid
		}
		match := len(p.ProductIDs) == 0
		for _, id := range p.ProductIDs {
			match = match || id == baseProduct
		}
		if !match {
			return Result{}, ErrInvalid
		}
	}
	if c.Action != "assignment.delete" {
		var safe bool
		if err = tx.QueryRow(ctx, `SELECT coalesce(sum((snapshot->>'monthly_price_minor')::numeric*amount),0)+$3::numeric*$4::numeric<=1000000000000000 FROM package_addon_assignments WHERE subscription_id=$1 AND id<>$2 AND revoked_at IS NULL`, a.SubscriptionID, a.ID, p.MonthlyPriceMinor, c.Amount).Scan(&safe); err != nil {
			return Result{}, err
		}
		if !safe {
			return Result{}, ErrInvalid
		}
		if p.Kind != "waf" && p.Kind != "custom_cc" {
			field, max, multiplier := p.Kind, int64(1000000000), int64(1)
			if p.Kind == "traffic" {
				field, max, multiplier = "monthly_traffic_bytes", int64(9223372036854775807), 1073741824
			}
			err = tx.QueryRow(ctx, `SELECT coalesce((SELECT sum((snapshot->>'quantity')::numeric*amount*$6::numeric) FROM package_addon_assignments WHERE subscription_id=$1 AND id<>$2 AND kind=$3 AND revoked_at IS NULL),0)+$4::numeric*$5::numeric*$6::numeric+greatest(0,coalesce((coalesce(e.product_snapshot,s.product_snapshot)->'spec'->'limits'->>$7)::numeric,0))<=$8::numeric FROM package_subscriptions s LEFT JOIN package_subscription_entitlement_versions e ON e.subscription_id=s.id AND e.revision=package_subscription_effective_entitlement_revision(s.id,$9) WHERE s.id=$1`, a.SubscriptionID, a.ID, p.Kind, p.Quantity, c.Amount, multiplier, field, max, now).Scan(&safe)
			if err != nil {
				return Result{}, err
			}
			if !safe {
				return Result{}, ErrInvalid
			}
		}
	}
	baseWAF := false
	var fields map[string]any
	_ = json.Unmarshal(limits, &fields)
	if value, ok := fields["waf"].(bool); ok {
		baseWAF = value
	}
	if value, ok := fields["waf_protect"].(bool); ok {
		baseWAF = baseWAF || value
	}
	if a.Kind == "waf" {
		if c.Action != "assignment.delete" && (c.Amount != 1 || p.Quantity != 1) {
			return Result{}, ErrInvalid
		}
		if c.Action == "assignment.create" && baseWAF {
			return Result{}, ErrDuplicate
		}
	}
	if c.Action == "assignment.create" {
		raw, _ := json.Marshal(p)
		_, err = tx.Exec(ctx, `INSERT INTO package_addon_assignments(id,addon_id,tenant_scope_id,owner_user_id,subscription_id,kind,amount,snapshot,created_at,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, a.ID, a.AddonID, tenant, owner, a.SubscriptionID, a.Kind, a.Amount, raw, now)
	} else {
		amount := c.Amount
		if c.Action == "assignment.delete" {
			amount = a.Amount
		}
		tag, e := tx.Exec(ctx, `UPDATE package_addon_assignments SET amount=$3,revision=revision+1,updated_at=$4,revoked_at=CASE WHEN $5::boolean THEN $4::timestamptz ELSE NULL END WHERE id=$1 AND revision=$2 AND revoked_at IS NULL`, a.ID, c.ExpectedRevision, amount, now, c.Action == "assignment.delete")
		err = e
		if err == nil && tag.RowsAffected() != 1 {
			return Result{}, ErrConflict
		}
		a.Revision++
	}
	if err == nil && (c.Action == "assignment.delete" || c.Action == "assignment.update" && c.Amount < a.Amount) {
		err = checkReducedAssignment(ctx, tx, tenant, a.SubscriptionID, a.Kind, now)
	}
	return Result{ID: a.ID, Revision: a.Revision}, err
}
