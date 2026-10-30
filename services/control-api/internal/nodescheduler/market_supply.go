package nodescheduler

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/marketsupplyguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Market supply line groups (ADR 0012 §3.3, migration 422): a seller's node
// selection becomes a hidden platform line group, so publication, probing
// and the market pool inventory keep working by line group.

const permissionMarketSell = "marketplace.sell"

// ErrMarketSupplyInUse: a hidden supply group still carries a market
// subscription product (marketsupply) and cannot be deleted, or a write
// would leave its normal subscribers without an online available node
// (ADR 0012 §18.4, user U3; then it wraps *marketsupplyguard.InUseError).
var ErrMarketSupplyInUse = fmt.Errorf("%w: market supply line group is in use", ErrReferenceConflict)

// PutMarketSupplyGroup writes a hidden market supply group of the platform
// scope. The actor needs platform.admin or marketplace.sell there (the same
// gate as listing an offer, marketsubscribehttp accessSell).
func (s *Service) PutMarketSupplyGroup(ctx context.Context, actor Actor, request PutGroupRequest) (WriteResult, error) {
	request.Purpose = PurposeMarketSupply
	return s.PutGroup(ctx, actor, request)
}

// DeleteMarketSupplyGroup deletes a hidden market supply group no market
// product uses.
func (s *Service) DeleteMarketSupplyGroup(ctx context.Context, actor Actor, groupID uuid.UUID, expectedRevision int64,
	idempotencyKey, requestID string,
) (DeleteResult, error) {
	return s.deleteGroup(ctx, actor, groupID, expectedRevision, idempotencyKey, requestID, PurposeMarketSupply)
}

// GetMarketSupplyGroup reads the current revision of a hidden supply group.
func (s *Service) GetMarketSupplyGroup(ctx context.Context, actor Actor, groupID uuid.UUID) (LineGroupRevision, error) {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || groupID == uuid.Nil {
		return LineGroupRevision{}, ErrInvalidInput
	}
	var result LineGroupRevision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeMarketSupply(ctx, tx, actor, false); err != nil {
			return err
		}
		var err error
		result, err = loadRevisionOfPurpose(ctx, tx, actor.ScopeID, groupID, 0, PurposeMarketSupply)
		return err
	})
	return result, err
}

// authorizePurpose is the write gate of a purpose: the line group API's
// node_scheduling.manage for general groups, the market seller gate for
// supply groups.
func (s *Service) authorizePurpose(ctx context.Context, tx pgx.Tx, actor Actor, purpose string) error {
	if purpose == PurposeMarketSupply {
		return s.authorizeMarketSupply(ctx, tx, actor, true)
	}
	return s.authorizeTx(ctx, tx, actor, permissionManage, true)
}

// authorizeMarketSupply admits an active platform member, acting on the
// platform scope itself, whose platform roles grant platform.admin or
// marketplace.sell (the offer listing gate, marketsubscribehttp accessSell).
// custom_rbac_effective_permissions covers tenant scopes only, so the
// platform role grants are read directly.
func (s *Service) authorizeMarketSupply(ctx context.Context, tx pgx.Tx, actor Actor, write bool) error {
	if actor.ResourceScopeID() != actor.ScopeID || actor.ScopeKind != "" && actor.ScopeKind != "platform" {
		return ErrPlatformWriteDenied
	}
	lock := ""
	if write {
		// Same lock as an ordinary write's authorization, so a concurrent
		// role change is ordered before or after this write.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`,
			"custom-rbac-tenant:"+actor.ScopeID.String()); err != nil {
			return fmt.Errorf("lock market supply authorization: %w", err)
		}
		lock = " FOR SHARE OF scope, membership, account"
	}
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM access_scopes scope
		JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=$2 AND membership.status='active'
		JOIN users account ON account.id=membership.user_id AND account.status='active'
		WHERE scope.id=$1 AND scope.kind='platform' AND scope.tenant_id IS NULL AND EXISTS (
			SELECT 1 FROM role_assignments assignment
			JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
			JOIN role_permissions grant_row ON grant_row.role_id=role.id
			WHERE assignment.scope_id=scope.id AND assignment.user_id=membership.user_id
			  AND grant_row.permission_name IN ('platform.admin', $3))`+lock+`)`,
		actor.ScopeID, actor.UserID, permissionMarketSell).Scan(&allowed)
	if err != nil {
		return fmt.Errorf("authorize market supply actor: %w", err)
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

// ensureMarketSupplyGroupUnused refuses deleting a supply group a market
// subscription product still points at (marketsupply.productSpec
// node_group_id).
func ensureMarketSupplyGroupUnused(ctx context.Context, tx pgx.Tx, groupID uuid.UUID) error {
	var used bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM package_products product
		WHERE product.deleted_at IS NULL AND product.spec ? 'market' AND product.spec->>'node_group_id'=$1::text)`,
		groupID).Scan(&used); err != nil {
		return fmt.Errorf("check market supply line group use: %w", err)
	}
	if used {
		return ErrMarketSupplyInUse
	}
	return nil
}

// CheckMarketSupplyGroupEmptying refuses emptying the group's node
// selection (rejected before any write) while that would leave a normal
// subscriber without an online node: ErrMarketSupplyInUse wrapping the
// *marketsupplyguard.InUseError.
func (s *Service) CheckMarketSupplyGroupEmptying(ctx context.Context, groupID uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := marketsupplyguard.CheckEmptying(ctx, tx, groupID); err != nil {
			return fmt.Errorf("%w: %w", ErrMarketSupplyInUse, err)
		}
		return nil
	})
}

// bindPurpose binds a non-general purpose into a write request digest, so an
// idempotency key replay cannot cross purposes.
func bindPurpose(digest [32]byte, purpose string) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.node-scheduling.group-purpose/v1\x00" + purpose + "\x00"))
	_, _ = hash.Write(digest[:])
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}
