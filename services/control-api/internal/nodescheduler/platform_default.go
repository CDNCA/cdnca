package nodescheduler

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SetPlatformDefault marks (or unmarks) the platform line group that sites
// without a package freeze their CNAME targets from (migration 533; at most
// one). Only a platform member acting on the platform scope with
// nodes.manage-equivalent write permission may change it; the line group
// revision does not advance. idempotencyKey is bound to (group, isDefault):
// another value under the same key is ErrIdempotencyConflict, and a replay
// writes nothing and returns the group as it is now.
func (s *Service) SetPlatformDefault(ctx context.Context, actor Actor, groupID uuid.UUID, isDefault bool,
	idempotencyKey, requestID string) (LineGroupRevision, error) {
	if ctx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || groupID == uuid.Nil ||
		!writeMetadataPattern.MatchString(idempotencyKey) || !writeMetadataPattern.MatchString(requestID) {
		return LineGroupRevision{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" || actor.ResourceScopeID() != actor.ScopeID {
		return LineGroupRevision{}, ErrPlatformWriteDenied
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var result LineGroupRevision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionManage, true); err != nil {
			return err
		}
		_, replayed, err := claimWrite(ctx, tx, actor, operationGroupPlatformDefault, idempotencyKey,
			platformDefaultRequestDigest(groupID, isDefault), groupID, now)
		if err != nil {
			return err
		}
		if replayed {
			if result, err = loadRevision(ctx, tx, actor.ScopeID, groupID, 0); err != nil {
				return err
			}
			return attachReadState(ctx, tx, &result)
		}
		var current bool
		err = tx.QueryRow(ctx, `SELECT is_platform_default FROM node_line_groups
			WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL AND purpose='general' FOR UPDATE`,
			actor.ScopeID, groupID).Scan(&current)
		if err == pgx.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock node line group: %w", err)
		}
		if current != isDefault {
			if isDefault {
				if _, err := tx.Exec(ctx, `UPDATE node_line_groups SET is_platform_default=false
					WHERE is_platform_default AND id<>$1`, groupID); err != nil {
					return fmt.Errorf("clear platform default line group: %w", err)
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE node_line_groups SET is_platform_default=$3
				WHERE tenant_scope_id=$1 AND id=$2`, actor.ScopeID, groupID, isDefault); err != nil {
				return fmt.Errorf("set platform default line group: %w", err)
			}
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "node_scheduling.group.platform_default",
				ResourceType: "node_line_group", ResourceID: groupID.String(), RequestID: requestID, Result: "success",
				Payload: map[string]any{"is_platform_default": isDefault},
			}); err != nil {
				return err
			}
		}
		if err := completeWrite(ctx, tx, actor, operationGroupPlatformDefault, idempotencyKey,
			map[string]any{"group_id": groupID, "is_platform_default": isDefault}, now); err != nil {
			return err
		}
		result, err = loadRevision(ctx, tx, actor.ScopeID, groupID, 0)
		if err != nil {
			return err
		}
		return attachReadState(ctx, tx, &result)
	})
	return result, err
}

func platformDefaultRequestDigest(groupID uuid.UUID, isDefault bool) [32]byte {
	value := byte(0)
	if isDefault {
		value = 1
	}
	return sha256.Sum256(append(append([]byte("cdnca.node-scheduling.group-platform-default-request/v1\x00"), groupID[:]...), value))
}
