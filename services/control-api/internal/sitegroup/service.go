package sitegroup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	readPermission  = "sites.read"
	writePermission = "sites.manage"
)

type auditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Service struct {
	pool       *pgxpool.Pool
	authorizer *iamlock.Authorizer
	now        func() time.Time
	auditor    auditAppender
}

type rowScanner interface {
	Scan(...any) error
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func NewService(pool *pgxpool.Pool, authorizer *iamlock.Authorizer, now func() time.Time) (*Service, error) {
	return newServiceWithDependencies(pool, authorizer, now, audit.New(pool))
}

func newServiceWithDependencies(
	pool *pgxpool.Pool,
	authorizer *iamlock.Authorizer,
	now func() time.Time,
	auditor auditAppender,
) (*Service, error) {
	if pool == nil || authorizer == nil || !authorizer.Configured() || now == nil || auditor == nil {
		return nil, ErrUnavailable
	}
	return &Service{pool: pool, authorizer: authorizer, now: now, auditor: auditor}, nil
}

func (service *Service) Create(ctx context.Context, actor Actor, request CreateRequest) (WriteResult, error) {
	name, err := normalizeName(request.Name)
	if err != nil {
		return WriteResult{}, err
	}
	if request.TargetScopeID == uuid.Nil || !validWriteMetadata(request.WriteMetadata) {
		return WriteResult{}, ErrInvalidInput
	}
	request.Name = name
	remark, err := normalizeRemark(request.Remark)
	if err != nil {
		return WriteResult{}, err
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		Name          string    `json:"name"`
		Remark        *string   `json:"remark,omitempty"`
	}{request.TargetScopeID, request.Name, request.Remark})
	if err != nil {
		return WriteResult{}, fmt.Errorf("digest site group create: %w", err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return WriteResult{}, fmt.Errorf("generate site group ID: %w", err)
	}
	return service.executeWrite(ctx, actor, request.TargetScopeID, "site_group.create", request.WriteMetadata,
		digest, id, 201, func(ctx context.Context, tx pgx.Tx, authorization iamlock.Authorization) (Group, error) {
			now := service.now().UTC().Truncate(time.Microsecond)
			group, err := scanGroup(tx.QueryRow(ctx, `INSERT INTO site_groups(
				id,scope_id,name,revision,created_at,updated_at,remark
			) VALUES($1,$2,$3,1,$4,$4,$5)
			RETURNING id,scope_id,name,revision,created_at,updated_at,deleted_at,remark,''::text`,
				id, authorization.TargetScopeID(), request.Name, now, remark))
			return group, classifyDatabaseError(err)
		})
}

func (service *Service) Rename(ctx context.Context, actor Actor, request RenameRequest) (WriteResult, error) {
	name, err := normalizeName(request.Name)
	if err != nil {
		return WriteResult{}, err
	}
	if request.TargetScopeID == uuid.Nil || request.ID == uuid.Nil ||
		request.ExpectedRevision < 1 || !validWriteMetadata(request.WriteMetadata) {
		return WriteResult{}, ErrInvalidInput
	}
	request.Name = name
	remark, err := normalizeRemark(request.Remark)
	if err != nil {
		return WriteResult{}, err
	}
	digest, err := digestRequest(struct {
		TargetScopeID    uuid.UUID `json:"target_scope_id"`
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Name             string    `json:"name"`
		Remark           *string   `json:"remark,omitempty"`
	}{request.TargetScopeID, request.ID, request.ExpectedRevision, request.Name, request.Remark})
	if err != nil {
		return WriteResult{}, fmt.Errorf("digest site group rename: %w", err)
	}
	return service.executeWrite(ctx, actor, request.TargetScopeID, "site_group.rename", request.WriteMetadata,
		digest, request.ID, 200, func(ctx context.Context, tx pgx.Tx, authorization iamlock.Authorization) (Group, error) {
			current, selectErr := scanGroup(tx.QueryRow(ctx, `SELECT
				id,scope_id,name,revision,created_at,updated_at,deleted_at,remark,''::text
				FROM site_groups
				WHERE scope_id=$1 AND id=$2 AND active AND deleted_at IS NULL
				FOR UPDATE`, authorization.TargetScopeID(), request.ID))
			if errors.Is(selectErr, pgx.ErrNoRows) {
				return Group{}, ErrNotFound
			}
			if selectErr != nil {
				return Group{}, classifyDatabaseError(selectErr)
			}
			if current.Revision != request.ExpectedRevision {
				return Group{}, ErrRevisionConflict
			}
			if request.Remark == nil {
				remark = current.Remark
			}
			if current.Name == request.Name && current.Remark == remark {
				return current, nil
			}
			now := service.now().UTC().Truncate(time.Microsecond)
			group, updateErr := scanGroup(tx.QueryRow(ctx, `UPDATE site_groups SET
				name=$3,revision=revision+1,updated_at=$4,remark=$6
			WHERE scope_id=$1 AND id=$2 AND revision=$5 AND deleted_at IS NULL
			RETURNING id,scope_id,name,revision,created_at,updated_at,deleted_at,remark,''::text`,
				authorization.TargetScopeID(), request.ID, request.Name, now, request.ExpectedRevision, remark))
			if errors.Is(updateErr, pgx.ErrNoRows) {
				return Group{}, missingOrRevision(ctx, tx, authorization.TargetScopeID(), request.ID, request.ExpectedRevision)
			}
			return group, classifyDatabaseError(updateErr)
		})
}

func (service *Service) Delete(ctx context.Context, actor Actor, request DeleteRequest) (WriteResult, error) {
	if request.TargetScopeID == uuid.Nil || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.WriteMetadata) {
		return WriteResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		TargetScopeID    uuid.UUID `json:"target_scope_id"`
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.TargetScopeID, request.ID, request.ExpectedRevision})
	if err != nil {
		return WriteResult{}, fmt.Errorf("digest site group delete: %w", err)
	}
	return service.executeWrite(ctx, actor, request.TargetScopeID, "site_group.delete", request.WriteMetadata,
		digest, request.ID, 200, func(ctx context.Context, tx pgx.Tx, authorization iamlock.Authorization) (Group, error) {
			now := service.now().UTC().Truncate(time.Microsecond)
			group, updateErr := scanGroup(tx.QueryRow(ctx, `UPDATE site_groups SET
					active=false,deleted_at=$3,revision=revision+1,updated_at=$3
			WHERE scope_id=$1 AND id=$2 AND revision=$4 AND deleted_at IS NULL
			RETURNING id,scope_id,name,revision,created_at,updated_at,deleted_at,remark,''::text`,
				authorization.TargetScopeID(), request.ID, now, request.ExpectedRevision))
			if errors.Is(updateErr, pgx.ErrNoRows) {
				return Group{}, missingOrRevision(ctx, tx, authorization.TargetScopeID(), request.ID, request.ExpectedRevision)
			}
			return group, classifyDatabaseError(updateErr)
		})
}

func (service *Service) Get(ctx context.Context, actor Actor, targetScopeID, id uuid.UUID) (Group, error) {
	if targetScopeID == uuid.Nil || id == uuid.Nil {
		return Group{}, ErrInvalidInput
	}
	var result Group
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		authorization, err := service.authorize(ctx, tx, actor, targetScopeID, readPermission)
		if err != nil {
			return err
		}
		result, err = scanGroup(tx.QueryRow(ctx, `SELECT g.id,g.scope_id,g.name,g.revision,g.created_at,g.updated_at,g.deleted_at,g.remark,d.display_id::text
			FROM site_groups g JOIN site_group_display_ids d ON d.scope_id=g.scope_id AND d.group_id=g.id
			WHERE g.scope_id=$1 AND g.id=$2 AND g.deleted_at IS NULL`,
			authorization.TargetScopeID(), id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return Group{}, fmt.Errorf("get site group: %w", err)
	}
	return result, nil
}

func (service *Service) List(ctx context.Context, actor Actor, request ListRequest) (GroupList, error) {
	if request.TargetScopeID == uuid.Nil || request.Page < 1 || request.Page > 1_000_000 ||
		request.Limit < 1 || request.Limit > 100 {
		return GroupList{}, ErrInvalidInput
	}
	result := GroupList{Items: []Group{}, Page: request.Page, Limit: request.Limit}
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		authorization, err := service.authorize(ctx, tx, actor, request.TargetScopeID, readPermission)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM site_groups
			WHERE scope_id=$1 AND deleted_at IS NULL`, authorization.TargetScopeID()).Scan(&result.Total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT g.id,g.scope_id,g.name,g.revision,g.created_at,g.updated_at,g.deleted_at,g.remark,d.display_id::text
			FROM site_groups g JOIN site_group_display_ids d ON d.scope_id=g.scope_id AND d.group_id=g.id
			WHERE g.scope_id=$1 AND g.deleted_at IS NULL
			ORDER BY g.created_at,g.id LIMIT $2 OFFSET $3`, authorization.TargetScopeID(), request.Limit,
			(request.Page-1)*request.Limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			group, err := scanGroup(rows)
			if err != nil {
				return err
			}
			result.Items = append(result.Items, group)
		}
		return rows.Err()
	})
	if err != nil {
		return GroupList{}, fmt.Errorf("list site groups: %w", err)
	}
	return result, nil
}

func ValidateActiveReference(
	ctx context.Context,
	querier rowQuerier,
	scopeID uuid.UUID,
	groupID *uuid.UUID,
	groupName *string,
) error {
	if groupID == nil && groupName == nil {
		return nil
	}
	if querier == nil || scopeID == uuid.Nil || groupID == nil || groupName == nil || *groupID == uuid.Nil {
		return ErrInvalidReference
	}
	var exists bool
	if err := querier.QueryRow(ctx, `SELECT true FROM site_groups
		WHERE scope_id=$1 AND id=$2 AND name=$3 AND active AND deleted_at IS NULL
		FOR SHARE`, scopeID, *groupID, *groupName).Scan(&exists); errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidReference
	} else if err != nil {
		return fmt.Errorf("%w: validate site group reference", ErrUnavailable)
	}
	if !exists {
		return ErrInvalidReference
	}
	return nil
}

func (service *Service) executeWrite(
	ctx context.Context,
	actor Actor,
	targetScopeID uuid.UUID,
	operation string,
	metadata WriteMetadata,
	digest [32]byte,
	resourceID uuid.UUID,
	responseStatus int,
	mutate func(context.Context, pgx.Tx, iamlock.Authorization) (Group, error),
) (WriteResult, error) {
	var result WriteResult
	tx, err := service.pool.Begin(ctx)
	if err != nil {
		return WriteResult{}, fmt.Errorf("%s: %w", operation, ErrUnavailable)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	err = func() error {
		authorization, err := service.authorize(ctx, tx, actor, targetScopeID, writePermission)
		if err != nil {
			return err
		}
		stored, replayed, err := claimWrite(ctx, tx, authorization, operation, metadata.IdempotencyKey,
			digest, resourceID, service.now().UTC().Truncate(time.Microsecond))
		if err != nil {
			return err
		}
		if replayed {
			if err := json.Unmarshal(stored, &result.Group); err != nil {
				return fmt.Errorf("decode stored site group response: %w", err)
			}
			result.Replayed = true
			result.Response = json.RawMessage(stored)
			return nil
		}
		group, err := mutate(ctx, tx, authorization)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT display_id::text FROM site_group_display_ids
			WHERE scope_id=$1 AND group_id=$2`, authorization.TargetScopeID(), group.ID).Scan(&group.DisplayID); err != nil {
			return fmt.Errorf("%w: read site group display ID", ErrUnavailable)
		}
		actorUserID := authorization.UserID()
		if err := service.auditor.Append(ctx, tx, audit.Event{
			ScopeID: authorization.TargetScopeID(), ActorUserID: &actorUserID,
			Action: operation, ResourceType: "site_group", ResourceID: group.ID.String(),
			RequestID: metadata.RequestID, Result: "success",
			Payload: map[string]any{"name": group.Name, "remark": group.Remark, "revision": group.Revision, "deleted": group.DeletedAt != nil},
		}); err != nil {
			return err
		}
		if err := completeWrite(ctx, tx, authorization, operation, metadata.IdempotencyKey,
			group, responseStatus, service.now().UTC().Truncate(time.Microsecond)); err != nil {
			return err
		}
		result.Group = group
		return nil
	}()
	if err != nil {
		return WriteResult{}, fmt.Errorf("%s: %w", operation, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return WriteResult{}, fmt.Errorf("%s: %w: %v", operation, ErrResultUnknown, err)
	}
	return result, nil
}

func (service *Service) authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (iamlock.Authorization, error) {
	var authorization iamlock.Authorization
	var err error
	switch actor.Credential.Kind {
	case CredentialSession:
		authorization, err = service.authorizer.AuthorizeSession(ctx, tx, actor.Credential.Raw, targetScopeID, permission)
	case CredentialAPIKey:
		authorization, err = service.authorizer.AuthorizeAPIKey(ctx, tx, actor.Credential.Raw, targetScopeID, permission)
	default:
		return iamlock.Authorization{}, ErrAuthenticationRequired
	}
	_, tenantTarget := authorization.TenantID()
	switch {
	case errors.Is(err, iamlock.ErrInvalidCredential):
		return iamlock.Authorization{}, ErrAuthenticationRequired
	case errors.Is(err, iamlock.ErrPermissionDenied):
		return iamlock.Authorization{}, ErrPermissionDenied
	case errors.Is(err, iamlock.ErrUnavailable):
		return iamlock.Authorization{}, ErrUnavailable
	case err != nil:
		return iamlock.Authorization{}, fmt.Errorf("%w: authorize site group", ErrUnavailable)
	case !authorization.Valid() || authorization.TargetScopeID() != targetScopeID || !tenantTarget:
		return iamlock.Authorization{}, ErrPermissionDenied
	default:
		return authorization, nil
	}
}

func claimWrite(
	ctx context.Context,
	tx pgx.Tx,
	authorization iamlock.Authorization,
	operation, idempotencyKey string,
	digest [32]byte,
	resourceID uuid.UUID,
	now time.Time,
) ([]byte, bool, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, false, err
	}
	command, err := tx.Exec(ctx, `INSERT INTO site_group_write_requests(
		id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,
		request_digest,resource_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
	ON CONFLICT(actor_user_id,actor_scope_id,operation,idempotency_key) DO NOTHING`,
		id, authorization.UserID(), authorization.AuthenticationScopeID(), authorization.TargetScopeID(),
		operation, idempotencyKey, digest[:], resourceID, now)
	if err != nil {
		return nil, false, classifyDatabaseError(err)
	}
	if command.RowsAffected() == 1 {
		return nil, false, nil
	}
	var storedDigest, response []byte
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT request_digest,response_body,completed_at
		FROM site_group_write_requests
		WHERE actor_user_id=$1 AND actor_scope_id=$2 AND operation=$3 AND idempotency_key=$4
		FOR UPDATE`, authorization.UserID(), authorization.AuthenticationScopeID(), operation, idempotencyKey).
		Scan(&storedDigest, &response, &completedAt); err != nil {
		return nil, false, classifyDatabaseError(err)
	}
	if !bytes.Equal(storedDigest, digest[:]) {
		return nil, false, ErrIdempotencyConflict
	}
	if completedAt == nil || len(response) == 0 {
		return nil, false, ErrResultUnknown
	}
	return response, true, nil
}

func completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	authorization iamlock.Authorization,
	operation, idempotencyKey string,
	group Group,
	responseStatus int,
	completedAt time.Time,
) error {
	response, err := json.Marshal(group)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE site_group_write_requests SET
		response_status=$5,response_body=$6,completed_at=$7
	WHERE actor_user_id=$1 AND actor_scope_id=$2 AND operation=$3 AND idempotency_key=$4
		AND completed_at IS NULL`, authorization.UserID(), authorization.AuthenticationScopeID(), operation,
		idempotencyKey, responseStatus, response, completedAt)
	if err != nil {
		return classifyDatabaseError(err)
	}
	if command.RowsAffected() != 1 {
		return ErrResultUnknown
	}
	return nil
}

func missingOrRevision(ctx context.Context, tx pgx.Tx, scopeID, id uuid.UUID, expected int64) error {
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM site_groups
		WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL`, scopeID, id).Scan(&revision); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return classifyDatabaseError(err)
	}
	if revision != expected {
		return ErrRevisionConflict
	}
	return ErrResultUnknown
}

func scanGroup(row rowScanner) (Group, error) {
	var group Group
	err := row.Scan(&group.ID, &group.ScopeID, &group.Name, &group.Revision,
		&group.CreatedAt, &group.UpdatedAt, &group.DeletedAt, &group.Remark, &group.DisplayID)
	return group, err
}

func classifyDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23505":
			if postgresError.ConstraintName == "site_groups_scope_name_active_idx" {
				return ErrNameConflict
			}
			return fmt.Errorf("%w: site group uniqueness failure", ErrUnavailable)
		case "23503", "23514", "P8205", "P8206":
			return ErrInvalidInput
		case "P8207":
			return ErrInUse
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}
