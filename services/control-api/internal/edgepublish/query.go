package edgepublish

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type publicationCursor struct {
	CreatedAt     time.Time `json:"created_at"`
	PublicationID uuid.UUID `json:"publication_id"`
}

func (s *Service) GetPublication(
	ctx context.Context,
	actor Actor,
	scopeID, publicationID uuid.UUID,
) (PublishResult, error) {
	if ctx == nil || !validQueryActor(actor) || scopeID == uuid.Nil || publicationID == uuid.Nil {
		return PublishResult{}, ErrInvalidInput
	}
	var result PublishResult
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	}, func(tx pgx.Tx) error {
		if err := authorizeActor(ctx, tx, actor, scopeID, PermissionRead); err != nil {
			return err
		}
		stored, err := scanStoredPublication(tx.QueryRow(ctx, `
			SELECT id,source_revision,request_digest,canonical_snapshot_sha256,artifact_sha256,
			       config_version_id,rollout_id,node_count,created_at,target_kind,
			       target_snapshot_id,target_snapshot_revision,target_resolver_sha256,target_snapshot_sha256
			FROM edge_config_publications
			WHERE configuration_scope_id=$1 AND id=$2`, scopeID, publicationID), scopeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("%w: get publication", ErrPersistence)
		}
		result = stored.result
		return nil
	})
	return result, err
}

func (s *Service) ListPublications(
	ctx context.Context,
	actor Actor,
	scopeID uuid.UUID,
	request PublicationPageRequest,
) (PublicationPage, error) {
	if ctx == nil || !validQueryActor(actor) || scopeID == uuid.Nil || request.Limit < 0 || request.Limit > 100 {
		return PublicationPage{}, ErrInvalidInput
	}
	if request.Limit == 0 {
		request.Limit = 20
	}
	cursor, err := decodePublicationCursor(request.Cursor)
	if err != nil {
		return PublicationPage{}, ErrInvalidInput
	}
	var result PublicationPage
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	}, func(tx pgx.Tx) error {
		if err := authorizeActor(ctx, tx, actor, scopeID, PermissionRead); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			SELECT COALESCE(configuration.source_revision,1)
			FROM access_scopes scope
			LEFT JOIN edge_configuration_scopes configuration ON configuration.scope_id=scope.id
			WHERE scope.id=$1 AND scope.kind='tenant'`, scopeID).Scan(&result.CurrentSourceRevision); errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidInput
		} else if err != nil || result.CurrentSourceRevision < 1 {
			return fmt.Errorf("%w: read current source revision", ErrPersistence)
		}
		var cursorTime *time.Time
		var cursorID *uuid.UUID
		if cursor != nil {
			cursorTime, cursorID = &cursor.CreatedAt, &cursor.PublicationID
		}
		rows, err := tx.Query(ctx, `
			SELECT id,source_revision,request_digest,canonical_snapshot_sha256,artifact_sha256,
			       config_version_id,rollout_id,node_count,created_at,target_kind,
			       target_snapshot_id,target_snapshot_revision,target_resolver_sha256,target_snapshot_sha256
			FROM edge_config_publications
			WHERE configuration_scope_id=$1
			  AND ($2::timestamptz IS NULL OR (created_at,id) < ($2,$3))
			ORDER BY created_at DESC,id DESC
			LIMIT $4`, scopeID, cursorTime, cursorID, request.Limit+1)
		if err != nil {
			return fmt.Errorf("%w: list publications", ErrPersistence)
		}
		defer rows.Close()
		items := make([]PublishResult, 0, request.Limit+1)
		for rows.Next() {
			stored, err := scanStoredPublication(rows, scopeID)
			if err != nil {
				return fmt.Errorf("%w: scan publication", ErrPersistence)
			}
			items = append(items, stored.result)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("%w: iterate publications", ErrPersistence)
		}
		if len(items) > request.Limit {
			last := items[request.Limit-1]
			result.NextCursor, err = encodePublicationCursor(publicationCursor{
				CreatedAt: last.CreatedAt, PublicationID: last.PublicationID,
			})
			if err != nil {
				return fmt.Errorf("%w: encode publication cursor", ErrPersistence)
			}
			items = items[:request.Limit]
		}
		result.Items = items
		return nil
	})
	return result, err
}

func validQueryActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.ScopeKind == ScopeKindPlatform
}

func decodePublicationCursor(encoded string) (*publicationCursor, error) {
	if encoded == "" {
		return nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var cursor publicationCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.CreatedAt.IsZero() || cursor.PublicationID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	return &cursor, nil
}

func encodePublicationCursor(cursor publicationCursor) (string, error) {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}
