package brandasset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/themepack"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const operationUpload = "platform_brand_asset.upload"

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func NewService(pool *pgxpool.Pool, auditor AuditAppender, objects ObjectStore, now Clock) (*Service, error) {
	if pool == nil || auditor == nil || objects == nil || now == nil {
		return nil, ErrInvalidStore
	}
	return &Service{pool: pool, auditor: auditor, objects: objects, now: now}, nil
}

func (s *Service) Get(ctx context.Context, actor Actor, slot Slot) (Asset, error) {
	if err := validActor(actor); err != nil || !slot.Valid() {
		return Asset{}, ErrPermissionDenied
	}
	var result Asset
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, "system_configuration.read"); err != nil {
			return err
		}
		result = emptyAsset(slot)
		var revision int64
		var reference, mimeType string
		var digest []byte
		var size int64
		var updatedAt time.Time
		err := tx.QueryRow(ctx, `SELECT revision,reference,mime_type,size_bytes,sha256,updated_at
			FROM platform_brand_assets WHERE platform_scope_id=$1 AND slot=$2`, actor.ScopeID, slot).
			Scan(&revision, &reference, &mimeType, &size, &digest, &updatedAt)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		result = Asset{Schema: schema, Slot: slot, Revision: revision, Reference: reference,
			MIMEType: mimeType, SizeBytes: size, SHA256: hex.EncodeToString(digest), UpdatedAt: updatedAt.UTC()}
		return nil
	})
	if err != nil {
		return Asset{}, fmt.Errorf("get platform brand asset: %w", err)
	}
	return result, nil
}

func (s *Service) List(ctx context.Context, actor Actor) ([]Asset, error) {
	if err := validActor(actor); err != nil {
		return nil, ErrPermissionDenied
	}
	result := make([]Asset, 0, len(Slots))
	for _, slot := range Slots {
		asset, err := s.Get(ctx, actor, slot)
		if err != nil {
			return nil, err
		}
		result = append(result, asset)
	}
	return result, nil
}

// Querier is the read side PublicRevisions needs (a pool or a transaction).
type Querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// PublicRevisions lists the slots the platform has uploaded, with each
// slot's revision, so a page requests only /v1/brand-assets/<slot> that exist
// and busts the cache with ?v=<revision> after an upload.
func PublicRevisions(ctx context.Context, q Querier) (map[Slot]int64, error) {
	rows, err := q.Query(ctx, `SELECT asset.slot,asset.revision
		FROM platform_brand_assets asset JOIN access_scopes scope ON scope.id=asset.platform_scope_id
		WHERE scope.kind='platform' AND scope.tenant_id IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("list public platform brand assets: %w", ErrUnavailable)
	}
	defer rows.Close()
	result := map[Slot]int64{}
	for rows.Next() {
		var slot Slot
		var revision int64
		if err := rows.Scan(&slot, &revision); err != nil {
			return nil, fmt.Errorf("list public platform brand assets: %w", ErrUnavailable)
		}
		if slot.Valid() && revision > 0 {
			result[slot] = revision
		}
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("list public platform brand assets: %w", ErrUnavailable)
	}
	return result, nil
}

// OpenPublic returns the immutable object bound to the singleton platform
// scope. It deliberately exposes no scope, object-key, or storage token.
func (s *Service) OpenPublic(ctx context.Context, slot Slot) (PublicAsset, error) {
	if !slot.Valid() {
		return PublicAsset{}, ErrNotFound
	}
	var asset Asset
	var scopeID uuid.UUID
	var objectKey, token string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var revision int64
		var reference, mimeType string
		var digest []byte
		var size int64
		var updatedAt time.Time
		if err := tx.QueryRow(ctx, `SELECT asset.platform_scope_id,asset.revision,asset.reference,asset.mime_type,asset.size_bytes,asset.sha256,asset.updated_at,asset.object_key,asset.immutable_token
			FROM platform_brand_assets asset JOIN access_scopes scope ON scope.id=asset.platform_scope_id
			WHERE scope.kind='platform' AND scope.tenant_id IS NULL AND asset.slot=$1`, slot).
			Scan(&scopeID, &revision, &reference, &mimeType, &size, &digest, &updatedAt, &objectKey, &token); err != nil {
			if err == pgx.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		asset = Asset{Schema: schema, Slot: slot, Revision: revision, Reference: reference,
			MIMEType: mimeType, SizeBytes: size, SHA256: hex.EncodeToString(digest), UpdatedAt: updatedAt.UTC()}
		return nil
	})
	if err != nil {
		return PublicAsset{}, fmt.Errorf("read public platform brand asset: %w", err)
	}
	body, err := s.objects.Open(ctx, scopeID, objectKey, token)
	if err != nil {
		return PublicAsset{}, fmt.Errorf("open public platform brand asset: %w", ErrUnavailable)
	}
	return PublicAsset{Asset: asset, Body: body}, nil
}

func (s *Service) Upload(ctx context.Context, actor Actor, request UploadRequest) (Asset, error) {
	if err := validActor(actor); err != nil || actor.ScopeKind != "platform" {
		return Asset{}, ErrPermissionDenied
	}
	if request.ExpectedRevision < 0 || request.ExpectedRevision >= 1<<63-1 ||
		!request.Slot.Valid() || !metadataPattern.MatchString(request.IdempotencyKey) ||
		!metadataPattern.MatchString(request.RequestID) || !validMedia(request.Slot, request.MIMEType) ||
		!validBody(request.Slot, request.MIMEType, request.Body) {
		return Asset{}, ErrInvalidInput
	}
	digest := sha256.Sum256(request.Body)
	shaString := hex.EncodeToString(digest[:])
	objectKey := "brand-assets/" + actor.ScopeID.String() + "/" + string(request.Slot) + "/" + shaString
	info, err := s.objects.Put(ctx, actor.ScopeID, objectKey, request.Body, request.MIMEType)
	if err != nil {
		return Asset{}, fmt.Errorf("stage platform brand asset: %w", ErrUnavailable)
	}
	if info.Size != int64(len(request.Body)) || strings.ToLower(info.SHA256) != shaString || info.ImmutableToken == "" {
		return Asset{}, ErrUnavailable
	}
	var result Asset
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, "system_configuration.manage"); err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		if now.Year() < 1 || now.Year() > 9999 {
			return ErrInvalidInput
		}
		requestDigest := sha256.Sum256(append([]byte(fmt.Sprintf("%d|%s|%s|", request.ExpectedRevision, request.Slot, request.MIMEType)), digest[:]...))
		var existingDigest []byte
		var existingResponse []byte
		err := tx.QueryRow(ctx, `SELECT request_digest,response_body FROM platform_brand_asset_write_requests
			WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`, actor.UserID, operationUpload, request.IdempotencyKey).
			Scan(&existingDigest, &existingResponse)
		if err == nil {
			if string(existingDigest) != string(requestDigest[:]) || len(existingResponse) == 0 {
				return ErrIdempotencyConflict
			}
			if err := json.Unmarshal(existingResponse, &result); err != nil {
				return ErrUnavailable
			}
			return nil
		}
		if err != pgx.ErrNoRows {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform_brand_asset_write_requests(
			id,actor_user_id,actor_scope_id,target_scope_id,operation,slot,idempotency_key,request_digest,created_at
		) VALUES($1,$2,$3,$3,$4,$5,$6,$7,$8)`, uuid.New(), actor.UserID, actor.ScopeID,
			operationUpload, request.Slot, request.IdempotencyKey, requestDigest[:], now); err != nil {
			return err
		}
		var currentRevision int64
		err = tx.QueryRow(ctx, `SELECT revision FROM platform_brand_assets WHERE platform_scope_id=$1 AND slot=$2 FOR UPDATE`, actor.ScopeID, request.Slot).Scan(&currentRevision)
		exists := err == nil
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if !exists {
			currentRevision = 0
		}
		if currentRevision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		nextRevision := currentRevision + 1
		reference := "asset://brand/" + string(request.Slot) + "/" + shaString
		if exists {
			_, err = tx.Exec(ctx, `UPDATE platform_brand_assets SET revision=$3,reference=$4,mime_type=$5,size_bytes=$6,sha256=decode($7,'hex'),object_key=$8,immutable_token=$9,updated_by_user_id=$10,updated_at=$11
				WHERE platform_scope_id=$1 AND slot=$2`, actor.ScopeID, request.Slot, nextRevision, reference, request.MIMEType, len(request.Body), shaString, objectKey, info.ImmutableToken, actor.UserID, now)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO platform_brand_assets(platform_scope_id,slot,revision,reference,mime_type,size_bytes,sha256,object_key,immutable_token,updated_by_user_id,updated_at)
				VALUES($1,$2,$3,$4,$5,$6,decode($7,'hex'),$8,$9,$10,$11)`, actor.ScopeID, request.Slot, nextRevision, reference, request.MIMEType, len(request.Body), shaString, objectKey, info.ImmutableToken, actor.UserID, now)
		}
		if err != nil {
			return err
		}
		result = Asset{Schema: schema, Slot: request.Slot, Revision: nextRevision, Reference: reference,
			MIMEType: request.MIMEType, SizeBytes: int64(len(request.Body)), SHA256: shaString, UpdatedAt: now}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: operationUpload, ResourceType: "platform_brand_asset", ResourceID: string(request.Slot),
			RequestID: request.RequestID, Result: "success", Payload: map[string]any{
				"slot": request.Slot, "revision": nextRevision, "mime_type": request.MIMEType, "size_bytes": len(request.Body), "sha256": shaString,
			}}); err != nil {
			return err
		}
		response, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE platform_brand_asset_write_requests SET response_body=$4,completed_at=$5
			WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`, actor.UserID, operationUpload, request.IdempotencyKey, response, now)
		return err
	})
	if err != nil {
		// The object key is content-addressed. Remove it only when the database
		// confirms no committed binding references it; on an unavailable DB we
		// retain the object for the reconciler rather than risking a live delete.
		var referenced bool
		if queryErr := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform_brand_assets WHERE platform_scope_id=$1 AND object_key=$2)`, actor.ScopeID, objectKey).Scan(&referenced); queryErr == nil && !referenced {
			_ = s.objects.Delete(context.WithoutCancel(ctx), actor.ScopeID, objectKey)
		}
		return Asset{}, fmt.Errorf("upload platform brand asset: %w", err)
	}
	return result, nil
}

func emptyAsset(slot Slot) Asset { return Asset{Schema: schema, Slot: slot, Revision: 0} }

func validActor(actor Actor) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	return nil
}

func validMedia(slot Slot, mimeType string) bool { return themepack.ValidBrandMedia(string(slot), mimeType) }

// ValidAsset applies the upload media checks to a theme package's brand image.
func ValidAsset(slot Slot, mimeType string, body []byte) bool {
	return slot.Valid() && themepack.ValidBrandAsset(string(slot), mimeType, body)
}

func validBody(slot Slot, mimeType string, body []byte) bool {
	return themepack.ValidBrandBody(string(slot), mimeType, body)
}

func authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('platform-brand-assets-authorization:' || $1::text || ':' || $2::text,0))`, actor.ScopeID, actor.UserID); err != nil {
		return err
	}
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR UPDATE`, actor.ScopeID).Scan(&kind, &tenantID); err != nil || kind != "platform" || tenantID != nil {
		return ErrPermissionDenied
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR UPDATE`, actor.UserID).Scan(&status); err != nil || status != "active" {
		return ErrPermissionDenied
	}
	var membershipStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`, actor.ScopeID, actor.UserID).Scan(&membershipStatus); err != nil || membershipStatus != "active" {
		return ErrPermissionDenied
	}
	var roleID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT assignment.role_id FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions grant_row ON grant_row.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND grant_row.permission_name=$3
		ORDER BY assignment.role_id LIMIT 1 FOR UPDATE OF assignment,role,grant_row`, actor.ScopeID, actor.UserID, permission).Scan(&roleID); err != nil {
		return ErrPermissionDenied
	}
	return nil
}
