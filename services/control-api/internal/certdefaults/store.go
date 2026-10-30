package certdefaults

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{store: &store{pool: pool, auditor: audit.NewWithClock(pool, now), now: now}}
}

func (s *store) Get(ctx context.Context, actor Actor, request Request) (Defaults, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Defaults{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := authorizeTarget(ctx, tx, actor, request.TargetScopeID, request.TargetUserID); err != nil {
		return Defaults{}, err
	}
	result, err := scanDefaults(tx.QueryRow(ctx, `
		SELECT scope_id, user_id, certificate_type, dns_provider_id, issuer, revision, updated_at
		FROM certificate_user_defaults
		WHERE scope_id = $1 AND user_id = $2`, request.TargetScopeID, request.TargetUserID))
	if errors.Is(err, pgx.ErrNoRows) {
		result = Defaults{ScopeID: request.TargetScopeID, UserID: request.TargetUserID, CertificateType: CertificateTypeACME}
	} else if err != nil {
		return Defaults{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Defaults{}, err
	}
	return result, nil
}

func (s *store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (Defaults, error) {
	var result Defaults
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTarget(ctx, tx, actor, request.TargetScopeID, request.TargetUserID); err != nil {
			return err
		}
		// The default DNS account is one the user's tenant entered itself:
		// the platform DNS copy cannot order DNS-01 for the tenant
		// (DNS-SEC-20261027-01).
		if request.DNSProviderID != nil {
			var valid bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(
				SELECT 1 FROM dns_providers WHERE id = $1 AND scope_id = $2 AND status <> 'disabled'
				  AND managed_by = 'tenant' AND id <> $3
			)`, *request.DNSProviderID, request.TargetScopeID,
				dnsacme.PlatformProviderCopyID(request.TargetScopeID)).Scan(&valid); err != nil {
				return err
			}
			if !valid {
				return ErrProviderInvalid
			}
		}
		const operation = "certificate.defaults.update"
		var previousDigest, responseBody []byte
		var resourceID *uuid.UUID
		var completedAt *time.Time
		err := tx.QueryRow(ctx, `SELECT request_digest, response_body, resource_id, completed_at
			FROM certificate_default_write_requests WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3`,
			actor.UserID, operation, request.IdempotencyKey).Scan(&previousDigest, &responseBody, &resourceID, &completedAt)
		if err == nil {
			if !bytes.Equal(previousDigest, digest[:]) || resourceID == nil || completedAt == nil {
				return ErrIdempotencyConflict
			}
			if err := json.Unmarshal(responseBody, &result); err != nil {
				return fmt.Errorf("decode certificate defaults replay: %w", err)
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO certificate_default_write_requests
			(id, actor_user_id, target_scope_id, operation, idempotency_key, request_digest)
			VALUES ($1,$2,$3,$4,$5,$6)`, uuid.New(), actor.UserID, request.TargetScopeID, operation, request.IdempotencyKey, digest[:]); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrIdempotencyConflict
			}
			return err
		}
		var currentRevision int64
		err = tx.QueryRow(ctx, `SELECT revision FROM certificate_user_defaults WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`, request.TargetScopeID, request.TargetUserID).Scan(&currentRevision)
		if errors.Is(err, pgx.ErrNoRows) {
			if request.ExpectedRevision != 0 {
				return ErrRevisionConflict
			}
			_, err = tx.Exec(ctx, `INSERT INTO certificate_user_defaults
				(scope_id,user_id,certificate_type,dns_provider_id,issuer,revision,updated_by_user_id,updated_at)
				VALUES($1,$2,$3,$4,$7,1,$5,$6)`, request.TargetScopeID, request.TargetUserID, request.CertificateType, request.DNSProviderID, actor.UserID, s.now().UTC(), request.Issuer)
		} else if err == nil {
			if currentRevision != request.ExpectedRevision {
				return ErrRevisionConflict
			}
			_, err = tx.Exec(ctx, `UPDATE certificate_user_defaults SET certificate_type=$3,dns_provider_id=$4,issuer=$7,
				revision=revision+1,updated_by_user_id=$5,updated_at=$6 WHERE scope_id=$1 AND user_id=$2`,
				request.TargetScopeID, request.TargetUserID, request.CertificateType, request.DNSProviderID, actor.UserID, s.now().UTC(), request.Issuer)
		}
		if err != nil {
			return err
		}
		result, err = scanDefaults(tx.QueryRow(ctx, `SELECT scope_id,user_id,certificate_type,dns_provider_id,issuer,revision,updated_at
			FROM certificate_user_defaults WHERE scope_id=$1 AND user_id=$2`, request.TargetScopeID, request.TargetUserID))
		if err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: request.TargetScopeID, ActorUserID: &actor.UserID,
			Action: operation, ResourceType: "certificate_user_defaults", ResourceID: request.TargetUserID.String(),
			RequestID: request.RequestID, Result: "success", Payload: map[string]any{"revision": result.Revision}}); err != nil {
			return err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE certificate_default_write_requests SET resource_id=$4,response_status=200,response_body=$5::jsonb,completed_at=$6
			WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`, actor.UserID, operation, request.IdempotencyKey, request.TargetUserID, encoded, s.now().UTC())
		return err
	})
	if err != nil {
		return Defaults{}, err
	}
	return result, nil
}

func scanDefaults(row pgx.Row) (Defaults, error) {
	var result Defaults
	return result, row.Scan(&result.ScopeID, &result.UserID, &result.CertificateType, &result.DNSProviderID, &result.Issuer, &result.Revision, &result.UpdatedAt)
}

func authorizeTarget(ctx context.Context, tx pgx.Tx, actor Actor, scopeID, userID uuid.UUID) error {
	var kind string
	var member bool
	if err := tx.QueryRow(ctx, `SELECT s.kind, EXISTS(SELECT 1 FROM memberships m WHERE m.scope_id=s.id AND m.user_id=$2 AND m.status='active')
		FROM access_scopes s WHERE s.id=$1`, scopeID, userID).Scan(&kind, &member); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if kind != "tenant" || !member {
		return ErrPermissionDenied
	}
	if actor.ScopeKind == "tenant" && (actor.ScopeID != scopeID || actor.UserID != userID) {
		return ErrPermissionDenied
	}
	return nil
}
