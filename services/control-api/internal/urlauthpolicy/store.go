package urlauthpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool       *pgxpool.Pool
	auditor    *audit.Log
	authorizer TxAuthorizer
	now        func() time.Time
}

type rowScanner interface{ Scan(...any) error }

type storedWrite struct{ ResponseBody []byte }

type keyFactory func(uuid.UUID) (encryptedKey, error)

func NewStore(pool *pgxpool.Pool) *Store { return NewStoreWithClock(pool, time.Now) }

func NewStoreWithClock(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, auditor: audit.New(pool), authorizer: snapshotTxAuthorizer{}, now: now}
}

func NewStoreWithAuthorizer(pool *pgxpool.Pool, now func() time.Time, authorizer TxAuthorizer) (*Store, error) {
	if pool == nil || now == nil || authorizer == nil {
		return nil, ErrUnavailable
	}
	return &Store{pool: pool, auditor: audit.New(pool), authorizer: authorizer, now: now}, nil
}

func (s *Store) Create(ctx context.Context, actor Actor, request CreateRequest, digest [32]byte, makeKey keyFactory) (SecretWriteResult, error) {
	var result SecretWriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		authorizedTenantID, err := s.authorizer.Authorize(ctx, tx, actor, request.TargetScopeID, PermissionManage)
		if err != nil {
			return err
		}
		tenantID, err := authorizeTarget(ctx, tx, actor, request.TargetScopeID, request.OwnerUserID, request.Fields.SiteID)
		if err != nil {
			return err
		}
		if tenantID != authorizedTenantID {
			return ErrPermissionDenied
		}
		if stored, found, err := s.findWrite(ctx, tx, actor.UserID, "url_auth_policy.create", request.IdempotencyKey, digest); err != nil {
			return err
		} else if found {
			if err := json.Unmarshal(stored.ResponseBody, &result.Policy); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		if stored, replayed, err := s.claimWrite(ctx, tx, actor, request.TargetScopeID, "url_auth_policy.create", request.IdempotencyKey, digest); err != nil {
			return err
		} else if replayed {
			if err := json.Unmarshal(stored.ResponseBody, &result.Policy); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		policyID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		key, err := makeKey(policyID)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		_, err = tx.Exec(ctx, `INSERT INTO url_auth_policies (
			id,scope_id,tenant_id,owner_user_id,site_id,name,enabled,algorithm,
			signature_parameter,expiration_parameter,key_id_parameter,bind_client_ip,
			max_clock_skew_seconds,max_validity_seconds,max_signature_uses,
			excluded_query_parameters,trusted_proxy_cidrs,created_by_user_id,updated_by_user_id,created_at,updated_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$18,$19,$19)`,
			policyID, request.TargetScopeID, tenantID, request.OwnerUserID, request.Fields.SiteID,
			request.Fields.Name, request.Fields.Enabled, request.Fields.Algorithm,
			request.Fields.SignatureParameter, request.Fields.ExpirationParameter, request.Fields.KeyIDParameter,
			request.Fields.BindClientIP, request.Fields.MaxClockSkewSeconds, request.Fields.MaxValiditySeconds,
			request.Fields.MaxSignatureUses, request.Fields.ExcludedQueryParameters, request.Fields.TrustedProxyCIDRs,
			actor.UserID, now)
		if err != nil {
			if uniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		if err := insertKey(ctx, tx, policyID, key, "current", now); err != nil {
			return err
		}
		item, err := selectPolicy(ctx, tx, policyID)
		if err != nil {
			return err
		}
		if err := s.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, item, request.RequestID, "url_auth_policy.create", map[string]any{"current_key_id": key.ID}); err != nil {
			return err
		}
		if err := s.completeWrite(ctx, tx, actor.UserID, "url_auth_policy.create", request.IdempotencyKey, item.ID, item); err != nil {
			return err
		}
		result = SecretWriteResult{Policy: item, Secret: key.Plaintext}
		return nil
	})
	if err != nil {
		return SecretWriteResult{}, fmt.Errorf("create URL auth policy: %w", err)
	}
	return result, nil
}

func (s *Store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (WriteResult, error) {
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, err := policyTargetScope(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if _, err := s.authorizer.Authorize(ctx, tx, actor, targetScopeID, PermissionManage); err != nil {
			return err
		}
		if stored, found, err := s.findWrite(ctx, tx, actor.UserID, "url_auth_policy.update", request.IdempotencyKey, digest); err != nil {
			return err
		} else if found {
			if err := json.Unmarshal(stored.ResponseBody, &result.Policy); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		current, err := lockPolicy(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if _, err := authorizeTarget(ctx, tx, actor, current.ScopeID, current.ownerID, request.Fields.SiteID); err != nil {
			return err
		}
		if stored, replayed, err := s.claimWrite(ctx, tx, actor, current.ScopeID, "url_auth_policy.update", request.IdempotencyKey, digest); err != nil {
			return err
		} else if replayed {
			if err := json.Unmarshal(stored.ResponseBody, &result.Policy); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		now := s.now().UTC()
		_, err = tx.Exec(ctx, `UPDATE url_auth_policies SET
			site_id=$2,name=$3,enabled=$4,algorithm=$5,signature_parameter=$6,expiration_parameter=$7,
			key_id_parameter=$8,bind_client_ip=$9,max_clock_skew_seconds=$10,max_validity_seconds=$11,
			max_signature_uses=$12,excluded_query_parameters=$13,trusted_proxy_cidrs=$14,
			revision=revision+1,updated_by_user_id=$15,updated_at=$16 WHERE id=$1`,
			request.ID, request.Fields.SiteID, request.Fields.Name, request.Fields.Enabled, request.Fields.Algorithm,
			request.Fields.SignatureParameter, request.Fields.ExpirationParameter, request.Fields.KeyIDParameter,
			request.Fields.BindClientIP, request.Fields.MaxClockSkewSeconds, request.Fields.MaxValiditySeconds,
			request.Fields.MaxSignatureUses, request.Fields.ExcludedQueryParameters, request.Fields.TrustedProxyCIDRs,
			actor.UserID, now)
		if err != nil {
			if uniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		item, err := selectPolicy(ctx, tx, request.ID)
		if err != nil {
			return err
		}
		if err := s.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, item, request.RequestID, "url_auth_policy.update", nil); err != nil {
			return err
		}
		if err := s.completeWrite(ctx, tx, actor.UserID, "url_auth_policy.update", request.IdempotencyKey, item.ID, item); err != nil {
			return err
		}
		result.Policy = item
		return nil
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("update URL auth policy: %w", err)
	}
	return result, nil
}

func (s *Store) SetEnabled(ctx context.Context, actor Actor, request StateRequest, digest [32]byte) (WriteResult, error) {
	auditOperation := "url_auth_policy.disable"
	if request.Enabled {
		auditOperation = "url_auth_policy.enable"
	}
	const writeOperation = "url_auth_policy.update"
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, err := policyTargetScope(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if _, err := s.authorizer.Authorize(ctx, tx, actor, targetScopeID, PermissionManage); err != nil {
			return err
		}
		if stored, found, err := s.findWrite(ctx, tx, actor.UserID, writeOperation, request.IdempotencyKey, digest); err != nil {
			return err
		} else if found {
			if err := json.Unmarshal(stored.ResponseBody, &result.Policy); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		current, err := lockPolicy(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if current.Enabled == request.Enabled {
			return ErrConflict
		}
		if stored, replayed, err := s.claimWrite(ctx, tx, actor, current.ScopeID, writeOperation, request.IdempotencyKey, digest); err != nil {
			return err
		} else if replayed {
			if err := json.Unmarshal(stored.ResponseBody, &result.Policy); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `UPDATE url_auth_policies SET enabled=$2,revision=revision+1,updated_by_user_id=$3,updated_at=$4 WHERE id=$1`, request.ID, request.Enabled, actor.UserID, now); err != nil {
			return err
		}
		item, err := selectPolicy(ctx, tx, request.ID)
		if err != nil {
			return err
		}
		if err := s.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, item, request.RequestID, auditOperation, nil); err != nil {
			return err
		}
		if err := s.completeWrite(ctx, tx, actor.UserID, writeOperation, request.IdempotencyKey, item.ID, item); err != nil {
			return err
		}
		result.Policy = item
		return nil
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("set URL auth policy state: %w", err)
	}
	return result, nil
}

func (s *Store) Rotate(ctx context.Context, actor Actor, request RotateRequest, digest [32]byte, makeKey keyFactory) (SecretWriteResult, error) {
	var result SecretWriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, err := policyTargetScope(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if _, err := s.authorizer.Authorize(ctx, tx, actor, targetScopeID, PermissionManage); err != nil {
			return err
		}
		if stored, found, err := s.findWrite(ctx, tx, actor.UserID, "url_auth_policy.rotate", request.IdempotencyKey, digest); err != nil {
			return err
		} else if found {
			if err := json.Unmarshal(stored.ResponseBody, &result.Policy); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		current, err := lockPolicy(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if stored, replayed, err := s.claimWrite(ctx, tx, actor, current.ScopeID, "url_auth_policy.rotate", request.IdempotencyKey, digest); err != nil {
			return err
		} else if replayed {
			if err := json.Unmarshal(stored.ResponseBody, &result.Policy); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		key, err := makeKey(request.ID)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `UPDATE url_auth_policy_keys SET role='revoked',revoked_at=$2 WHERE policy_id=$1 AND role='previous'`, request.ID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE url_auth_policy_keys SET role='previous' WHERE policy_id=$1 AND role='current'`, request.ID); err != nil {
			return err
		}
		if err := insertKey(ctx, tx, request.ID, key, "current", now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE url_auth_policies SET revision=revision+1,updated_by_user_id=$2,updated_at=$3 WHERE id=$1`, request.ID, actor.UserID, now); err != nil {
			return err
		}
		item, err := selectPolicy(ctx, tx, request.ID)
		if err != nil {
			return err
		}
		if err := s.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, item, request.RequestID, "url_auth_policy.rotate", map[string]any{"current_key_id": key.ID, "previous_key_id": current.CurrentKey.KeyID}); err != nil {
			return err
		}
		if err := s.completeWrite(ctx, tx, actor.UserID, "url_auth_policy.rotate", request.IdempotencyKey, item.ID, item); err != nil {
			return err
		}
		result = SecretWriteResult{Policy: item, Secret: key.Plaintext}
		return nil
	})
	if err != nil {
		return SecretWriteResult{}, fmt.Errorf("rotate URL auth policy key: %w", err)
	}
	return result, nil
}

func (s *Store) Revoke(ctx context.Context, actor Actor, request RevokeRequest, digest [32]byte) (WriteResult, error) {
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, err := policyTargetScope(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if _, err := s.authorizer.Authorize(ctx, tx, actor, targetScopeID, PermissionManage); err != nil {
			return err
		}
		if stored, found, err := s.findWrite(ctx, tx, actor.UserID, "url_auth_policy.revoke", request.IdempotencyKey, digest); err != nil {
			return err
		} else if found {
			if err := json.Unmarshal(stored.ResponseBody, &result.Policy); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		current, err := lockPolicy(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if current.PreviousKey == nil || current.PreviousKey.KeyID != request.KeyID {
			return ErrKeyNotRevocable
		}
		if stored, replayed, err := s.claimWrite(ctx, tx, actor, current.ScopeID, "url_auth_policy.revoke", request.IdempotencyKey, digest); err != nil {
			return err
		} else if replayed {
			if err := json.Unmarshal(stored.ResponseBody, &result.Policy); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		now := s.now().UTC()
		command, err := tx.Exec(ctx, `UPDATE url_auth_policy_keys SET role='revoked',revoked_at=$3 WHERE policy_id=$1 AND key_id=$2 AND role='previous'`, request.ID, request.KeyID, now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrKeyNotRevocable
		}
		if _, err := tx.Exec(ctx, `UPDATE url_auth_policies SET revision=revision+1,updated_by_user_id=$2,updated_at=$3 WHERE id=$1`, request.ID, actor.UserID, now); err != nil {
			return err
		}
		item, err := selectPolicy(ctx, tx, request.ID)
		if err != nil {
			return err
		}
		if err := s.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, item, request.RequestID, "url_auth_policy.revoke", map[string]any{"revoked_key_id": request.KeyID}); err != nil {
			return err
		}
		if err := s.completeWrite(ctx, tx, actor.UserID, "url_auth_policy.revoke", request.IdempotencyKey, item.ID, item); err != nil {
			return err
		}
		result.Policy = item
		return nil
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("revoke URL auth policy key: %w", err)
	}
	return result, nil
}

func (s *Store) Get(ctx context.Context, actor Actor, id uuid.UUID) (Policy, error) {
	query := `SELECT ` + policyColumns("p") + ` FROM url_auth_policies p WHERE p.id=$1`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND p.scope_id=$2 AND p.owner_user_id=$3"
		args = append(args, actor.ScopeID, actor.UserID)
	}
	item, err := scanPolicy(s.pool.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("get URL auth policy: %w", err)
	}
	return item, nil
}

func (s *Store) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	where, args := listWhere(actor, filter)
	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM url_auth_policies p `+where, args...).Scan(&total); err != nil {
		return ListResult{}, err
	}
	limitPos, offsetPos := len(args)+1, len(args)+2
	args = append(args, filter.Limit, (filter.Page-1)*filter.Limit)
	rows, err := s.pool.Query(ctx, `SELECT `+policyColumns("p")+` FROM url_auth_policies p `+where+` ORDER BY p.created_at DESC,p.id DESC LIMIT $`+fmt.Sprint(limitPos)+` OFFSET $`+fmt.Sprint(offsetPos), args...)
	if err != nil {
		return ListResult{}, fmt.Errorf("list URL auth policies: %w", err)
	}
	defer rows.Close()
	items := make([]Policy, 0, filter.Limit)
	for rows.Next() {
		item, err := scanPolicy(rows)
		if err != nil {
			return ListResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, err
	}
	return ListResult{Items: items, Total: total, Page: filter.Page, Limit: filter.Limit}, nil
}

func (s *Store) Snapshot(ctx context.Context, actor Actor, id uuid.UUID) (SnapshotResult, error) {
	query := `SELECT v.revision,v.edge_snapshot,v.snapshot_sha256 FROM url_auth_policy_versions v JOIN url_auth_policies p ON p.id=v.policy_id WHERE p.id=$1 AND v.revision=p.revision`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND p.scope_id=$2 AND p.owner_user_id=$3"
		args = append(args, actor.ScopeID, actor.UserID)
	}
	var revision int64
	var raw, digest []byte
	if err := s.pool.QueryRow(ctx, query, args...).Scan(&revision, &raw, &digest); errors.Is(err, pgx.ErrNoRows) {
		return SnapshotResult{}, ErrNotFound
	} else if err != nil {
		return SnapshotResult{}, err
	}
	var document EdgePolicy
	if err := json.Unmarshal(raw, &document); err != nil {
		return SnapshotResult{}, err
	}
	return SnapshotResult{PolicyID: id, Revision: revision, SHA256: hex.EncodeToString(digest), Document: document}, nil
}

func policyTargetScope(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID) (uuid.UUID, error) {
	query := `SELECT scope_id FROM url_auth_policies WHERE id=$1`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND scope_id=$2 AND owner_user_id=$3"
		args = append(args, actor.ScopeID, actor.UserID)
	}
	var scopeID uuid.UUID
	if err := tx.QueryRow(ctx, query, args...).Scan(&scopeID); errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	} else if err != nil {
		return uuid.Nil, err
	}
	return scopeID, nil
}

func lockPolicy(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID) (Policy, error) {
	query := `SELECT ` + policyColumns("p") + ` FROM url_auth_policies p WHERE p.id=$1`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND p.scope_id=$2 AND p.owner_user_id=$3"
		args = append(args, actor.ScopeID, actor.UserID)
	}
	query += " FOR UPDATE OF p"
	item, err := scanPolicy(tx.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	return item, err
}

func selectPolicy(ctx context.Context, tx pgx.Tx, id uuid.UUID) (Policy, error) {
	return scanPolicy(tx.QueryRow(ctx, `SELECT `+policyColumns("p")+` FROM url_auth_policies p WHERE p.id=$1`, id))
}

func policyColumns(alias string) string {
	return alias + `.id,` + alias + `.scope_id,` + alias + `.tenant_id,` + alias + `.owner_user_id,` + alias + `.site_id,` +
		alias + `.name,` + alias + `.enabled,` + alias + `.algorithm,` + alias + `.migration_marker,` +
		alias + `.signature_parameter,` + alias + `.expiration_parameter,` + alias + `.key_id_parameter,` +
		alias + `.bind_client_ip,` + alias + `.max_clock_skew_seconds,` + alias + `.max_validity_seconds,` +
		alias + `.max_signature_uses,` + alias + `.excluded_query_parameters,` + alias + `.trusted_proxy_cidrs,` +
		alias + `.revision,` + alias + `.created_at,` + alias + `.updated_at,` +
		`(SELECT display_name FROM users WHERE id=` + alias + `.owner_user_id),` +
		`(SELECT domain FROM sites WHERE id=` + alias + `.site_id),` +
		`(SELECT key_id FROM url_auth_policy_keys WHERE policy_id=` + alias + `.id AND role='current'),` +
		`(SELECT created_at FROM url_auth_policy_keys WHERE policy_id=` + alias + `.id AND role='current'),` +
		`(SELECT key_id FROM url_auth_policy_keys WHERE policy_id=` + alias + `.id AND role='previous'),` +
		`(SELECT created_at FROM url_auth_policy_keys WHERE policy_id=` + alias + `.id AND role='previous')`
}

func scanPolicy(row rowScanner) (Policy, error) {
	var item Policy
	var ownerName, domain, currentKeyID string
	var currentCreated time.Time
	var previousKeyID *string
	var previousCreated *time.Time
	err := row.Scan(&item.ID, &item.ScopeID, &item.tenantID, &item.ownerID, &item.Site.ID, &item.Name, &item.Enabled, &item.Algorithm, &item.MigrationMarker,
		&item.SignatureParameter, &item.ExpirationParameter, &item.KeyIDParameter, &item.BindClientIP, &item.MaxClockSkewSeconds,
		&item.MaxValiditySeconds, &item.MaxSignatureUses, &item.ExcludedQueryParameters, &item.TrustedProxyCIDRs, &item.Revision, &item.CreatedAt,
		&item.UpdatedAt, &ownerName, &domain, &currentKeyID, &currentCreated, &previousKeyID, &previousCreated)
	if err != nil {
		return Policy{}, err
	}
	item.Owner = &OwnerReference{ID: item.ownerID, DisplayName: ownerName}
	item.Site.Domain = domain
	item.CurrentKey = KeyMetadata{KeyID: currentKeyID, CreatedAt: currentCreated}
	if previousKeyID != nil && previousCreated != nil {
		item.PreviousKey = &KeyMetadata{KeyID: *previousKeyID, CreatedAt: *previousCreated}
	}
	if item.ExcludedQueryParameters == nil {
		item.ExcludedQueryParameters = []string{}
	}
	if item.TrustedProxyCIDRs == nil {
		item.TrustedProxyCIDRs = []string{}
	}
	return item, nil
}

func authorizeTarget(ctx context.Context, tx pgx.Tx, actor Actor, scopeID, ownerID, siteID uuid.UUID) (uuid.UUID, error) {
	var kind string
	var tenantID *uuid.UUID
	var ownerMember, siteOwned bool
	err := tx.QueryRow(ctx, `SELECT scope.kind,scope.tenant_id,
		EXISTS(SELECT 1 FROM memberships m WHERE m.scope_id=scope.id AND m.user_id=$2 AND m.status='active'),
		EXISTS(SELECT 1 FROM sites s WHERE s.id=$3 AND s.scope_id=scope.id AND s.owner_user_id=$2 AND s.deleted_at IS NULL)
		FROM access_scopes scope WHERE scope.id=$1`, scopeID, ownerID, siteID).Scan(&kind, &tenantID, &ownerMember, &siteOwned)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrInvalidInput
	}
	if err != nil {
		return uuid.Nil, err
	}
	if kind != "tenant" || tenantID == nil || !ownerMember {
		return uuid.Nil, ErrInvalidInput
	}
	if !siteOwned {
		// The chosen site is not a live site of the owner (fix-fielderr-be4).
		return uuid.Nil, fielderr.New(ErrInvalidInput, "site_id", fielderr.Invalid)
	}
	if actor.ScopeKind == "tenant" && (actor.ScopeID != scopeID || actor.UserID != ownerID) {
		return uuid.Nil, ErrPermissionDenied
	}
	return *tenantID, nil
}

func insertKey(ctx context.Context, tx pgx.Tx, policyID uuid.UUID, key encryptedKey, role string, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO url_auth_policy_keys(policy_id,key_id,role,kek_key_id,ciphertext,secret_digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, policyID, key.ID, role, key.KEKKeyID, key.Ciphertext, key.Digest[:], now)
	return err
}

func (s *Store) insertVersion(ctx context.Context, tx pgx.Tx, item Policy, actorID uuid.UUID, now time.Time) error {
	raw, digest, err := edgeSnapshot(item)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO url_auth_policy_versions(policy_id,revision,edge_snapshot,snapshot_sha256,created_by_user_id,created_at) VALUES($1,$2,$3,$4,$5,$6)`, item.ID, item.Revision, raw, digest[:], actorID, now)
	return err
}

func edgeSnapshot(item Policy) ([]byte, [32]byte, error) {
	document := EdgePolicy{
		SchemaVersion: SchemaVersion, PolicyVersion: uint64(item.Revision), TenantID: item.tenantID.String(), SiteID: item.Site.ID.String(), Algorithm: item.Algorithm,
		SignatureParameter: item.SignatureParameter, ExpirationParameter: item.ExpirationParameter, KeyIDParameter: item.KeyIDParameter,
		BindClientIP: item.BindClientIP, MaxClockSkewSeconds: item.MaxClockSkewSeconds, MaxValiditySeconds: item.MaxValiditySeconds,
		MaxSignatureUses: item.MaxSignatureUses, ExcludedQueryParameters: append([]string(nil), item.ExcludedQueryParameters...),
		TrustedProxies: append([]string(nil), item.TrustedProxyCIDRs...), CurrentKey: edgeKey(item.ID, item.CurrentKey.KeyID),
	}
	if item.PreviousKey != nil {
		value := edgeKey(item.ID, item.PreviousKey.KeyID)
		document.PreviousKey = &value
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, [32]byte{}, err
	}
	raw = append(raw, '\n')
	return raw, sha256.Sum256(raw), nil
}

func edgeKey(policyID uuid.UUID, keyID string) EdgeKey {
	return EdgeKey{KeyID: keyID, KeyFile: filepath.Join("/var/lib/cdnca-edge/urlauth/keys", policyID.String(), keyID+".key")}
}

func listWhere(actor Actor, filter ListFilter) (string, []any) {
	conditions := []string{"true"}
	args := make([]any, 0, 4)
	add := func(format string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(format, len(args)))
	}
	if actor.ScopeKind == "tenant" {
		add("p.scope_id=$%d", actor.ScopeID)
		add("p.owner_user_id=$%d", actor.UserID)
	}
	if filter.Status != "" {
		add("p.enabled=$%d", filter.Status == "enabled")
	}
	if filter.Name != "" {
		add("position($%d in lower(p.name))>0", strings.ToLower(filter.Name))
	}
	if filter.SiteID != uuid.Nil {
		add("p.site_id=$%d", filter.SiteID)
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (s *Store) appendAudit(ctx context.Context, tx pgx.Tx, actor Actor, item Policy, requestID, action string, extra map[string]any) error {
	payload := map[string]any{"version": item.Revision, "site_id": item.Site.ID, "enabled": item.Enabled, "algorithm": item.Algorithm}
	for key, value := range extra {
		payload[key] = value
	}
	return s.auditor.Append(ctx, tx, audit.Event{ScopeID: item.ScopeID, ActorUserID: &actor.UserID, Action: action, ResourceType: "url_auth_policy", ResourceID: item.ID.String(), RequestID: requestID, Result: "success", Payload: payload})
}

func (s *Store) findWrite(ctx context.Context, tx pgx.Tx, actorID uuid.UUID, operation, key string, digest [32]byte) (storedWrite, bool, error) {
	var existingDigest, response []byte
	var completed *time.Time
	err := tx.QueryRow(ctx, `SELECT request_digest,response_body,completed_at FROM url_auth_policy_write_requests WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`, actorID, operation, key).Scan(&existingDigest, &response, &completed)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedWrite{}, false, nil
	}
	if err != nil {
		return storedWrite{}, false, err
	}
	if !bytes.Equal(existingDigest, digest[:]) || completed == nil || len(response) == 0 {
		return storedWrite{}, false, ErrIdempotencyConflict
	}
	return storedWrite{ResponseBody: response}, true, nil
}

func (s *Store) claimWrite(ctx context.Context, tx pgx.Tx, actor Actor, targetScope uuid.UUID, operation, key string, digest [32]byte) (storedWrite, bool, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return storedWrite{}, false, err
	}
	command, err := tx.Exec(ctx, `INSERT INTO url_auth_policy_write_requests(id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(actor_user_id,operation,idempotency_key) DO NOTHING`, id, actor.UserID, actor.ScopeID, targetScope, operation, key, digest[:], s.now().UTC())
	if err != nil {
		return storedWrite{}, false, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, false, nil
	}
	stored, found, err := s.findWrite(ctx, tx, actor.UserID, operation, key, digest)
	return stored, found, err
}

func (s *Store) completeWrite(ctx context.Context, tx pgx.Tx, actorID uuid.UUID, operation, key string, resourceID uuid.UUID, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE url_auth_policy_write_requests SET resource_id=$4,response_body=$5,completed_at=$6 WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 AND completed_at IS NULL`, actorID, operation, key, resourceID, encoded, s.now().UTC())
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func uniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
