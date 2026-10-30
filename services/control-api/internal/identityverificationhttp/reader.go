package identityverificationhttp

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const listCasesSQL = `
	SELECT verification_case.id,verification_case.applicant_user_id,verification_case.kind,
	       verification_case.status,verification_case.reviewer_user_id,verification_case.revision,
	       verification_case.created_at,verification_case.state_changed_at,
	       verification_case.submitted_at,verification_case.expires_at
	FROM identity_verification_cases verification_case
	WHERE verification_case.tenant_scope_id=$1
	  AND ($2='' OR verification_case.kind=$2)
	  AND ($3='' OR verification_case.status=$3)
	  AND ($4::timestamptz IS NULL OR
	       (verification_case.created_at,verification_case.id) < ($4,$5::uuid))
	ORDER BY verification_case.created_at DESC,verification_case.id DESC
	LIMIT $6`

// listAdminCasesSQL: every tenant's cases for the platform administrator,
// with the tenant's display name and the applicant's username.
const listAdminCasesSQL = `
	SELECT verification_case.id,verification_case.applicant_user_id,verification_case.kind,
	       verification_case.status,verification_case.reviewer_user_id,verification_case.revision,
	       verification_case.created_at,verification_case.state_changed_at,
	       verification_case.submitted_at,verification_case.expires_at,
	       verification_case.tenant_scope_id,tenant.display_name,applicant.username
	FROM identity_verification_cases verification_case
	JOIN access_scopes scope ON scope.id=verification_case.tenant_scope_id AND scope.kind='tenant'
	JOIN tenants tenant ON tenant.id=scope.tenant_id
	JOIN users applicant ON applicant.id=verification_case.applicant_user_id
	WHERE ($1='' OR verification_case.kind=$1)
	  AND ($2='' OR verification_case.status=$2)
	  AND ($3::timestamptz IS NULL OR
	       (verification_case.created_at,verification_case.id) < ($3,$4::uuid))
	ORDER BY verification_case.created_at DESC,verification_case.id DESC
	LIMIT $5`

type reviewListAuthorizer interface {
	AuthorizeReviewerList(context.Context, pgx.Tx, identityverification.Actor) error
	AuthorizePlatformAdminList(context.Context, pgx.Tx, identityverification.PlatformAdmin) error
}

type PostgresReader struct {
	pool       *pgxpool.Pool
	authorizer reviewListAuthorizer
}

func NewPostgresReader(pool *pgxpool.Pool) (*PostgresReader, error) {
	if !configuredPool(pool) {
		return nil, ErrInvalidService
	}
	return &PostgresReader{pool: pool}, nil
}

func newPostgresReader(pool *pgxpool.Pool, authorizer reviewListAuthorizer) (*PostgresReader, error) {
	if !configuredPool(pool) || isNilDependency(authorizer) {
		return nil, ErrInvalidService
	}
	return &PostgresReader{pool: pool, authorizer: authorizer}, nil
}

func (reader *PostgresReader) ListCases(ctx context.Context, actor identityverification.Actor, query CasePageQuery) ([]CaseSummary, error) {
	if reader == nil || isNilDependency(reader.authorizer) || !configuredPool(reader.pool) {
		return nil, ErrPermissionDenied
	}
	if !validActor(actor) || query.Limit < 1 || !validKindFilter(query.Kind) || !validStatusFilter(query.Status) ||
		(query.AfterCreatedAt == nil) != (query.AfterID == nil) {
		return nil, ErrInvalidRequest
	}
	items := make([]CaseSummary, 0, query.Limit)
	err := pgx.BeginFunc(ctx, reader.pool, func(tx pgx.Tx) error {
		if err := reader.authorizer.AuthorizeReviewerList(ctx, tx, actor); err != nil {
			if errors.Is(err, identityverification.ErrPermissionDenied) {
				return ErrPermissionDenied
			}
			return err
		}
		rows, err := tx.Query(ctx, listCasesSQL, actor.TenantScopeID(), query.Kind, query.Status,
			query.AfterCreatedAt, query.AfterID, query.Limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item CaseSummary
			if err := rows.Scan(&item.ID, &item.ApplicantUserID, &item.Kind, &item.Status,
				&item.ReviewerUserID, &item.Revision, &item.CreatedAt, &item.StateChangedAt,
				&item.SubmittedAt, &item.ExpiresAt); err != nil {
				return err
			}
			normalizeSummaryTimes(&item)
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (reader *PostgresReader) ListAdminCases(ctx context.Context, admin identityverification.PlatformAdmin,
	query CasePageQuery,
) ([]AdminCaseSummary, error) {
	if reader == nil || isNilDependency(reader.authorizer) || !configuredPool(reader.pool) {
		return nil, ErrPermissionDenied
	}
	if !admin.Valid() || query.Limit < 1 || !validKindFilter(query.Kind) || !validStatusFilter(query.Status) ||
		(query.AfterCreatedAt == nil) != (query.AfterID == nil) {
		return nil, ErrInvalidRequest
	}
	items := make([]AdminCaseSummary, 0, query.Limit)
	err := pgx.BeginFunc(ctx, reader.pool, func(tx pgx.Tx) error {
		if err := reader.authorizer.AuthorizePlatformAdminList(ctx, tx, admin); err != nil {
			if errors.Is(err, identityverification.ErrPermissionDenied) {
				return ErrPermissionDenied
			}
			return err
		}
		rows, err := tx.Query(ctx, listAdminCasesSQL, query.Kind, query.Status,
			query.AfterCreatedAt, query.AfterID, query.Limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item AdminCaseSummary
			if err := rows.Scan(&item.ID, &item.ApplicantUserID, &item.Kind, &item.Status,
				&item.ReviewerUserID, &item.Revision, &item.CreatedAt, &item.StateChangedAt,
				&item.SubmittedAt, &item.ExpiresAt, &item.TenantScopeID, &item.TenantName,
				&item.ApplicantUsername); err != nil {
				return err
			}
			normalizeSummaryTimes(&item.CaseSummary)
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

func normalizeSummaryTimes(item *CaseSummary) {
	item.CreatedAt = item.CreatedAt.UTC().Truncate(time.Microsecond)
	item.StateChangedAt = item.StateChangedAt.UTC().Truncate(time.Microsecond)
	item.SubmittedAt = utcTime(item.SubmittedAt)
	item.ExpiresAt = utcTime(item.ExpiresAt)
}

func utcTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC().Truncate(time.Microsecond)
	return &normalized
}

func mapReaderNoRows(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

var _ ReviewReadStore = (*PostgresReader)(nil)
var _ reviewListAuthorizer = (*identityverification.Service)(nil)
