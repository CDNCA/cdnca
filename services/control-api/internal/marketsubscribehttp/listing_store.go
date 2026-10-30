package marketsubscribehttp

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Listing templates and batch items (migration 429, ML-11b).

type ListingTemplate struct {
	ID        uuid.UUID       `json:"id"`
	Name      string          `json:"name"`
	Body      json.RawMessage `json:"body"`
	Revision  int64           `json:"revision"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// BatchItem is the stored state of one batch item: the hidden group made for
// it and the market offer, once known.
type BatchItem struct {
	GroupID *uuid.UUID
	OfferID *uuid.UUID
}

var (
	ErrListingConflict = errors.New("market listing: conflict")
	// ErrItemBusy: another submission holds the item's lease.
	ErrItemBusy = errors.New("market listing: item in progress")
)

// ListingStore is *PostgresListingStore.
type ListingStore interface {
	Templates(ctx context.Context, platform uuid.UUID) ([]ListingTemplate, error)
	PutTemplate(ctx context.Context, platform, user uuid.UUID, t ListingTemplate) (ListingTemplate, error)
	DeleteTemplate(ctx context.Context, platform, id uuid.UUID, revision int64) error
	// ClaimItem returns the item's stored state and takes its lease for
	// lease (ErrItemBusy while someone else holds it).
	ClaimItem(ctx context.Context, platform, user uuid.UUID, digest []byte, lease time.Duration) (BatchItem, error)
	// SaveItem records the group/offer made; recording the offer releases the lease.
	SaveItem(ctx context.Context, platform uuid.UUID, digest []byte, item BatchItem) error
	ReleaseItem(ctx context.Context, platform uuid.UUID, digest []byte) error
}

type PostgresListingStore struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewPostgresListingStore(pool *pgxpool.Pool) *PostgresListingStore {
	return &PostgresListingStore{pool: pool, now: func() time.Time { return time.Now().UTC() }}
}

const maxTemplates = 100

func (s *PostgresListingStore) Templates(ctx context.Context, platform uuid.UUID) ([]ListingTemplate, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, body, revision, updated_at FROM market_listing_templates
		WHERE platform_scope_id=$1 ORDER BY lower(name), id LIMIT $2`, platform, maxTemplates)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ListingTemplate, error) {
		var t ListingTemplate
		return t, row.Scan(&t.ID, &t.Name, &t.Body, &t.Revision, &t.UpdatedAt)
	})
}

// PutTemplate creates (Revision 0) or replaces at Revision a template.
func (s *PostgresListingStore) PutTemplate(ctx context.Context, platform, user uuid.UUID, t ListingTemplate) (ListingTemplate, error) {
	now := s.now()
	var out ListingTemplate
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if t.Revision == 0 {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM market_listing_templates WHERE platform_scope_id=$1`, platform).Scan(&count); err != nil {
				return err
			}
			if count >= maxTemplates {
				return ErrStoreInvalid
			}
			return tx.QueryRow(ctx, `INSERT INTO market_listing_templates(id, platform_scope_id, name, body, revision, updated_by_user_id, created_at, updated_at)
				VALUES($1,$2,$3,$4,1,$5,$6,$6) RETURNING id, name, body, revision, updated_at`, uuid.New(), platform, t.Name, t.Body, user, now).
				Scan(&out.ID, &out.Name, &out.Body, &out.Revision, &out.UpdatedAt)
		}
		err := tx.QueryRow(ctx, `UPDATE market_listing_templates SET name=$4, body=$5, revision=revision+1, updated_by_user_id=$6, updated_at=$7
			WHERE platform_scope_id=$1 AND id=$2 AND revision=$3 RETURNING id, name, body, revision, updated_at`,
			platform, t.ID, t.Revision, t.Name, t.Body, user, now).Scan(&out.ID, &out.Name, &out.Body, &out.Revision, &out.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return s.missingOrStale(ctx, tx, platform, t.ID)
		}
		return err
	})
	return out, listingPG(err)
}

func (s *PostgresListingStore) DeleteTemplate(ctx context.Context, platform, id uuid.UUID, revision int64) error {
	return listingPG(pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM market_listing_templates WHERE platform_scope_id=$1 AND id=$2 AND revision=$3`, platform, id, revision)
		if err != nil || tag.RowsAffected() == 1 {
			return err
		}
		return s.missingOrStale(ctx, tx, platform, id)
	}))
}

func (s *PostgresListingStore) missingOrStale(ctx context.Context, tx pgx.Tx, platform, id uuid.UUID) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM market_listing_templates WHERE platform_scope_id=$1 AND id=$2)`,
		platform, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrListingConflict
	}
	return ErrStoreNotFound
}

func (s *PostgresListingStore) ClaimItem(ctx context.Context, platform, user uuid.UUID, digest []byte, lease time.Duration) (BatchItem, error) {
	now := s.now()
	var item BatchItem
	var until time.Time
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO market_listing_batch_items(platform_scope_id, digest, lease_until, created_by_user_id, created_at, updated_at)
			VALUES($1,$2,'epoch',$3,$4,$4) ON CONFLICT DO NOTHING`, platform, digest, user, now); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT group_id, offer_id, lease_until FROM market_listing_batch_items
			WHERE platform_scope_id=$1 AND digest=$2 FOR UPDATE`, platform, digest).Scan(&item.GroupID, &item.OfferID, &until); err != nil {
			return err
		}
		if item.OfferID != nil {
			return nil
		}
		if until.After(now) {
			return ErrItemBusy
		}
		_, err := tx.Exec(ctx, `UPDATE market_listing_batch_items SET lease_until=$3, updated_at=$4 WHERE platform_scope_id=$1 AND digest=$2`,
			platform, digest, now.Add(lease), now)
		return err
	})
	return item, listingPG(err)
}

func (s *PostgresListingStore) SaveItem(ctx context.Context, platform uuid.UUID, digest []byte, item BatchItem) error {
	_, err := s.pool.Exec(ctx, `UPDATE market_listing_batch_items SET group_id=COALESCE($3, group_id), offer_id=COALESCE($4, offer_id),
		lease_until=CASE WHEN $4::uuid IS NULL THEN lease_until ELSE 'epoch' END, updated_at=$5
		WHERE platform_scope_id=$1 AND digest=$2`, platform, digest, item.GroupID, item.OfferID, s.now())
	return listingPG(err)
}

func (s *PostgresListingStore) ReleaseItem(ctx context.Context, platform uuid.UUID, digest []byte) error {
	_, err := s.pool.Exec(ctx, `UPDATE market_listing_batch_items SET lease_until='epoch', updated_at=$3
		WHERE platform_scope_id=$1 AND digest=$2 AND offer_id IS NULL`, platform, digest, s.now())
	return err
}

func listingPG(err error) error {
	if mapped := mapPG(err); errors.Is(mapped, ErrStoreInvalid) {
		return mapped
	}
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
		return ErrListingConflict
	}
	return err
}
