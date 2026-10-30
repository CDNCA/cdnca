package migrationowner

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type Repository struct {
	tx pgx.Tx
}

func (r Repository) Put(ctx context.Context, id string) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO migration_owner_records (id) VALUES ($1)`, id)
	return err
}

func (r Repository) SharedExists(ctx context.Context, id string) bool {
	return r.tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM shared_records WHERE id = $1)`, id).Scan(new(bool)) == nil
}
