package orders

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type Repository struct {
	tx pgx.Tx
}

func (r Repository) Put(ctx context.Context, id string) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO order_records (id) VALUES ($1)`, id)
	return err
}
