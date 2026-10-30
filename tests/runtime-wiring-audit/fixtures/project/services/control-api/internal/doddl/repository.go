package doddl

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type Repository struct {
	tx pgx.Tx
}

func (repository Repository) Create(ctx context.Context, id string) error {
	_, err := repository.tx.Exec(ctx, `INSERT INTO do_ddl_records (id) VALUES ($1)`, id)
	return err
}
