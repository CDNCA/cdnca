package samea

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct{ pool *pgxpool.Pool }

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/same-a", func(http.ResponseWriter, *http.Request) {})
	return mux
}

func (s *Service) Get(ctx context.Context) error {
	return s.pool.QueryRow(ctx, `SELECT id FROM samea_records`).Scan(new(string))
}

func (s *Service) Put(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO samea_records (id) VALUES ($1)`, id)
	return err
}
