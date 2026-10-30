package proofok

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
)

const PermissionManage = "proof.manage"

type Handler struct{ service *Service }

func NewHandler(pool any) *Handler { return &Handler{service: NewService(pool)} }

func (handler *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/proof", handler.create)
	return mux
}

func (handler *Handler) create(writer http.ResponseWriter, request *http.Request) {
	key := request.Header.Get("Idempotency-Key")
	_ = handler.service.Create(request.Context(), key)
}

type Service struct{ store *Store }

func NewService(pool any) *Service {
	return &Service{store: &Store{pool: pool, authorizer: PostgresAuthorizer{}, auditor: PostgresAuditor{}}}
}

func (service *Service) Create(ctx context.Context, key string) error {
	return service.store.Create(ctx, key)
}

type Store struct {
	pool       any
	authorizer TxAuthorizer
	auditor    Auditor
}

type TxAuthorizer interface {
	Authorize(context.Context, pgx.Tx, string) error
}

type Auditor interface {
	Append(context.Context, pgx.Tx, string) error
}

func (store *Store) Create(ctx context.Context, key string) error {
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, PermissionManage); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO proof_idempotency (key) VALUES ($1)`, key); err != nil {
			return err
		}
		return store.auditor.Append(ctx, tx, key)
	})
}

type PostgresAuthorizer struct{}

func (PostgresAuthorizer) Authorize(ctx context.Context, tx pgx.Tx, permission string) error {
	return tx.QueryRow(ctx, `SELECT permission FROM proof_permissions WHERE permission=$1`, permission).Scan(new(string))
}

type PostgresAuditor struct{}

func (PostgresAuditor) Append(context.Context, pgx.Tx, string) error { return nil }
