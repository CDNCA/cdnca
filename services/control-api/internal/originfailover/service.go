package originfailover

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Actor is the caller of the HTTP API (tenant members see their own sites).
type Actor struct {
	UserID, ScopeID uuid.UUID
	ScopeKind       string
}

// Service is the read-only status (also used in process by aggregated edge
// scheduling) and the manual switch back.
type Service struct {
	store *Store
}

func NewService(store *Store) *Service { return &Service{store: store} }

// PoolStatus is the site's pool state; ErrNotFound: missing or deleted.
func (s *Service) PoolStatus(ctx context.Context, siteID uuid.UUID) (PoolStatus, error) {
	if siteID == uuid.Nil {
		return PoolStatus{}, ErrNotFound
	}
	status, err := s.store.PoolStatus(ctx, siteID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return PoolStatus{}, fmt.Errorf("origin pool status: %w", err)
	}
	return status, err
}

// Status is PoolStatus for an API caller.
func (s *Service) Status(ctx context.Context, actor Actor, siteID uuid.UUID) (PoolStatus, error) {
	if err := s.visible(ctx, actor, siteID); err != nil {
		return PoolStatus{}, err
	}
	return s.PoolStatus(ctx, siteID)
}

// Failback moves a pool back to its best healthy higher level.
func (s *Service) Failback(ctx context.Context, actor Actor, siteID uuid.UUID, idempotencyKey string) (PoolStatus, error) {
	if actor.UserID == uuid.Nil || idempotencyKey == "" || len(idempotencyKey) > 128 {
		return PoolStatus{}, ErrInvalidInput
	}
	if err := s.visible(ctx, actor, siteID); err != nil {
		return PoolStatus{}, err
	}
	if err := s.store.Failback(ctx, actor.UserID, siteID, idempotencyKey); err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrFailbackUnavailable) {
			return PoolStatus{}, err
		}
		return PoolStatus{}, fmt.Errorf("origin failback: %w", err)
	}
	return s.PoolStatus(ctx, siteID)
}

func (s *Service) visible(ctx context.Context, actor Actor, siteID uuid.UUID) error {
	if siteID == uuid.Nil {
		return ErrNotFound
	}
	scopeID, err := s.store.SiteScope(ctx, siteID)
	if err != nil {
		return err
	}
	if actor.ScopeKind == "tenant" && scopeID != actor.ScopeID {
		return ErrNotFound
	}
	return nil
}
