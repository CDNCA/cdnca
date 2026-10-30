package securityban

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

type Service struct{ store *Store }

func NewService(store *Store) *Service { return &Service{store: store} }

func (s *Service) Store() *Store { return s.store }

// List validates the filter (page >= 1, 1..100 per page).
func (s *Service) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	if !actor.valid() || filter.Page < 1 || filter.Limit < 1 || filter.Limit > 100 ||
		(filter.SiteID != nil && *filter.SiteID == uuid.Nil) {
		return ListResult{}, ErrInvalidInput
	}
	return s.store.List(ctx, actor, filter)
}

// Create adds a manual ban of one client (an IPv4 / IPv6 address, or a
// network IPv4 /8../31, IPv6 /32../127 since fix-cidrban) on one site for
// 60 s .. 30 days.
func (s *Service) Create(ctx context.Context, actor Actor, request CreateRequest) (Entry, error) {
	client, ok := canonicalClient(request.ClientIP)
	request.Reason = strings.TrimSpace(request.Reason)
	if !actor.valid() || request.SiteID == uuid.Nil || !ok || request.DurationSecond < 60 ||
		request.DurationSecond > MaxManualSeconds || !validReason(request.Reason) ||
		!idempotencyPattern.MatchString(request.IdempotencyKey) || strings.TrimSpace(request.RequestID) == "" {
		return Entry{}, ErrInvalidInput
	}
	return s.store.Create(ctx, actor, request, client)
}

func (s *Service) Release(ctx context.Context, actor Actor, request ReleaseRequest) (Entry, error) {
	if !actor.valid() || request.EntryID == uuid.Nil || strings.TrimSpace(request.RequestID) == "" {
		return Entry{}, ErrInvalidInput
	}
	return s.store.Release(ctx, actor, request)
}
