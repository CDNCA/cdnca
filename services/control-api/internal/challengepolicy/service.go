package challengepolicy

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

type Service struct {
	store *Store
}

func NewService(store *Store) *Service {
	if store == nil {
		return nil
	}
	return &Service{store: store}
}

func (service *Service) Create(ctx context.Context, actor Actor, request CreateRequest) (WriteResult, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return WriteResult{}, err
	}
	if request.SiteID == uuid.Nil || !validWriteMetadata(request.WriteMetadata) {
		return WriteResult{}, ErrInvalidInput
	}
	host, err := normalizeHost(request.Host)
	if err != nil {
		return WriteResult{}, err
	}
	request.Host = host
	if err := normalizeConfig(&request.Config); err != nil {
		return WriteResult{}, err
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		SiteID        uuid.UUID `json:"site_id"`
		Host          string    `json:"host"`
		Enabled       bool      `json:"enabled"`
		Config        Config    `json:"config"`
	}{request.TargetScopeID, request.SiteID, request.Host, request.Enabled, request.Config})
	if err != nil {
		return WriteResult{}, ErrUnavailable
	}
	return service.store.Create(ctx, actor, request, digest)
}

func (service *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (WriteResult, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return WriteResult{}, err
	}
	if request.ID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.WriteMetadata) {
		return WriteResult{}, ErrInvalidInput
	}
	if err := normalizeConfig(&request.Config); err != nil {
		return WriteResult{}, err
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		ID            uuid.UUID `json:"id"`
		Revision      int64     `json:"revision"`
		Config        Config    `json:"config"`
	}{request.TargetScopeID, request.ID, request.ExpectedRevision, request.Config})
	if err != nil {
		return WriteResult{}, ErrUnavailable
	}
	return service.store.Update(ctx, actor, request, digest)
}

func (service *Service) SetEnabled(ctx context.Context, actor Actor, request StateRequest) (WriteResult, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return WriteResult{}, err
	}
	if request.ID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.WriteMetadata) {
		return WriteResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		ID            uuid.UUID `json:"id"`
		Revision      int64     `json:"revision"`
		Enabled       bool      `json:"enabled"`
	}{request.TargetScopeID, request.ID, request.ExpectedRevision, request.Enabled})
	if err != nil {
		return WriteResult{}, ErrUnavailable
	}
	return service.store.SetEnabled(ctx, actor, request, digest)
}

func (service *Service) Delete(ctx context.Context, actor Actor, request DeleteRequest) (WriteResult, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return WriteResult{}, err
	}
	if request.ID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.WriteMetadata) {
		return WriteResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		ID            uuid.UUID `json:"id"`
		Revision      int64     `json:"revision"`
	}{request.TargetScopeID, request.ID, request.ExpectedRevision})
	if err != nil {
		return WriteResult{}, ErrUnavailable
	}
	return service.store.Delete(ctx, actor, request, digest)
}

func (service *Service) Get(ctx context.Context, actor Actor, targetScopeID, id uuid.UUID) (Policy, error) {
	if err := validateTarget(actor, targetScopeID); err != nil {
		return Policy{}, err
	}
	if id == uuid.Nil {
		return Policy{}, ErrInvalidInput
	}
	return service.store.Get(ctx, actor, targetScopeID, id)
}

func (service *Service) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	if err := validateTarget(actor, filter.TargetScopeID); err != nil {
		return ListResult{}, err
	}
	if filter.Limit < 1 || filter.Limit > 100 || len(filter.Cursor) > maxCursorBytes {
		return ListResult{}, ErrInvalidInput
	}
	filter.Host = strings.TrimSpace(filter.Host)
	if filter.Host != "" {
		host, err := normalizeHost(filter.Host)
		if err != nil {
			return ListResult{}, err
		}
		filter.Host = host
	}
	return service.store.List(ctx, actor, filter)
}
