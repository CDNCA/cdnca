package httppolicycontrol

import (
	"context"

	"github.com/google/uuid"
)

type Service struct {
	store *Store
}

func NewService(store *Store) *Service {
	return &Service{store: store}
}

func (service *Service) Create(ctx context.Context, actor Actor, request CreateRequest) (WriteResult, error) {
	if service == nil || service.store == nil {
		return WriteResult{}, ErrUnavailable
	}
	if request.TargetScopeID == uuid.Nil || request.SiteID == uuid.Nil || !validWriteMetadata(request.WriteMetadata) {
		return WriteResult{}, ErrInvalidInput
	}
	config, err := normalizeConfig(request.Config)
	if err != nil {
		return WriteResult{}, err
	}
	request.Config = config
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		SiteID        uuid.UUID `json:"site_id"`
		Enabled       bool      `json:"enabled"`
		Config        Config    `json:"config"`
	}{request.TargetScopeID, request.SiteID, request.Enabled, request.Config})
	if err != nil {
		return WriteResult{}, ErrUnavailable
	}
	return service.store.Create(ctx, actor, request, digest)
}

func (service *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (WriteResult, error) {
	if service == nil || service.store == nil {
		return WriteResult{}, ErrUnavailable
	}
	if request.TargetScopeID == uuid.Nil || request.ID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.WriteMetadata) {
		return WriteResult{}, ErrInvalidInput
	}
	config, err := normalizeConfig(request.Config)
	if err != nil {
		return WriteResult{}, err
	}
	request.Config = config
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
	if service == nil || service.store == nil {
		return WriteResult{}, ErrUnavailable
	}
	if request.TargetScopeID == uuid.Nil || request.ID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.WriteMetadata) {
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
	if service == nil || service.store == nil {
		return WriteResult{}, ErrUnavailable
	}
	if request.TargetScopeID == uuid.Nil || request.ID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.WriteMetadata) {
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
	if service == nil || service.store == nil {
		return Policy{}, ErrUnavailable
	}
	if targetScopeID == uuid.Nil || id == uuid.Nil {
		return Policy{}, ErrInvalidInput
	}
	return service.store.Get(ctx, actor, targetScopeID, id)
}

func (service *Service) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	if service == nil || service.store == nil {
		return ListResult{}, ErrUnavailable
	}
	if filter.TargetScopeID == uuid.Nil || filter.Limit < 1 || filter.Limit > 100 || len(filter.Cursor) > maxCursorBytes {
		return ListResult{}, ErrInvalidInput
	}
	return service.store.List(ctx, actor, filter)
}

func (service *Service) PublicationPreview(ctx context.Context, actor Actor, targetScopeID uuid.UUID) (PublicationPreview, error) {
	if service == nil || service.store == nil {
		return PublicationPreview{}, ErrUnavailable
	}
	if targetScopeID == uuid.Nil {
		return PublicationPreview{}, ErrInvalidInput
	}
	return service.store.PublicationPreview(ctx, actor, targetScopeID)
}
