package analyticslog

import (
	"context"
	"slices"
	"strings"
	"time"
)

type Store interface {
	ListAccess(context.Context, scope, Filter, uint16, string) (AccessPage, error)
	ListBlockEvents(context.Context, scope, Filter, uint16, string) (BlockEventPage, error)
}

type Service struct {
	store   Store
	exports *ExportManager
}

func NewServiceWithExports(store Store, exports *ExportManager) (*Service, error) {
	if exports == nil {
		return nil, ErrInvalidConfiguration
	}
	service, err := NewService(store)
	if err != nil {
		return nil, err
	}
	service.exports = exports
	return service, nil
}

func NewService(store Store) (*Service, error) {
	if store == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Service{store: store}, nil
}

func (service *Service) ListAccess(ctx context.Context, actor Actor, request QueryRequest) (AccessPage, error) {
	scope, filter, err := authorizeQuery(actor, request)
	if err != nil {
		return AccessPage{}, err
	}
	if filter.HasStatus && filter.StatusCode == 0 {
		return AccessPage{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return AccessPage{}, err
	}
	page, err := service.store.ListAccess(ctx, scope, filter, request.Limit, request.Cursor)
	if contextErr := ctx.Err(); contextErr != nil {
		return AccessPage{}, contextErr
	}
	if err == nil {
		if err := validateAccessPage(page, request.Limit); err != nil {
			return AccessPage{}, err
		}
	}
	return page, err
}

func (service *Service) ListBlockEvents(ctx context.Context, actor Actor, request QueryRequest) (BlockEventPage, error) {
	scope, filter, err := authorizeQuery(actor, request)
	if err != nil {
		return BlockEventPage{}, err
	}
	if filter.Method != "" || filter.Protocol != "" || filter.CacheStatus != "" || filter.UpstreamResult != "" ||
		filter.ContentType != "" || filter.UserAgent != "" || filter.RequestBytesMin != nil || filter.RequestBytesMax != nil ||
		filter.ResponseBytesMin != nil || filter.ResponseBytesMax != nil {
		return BlockEventPage{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return BlockEventPage{}, err
	}
	page, err := service.store.ListBlockEvents(ctx, scope, filter, request.Limit, request.Cursor)
	if contextErr := ctx.Err(); contextErr != nil {
		return BlockEventPage{}, contextErr
	}
	if err == nil {
		if err := validateBlockEventPage(page, request.Limit); err != nil {
			return BlockEventPage{}, err
		}
	}
	return page, err
}

type ccBanStore interface {
	ListCCBans(context.Context, scope, Filter, uint16) (CCBanPage, error)
}

// ListCCBans lists IPs auto-banned by CC rules (NF34). Only the window, site
// and client IP narrow it.
func (service *Service) ListCCBans(ctx context.Context, actor Actor, request QueryRequest) (CCBanPage, error) {
	if request.Cursor != "" {
		return CCBanPage{}, ErrInvalidInput
	}
	scope, filter, err := authorizeQuery(actor, request)
	if err != nil {
		return CCBanPage{}, err
	}
	store, ok := service.store.(ccBanStore)
	if !ok {
		return CCBanPage{}, ErrCapabilityUnsupported
	}
	if err := ctx.Err(); err != nil {
		return CCBanPage{}, err
	}
	page, err := store.ListCCBans(ctx, scope, filter, request.Limit)
	if contextErr := ctx.Err(); contextErr != nil {
		return CCBanPage{}, contextErr
	}
	if err == nil && len(page.Items) > int(request.Limit) {
		return CCBanPage{}, ErrInvalidResponse
	}
	return page, err
}

func validateAccessPage(page AccessPage, limit uint16) error {
	if len(page.Items) > int(limit) || page.NextCursor != "" && (len(page.Items) == 0 || page.SnapshotAt.IsZero()) {
		return ErrInvalidResponse
	}
	seen := make(map[string]struct{}, len(page.Items))
	for index, item := range page.Items {
		if !validEventID(item.EventID) || item.OccurredAt.IsZero() || item.OccurredAt.Nanosecond()%int(time.Millisecond) != 0 ||
			!validCanonicalUUID(item.SiteID) || !validCanonicalUUID(item.NodeID) {
			return ErrInvalidResponse
		}
		if _, duplicate := seen[item.EventID]; duplicate {
			return ErrInvalidResponse
		}
		seen[item.EventID] = struct{}{}
		if index > 0 && !rowsOrdered(page.Items[index-1].OccurredAt.UnixMilli(), page.Items[index-1].EventID,
			item.OccurredAt.UnixMilli(), item.EventID) {
			return ErrInvalidResponse
		}
	}
	return nil
}

func validateBlockEventPage(page BlockEventPage, limit uint16) error {
	if len(page.Items) > int(limit) || page.NextCursor != "" && (len(page.Items) == 0 || page.SnapshotAt.IsZero()) {
		return ErrInvalidResponse
	}
	seen := make(map[string]struct{}, len(page.Items))
	for index, item := range page.Items {
		if !validEventID(item.EventID) || item.OccurredAt.IsZero() || item.OccurredAt.Nanosecond()%int(time.Millisecond) != 0 ||
			!validCanonicalUUID(item.SiteID) || !validCanonicalUUID(item.NodeID) {
			return ErrInvalidResponse
		}
		if _, duplicate := seen[item.EventID]; duplicate {
			return ErrInvalidResponse
		}
		seen[item.EventID] = struct{}{}
		if index > 0 && !rowsOrdered(page.Items[index-1].OccurredAt.UnixMilli(), page.Items[index-1].EventID,
			item.OccurredAt.UnixMilli(), item.EventID) {
			return ErrInvalidResponse
		}
	}
	return nil
}

func (service *Service) Unsupported(actor Actor, audience Audience, tenantID string) error {
	if _, err := authorizeScope(actor, audience, tenantID); err != nil {
		return err
	}
	return ErrCapabilityUnsupported
}

func authorizeQuery(actor Actor, request QueryRequest) (scope, Filter, error) {
	queryScope, err := authorizeScope(actor, request.Audience, request.TenantID)
	if err != nil {
		return scope{}, Filter{}, err
	}
	if request.Limit == 0 || request.Limit > MaxLimit {
		return scope{}, Filter{}, ErrInvalidInput
	}
	if request.Cursor != "" && !validOpaqueCursor(request.Cursor) {
		return scope{}, Filter{}, ErrCapabilityUnsupported
	}
	if err := validateFilter(request.Filter); err != nil {
		return scope{}, Filter{}, err
	}
	return queryScope, normalizeFilter(request.Filter), nil
}

func authorizeScope(actor Actor, audience Audience, tenantID string) (scope, error) {
	platformAdmin := actor.ScopeKind == "platform" && slices.Contains(actor.Permissions, "platform.admin")
	if !slices.Contains(actor.Permissions, ReadPermission) && !platformAdmin {
		return scope{}, ErrPermissionDenied
	}
	switch audience {
	case AudiencePlatform:
		if actor.ScopeKind != "platform" {
			return scope{}, ErrScopeForbidden
		}
		if tenantID == "" {
			// Platform operators read every tenant unless they filter one.
			return scope{}, nil
		}
		if !validUUID(strings.ToLower(tenantID)) {
			return scope{}, ErrInvalidInput
		}
		return scope{tenantID: strings.ToLower(tenantID)}, nil
	case AudienceTenant:
		if actor.ScopeKind != "tenant" || tenantID != "" {
			return scope{}, ErrScopeForbidden
		}
		if !validUUID(strings.ToLower(actor.TenantID)) {
			return scope{}, ErrScopeForbidden
		}
		return scope{tenantID: strings.ToLower(actor.TenantID)}, nil
	default:
		return scope{}, ErrInvalidInput
	}
}
