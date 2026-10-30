package analyticsdiagnostic

import (
	"context"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/google/uuid"
)

type Service struct {
	source AccessSource
}

func NewService(source AccessSource) (*Service, error) {
	if source == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Service{source: source}, nil
}

func (service *Service) List(ctx context.Context, actor Actor, request QueryRequest) (Page, error) {
	if service == nil || service.source == nil {
		return Page{}, ErrInvalidConfiguration
	}
	request.From, request.To = request.From.UTC(), request.To.UTC()
	if err := validateQuery(actor, request); err != nil {
		return Page{}, err
	}
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}
	sourcePage, err := service.source.ReadAccess(ctx, actor, request)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Page{}, ctxErr
	}
	if err != nil {
		return Page{}, err
	}
	if len(sourcePage.Items) > int(request.Limit) || sourcePage.NextCursor != "" && sourcePage.SnapshotAt.IsZero() {
		return Page{}, ErrInvalidResponse
	}
	page := Page{Items: make([]Item, 0, len(sourcePage.Items)), NextCursor: sourcePage.NextCursor}
	if !sourcePage.SnapshotAt.IsZero() {
		snapshot := sourcePage.SnapshotAt.UTC()
		page.SnapshotAt = &snapshot
	}
	seen := make(map[string]struct{}, len(sourcePage.Items))
	for index, source := range sourcePage.Items {
		if err := validateSourceItem(source, request); err != nil {
			return Page{}, err
		}
		if _, duplicate := seen[source.EventID]; duplicate {
			return Page{}, ErrInvalidResponse
		}
		seen[source.EventID] = struct{}{}
		if index > 0 && !sourceRowsOrdered(sourcePage.Items[index-1], source) {
			return Page{}, ErrInvalidResponse
		}
		category, reason, diagnostic := classify(source)
		if !diagnostic {
			continue
		}
		page.Items = append(page.Items, Item{
			EventID: source.EventID, OccurredAt: source.OccurredAt.UTC(), SiteID: source.SiteID, NodeID: source.NodeID,
			RequestID: source.RequestID, TraceID: source.TraceID, ConfigVersionID: source.ConfigVersion,
			Host: source.Host, URIPath: source.URIPath, StatusCode: source.StatusCode, Category: category, ReasonCode: reason,
		})
	}
	return page, nil
}

func validateQuery(actor Actor, request QueryRequest) error {
	platformAdmin := actor.ScopeKind == "platform" && slices.Contains(actor.Permissions, "platform.admin")
	if !slices.Contains(actor.Permissions, analyticslog.ReadPermission) && !platformAdmin {
		return ErrPermissionDenied
	}
	switch request.Audience {
	case AudiencePlatform:
		if actor.ScopeKind != "platform" {
			return ErrScopeForbidden
		}
		if !validUUID(request.TenantID) {
			return ErrInvalidInput
		}
	case AudienceTenant:
		if actor.ScopeKind != "tenant" || request.TenantID != "" || !validUUID(actor.TenantID) {
			return ErrScopeForbidden
		}
	default:
		return ErrInvalidInput
	}
	if request.From.IsZero() || request.To.IsZero() || !request.From.Before(request.To) ||
		request.To.Sub(request.From) > 31*24*time.Hour || request.From.Nanosecond()%int(time.Millisecond) != 0 ||
		request.To.Nanosecond()%int(time.Millisecond) != 0 || request.Limit == 0 || request.Limit > MaxLimit ||
		len(request.Cursor) > 2048 || request.SiteID != "" && !validUUID(request.SiteID) ||
		request.NodeID != "" && !validUUID(request.NodeID) {
		return ErrInvalidInput
	}
	return nil
}

func validateSourceItem(item analyticslog.AccessLog, request QueryRequest) error {
	if !validEventID(item.EventID) || item.OccurredAt.Location() != time.UTC || item.OccurredAt.Before(request.From) ||
		!item.OccurredAt.Before(request.To) || !validUUID(item.SiteID) || !validUUID(item.NodeID) ||
		!validIdentity(item.RequestID) || !validIdentity(item.TraceID) || !validIdentity(item.ConfigVersion) ||
		request.SiteID != "" && item.SiteID != request.SiteID || request.NodeID != "" && item.NodeID != request.NodeID ||
		len(item.Host) > 253 || strings.TrimSpace(item.Host) != item.Host || !validPath(item.URIPath) {
		return ErrInvalidResponse
	}
	return nil
}

func classify(item analyticslog.AccessLog) (Category, ReasonCode, bool) {
	switch {
	case item.UpstreamResult == "no_host":
		return CategoryNoHost, ReasonUpstreamNoHost, true
	case item.Host == "":
		return CategoryNoHost, ReasonHostMissing, true
	case item.UpstreamResult == "config_mismatch":
		return CategoryConfigMismatch, ReasonUpstreamConfigMismatch, true
	case item.StatusCode == 530:
		return CategoryConfigMismatch, ReasonStatus530, true
	case item.StatusCode >= 500 && item.StatusCode <= 599 && item.UpstreamResult != "":
		return CategoryUpstream5xx, ReasonStatus5xxWithUpstream, true
	case item.StatusCode >= 500 && item.StatusCode <= 599:
		return CategoryUnknown, ReasonStatus5xxUnclassified, true
	default:
		return "", "", false
	}
}

func sourceRowsOrdered(previous, current analyticslog.AccessLog) bool {
	return previous.OccurredAt.After(current.OccurredAt) ||
		previous.OccurredAt.Equal(current.OccurredAt) && previous.EventID > current.EventID
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validIdentity(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validEventID(value string) bool {
	if !validIdentity(value) {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character)) {
			return false
		}
	}
	return true
}

func validPath(value string) bool {
	return value == "" || len(value) <= 4096 && strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "?#\r\n\x00")
}
