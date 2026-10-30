package analyticsgeo

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

type Service struct {
	source  EventSource
	catalog *Catalog
}

func NewService(source EventSource, catalog *Catalog) (*Service, error) {
	if source == nil || catalog == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Service{source: source, catalog: catalog}, nil
}

func (service *Service) Lookup(ctx context.Context, actor Actor, request QueryRequest) (Item, error) {
	if service == nil || service.source == nil || service.catalog == nil {
		return Item{}, ErrInvalidConfiguration
	}
	request.From, request.To = request.From.UTC(), request.To.UTC()
	address, err := validateQuery(actor, request)
	if err != nil {
		return Item{}, err
	}
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}
	page, err := service.source.ReadEvents(ctx, actor, request)
	if contextErr := ctx.Err(); contextErr != nil {
		return Item{}, contextErr
	}
	if err != nil {
		return Item{}, err
	}
	if page.NextCursor != "" || len(page.Items) > 1 {
		return Item{}, ErrCapacityExceeded
	}
	if len(page.Items) == 0 {
		return Item{}, ErrNotFound
	}
	source := page.Items[0]
	if source.EventID != request.EventID || !source.OccurredAt.Equal(request.From) || source.OccurredAt.Location() != time.UTC ||
		source.SiteID != request.SiteID || source.NodeID != request.NodeID || source.ClientIP != request.ClientIP ||
		!validCodeOrUnknown(source.CountryCode, 8) || !validStoredText(source.Carrier, 128) {
		return Item{}, ErrInvalidResponse
	}
	attribution, provenance, err := service.catalog.Resolve(request.DatabaseVersion, address)
	if err != nil {
		return Item{}, err
	}
	reconciliation := ReconciliationUnverified
	if attribution.Resolution == ResolutionMatched {
		if source.CountryCode == attribution.CountryCode && source.Carrier == attribution.Carrier {
			reconciliation = ReconciliationMatch
		} else if source.CountryCode != "" || source.Carrier != "" {
			reconciliation = ReconciliationMismatch
		}
	}
	return Item{
		EventID: source.EventID, OccurredAt: source.OccurredAt, SiteID: source.SiteID, NodeID: source.NodeID,
		SourceCountryCode: source.CountryCode, SourceCarrier: source.Carrier,
		CountryCode: attribution.CountryCode, Region: attribution.Region, City: attribution.City,
		Carrier: attribution.Carrier, ASN: attribution.ASN, AddressFamily: attribution.AddressFamily,
		LookupReason: attribution.LookupReason,
		Resolution:   attribution.Resolution, Reconciliation: reconciliation, PrefixLength: attribution.PrefixLength,
		Provenance: provenance,
	}, nil
}

func validateQuery(actor Actor, request QueryRequest) (netip.Addr, error) {
	platformAdmin := actor.ScopeKind == "platform" && slices.Contains(actor.Permissions, "platform.admin")
	if !slices.Contains(actor.Permissions, analyticslog.ReadPermission) && !platformAdmin {
		return netip.Addr{}, ErrPermissionDenied
	}
	switch request.Audience {
	case AudiencePlatform:
		if actor.ScopeKind != "platform" {
			return netip.Addr{}, ErrScopeForbidden
		}
		if !validUUID(request.TenantID) {
			return netip.Addr{}, ErrInvalidInput
		}
	case AudienceTenant:
		if actor.ScopeKind != "tenant" || request.TenantID != "" || !validUUID(actor.TenantID) {
			return netip.Addr{}, ErrScopeForbidden
		}
	default:
		return netip.Addr{}, ErrInvalidInput
	}
	address, ok := parseCanonicalAddress(request.ClientIP)
	if !ok || request.Kind != KindAccess && request.Kind != KindBlock || !validEventID(request.EventID) ||
		!validUUID(request.SiteID) || !validUUID(request.NodeID) || request.From.IsZero() || request.To.IsZero() ||
		request.From.Location() != time.UTC || request.To.Location() != time.UTC ||
		request.To.Sub(request.From) != time.Millisecond || request.From.Nanosecond()%int(time.Millisecond) != 0 ||
		request.To.Nanosecond()%int(time.Millisecond) != 0 || request.DatabaseVersion != "" && !validVersion(request.DatabaseVersion) {
		return netip.Addr{}, ErrInvalidInput
	}
	return address, nil
}

func validCodeOrUnknown(value string, limit int) bool { return value == "" || validCode(value, limit) }
func validStoredText(value string, limit int) bool    { return value == "" || validIdentity(value, limit) }

type AnalyticsLogReader interface {
	ListAccess(context.Context, analyticslog.Actor, analyticslog.QueryRequest) (analyticslog.AccessPage, error)
	ListBlockEvents(context.Context, analyticslog.Actor, analyticslog.QueryRequest) (analyticslog.BlockEventPage, error)
}

type AnalyticsLogAdapter struct{ reader AnalyticsLogReader }

func NewAnalyticsLogAdapter(reader AnalyticsLogReader) (*AnalyticsLogAdapter, error) {
	if reader == nil {
		return nil, ErrInvalidConfiguration
	}
	return &AnalyticsLogAdapter{reader: reader}, nil
}

func (adapter *AnalyticsLogAdapter) ReadEvents(ctx context.Context, actor Actor, request QueryRequest) (SourcePage, error) {
	query := analyticslog.QueryRequest{Audience: request.Audience, TenantID: request.TenantID, Limit: 2, Filter: analyticslog.Filter{
		From: request.From, To: request.To, SiteID: request.SiteID, NodeID: request.NodeID, ClientIP: request.ClientIP,
	}}
	if request.Kind == KindAccess {
		page, err := adapter.reader.ListAccess(ctx, actor, query)
		if err != nil {
			return SourcePage{}, mapSourceError(err)
		}
		result := SourcePage{NextCursor: page.NextCursor, Items: make([]SourceEvent, 0, len(page.Items))}
		for _, item := range page.Items {
			result.Items = append(result.Items, SourceEvent{EventID: item.EventID, OccurredAt: item.OccurredAt,
				SiteID: item.SiteID, NodeID: item.NodeID, ClientIP: item.ClientIP, CountryCode: item.CountryCode, Carrier: item.Carrier})
		}
		return result, nil
	}
	page, err := adapter.reader.ListBlockEvents(ctx, actor, query)
	if err != nil {
		return SourcePage{}, mapSourceError(err)
	}
	result := SourcePage{NextCursor: page.NextCursor, Items: make([]SourceEvent, 0, len(page.Items))}
	for _, item := range page.Items {
		result.Items = append(result.Items, SourceEvent{EventID: item.EventID, OccurredAt: item.OccurredAt,
			SiteID: item.SiteID, NodeID: item.NodeID, ClientIP: item.ClientIP, CountryCode: item.CountryCode, Carrier: item.Carrier})
	}
	return result, nil
}

func mapSourceError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, analyticslog.ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, analyticslog.ErrPermissionDenied):
		return ErrPermissionDenied
	case errors.Is(err, analyticslog.ErrScopeForbidden):
		return ErrScopeForbidden
	case errors.Is(err, analyticslog.ErrInvalidResponse):
		return ErrInvalidResponse
	default:
		return ErrEvidenceUnavailable
	}
}
