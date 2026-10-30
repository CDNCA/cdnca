package analyticsgeo

import (
	"context"
	"time"
)

type AuthorityItem struct {
	Item      Item
	Revision  uint64
	ExpiresAt time.Time
	State     AuthorityState
	Reason    AuthorityReason
}

type AuthorityReaderAdapter struct {
	source    EventSource
	authority AuthorityReader
}

func NewAuthorityReaderAdapter(source EventSource, authority AuthorityReader) (*AuthorityReaderAdapter, error) {
	if source == nil || authority == nil {
		return nil, ErrInvalidConfiguration
	}
	return &AuthorityReaderAdapter{source: source, authority: authority}, nil
}

func (adapter *AuthorityReaderAdapter) Lookup(ctx context.Context, actor Actor, request QueryRequest) (Item, error) {
	result, err := adapter.LookupWithAuthority(ctx, actor, request)
	return result.Item, err
}

func (adapter *AuthorityReaderAdapter) LookupWithAuthority(ctx context.Context, actor Actor, request QueryRequest) (AuthorityItem, error) {
	if adapter == nil || adapter.source == nil || adapter.authority == nil || ctx == nil {
		return AuthorityItem{}, ErrInvalidConfiguration
	}
	request.From, request.To = request.From.UTC(), request.To.UTC()
	address, err := validateQuery(actor, request)
	if err != nil {
		return AuthorityItem{}, err
	}
	if err := ctx.Err(); err != nil {
		return AuthorityItem{}, err
	}
	page, err := adapter.source.ReadEvents(ctx, actor, request)
	if contextErr := ctx.Err(); contextErr != nil {
		return AuthorityItem{}, contextErr
	}
	if err != nil {
		return AuthorityItem{}, err
	}
	if page.NextCursor != "" || len(page.Items) > 1 {
		return AuthorityItem{}, ErrCapacityExceeded
	}
	if len(page.Items) == 0 {
		return AuthorityItem{}, ErrNotFound
	}
	source := page.Items[0]
	if source.EventID != request.EventID || !source.OccurredAt.Equal(request.From) || source.OccurredAt.Location() != time.UTC ||
		source.SiteID != request.SiteID || source.NodeID != request.NodeID || source.ClientIP != request.ClientIP ||
		!validCodeOrUnknown(source.CountryCode, 8) || !validStoredText(source.Carrier, 128) {
		return AuthorityItem{}, ErrInvalidResponse
	}
	lookup, err := adapter.authority.Lookup(ctx, request.DatabaseVersion, address)
	if err != nil {
		return AuthorityItem{}, err
	}
	reconciliation := ReconciliationUnverified
	if lookup.Attribution.Resolution == ResolutionMatched {
		if source.CountryCode == lookup.Attribution.CountryCode && source.Carrier == lookup.Attribution.Carrier {
			reconciliation = ReconciliationMatch
		} else if source.CountryCode != "" || source.Carrier != "" {
			reconciliation = ReconciliationMismatch
		}
	}
	return AuthorityItem{Item: Item{
		EventID: source.EventID, OccurredAt: source.OccurredAt, SiteID: source.SiteID, NodeID: source.NodeID,
		SourceCountryCode: source.CountryCode, SourceCarrier: source.Carrier,
		CountryCode: lookup.Attribution.CountryCode, Region: lookup.Attribution.Region, City: lookup.Attribution.City,
		Carrier: lookup.Attribution.Carrier, ASN: lookup.Attribution.ASN, AddressFamily: lookup.Attribution.AddressFamily,
		LookupReason: lookup.Attribution.LookupReason, Resolution: lookup.Attribution.Resolution, Reconciliation: reconciliation,
		PrefixLength: lookup.Attribution.PrefixLength, Provenance: lookup.Provenance,
	}, Revision: lookup.Revision, ExpiresAt: lookup.ExpiresAt, State: lookup.State, Reason: lookup.Reason}, nil
}
