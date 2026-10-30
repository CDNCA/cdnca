package analytics

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

const ReadPermission = "sites.read"

var (
	ErrInvalidServiceConfig = errors.New("invalid analytics service configuration")
	ErrPermissionDenied     = errors.New("analytics permission denied")
	ErrScopeForbidden       = errors.New("analytics scope forbidden")
)

type Actor struct {
	ScopeKind   string
	TenantID    string
	Permissions []string
}

type Audience uint8

const (
	AudienceInvalid Audience = iota
	AudiencePlatform
	AudienceTenant
)

type QueryRequest struct {
	Audience   Audience
	TenantID   string
	From       time.Time
	To         time.Time
	SiteID     string
	Domain     string
	NodeID     string
	ListenPort uint16
	Timezone   string
	SnapshotAt time.Time
}

type QueryStore interface {
	Summary(context.Context, Scope, Filter) (Summary, error)
	Trend(context.Context, Scope, Filter) ([]TrendPoint, error)
	Rank(context.Context, Scope, Filter, RankDimension, uint16, string) (RankPage, error)
}

type blockedIPCountStore interface {
	BlockedIPCount(context.Context, Scope, Filter) (uint64, error)
}

type peakBandwidthStore interface {
	PeakBandwidth(context.Context, Scope, Filter) (PeakBandwidth, error)
}

type blockedIPTrendStore interface {
	BlockedIPTrend(context.Context, Scope, Filter) ([]BlockedIPTrendPoint, error)
}

type wafOverviewStore interface {
	WAFOverview(context.Context, Scope, Filter) (WAFOverview, error)
}

type Service struct {
	store                  QueryStore
	ruleNames              RuleNameLookup
	realtimeExpectedCounts RealtimeExpectedCountReader
	retention              RetentionReader
	httpsPorts             SiteHTTPSPortReader
	now                    func() time.Time
}

// SiteHTTPSPortReader reads the HTTPS listen ports of sites (sites.https_ports),
// so the URL ranking can tell https from http: the access facts have no
// scheme (protocol is the HTTP version).
type SiteHTTPSPortReader interface {
	SiteHTTPSPorts(ctx context.Context, siteIDs []string) (map[string][]uint16, error)
}

func (service *Service) SetSiteHTTPSPortReader(reader SiteHTTPSPortReader) {
	service.httpsPorts = reader
}

// fillRankSchemes sets the scheme of URL rows from their site's HTTPS ports;
// rows of unknown port or a failed lookup keep it empty (the page then shows
// host[:port]/path). SiteID is cleared: it is internal to this lookup.
func (service *Service) fillRankSchemes(ctx context.Context, items []RankItem) {
	sites := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if _, ok := seen[item.SiteID]; item.SiteID != "" && item.Port != 0 && !ok {
			seen[item.SiteID] = struct{}{}
			sites = append(sites, item.SiteID)
		}
	}
	var ports map[string][]uint16
	if service.httpsPorts != nil && len(sites) > 0 {
		var err error
		if ports, err = service.httpsPorts.SiteHTTPSPorts(ctx, sites); err != nil {
			ports = nil
		}
	}
	for index := range items {
		item := &items[index]
		if siteHTTPSPorts, ok := ports[item.SiteID]; ok && item.Port != 0 {
			item.Scheme = "http"
			for _, port := range siteHTTPSPorts {
				if port == item.Port {
					item.Scheme = "https"
				}
			}
		}
		item.SiteID = ""
	}
}

// Retention is how many days ClickHouse keeps the raw access log
// (access_logs_days) and the hourly history facts (bandwidth_history_days);
// 0 means kept forever (no TTL).
type Retention struct {
	AccessLogDays, HistoryDays int
}

// RetentionReader reads the cleanup settings the ClickHouse TTLs follow.
type RetentionReader interface {
	AnalyticsRetention(context.Context) (Retention, error)
}

// SetRetentionReader lets Rank report the first instant the dimension's
// source still holds (RankPage.RetainedFrom), so pages can say that an older
// part of the range is gone instead of showing a silently short ranking.
// RuleNameLookup names the WAF overview's attack types (analyticslog
// PostgresEventNameLookup: the tenant's policy rule names, CRS rule names).
type RuleNameLookup interface {
	Lookup(ctx context.Context, tenantID string, refs []analyticslog.EventNameRef) analyticslog.EventNames
}

func (service *Service) SetRuleNameLookup(lookup RuleNameLookup) { service.ruleNames = lookup }

// nameAttackTypes fills the names of the attack types; a lookup failure
// leaves them unnamed (the key is still shown). Rows stay one per rule ID
// (the drill-down filters by it); rows sharing a name get the first 8
// characters of their rule ID appended so they can be told apart
// (fix-wafname).
func (service *Service) nameAttackTypes(ctx context.Context, scope Scope, items []WAFRankItem) {
	if service.ruleNames == nil || len(items) == 0 {
		return
	}
	refs := make([]analyticslog.EventNameRef, len(items))
	for index, item := range items {
		refs[index] = analyticslog.EventNameRef{RuleID: item.Key}
	}
	names := service.ruleNames.Lookup(ctx, scope.tenantID, refs)
	seen := make(map[string]int, len(items))
	for index := range items {
		items[index].Name = names.RuleName("", items[index].Key)
		if items[index].Name != "" {
			seen[items[index].Name]++
		}
	}
	for index := range items {
		if name, key := items[index].Name, items[index].Key; seen[name] > 1 && len(key) >= 8 {
			items[index].Name = name + "（" + key[:8] + "）"
		}
	}
}

func (service *Service) SetRetentionReader(reader RetentionReader) {
	service.retention = reader
}

func NewService(store QueryStore) (*Service, error) {
	if store == nil {
		return nil, ErrInvalidServiceConfig
	}
	return &Service{store: store}, nil
}

func NewServiceWithRealtimeExpectedCounts(store QueryStore, reader RealtimeExpectedCountReader) (*Service, error) {
	if store == nil || reader == nil {
		return nil, ErrInvalidServiceConfig
	}
	return &Service{store: store, realtimeExpectedCounts: reader}, nil
}

func (service *Service) Summary(ctx context.Context, actor Actor, request QueryRequest) (Summary, error) {
	scope, filter, err := authorizeQueryWithValidation(actor, request, validateSummaryScopeFilter)
	if err != nil {
		return Summary{}, err
	}
	if err := ctx.Err(); err != nil {
		return Summary{}, err
	}
	summary, err := service.store.Summary(ctx, scope, filter)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Summary{}, ctxErr
	}
	return summary, err
}

func (service *Service) BlockedIPCount(ctx context.Context, actor Actor, request QueryRequest) (uint64, error) {
	scope, filter, err := authorizeQuery(actor, request)
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	store, ok := service.store.(blockedIPCountStore)
	if !ok {
		return 0, ErrTransport
	}
	count, err := store.BlockedIPCount(ctx, scope, filter)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, ctxErr
	}
	return count, err
}

func (service *Service) PeakBandwidth(ctx context.Context, actor Actor, request QueryRequest) (PeakBandwidth, error) {
	scope, filter, err := authorizeQuery(actor, request)
	if err != nil {
		return PeakBandwidth{}, err
	}
	if err := ctx.Err(); err != nil {
		return PeakBandwidth{}, err
	}
	store, ok := service.store.(peakBandwidthStore)
	if !ok {
		return PeakBandwidth{}, ErrTransport
	}
	peak, err := store.PeakBandwidth(ctx, scope, filter)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return PeakBandwidth{}, ctxErr
	}
	return peak, err
}

func (service *Service) BlockedIPTrend(ctx context.Context, actor Actor, request QueryRequest) ([]BlockedIPTrendPoint, error) {
	scope, filter, err := authorizeQuery(actor, request)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store, ok := service.store.(blockedIPTrendStore)
	if !ok {
		return nil, ErrTransport
	}
	trend, err := store.BlockedIPTrend(ctx, scope, filter)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return trend, err
}

func (service *Service) WAFOverview(ctx context.Context, actor Actor, request QueryRequest) (WAFOverview, error) {
	scope, filter, err := authorizeQueryWithValidation(actor, request, validateWAFScopeFilter)
	if err != nil {
		return WAFOverview{}, err
	}
	if err := ctx.Err(); err != nil {
		return WAFOverview{}, err
	}
	store, ok := service.store.(wafOverviewStore)
	if !ok {
		return WAFOverview{}, ErrTransport
	}
	overview, err := store.WAFOverview(ctx, scope, filter)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return WAFOverview{}, ctxErr
	}
	if err == nil {
		service.nameAttackTypes(ctx, scope, overview.AttackTypes)
	}
	return overview, err
}

func (service *Service) Trend(ctx context.Context, actor Actor, request QueryRequest) ([]TrendPoint, error) {
	scope, filter, err := authorizeQuery(actor, request)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	trend, err := service.store.Trend(ctx, scope, filter)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return trend, err
}

func (service *Service) Rank(
	ctx context.Context,
	actor Actor,
	request QueryRequest,
	dimension RankDimension,
	limit uint16,
	cursor string,
) (RankPage, error) {
	scope, filter, err := authorizeRankQuery(actor, request)
	if err != nil {
		return RankPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return RankPage{}, err
	}
	page, err := service.store.Rank(ctx, scope, filter, dimension, limit, cursor)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return RankPage{}, ctxErr
	}
	if err == nil {
		page.RetainedFrom = service.retainedFrom(ctx, dimension, filter.From)
		service.fillRankSchemes(ctx, page.Items)
	}
	return page, err
}

// retainedFrom: the later of from and the oldest instant the dimension's
// source keeps (zero when unknown or kept forever).
func (service *Service) retainedFrom(ctx context.Context, dimension RankDimension, from time.Time) time.Time {
	if service.retention == nil {
		return time.Time{}
	}
	retention, err := service.retention.AnalyticsRetention(ctx)
	if err != nil {
		return time.Time{}
	}
	days := retention.AccessLogDays
	if HistoryRankable(dimension) {
		days = retention.HistoryDays
	}
	if days <= 0 {
		return time.Time{}
	}
	now := time.Now
	if service.now != nil {
		now = service.now
	}
	oldest := now().UTC().Truncate(time.Minute).Add(-time.Duration(days) * 24 * time.Hour)
	if oldest.After(from) {
		return oldest
	}
	return time.Time{}
}

func authorizeQuery(actor Actor, request QueryRequest) (Scope, Filter, error) {
	return authorizeQueryWithValidation(actor, request, validateScopeFilter)
}

func authorizeRankQuery(actor Actor, request QueryRequest) (Scope, Filter, error) {
	return authorizeQueryWithValidation(actor, request, validateRankScopeFilter)
}

func authorizeQueryWithValidation(actor Actor, request QueryRequest, validate func(Scope, Filter) error) (Scope, Filter, error) {
	platformAdmin := actor.ScopeKind == "platform" && slices.Contains(actor.Permissions, "platform.admin")
	if !slices.Contains(actor.Permissions, ReadPermission) && !platformAdmin {
		return Scope{}, Filter{}, ErrPermissionDenied
	}

	var scope Scope
	var err error
	switch request.Audience {
	case AudiencePlatform:
		if actor.ScopeKind != "platform" {
			return Scope{}, Filter{}, ErrScopeForbidden
		}
		if request.TenantID == "" {
			scope = AdminScope()
		} else {
			scope, err = TenantScope(request.TenantID)
		}
	case AudienceTenant:
		if actor.ScopeKind != "tenant" || request.TenantID != "" {
			return Scope{}, Filter{}, ErrScopeForbidden
		}
		scope, err = TenantScope(actor.TenantID)
	default:
		return Scope{}, Filter{}, ErrInvalidInput
	}
	if err != nil {
		return Scope{}, Filter{}, err
	}

	filter := Filter{
		From:       request.From.UTC(),
		To:         request.To.UTC(),
		SiteID:     request.SiteID,
		Domain:     request.Domain,
		NodeID:     request.NodeID,
		ListenPort: request.ListenPort,
		Timezone:   request.Timezone,
		SnapshotAt: request.SnapshotAt,
	}
	if err := validate(scope, filter); err != nil {
		return Scope{}, Filter{}, err
	}
	return scope, filter, nil
}
