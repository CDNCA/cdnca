package dashboard

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var tenantReadPermissions = []string{
	"sites.read",
	"certificates.read",
	"billing.account.read",
	"package_subscriptions.read",
	"traffic_packages.read",
	"announcements.read",
	"jobs.read",
}

type AnalyticsReader interface {
	Summary(context.Context, analytics.Actor, analytics.QueryRequest) (analytics.Summary, error)
	Trend(context.Context, analytics.Actor, analytics.QueryRequest) ([]analytics.TrendPoint, error)
	Rank(context.Context, analytics.Actor, analytics.QueryRequest, analytics.RankDimension, uint16, string) (analytics.RankPage, error)
}

// analyticsHomeMetricsReader is optional: the home peak and blocked-IP count
// are best-effort extras of the overview (FX36).
type analyticsHomeMetricsReader interface {
	PeakBandwidth(context.Context, analytics.Actor, analytics.QueryRequest) (analytics.PeakBandwidth, error)
	BlockedIPCount(context.Context, analytics.Actor, analytics.QueryRequest) (uint64, error)
}

var _ analyticsHomeMetricsReader = (*analytics.Service)(nil)

func (store *Store) withHomeMetrics(
	ctx context.Context,
	actor analytics.Actor,
	request analytics.QueryRequest,
	overview AnalyticsOverview,
) AnalyticsOverview {
	reader, ok := store.analytics.(analyticsHomeMetricsReader)
	if !ok {
		return overview
	}
	if peak, err := reader.PeakBandwidth(ctx, actor, request); err == nil {
		value := strconv.FormatUint(peak.PeakBandwidthBPS, 10)
		overview.PeakBandwidthBPS = &value
	}
	if count, err := reader.BlockedIPCount(ctx, actor, request); err == nil {
		value := strconv.FormatUint(count, 10)
		overview.BlockedIPCount = &value
	}
	return overview
}

type analyticsFinalizationSnapshot struct {
	ExpectedTenants  int64
	AccessTenants    int64
	SecurityTenants  int64
	Rows             int64
	ReadyRows        int64
	FinalizedThrough *time.Time
}

type analyticsFinalizationReader interface {
	Read(context.Context, pgx.Tx, Audience, uuid.UUID) (analyticsFinalizationSnapshot, error)
}

type postgresAnalyticsFinalizationReader struct{}

type Store struct {
	pool              *pgxpool.Pool
	authorizer        *iamlock.Authorizer
	analytics         AnalyticsReader
	finalization      analyticsFinalizationReader
	parallelAnalytics bool
}

func NewStore(pool *pgxpool.Pool, authorizer *iamlock.Authorizer, analyticsReader AnalyticsReader) (*Store, error) {
	if pool == nil || authorizer == nil || !authorizer.Configured() {
		return nil, ErrInvalidConfig
	}
	finalization := analyticsFinalizationReader(postgresAnalyticsFinalizationReader{})
	if override, ok := analyticsReader.(analyticsFinalizationReader); ok {
		finalization = override
	}
	return &Store{
		pool: pool, authorizer: authorizer, analytics: analyticsReader, finalization: finalization,
	}, nil
}

func (store *Store) Admin(ctx context.Context, actor Actor, query Query) (AdminResponse, error) {
	if store == nil || store.pool == nil || store.authorizer == nil {
		return AdminResponse{}, ErrUnavailable
	}
	if !actor.Valid() || actor.ScopeKind != "platform" || actor.TenantID != uuid.Nil {
		return AdminResponse{}, ErrScopeForbidden
	}
	if err := validateFrozenQuery(AudienceAdmin, query); err != nil {
		return AdminResponse{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return AdminResponse{}, storageError(ctx, "begin admin dashboard snapshot", err)
	}
	defer tx.Rollback(context.Background())
	if err := store.authorize(ctx, tx, actor, []string{"platform.admin"}); err != nil {
		return AdminResponse{}, err
	}

	response := AdminResponse{DashboardVersion: Version, Meta: MetaFor(query)}
	accounts, err := readAdminAccounts(ctx, tx)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read admin account facts", err)
	}
	response.Accounts = Available(accounts)
	subscriptions, err := readAdminSubscriptions(ctx, tx, query.AsOf)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read admin subscription facts", err)
	}
	response.Subscriptions = Available(subscriptions)
	billing, err := readSettlements(ctx, tx, query)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read admin settlement facts", err)
	}
	response.Billing = Available(billing)
	resources, err := readAdminResources(ctx, tx, query.AsOf)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read admin resource facts", err)
	}
	response.Resources = Available(resources)
	operations, err := readOperations(ctx, tx, nil, nil, query)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read admin operation facts", err)
	}
	response.Operations = Available(operations)
	operationCharts, err := readOperationCharts(ctx, tx, query)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read admin operation chart facts", err)
	}
	response.OperationCharts = Available(operationCharts)
	profile, err := readAdminProfile(ctx, tx, actor.ScopeID, actor.UserID, query.AsOf)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read admin profile facts", err)
	}
	response.Profile = Available(profile)
	entitlement, err := readEntitlement(ctx, tx)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read entitlement facts", err)
	}
	response.Entitlement = Available(entitlement)
	nodeHealth, err := readNodeHealth(ctx, tx, query.AsOf)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read node health facts", err)
	}
	response.NodeHealth = Available(nodeHealth)
	analyticsHealth, err := readAnalyticsHealth(ctx, tx)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read analytics health facts", err)
	}
	response.AnalyticsHealth = Available(analyticsHealth)
	accountSecurity, err := readAccountSecurity(ctx, tx, nil, nil, query.AsOf)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read admin account security facts", err)
	}
	response.AccountSecurity = Available(accountSecurity)
	network, err := readNetwork(ctx, tx, nil, query.AsOf)
	if err != nil {
		return AdminResponse{}, storageError(ctx, "read admin network facts", err)
	}
	response.Network = Available(network)
	response.Analytics, err = store.readAnalytics(ctx, tx, actor, AudienceAdmin, query)
	if err != nil {
		return AdminResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AdminResponse{}, storageError(ctx, "commit admin dashboard snapshot", err)
	}
	return response, nil
}

func (store *Store) Tenant(ctx context.Context, actor Actor, query Query) (TenantResponse, error) {
	if store == nil || store.pool == nil || store.authorizer == nil {
		return TenantResponse{}, ErrUnavailable
	}
	if !actor.Valid() || actor.ScopeKind != "tenant" || actor.TenantID == uuid.Nil {
		return TenantResponse{}, ErrScopeForbidden
	}
	if err := validateFrozenQuery(AudienceTenant, query); err != nil {
		return TenantResponse{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return TenantResponse{}, storageError(ctx, "begin tenant dashboard snapshot", err)
	}
	defer tx.Rollback(context.Background())
	if err := store.authorize(ctx, tx, actor, tenantReadPermissions); err != nil {
		return TenantResponse{}, err
	}

	hasNodeRead := true
	if err := store.authorize(ctx, tx, actor, []string{"nodes.read"}); err != nil {
		if !errors.Is(err, ErrPermissionDenied) {
			return TenantResponse{}, err
		}
		hasNodeRead = false
	}

	response := TenantResponse{DashboardVersion: Version, Meta: MetaFor(query)}
	identityVerification, err := readTenantIdentityVerification(ctx, tx, actor.ScopeID, actor.UserID)
	if err != nil {
		return TenantResponse{}, storageError(ctx, "read tenant identity verification facts", err)
	}
	response.IdentityVerification = Available(identityVerification)
	profile, err := readAdminProfile(ctx, tx, actor.ScopeID, actor.UserID, query.AsOf)
	if err != nil {
		return TenantResponse{}, storageError(ctx, "read tenant profile facts", err)
	}
	response.Profile = Available(profile)
	// 网站/域名/四层转发计数只读本租户自己的资源，已由 sites.read 等基础权限覆盖；
	// 租户系统角色按 042/079/094 迁移永远不能持有 nodes.read，若这里也要求它，
	// 用户首页的「域名」「转发」会永久显示占位符。节点网络区块仍由 nodes.read 控制。
	resources, err := readTenantResources(ctx, tx, actor.ScopeID)
	if err != nil {
		return TenantResponse{}, storageError(ctx, "read tenant resource facts", err)
	}
	response.Resources = Available(resources)
	certificates, err := readCertificateStats(ctx, tx, &actor.ScopeID, query.AsOf)
	if err != nil {
		return TenantResponse{}, storageError(ctx, "read tenant certificate facts", err)
	}
	response.Certificates = Available(certificates)
	balance, balanceFound, err := readBalance(ctx, tx, actor.ScopeID)
	if err != nil {
		return TenantResponse{}, storageError(ctx, "read tenant balance facts", err)
	}
	if !balanceFound {
		// 从未充值的租户没有 billing_accounts 行：余额就是 ¥0.00（与余额页 balance_minor ?? 0 一致）。
		balance = BalanceStats{Currency: "CNY"}
	}
	response.Billing = Available(balance)
	subscriptions, err := readTenantSubscriptions(ctx, tx, actor.ScopeID, query.AsOf)
	if err != nil {
		return TenantResponse{}, storageError(ctx, "read tenant subscription facts", err)
	}
	response.Subscriptions = Available(subscriptions)
	traffic, err := readTrafficPackages(ctx, tx, actor.ScopeID, query.AsOf)
	if err != nil {
		return TenantResponse{}, storageError(ctx, "read tenant traffic package facts", err)
	}
	response.TrafficPackages = Available(traffic)
	operations, err := readOperations(ctx, tx, &actor.ScopeID, &actor.TenantID, query)
	if err != nil {
		return TenantResponse{}, storageError(ctx, "read tenant operation facts", err)
	}
	response.Operations = Available(operations)
	notices, err := readNotices(ctx, tx, actor.ScopeID, actor.UserID)
	if err != nil {
		return TenantResponse{}, storageError(ctx, "read tenant notice facts", err)
	}
	response.Notices = Available(notices)
	accountSecurity, err := readAccountSecurity(ctx, tx, &actor.ScopeID, &actor.UserID, query.AsOf)
	if err != nil {
		return TenantResponse{}, storageError(ctx, "read tenant account security facts", err)
	}
	response.AccountSecurity = Available(accountSecurity)
	if hasNodeRead {
		network, err := readNetwork(ctx, tx, &actor.ScopeID, query.AsOf)
		if err != nil {
			return TenantResponse{}, storageError(ctx, "read tenant network facts", err)
		}
		response.Network = Available(network)
	} else {
		response.Network = Unavailable[NetworkStats](ReasonAuthoritativeFactMissing)
	}
	response.Analytics, err = store.readAnalytics(ctx, tx, actor, AudienceTenant, query)
	if err != nil {
		return TenantResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TenantResponse{}, storageError(ctx, "commit tenant dashboard snapshot", err)
	}
	return response, nil
}

func (store *Store) authorize(ctx context.Context, tx pgx.Tx, actor Actor, permissions []string) error {
	for _, permission := range permissions {
		sealed, err := store.authorizer.AuthorizeSession(ctx, tx, actor.RawSession, actor.ScopeID, permission)
		if err != nil {
			if errors.Is(err, iamlock.ErrPermissionDenied) {
				return ErrPermissionDenied
			}
			return storageError(ctx, "authorize dashboard session", err)
		}
		tenantID, hasTenant := sealed.TenantID()
		if !sealed.Valid() || sealed.UserID() != actor.UserID ||
			sealed.AuthenticationScopeID() != actor.ScopeID || sealed.TargetScopeID() != actor.ScopeID ||
			sealed.CredentialID() != actor.SessionID || sealed.CredentialKind() != "session" ||
			(actor.ScopeKind == "tenant" && (!hasTenant || tenantID != actor.TenantID)) ||
			(actor.ScopeKind == "platform" && hasTenant) {
			return ErrPermissionDenied
		}
	}
	return nil
}

func (store *Store) readAnalytics(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	audience Audience,
	query Query,
) (Section[AnalyticsOverview], error) {
	if store.analytics == nil {
		return Unavailable[AnalyticsOverview](ReasonDependencyUnavailable), nil
	}
	finalizationReader := store.finalization
	if finalizationReader == nil {
		finalizationReader = postgresAnalyticsFinalizationReader{}
	}
	// 概览与数据分析页同源直查 ClickHouse（查询已按快照截断）。
	// 107 水位只用来提示「最近 N 分钟数据仍在结算」，缺失或落后都不再拦截展示。
	finalization, err := finalizationReader.Read(ctx, tx, audience, actor.TenantID)
	if err != nil {
		return analyticsReadFailure(ctx, err)
	}
	settling := finalization.settlingMinutes(query)
	analyticsActor := analytics.Actor{ScopeKind: actor.ScopeKind}
	request := analytics.QueryRequest{
		From: query.From, To: query.To, SiteID: query.SiteID, NodeID: query.NodeID,
		Timezone: query.Timezone, SnapshotAt: query.AsOf.UTC().Truncate(time.Millisecond),
	}
	if audience == AudienceAdmin {
		analyticsActor.Permissions = []string{"platform.admin"}
		request.Audience = analytics.AudiencePlatform
	} else {
		analyticsActor.TenantID = actor.TenantID.String()
		analyticsActor.Permissions = []string{analytics.ReadPermission}
		request.Audience = analytics.AudienceTenant
	}
	rankDimensions := []analytics.RankDimension{
		analytics.RankByDomain, analytics.RankByURL, analytics.RankByIP, analytics.RankByRegion, analytics.RankByCarrier,
	}
	if store.parallelAnalytics {
		return store.readAnalyticsParallel(ctx, analyticsActor, request, settling)
	}
	summary, err := store.analytics.Summary(ctx, analyticsActor, request)
	if err != nil {
		return analyticsReadFailure(ctx, err)
	}
	trend, err := store.analytics.Trend(ctx, analyticsActor, request)
	if err != nil {
		return analyticsReadFailure(ctx, err)
	}
	if !analyticsTotalsConsistent(summary, trend) {
		return Unavailable[AnalyticsOverview](ReasonAuthoritativeFactMissing), nil
	}
	overview := AnalyticsOverview{
		Summary: AnalyticsStats(summary),
		Trend:   make([]AnalyticsTrendPoint, 0, len(trend)),
		Top:     make([]AnalyticsRankSnapshot, 0, 3),
	}
	for _, point := range trend {
		overview.Trend = append(overview.Trend, analyticsTrendPoint(point))
	}
	rankSnapshots := make([]AnalyticsRankSnapshot, 0, len(rankDimensions))
	for _, dimension := range rankDimensions {
		page, rankErr := store.analytics.Rank(ctx, analyticsActor, request, dimension, 10, "")
		if rankErr != nil {
			return analyticsReadFailure(ctx, rankErr)
		}
		if !page.SnapshotAt.Equal(request.SnapshotAt) {
			return Section[AnalyticsOverview]{}, ErrUnavailable
		}
		if len(page.Items) > 10 || !rankFitsSummary(page.Items, summary) {
			return Unavailable[AnalyticsOverview](ReasonAuthoritativeFactMissing), nil
		}
		snapshot := AnalyticsRankSnapshot{
			Dimension: string(dimension), SnapshotAt: page.SnapshotAt,
			Items: make([]AnalyticsRankItem, 0, len(page.Items)),
		}
		for _, item := range page.Items {
			snapshot.Items = append(snapshot.Items, analyticsRankItem(item))
		}
		rankSnapshots = append(rankSnapshots, snapshot)
	}
	overview.TopExtended = rankSnapshots
	for _, dimension := range []analytics.RankDimension{analytics.RankByDomain, analytics.RankByRegion, analytics.RankByCarrier} {
		for _, snapshot := range rankSnapshots {
			if snapshot.Dimension == string(dimension) {
				overview.Top = append(overview.Top, snapshot)
				break
			}
		}
	}
	overview.SettlingMinutes = settling
	return Available(store.withHomeMetrics(ctx, analyticsActor, request, overview)), nil
}

func (store *Store) readAnalyticsParallel(
	ctx context.Context,
	actor analytics.Actor,
	request analytics.QueryRequest,
	settling *uint32,
) (Section[AnalyticsOverview], error) {
	dimensions := []analytics.RankDimension{
		analytics.RankByDomain, analytics.RankByURL, analytics.RankByIP, analytics.RankByRegion, analytics.RankByCarrier,
	}
	var summary analytics.Summary
	var trend []analytics.TrendPoint
	ranks := make([]analytics.RankPage, len(dimensions))
	readErrors := make([]error, 2+len(dimensions))
	var group sync.WaitGroup
	group.Add(len(readErrors))
	go func() {
		defer group.Done()
		summary, readErrors[0] = store.analytics.Summary(ctx, actor, request)
	}()
	go func() {
		defer group.Done()
		trend, readErrors[1] = store.analytics.Trend(ctx, actor, request)
	}()
	for index, dimension := range dimensions {
		index, dimension := index, dimension
		go func() {
			defer group.Done()
			ranks[index], readErrors[index+2] = store.analytics.Rank(ctx, actor, request, dimension, 10, "")
		}()
	}
	group.Wait()
	if section, handled, err := parallelAnalyticsErrors(ctx, readErrors[:]); handled {
		return section, err
	}
	if !analyticsTotalsConsistent(summary, trend) {
		return Unavailable[AnalyticsOverview](ReasonAuthoritativeFactMissing), nil
	}
	overview := AnalyticsOverview{
		Summary: AnalyticsStats(summary),
		Trend:   make([]AnalyticsTrendPoint, 0, len(trend)),
		Top:     make([]AnalyticsRankSnapshot, 0, len(dimensions)),
	}
	for _, point := range trend {
		overview.Trend = append(overview.Trend, analyticsTrendPoint(point))
	}
	rankSnapshots := make([]AnalyticsRankSnapshot, 0, len(dimensions))
	for index, dimension := range dimensions {
		page := ranks[index]
		if !page.SnapshotAt.Equal(request.SnapshotAt) {
			return Section[AnalyticsOverview]{}, ErrUnavailable
		}
		if len(page.Items) > 10 || !rankFitsSummary(page.Items, summary) {
			return Unavailable[AnalyticsOverview](ReasonAuthoritativeFactMissing), nil
		}
		snapshot := AnalyticsRankSnapshot{
			Dimension: string(dimension), SnapshotAt: page.SnapshotAt,
			Items: make([]AnalyticsRankItem, 0, len(page.Items)),
		}
		for _, item := range page.Items {
			snapshot.Items = append(snapshot.Items, analyticsRankItem(item))
		}
		rankSnapshots = append(rankSnapshots, snapshot)
	}
	overview.TopExtended = rankSnapshots
	for _, dimension := range []analytics.RankDimension{analytics.RankByDomain, analytics.RankByRegion, analytics.RankByCarrier} {
		for _, snapshot := range rankSnapshots {
			if snapshot.Dimension == string(dimension) {
				overview.Top = append(overview.Top, snapshot)
				break
			}
		}
	}
	overview.SettlingMinutes = settling
	return Available(store.withHomeMetrics(ctx, actor, request, overview)), nil
}

func parallelAnalyticsErrors(
	ctx context.Context,
	readErrors []error,
) (Section[AnalyticsOverview], bool, error) {
	if err := ctx.Err(); err != nil {
		return Section[AnalyticsOverview]{}, true, err
	}
	for _, err := range readErrors {
		if errors.Is(err, analytics.ErrInvalidInput) || errors.Is(err, analytics.ErrInvalidResponse) ||
			errors.Is(err, analytics.ErrPermissionDenied) || errors.Is(err, analytics.ErrScopeForbidden) {
			return Section[AnalyticsOverview]{}, true, ErrUnavailable
		}
	}
	for _, err := range readErrors {
		if errors.Is(err, context.Canceled) {
			return Section[AnalyticsOverview]{}, true, context.Canceled
		}
	}
	for _, err := range readErrors {
		if errors.Is(err, context.DeadlineExceeded) {
			return Unavailable[AnalyticsOverview](ReasonDependencyTimeout), true, nil
		}
	}
	for _, err := range readErrors {
		if err != nil {
			return Unavailable[AnalyticsOverview](ReasonDependencyUnavailable), true, nil
		}
	}
	return Section[AnalyticsOverview]{}, false, nil
}

// analyticsSettleGrace：水位缺失时，含当前时刻的窗口按实时覆盖宽限
// （analytics.defaultRealtimeCoverageGrace，2 分钟）提示最近数据仍在结算。
const analyticsSettleGrace = 2 * time.Minute

// settlingMinutes 返回「最近 N 分钟数据仍在结算」的 N；无需提示时为 nil。
// 水位齐全时 N = 窗口有效终点（To 与 AsOf 取早）减 finalized_through；
// 水位缺失或依赖未就绪时，仅当窗口含当前时刻才按宽限提示。
func (snapshot analyticsFinalizationSnapshot) settlingMinutes(query Query) *uint32 {
	horizon := query.To
	if !query.AsOf.IsZero() && query.AsOf.Before(horizon) {
		horizon = query.AsOf
	}
	known := snapshot.ExpectedTenants > 0 && snapshot.AccessTenants == snapshot.ExpectedTenants &&
		snapshot.SecurityTenants == snapshot.ExpectedTenants && snapshot.Rows >= snapshot.ExpectedTenants*2 &&
		snapshot.ReadyRows == snapshot.Rows && snapshot.FinalizedThrough != nil
	var lag time.Duration
	switch {
	case known:
		lag = horizon.Sub(*snapshot.FinalizedThrough)
	case !query.AsOf.IsZero() && query.AsOf.Before(query.To):
		lag = analyticsSettleGrace
	}
	if lag <= 0 {
		return nil
	}
	minutes := uint32(min(math.Ceil(lag.Minutes()), math.MaxUint32))
	return &minutes
}

func (postgresAnalyticsFinalizationReader) Read(
	ctx context.Context,
	tx pgx.Tx,
	audience Audience,
	tenantID uuid.UUID,
) (analyticsFinalizationSnapshot, error) {
	if tx == nil {
		return analyticsFinalizationSnapshot{}, errors.New("dashboard analytics finalization transaction is unavailable")
	}
	var scopedTenantID *uuid.UUID
	if audience == AudienceTenant {
		scopedTenantID = &tenantID
	}
	var snapshot analyticsFinalizationSnapshot
	err := tx.QueryRow(ctx, `WITH expected_tenants AS (
		SELECT id FROM tenants
		WHERE status='active' AND ($1::uuid IS NULL OR id=$1)
	), scoped_watermarks AS (
		SELECT watermark.* FROM analytics_ingest_watermarks_107 watermark
		JOIN expected_tenants tenant ON tenant.id=watermark.tenant_id
	)
	SELECT
		(SELECT count(*) FROM expected_tenants),
		count(DISTINCT tenant_id) FILTER (WHERE kind='access.v1'),
		count(DISTINCT tenant_id) FILTER (WHERE kind='security.v1'),
		count(*), count(*) FILTER (WHERE dependency_state='ready'),
		min(finalized_through)
	FROM scoped_watermarks`, scopedTenantID).Scan(
		&snapshot.ExpectedTenants,
		&snapshot.AccessTenants,
		&snapshot.SecurityTenants,
		&snapshot.Rows,
		&snapshot.ReadyRows,
		&snapshot.FinalizedThrough,
	)
	return snapshot, err
}

func analyticsReadFailure(ctx context.Context, err error) (Section[AnalyticsOverview], error) {
	if ctx.Err() != nil {
		return Section[AnalyticsOverview]{}, ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return Section[AnalyticsOverview]{}, context.Canceled
	}
	if errors.Is(err, analytics.ErrInvalidInput) || errors.Is(err, analytics.ErrInvalidResponse) {
		return Section[AnalyticsOverview]{}, ErrUnavailable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Unavailable[AnalyticsOverview](ReasonDependencyTimeout), nil
	}
	return Unavailable[AnalyticsOverview](ReasonDependencyUnavailable), nil
}

func analyticsTrendPoint(point analytics.TrendPoint) AnalyticsTrendPoint {
	return AnalyticsTrendPoint{
		Hour: point.Hour, MetricVersion: point.MetricVersion,
		RequestCount:        strconv.FormatUint(point.RequestCount, 10),
		RequestBytes:        strconv.FormatUint(point.RequestBytes, 10),
		ResponseBytes:       strconv.FormatUint(point.ResponseBytes, 10),
		TotalBytes:          strconv.FormatUint(point.TotalBytes, 10),
		AverageBandwidthBPS: point.AverageBandwidthBPS,
		Status2xx:           strconv.FormatUint(point.Status2xx, 10),
		Status3xx:           strconv.FormatUint(point.Status3xx, 10),
		Status4xx:           strconv.FormatUint(point.Status4xx, 10),
		Status5xx:           strconv.FormatUint(point.Status5xx, 10),
		SecurityEvents:      strconv.FormatUint(point.SecurityEvents, 10),
	}
}

func analyticsTotalsConsistent(summary analytics.Summary, trend []analytics.TrendPoint) bool {
	total := analytics.Summary{MetricVersion: analytics.MetricVersion}
	for _, point := range trend {
		if point.MetricVersion != analytics.MetricVersion ||
			!addUint64(&total.RequestCount, point.RequestCount) ||
			!addUint64(&total.RequestBytes, point.RequestBytes) ||
			!addUint64(&total.ResponseBytes, point.ResponseBytes) ||
			!addUint64(&total.TotalBytes, point.TotalBytes) ||
			!addUint64(&total.Status2xx, point.Status2xx) ||
			!addUint64(&total.Status3xx, point.Status3xx) ||
			!addUint64(&total.Status4xx, point.Status4xx) ||
			!addUint64(&total.Status5xx, point.Status5xx) ||
			!addUint64(&total.SecurityEvents, point.SecurityEvents) ||
			!addUint64(&total.SecurityEventRows, point.SecurityEventRows) {
			return false
		}
	}
	return summary.MetricVersion == analytics.MetricVersion &&
		total.RequestCount == summary.RequestCount && total.RequestBytes == summary.RequestBytes &&
		total.ResponseBytes == summary.ResponseBytes && total.TotalBytes == summary.TotalBytes &&
		total.Status2xx == summary.Status2xx && total.Status3xx == summary.Status3xx &&
		total.Status4xx == summary.Status4xx && total.Status5xx == summary.Status5xx &&
		total.SecurityEvents == summary.SecurityEvents && total.SecurityEventRows == summary.SecurityEventRows
}

func addUint64(total *uint64, value uint64) bool {
	if value > math.MaxUint64-*total {
		return false
	}
	*total += value
	return true
}

func rankFitsSummary(items []analytics.RankItem, summary analytics.Summary) bool {
	for _, item := range items {
		if item.RequestCount > summary.RequestCount || item.ResponseBytes > summary.ResponseBytes {
			return false
		}
	}
	return true
}

func validateFrozenQuery(audience Audience, query Query) error {
	expected, err := NewFilteredQuery(audience, query.Range, query.Timezone, query.SiteID, query.NodeID, query.AsOf)
	if err != nil || !expected.From.Equal(query.From) || !expected.To.Equal(query.To) {
		return ErrInvalidQuery
	}
	return nil
}

func readAdminAccounts(ctx context.Context, tx pgx.Tx) (AdminAccountStats, error) {
	var result AdminAccountStats
	err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM tenants),
		(SELECT count(*) FROM tenants WHERE status='active'),
		(SELECT count(DISTINCT membership.user_id) FROM memberships membership
			JOIN access_scopes scope ON scope.id=membership.scope_id WHERE scope.kind='tenant'),
		(SELECT count(DISTINCT membership.user_id) FROM memberships membership
			JOIN access_scopes scope ON scope.id=membership.scope_id
			JOIN tenants tenant ON tenant.id=scope.tenant_id
			JOIN users account ON account.id=membership.user_id
			WHERE scope.kind='tenant' AND tenant.status='active' AND membership.status='active'
			  AND account.status='active')`).Scan(
		&result.TenantsTotal, &result.TenantsActive, &result.TenantUsersTotal, &result.TenantUsersActive,
	)
	return result, err
}

func readAccountSecurity(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, userID *uuid.UUID,
	asOf time.Time,
) (AccountSecurityStats, error) {
	var result AccountSecurityStats
	err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM auth_sessions session
		 WHERE session.revoked_at IS NULL AND session.replaced_by_id IS NULL AND session.expires_at>$1
		   AND ($2::uuid IS NULL OR session.scope_id=$2)
		   AND ($3::uuid IS NULL OR session.user_id=$3)),
		(SELECT count(*) FROM (
			SELECT credential.scope_id,credential.user_id
			FROM mfa_credentials credential
			WHERE ($2::uuid IS NULL OR credential.scope_id=$2)
			  AND ($3::uuid IS NULL OR credential.user_id=$3)
			  AND EXISTS (SELECT 1 FROM mfa_credential_events activation
				WHERE activation.credential_id=credential.id AND activation.event_type='activated')
			  AND NOT EXISTS (SELECT 1 FROM mfa_credential_events terminal
				WHERE terminal.credential_id=credential.id AND terminal.event_type IN ('disabled','reset'))
			GROUP BY credential.scope_id,credential.user_id
		) active_mfa),
		(SELECT count(*) FROM api_keys api_key
		 WHERE api_key.status='active' AND (api_key.expires_at IS NULL OR api_key.expires_at>$1)
		   AND ($2::uuid IS NULL OR api_key.scope_id=$2)
		   AND ($3::uuid IS NULL OR api_key.user_id=$3)),
		(SELECT count(*) FROM mfa_recovery_codes recovery
		 JOIN mfa_credentials credential ON credential.id=recovery.credential_id
		 WHERE ($2::uuid IS NULL OR credential.scope_id=$2)
		   AND ($3::uuid IS NULL OR credential.user_id=$3)
		   AND EXISTS (SELECT 1 FROM mfa_credential_events activation
			WHERE activation.credential_id=credential.id AND activation.event_type='activated')
		   AND NOT EXISTS (SELECT 1 FROM mfa_credential_events terminal
			WHERE terminal.credential_id=credential.id AND terminal.event_type IN ('disabled','reset'))
		   AND NOT EXISTS (SELECT 1 FROM mfa_recovery_code_consumptions consumption
			WHERE consumption.recovery_code_id=recovery.id)),
		(SELECT max(event.occurred_at) FROM audit_events event
		 WHERE ($2::uuid IS NULL OR event.scope_id=$2)
		   AND ($3::uuid IS NULL OR event.actor_user_id=$3)
		   AND (event.action LIKE 'identity.%' OR event.action LIKE 'mfa.%' OR event.action LIKE 'api_key.%'))`,
		asOf, scopeID, userID).Scan(
		&result.ActiveSessions, &result.UsersWithMFA, &result.ActiveAPIKeys,
		&result.RecoveryCodesRemaining, &result.LastSecurityEventAt,
	)
	return result, err
}

func readNetwork(ctx context.Context, tx pgx.Tx, scopeID *uuid.UUID, asOf time.Time) (NetworkStats, error) {
	result := NetworkStats{FreshnessCutoff: uint32(NodeFreshnessCutoff / time.Second), Regions: []NetworkRegionStats{}}
	if err := tx.QueryRow(ctx, `SELECT count(node.id),
		count(node.id) FILTER (WHERE node.admin_state='active'),
		count(node.id) FILTER (WHERE presence.status='online' AND presence.last_seen_at >= $1),
		count(node.id) FILTER (WHERE presence.node_id IS NULL OR presence.status<>'online' OR presence.last_seen_at < $1)
	FROM nodes node LEFT JOIN node_presence presence ON presence.node_id=node.id
	WHERE ($2::uuid IS NULL OR node.scope_id=$2) AND node.admin_state<>'retired'`, asOf.Add(-NodeFreshnessCutoff), scopeID).Scan(
		&result.NodesTotal, &result.NodesActive, &result.NodesOnline, &result.NodesStale,
	); err != nil {
		return NetworkStats{}, err
	}
	rows, err := tx.Query(ctx, `SELECT COALESCE(NULLIF(btrim(node.region),''),'unassigned') AS region,
		count(node.id),count(node.id) FILTER (WHERE presence.status='online' AND presence.last_seen_at >= $1)
	FROM nodes node LEFT JOIN node_presence presence ON presence.node_id=node.id
	WHERE ($2::uuid IS NULL OR node.scope_id=$2) AND node.admin_state<>'retired'
	GROUP BY region ORDER BY count(node.id) DESC,region LIMIT 10`, asOf.Add(-NodeFreshnessCutoff), scopeID)
	if err != nil {
		return NetworkStats{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var region NetworkRegionStats
		if err := rows.Scan(&region.Region, &region.NodesTotal, &region.NodesOnline); err != nil {
			return NetworkStats{}, err
		}
		result.Regions = append(result.Regions, region)
	}
	return result, rows.Err()
}

func readAdminSubscriptions(ctx context.Context, tx pgx.Tx, asOf time.Time) (AdminSubscriptionStats, error) {
	var result AdminSubscriptionStats
	err := tx.QueryRow(ctx, `SELECT count(*) FROM package_subscriptions
		WHERE lifecycle_status='active' AND starts_at <= $1 AND $1 < ends_at`, asOf).Scan(&result.Active)
	return result, err
}

func readSettlements(ctx context.Context, tx pgx.Tx, query Query) (SettlementStats, error) {
	result := SettlementStats{Currency: "CNY"}
	err := tx.QueryRow(ctx, `WITH settled AS (
		SELECT
			COALESCE(sum(amount_minor) FILTER (WHERE direction='debit'),0)::numeric AS gross,
			COALESCE(sum(amount_minor) FILTER (
				WHERE direction='credit' AND reverses_transaction_id IS NOT NULL),0)::numeric AS reversed
		FROM billing_transactions
		WHERE created_at >= $1 AND created_at < $2 AND operation IN (
			'package_purchase','package_renewal','package_upgrade','package_downgrade',
			'traffic_package_purchase','package_refund','package_void'
		)
	)
	SELECT gross::text,reversed::text,(gross-reversed)::text FROM settled`, query.From, query.To).Scan(
		&result.GrossSettledDebitMinor, &result.ReversedCreditMinor, &result.NetSettledMinor,
	)
	return result, err
}

func readAdminResources(ctx context.Context, tx pgx.Tx, asOf time.Time) (AdminResourceStats, error) {
	var result AdminResourceStats
	err := tx.QueryRow(ctx, `WITH current_site_domains AS (
		SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain, fact.action
		FROM site_domain_facts fact
		JOIN sites site ON site.scope_id=fact.scope_id AND site.id=fact.site_id
		WHERE site.deleted_at IS NULL
		ORDER BY fact.canonical_domain,fact.global_sequence DESC
	)
	SELECT count(*),
		count(*) FILTER (WHERE enabled AND status='active'),
		count(*) FILTER (WHERE site_sync_status_503(scope_id, id)='failed'),
		(SELECT count(*) FROM current_site_domains WHERE action='activate')
		FROM sites WHERE deleted_at IS NULL`).Scan(
		&result.SitesTotal, &result.SitesActive, &result.SitesSyncFailed, &result.DomainsTotal,
	)
	if err != nil {
		return AdminResourceStats{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM nodes WHERE admin_state<>'retired'`).Scan(&result.NodesTotal); err != nil {
		return AdminResourceStats{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM l4_forwards WHERE deleted_at IS NULL`).Scan(&result.ForwardsTotal); err != nil {
		return AdminResourceStats{}, err
	}
	certificates, err := readCertificateStats(ctx, tx, nil, asOf)
	if err != nil {
		return AdminResourceStats{}, err
	}
	result.CertificatesTotal = certificates.Total
	result.CertificatesValid = certificates.Valid
	result.CertificatesExpiring30D = certificates.Expiring30D
	return result, nil
}

func readTenantResources(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (TenantResourceStats, error) {
	var result TenantResourceStats
	err := tx.QueryRow(ctx, `WITH current_site_domains AS (
		SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain, fact.action
		FROM site_domain_facts fact
		JOIN sites site ON site.scope_id=fact.scope_id AND site.id=fact.site_id
		WHERE fact.scope_id=$1 AND site.deleted_at IS NULL
		ORDER BY fact.canonical_domain,fact.global_sequence DESC
	)
	SELECT count(*),
		count(*) FILTER (WHERE enabled AND status='active'),
		count(*) FILTER (WHERE site_sync_status_503(scope_id, id)='failed'),
		(SELECT count(*) FROM current_site_domains WHERE action='activate'),
		(SELECT count(*) FROM l4_forwards WHERE scope_id=$1 AND deleted_at IS NULL),
		(SELECT count(*) FROM nodes WHERE scope_id=$1 AND admin_state<>'retired')
		FROM sites WHERE scope_id=$1 AND deleted_at IS NULL`, scopeID).Scan(
		&result.SitesTotal, &result.SitesActive, &result.SitesSyncFailed,
		&result.DomainsTotal, &result.ForwardsTotal, &result.NodesTotal,
	)
	return result, err
}

type identityVerificationQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readTenantIdentityVerification(
	ctx context.Context,
	query identityVerificationQuerier,
	scopeID, userID uuid.UUID,
) (IdentityVerificationStats, error) {
	var result IdentityVerificationStats
	err := query.QueryRow(ctx, `WITH latest_person AS (
		SELECT id,status,subject_fingerprint
		FROM identity_verification_cases
		WHERE tenant_scope_id=$1 AND applicant_user_id=$2
		  AND kind IN ('personal_initial','personal_reverification')
		ORDER BY created_at DESC,id DESC LIMIT 1
	), latest_enterprise AS (
		SELECT id,status,subject_fingerprint
		FROM identity_verification_cases
		WHERE tenant_scope_id=$1 AND applicant_user_id=$2 AND kind='enterprise'
		ORDER BY created_at DESC,id DESC LIMIT 1
	)
	SELECT EXISTS(
		SELECT 1 FROM latest_person latest
		JOIN identity_verified_persons person
		  ON person.tenant_scope_id=$1 AND person.applicant_user_id=$2
		 AND person.identity_fingerprint=latest.subject_fingerprint
		JOIN identity_verification_evidence_settlements settlement
		  ON settlement.tenant_scope_id=$1 AND settlement.case_id=latest.id
		 AND settlement.actor_user_id=$2
		WHERE latest.status='approved' AND settlement.state='settled'
	) OR EXISTS(
		SELECT 1 FROM latest_enterprise latest
		JOIN identity_verified_organizations organization
		  ON organization.tenant_scope_id=$1 AND organization.approved_case_id=latest.id
		 AND organization.subject_fingerprint=latest.subject_fingerprint
		JOIN identity_verification_evidence_settlements settlement
		  ON settlement.tenant_scope_id=$1 AND settlement.case_id=latest.id
		 AND settlement.actor_user_id=$2
		WHERE latest.status='approved' AND settlement.state='settled'
	)`, scopeID, userID).Scan(&result.Verified)
	return result, err
}

func readCertificateStats(ctx context.Context, tx pgx.Tx, scopeID *uuid.UUID, asOf time.Time) (CertificateStats, error) {
	var result CertificateStats
	err := tx.QueryRow(ctx, `WITH latest_activation AS (
		SELECT DISTINCT ON (tenant_scope_id,asset_id) tenant_scope_id,asset_id,version_id
		FROM certificate_asset_activation_facts
		ORDER BY tenant_scope_id,asset_id,sequence DESC
	)
	SELECT count(asset.id),
		count(asset.id) FILTER (WHERE version.not_before <= $2 AND $2 < version.not_after
			AND revoked.version_id IS NULL),
		count(asset.id) FILTER (WHERE version.not_before <= $2 AND $2 < version.not_after
			AND version.not_after < $2 + interval '30 days' AND revoked.version_id IS NULL)
	FROM certificate_assets asset
	LEFT JOIN latest_activation active ON active.tenant_scope_id=asset.tenant_scope_id AND active.asset_id=asset.id
	LEFT JOIN certificate_asset_versions version ON version.tenant_scope_id=asset.tenant_scope_id
		AND version.asset_id=asset.id AND version.id=active.version_id
	LEFT JOIN certificate_asset_revocation_facts revoked ON revoked.tenant_scope_id=asset.tenant_scope_id
		AND revoked.asset_id=asset.id AND revoked.version_id=version.id
	WHERE asset.deleted_at IS NULL AND ($1::uuid IS NULL OR asset.tenant_scope_id=$1)`, scopeID, asOf).Scan(
		&result.Total, &result.Valid, &result.Expiring30D,
	)
	return result, err
}

func readOperations(
	ctx context.Context,
	tx pgx.Tx,
	scopeID *uuid.UUID,
	tenantID *uuid.UUID,
	query Query,
) (OperationStats, error) {
	var result OperationStats
	if err := tx.QueryRow(ctx, `SELECT count(*),
		count(*) FILTER (WHERE state IN ('queued','running')),
		count(*) FILTER (WHERE state IN ('partial_failed','failed')),max(updated_at)
		FROM cache_operations WHERE created_at >= $2 AND created_at < $3
		  AND ($1::uuid IS NULL OR scope_id=$1)`, scopeID, query.From, query.To).Scan(
		&result.CacheTotal, &result.CacheOpen, &result.CacheFailed, &result.CacheUpdated,
	); err != nil {
		return OperationStats{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*),
		count(*) FILTER (WHERE state IN ('queued','running')),
		count(*) FILTER (WHERE state IN ('partial_failed','failed')),max(updated_at)
		FROM background_jobs WHERE created_at >= $2 AND created_at < $3
		  AND ($1::uuid IS NULL OR tenant_id=$1)`, tenantID, query.From, query.To).Scan(
		&result.JobsTotal, &result.JobsOpen, &result.JobsFailed, &result.JobsUpdated,
	); err != nil {
		return OperationStats{}, err
	}
	return result, nil
}

func readOperationCharts(ctx context.Context, tx pgx.Tx, query Query) (OperationCharts, error) {
	result := OperationCharts{
		NewUsers:    make([]OperationCountPoint, 0),
		PackageSold: make([]OperationCountPoint, 0),
		Recharge:    make([]OperationAmountPoint, 0),
	}
	rows, err := tx.Query(ctx, `SELECT
		date_trunc('day', account.created_at AT TIME ZONE $3::text),
		count(DISTINCT account.id)
		FROM users account
		JOIN memberships membership ON membership.user_id=account.id AND membership.status='active'
		JOIN access_scopes scope ON scope.id=membership.scope_id AND scope.kind='tenant'
		WHERE account.created_at >= $1 AND account.created_at < $2
		GROUP BY 1 ORDER BY 1`, query.From, query.To, query.Timezone)
	if err != nil {
		return OperationCharts{}, err
	}
	for rows.Next() {
		var point OperationCountPoint
		if err := rows.Scan(&point.Time, &point.Count); err != nil {
			rows.Close()
			return OperationCharts{}, err
		}
		result.NewUsers = append(result.NewUsers, point)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return OperationCharts{}, err
	}
	rows.Close()

	rows, err = tx.Query(ctx, `SELECT
		date_trunc('day', subscription.created_at AT TIME ZONE $3::text),
		count(*)
		FROM package_subscriptions subscription
		WHERE subscription.created_at >= $1 AND subscription.created_at < $2
		GROUP BY 1 ORDER BY 1`, query.From, query.To, query.Timezone)
	if err != nil {
		return OperationCharts{}, err
	}
	for rows.Next() {
		var point OperationCountPoint
		if err := rows.Scan(&point.Time, &point.Count); err != nil {
			rows.Close()
			return OperationCharts{}, err
		}
		result.PackageSold = append(result.PackageSold, point)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return OperationCharts{}, err
	}
	rows.Close()

	rows, err = tx.Query(ctx, `SELECT
		date_trunc('day', ledger.created_at AT TIME ZONE $3::text),
		COALESCE(sum(ledger.amount_minor),0)::text
		FROM billing_transactions ledger
		WHERE ledger.created_at >= $1 AND ledger.created_at < $2
		  AND ledger.operation='recharge_payment' AND ledger.direction='credit'
		GROUP BY 1 ORDER BY 1`, query.From, query.To, query.Timezone)
	if err != nil {
		return OperationCharts{}, err
	}
	for rows.Next() {
		var point OperationAmountPoint
		if err := rows.Scan(&point.Time, &point.SumMinor); err != nil {
			rows.Close()
			return OperationCharts{}, err
		}
		result.Recharge = append(result.Recharge, point)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return OperationCharts{}, err
	}
	rows.Close()
	return result, nil
}

func readEntitlement(ctx context.Context, tx pgx.Tx) (EntitlementStats, error) {
	var result EntitlementStats
	var signedLease []byte
	err := tx.QueryRow(ctx, `SELECT entitlement.installation_id,entitlement.last_status,
		entitlement.current_serial,lease.status,lease.expires_at,lease.grace_until,
		entitlement.last_verified_at,lease.signed_lease
	FROM control_installation_entitlement entitlement
	LEFT JOIN entitlement_cached_leases lease ON lease.serial=entitlement.current_serial
	WHERE entitlement.singleton`).Scan(
		&result.InstallationID, &result.Status, &result.CurrentSerial, &result.LeaseStatus,
		&result.ExpiresAt, &result.GraceUntil, &result.LastVerifiedAt, &signedLease,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		result.Status = "uninstalled"
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.NodeLimit, err = entitlementNodeLimit(signedLease)
	if err != nil {
		return result, err
	}
	return result, nil
}

func entitlementNodeLimit(encoded []byte) (*int64, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	lease, err := entitlement.Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode cached entitlement lease: %w", err)
	}
	limit, ok := lease.Lease.Quota(entitlement.QuotaNodesCount)
	if !ok {
		return nil, nil
	}
	return &limit, nil
}

func readNodeHealth(ctx context.Context, tx pgx.Tx, asOf time.Time) (NodeHealthStats, error) {
	result := NodeHealthStats{FreshnessCutoffSeconds: uint32(NodeFreshnessCutoff / time.Second)}
	err := tx.QueryRow(ctx, `SELECT count(node.id),
		count(node.id) FILTER (WHERE presence.status='online' AND presence.last_seen_at >= $1),
		count(node.id) FILTER (WHERE presence.node_id IS NULL OR presence.status<>'online' OR presence.last_seen_at < $1),
		count(node.id) FILTER (WHERE presence.node_id IS NULL),max(presence.last_seen_at)
	FROM nodes node LEFT JOIN node_presence presence ON presence.node_id=node.id
	WHERE node.admin_state<>'retired'`, asOf.Add(-NodeFreshnessCutoff)).Scan(
		&result.Total, &result.OnlineFresh, &result.StaleOrOffline, &result.PresenceMissing, &result.LatestLastSeenAt,
	)
	return result, err
}

func readAnalyticsHealth(ctx context.Context, tx pgx.Tx) (AnalyticsHealthStats, error) {
	var result AnalyticsHealthStats
	err := tx.QueryRow(ctx, `SELECT count(*),max(last_reconciled_at),max(updated_at),
		COALESCE(sum(broker_stream_ack_floor-committed_stream_ack_floor),0)::text
	FROM analytics_history_streams WHERE retired_at IS NULL`).Scan(
		&result.ActiveStreams, &result.LatestReconciledAt, &result.LatestUpdatedAt, &result.UnpreparedStreamGap,
	)
	return result, err
}

func readAdminProfile(ctx context.Context, tx pgx.Tx, scopeID, userID uuid.UUID, asOf time.Time) (AdminProfileStats, error) {
	var result AdminProfileStats
	err := tx.QueryRow(ctx, `
		SELECT audit_event.occurred_at,
			COALESCE(host(session.source_ip), NULLIF(audit_event.payload->>'source_ip', ''), 'unknown'),
			COALESCE(NULLIF(audit_event.payload->>'geo_code', ''), 'unknown'),
			COALESCE(audit_event.payload->>'geo_region', ''),
			COALESCE(audit_event.payload->>'geo_city', '')
		FROM audit_events audit_event
		LEFT JOIN auth_sessions session
			ON audit_event.action='auth.login' AND session.id::text=audit_event.payload->>'session_id'
		WHERE audit_event.scope_id=$1 AND audit_event.actor_user_id=$2 AND audit_event.action='auth.login'
			AND audit_event.result='success' AND audit_event.occurred_at <= $3
		ORDER BY audit_event.occurred_at DESC, audit_event.id DESC
		LIMIT 1`, scopeID, userID, asOf).Scan(
		&result.LastLoginAt, &result.LastLoginIP, &result.LastLoginGeo, &result.LastLoginRegion, &result.LastLoginCity,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdminProfileStats{}, nil
	}
	return result, err
}

func readBalance(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (BalanceStats, bool, error) {
	result := BalanceStats{Currency: "CNY"}
	err := tx.QueryRow(ctx, `SELECT balance_minor,revision,updated_at
		FROM billing_accounts WHERE scope_id=$1 AND kind='tenant_liability' AND currency='CNY'`, scopeID).Scan(
		&result.BalanceMinor, &result.Revision, &result.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return BalanceStats{}, false, nil
	}
	return result, err == nil, err
}

const tenantSubscriptionsSQL = `SELECT subscription.id,subscription.product_snapshot->>'name',
	subscription.ends_at,subscription.timezone,subscription.site_limit,subscription.domain_limit,
	subscription.node_limit,subscription.traffic_limit_bytes,progress.period_key,
	progress.observed_value::text,progress.finalized_through,progress.source_watermark::text,
	progress.source_evidence_digest
	FROM package_subscriptions subscription
	LEFT JOIN LATERAL (
		SELECT observation.period_key,observation.observed_value,observation.finalized_through,
			observation.source_watermark,observation.source_evidence_digest
		FROM package_monitor_policy_heads head
		JOIN package_monitor_policy_versions policy
		  ON policy.policy_id=head.policy_id AND policy.revision=head.current_revision
		 AND policy.tenant_scope_id=head.tenant_scope_id
		 AND policy.subscription_id=head.subscription_id AND policy.metric=head.metric
		CROSS JOIN LATERAL package_monitor_resolve_period_114(
			subscription.starts_at,subscription.ends_at,subscription.timezone,
			subscription.cycle_kind,subscription.custom_cycle_days,
			CASE WHEN $2>subscription.starts_at THEN $2 END
		) period
		JOIN package_monitor_metric_observations_114 observation
		  ON observation.tenant_scope_id=policy.tenant_scope_id
		 AND observation.subscription_id=policy.subscription_id
		 AND observation.policy_id=policy.policy_id
		 AND observation.policy_revision=policy.revision
		 AND observation.metric=policy.metric AND observation.period_key=period.period_key
		WHERE head.tenant_scope_id=subscription.tenant_scope_id
		  AND head.subscription_id=subscription.id AND head.metric='traffic_bytes'
		  AND policy.enabled AND observation.committed_at<=$2
		  AND observation.finalized_through<=$2
		ORDER BY observation.source_watermark DESC LIMIT 1
	) progress ON true
	WHERE subscription.tenant_scope_id=$1 AND subscription.lifecycle_status='active'
	  AND subscription.starts_at<=$2 AND $2<subscription.ends_at
	ORDER BY subscription.ends_at,subscription.id LIMIT 10`

func readTenantSubscriptions(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	asOf time.Time,
) (TenantSubscriptionStats, error) {
	result := TenantSubscriptionStats{Items: []SubscriptionItem{}}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM package_subscriptions
		WHERE tenant_scope_id=$1 AND lifecycle_status='active' AND starts_at <= $2 AND $2 < ends_at`,
		scopeID, asOf).Scan(&result.Active); err != nil {
		return TenantSubscriptionStats{}, err
	}
	rows, err := tx.Query(ctx, tenantSubscriptionsSQL, scopeID, asOf)
	if err != nil {
		return TenantSubscriptionStats{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item SubscriptionItem
		var siteLimit, domainLimit, nodeLimit, trafficLimit int64
		var periodKey, usedBytes, sourceWatermark *string
		var finalizedThrough *time.Time
		var evidenceDigest []byte
		if err := rows.Scan(&item.ID, &item.Name, &item.EndsAt, &item.Timezone, &siteLimit,
			&domainLimit, &nodeLimit, &trafficLimit, &periodKey, &usedBytes, &finalizedThrough,
			&sourceWatermark, &evidenceDigest); err != nil {
			return TenantSubscriptionStats{}, err
		}
		item.SiteLimit = SubscriptionLimit(siteLimit)
		item.DomainLimit = SubscriptionLimit(domainLimit)
		item.NodeLimit = SubscriptionLimit(nodeLimit)
		item.TrafficLimitBytes = SubscriptionLimit(trafficLimit)
		if periodKey != nil && usedBytes != nil && finalizedThrough != nil && sourceWatermark != nil && len(evidenceDigest) == 32 {
			item.TrafficProgress = Available(SubscriptionTrafficProgress{
				PeriodKey: *periodKey, UsedBytes: *usedBytes, FinalizedThrough: *finalizedThrough,
				SourceWatermark: *sourceWatermark, SourceEvidenceSHA256: hex.EncodeToString(evidenceDigest),
			})
		} else {
			item.TrafficProgress = Unavailable[SubscriptionTrafficProgress](ReasonAuthoritativeFactMissing)
		}
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}

func readTrafficPackages(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, asOf time.Time) (TrafficPackageStats, error) {
	var result TrafficPackageStats
	err := tx.QueryRow(ctx, `SELECT count(*),COALESCE(sum(granted_bytes),0)::text,
		COALESCE(sum(remaining_bytes),0)::text,
		COALESCE(sum(granted_bytes-remaining_bytes),0)::text
	FROM traffic_package_grants
	WHERE tenant_scope_id=$1 AND starts_at <= $2 AND $2 < expires_at
	  AND status IN ('active','exhausted')`, scopeID, asOf).Scan(
		&result.Active, &result.GrantedBytes, &result.RemainingBytes, &result.UsedBytes,
	)
	return result, err
}

func readNotices(ctx context.Context, tx pgx.Tx, scopeID, userID uuid.UUID) (NoticeStats, error) {
	result := NoticeStats{Items: []NoticeItem{}}
	// Tenant announcements and platform (global) announcements share the
	// message page; the home page shows both with the same visibility rules.
	const visible = ` FROM (
		SELECT event.id,event.title,event.published_at,state.read_at
		  FROM announcement_inbox_events event
		  JOIN announcement_versions version ON version.tenant_scope_id=event.tenant_scope_id
			AND version.announcement_id=event.announcement_id AND version.version=event.announcement_version
		  LEFT JOIN announcement_inbox_states state ON state.tenant_scope_id=event.tenant_scope_id
			AND state.event_id=event.id AND state.user_id=event.recipient_user_id
		 WHERE event.tenant_scope_id=$1 AND event.recipient_user_id=$2 AND version.is_visible
		   AND (version.status<>'withdrawn' OR version.withdrawal_visibility='retain')
		UNION ALL
		SELECT recipient.event_id,root.title,recipient.published_at,recipient.read_at
		  FROM platform_announcement_recipients_141 recipient
		  JOIN platform_announcements_141 root ON root.id=recipient.announcement_id
		 WHERE recipient.tenant_scope_id=$1 AND recipient.user_id=$2 AND root.is_visible
		   AND (root.status<>'withdrawn' OR root.withdrawal_visibility='retain')
	) notice`
	if err := tx.QueryRow(ctx, `SELECT count(*)`+visible+` WHERE notice.read_at IS NULL`, scopeID, userID).Scan(&result.Unread); err != nil {
		return NoticeStats{}, err
	}
	rows, err := tx.Query(ctx, `SELECT notice.id,notice.title,notice.published_at,notice.read_at`+visible+
		` ORDER BY notice.published_at DESC,notice.id DESC LIMIT 5`, scopeID, userID)
	if err != nil {
		return NoticeStats{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item NoticeItem
		if err := rows.Scan(&item.ID, &item.Title, &item.PublishedAt, &item.ReadAt); err != nil {
			return NoticeStats{}, err
		}
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}

func storageError(ctx context.Context, operation string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%w: %s", ErrUnavailable, operation)
}

var _ Reader = (*Store)(nil)
