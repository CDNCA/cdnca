package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/google/uuid"
)

const (
	Version             uint16 = 2
	NoticeLimit                = 5
	NodeFreshnessCutoff        = 45 * time.Second
)

var (
	ErrInvalidConfig    = errors.New("dashboard configuration invalid")
	ErrInvalidQuery     = errors.New("dashboard query invalid")
	ErrInvalidActor     = errors.New("dashboard actor invalid")
	ErrPermissionDenied = errors.New("dashboard permission denied")
	ErrScopeForbidden   = errors.New("dashboard scope forbidden")
	ErrUnavailable      = errors.New("dashboard storage unavailable")
)

const (
	ReasonDependencyUnavailable    = "dependency_unavailable"
	ReasonDependencyTimeout        = "dependency_timeout"
	ReasonAuthoritativeFactMissing = "authoritative_fact_missing"
)

type Audience uint8

const (
	AudienceInvalid Audience = iota
	AudienceAdmin
	AudienceTenant
)

type Query struct {
	Range    string
	Timezone string
	From     time.Time
	To       time.Time
	AsOf     time.Time
	SiteID   string
	NodeID   string
}

type Actor struct {
	RawSession string
	SessionID  uuid.UUID
	UserID     uuid.UUID
	ScopeID    uuid.UUID
	ScopeKind  string
	TenantID   uuid.UUID
}

func (actor Actor) Valid() bool {
	if actor.RawSession == "" || actor.SessionID == uuid.Nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil {
		return false
	}
	return actor.ScopeKind == "platform" && actor.TenantID == uuid.Nil ||
		actor.ScopeKind == "tenant" && actor.TenantID != uuid.Nil
}

type Meta struct {
	Range          string    `json:"range"`
	Timezone       string    `json:"timezone"`
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`
	GeneratedAt    time.Time `json:"generated_at"`
	SnapshotAt     time.Time `json:"snapshot_at"`
	WindowComplete bool      `json:"window_complete"`
}

func MetaFor(query Query) Meta {
	snapshotAt := query.AsOf.UTC().Truncate(time.Millisecond)
	return Meta{
		Range: query.Range, Timezone: query.Timezone, From: query.From, To: query.To,
		GeneratedAt: query.AsOf, SnapshotAt: snapshotAt, WindowComplete: !query.AsOf.Before(query.To),
	}
}

type Section[T any] struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Value     *T     `json:"value,omitempty"`
}

func Available[T any](value T) Section[T] {
	return Section[T]{Available: true, Value: &value}
}

func Unavailable[T any](reason string) Section[T] {
	return Section[T]{Reason: reason}
}

type AdminResponse struct {
	DashboardVersion uint16                          `json:"dashboard_version"`
	Meta             Meta                            `json:"meta"`
	Accounts         Section[AdminAccountStats]      `json:"accounts"`
	Subscriptions    Section[AdminSubscriptionStats] `json:"subscriptions"`
	Billing          Section[SettlementStats]        `json:"billing"`
	Resources        Section[AdminResourceStats]     `json:"resources"`
	Operations       Section[OperationStats]         `json:"operations"`
	OperationCharts  Section[OperationCharts]        `json:"operation_charts,omitempty"`
	Profile          Section[AdminProfileStats]      `json:"profile"`
	Entitlement      Section[EntitlementStats]       `json:"entitlement"`
	NodeHealth       Section[NodeHealthStats]        `json:"node_health"`
	AnalyticsHealth  Section[AnalyticsHealthStats]   `json:"analytics_health"`
	AccountSecurity  Section[AccountSecurityStats]   `json:"account_security"`
	Network          Section[NetworkStats]           `json:"network"`
	Analytics        Section[AnalyticsOverview]      `json:"analytics"`
}

type TenantResponse struct {
	DashboardVersion     uint16                             `json:"dashboard_version"`
	Meta                 Meta                               `json:"meta"`
	IdentityVerification Section[IdentityVerificationStats] `json:"identity_verification"`
	Profile              Section[AdminProfileStats]         `json:"profile"`
	Resources            Section[TenantResourceStats]       `json:"resources"`
	Certificates         Section[CertificateStats]          `json:"certificates"`
	Billing              Section[BalanceStats]              `json:"billing"`
	Subscriptions        Section[TenantSubscriptionStats]   `json:"subscriptions"`
	TrafficPackages      Section[TrafficPackageStats]       `json:"traffic_packages"`
	Operations           Section[OperationStats]            `json:"operations"`
	Notices              Section[NoticeStats]               `json:"notices"`
	AccountSecurity      Section[AccountSecurityStats]      `json:"account_security"`
	Network              Section[NetworkStats]              `json:"network"`
	Analytics            Section[AnalyticsOverview]         `json:"analytics"`
}

type IdentityVerificationStats struct {
	Verified bool `json:"verified"`
}

type AdminAccountStats struct {
	TenantsTotal      uint64 `json:"tenants_total"`
	TenantsActive     uint64 `json:"tenants_active"`
	TenantUsersTotal  uint64 `json:"tenant_users_total"`
	TenantUsersActive uint64 `json:"tenant_users_active"`
}

type AdminSubscriptionStats struct {
	Active uint64 `json:"active"`
}

type SettlementStats struct {
	Currency               string `json:"currency"`
	GrossSettledDebitMinor string `json:"gross_settled_debit_minor"`
	ReversedCreditMinor    string `json:"reversed_credit_minor"`
	NetSettledMinor        string `json:"net_settled_minor"`
}

type AdminResourceStats struct {
	SitesTotal              uint64 `json:"sites_total"`
	SitesActive             uint64 `json:"sites_active"`
	SitesSyncFailed         uint64 `json:"sites_sync_failed"`
	DomainsTotal            uint64 `json:"domains_total"`
	ForwardsTotal           uint64 `json:"forwards_total"`
	NodesTotal              uint64 `json:"nodes_total"`
	CertificatesTotal       uint64 `json:"certificates_total"`
	CertificatesValid       uint64 `json:"certificates_valid"`
	CertificatesExpiring30D uint64 `json:"certificates_expiring_30d"`
}

type AdminProfileStats struct {
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP     string     `json:"last_login_ip,omitempty"`
	LastLoginGeo    string     `json:"last_login_geo,omitempty"`
	LastLoginRegion string     `json:"last_login_region,omitempty"`
	LastLoginCity   string     `json:"last_login_city,omitempty"`
}

type TenantResourceStats struct {
	SitesTotal      uint64 `json:"sites_total"`
	SitesActive     uint64 `json:"sites_active"`
	SitesSyncFailed uint64 `json:"sites_sync_failed"`
	DomainsTotal    uint64 `json:"domains_total"`
	ForwardsTotal   uint64 `json:"forwards_total"`
	NodesTotal      uint64 `json:"nodes_total"`
}

type CertificateStats struct {
	Total       uint64 `json:"total"`
	Valid       uint64 `json:"valid"`
	Expiring30D uint64 `json:"expiring_30d"`
}

type OperationStats struct {
	CacheTotal   uint64     `json:"cache_total"`
	CacheOpen    uint64     `json:"cache_open"`
	CacheFailed  uint64     `json:"cache_failed"`
	CacheUpdated *time.Time `json:"cache_updated_at,omitempty"`
	JobsTotal    uint64     `json:"jobs_total"`
	JobsOpen     uint64     `json:"jobs_open"`
	JobsFailed   uint64     `json:"jobs_failed"`
	JobsUpdated  *time.Time `json:"jobs_updated_at,omitempty"`
}

// OperationCharts contains the day-bucketed facts used by the administrator
// overview charts. Empty slices intentionally represent no observations in
// the selected window and are rendered as the reference UI's “无数据” state.
type OperationCharts struct {
	NewUsers    []OperationCountPoint  `json:"new_users"`
	PackageSold []OperationCountPoint  `json:"package_sold"`
	Recharge    []OperationAmountPoint `json:"recharge"`
}

type OperationCountPoint struct {
	Time  time.Time `json:"time"`
	Count uint64    `json:"count"`
}

type OperationAmountPoint struct {
	Time     time.Time `json:"time"`
	SumMinor string    `json:"sum_minor"`
}

type EntitlementStats struct {
	InstallationID string     `json:"installation_id"`
	Status         string     `json:"status"`
	CurrentSerial  *int64     `json:"current_serial,omitempty"`
	NodeLimit      *int64     `json:"node_limit,omitempty"`
	LeaseStatus    *string    `json:"lease_status"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	GraceUntil     *time.Time `json:"grace_until,omitempty"`
	LastVerifiedAt *time.Time `json:"last_verified_at,omitempty"`
}

type NodeHealthStats struct {
	Total                  uint64     `json:"total"`
	OnlineFresh            uint64     `json:"online_fresh"`
	StaleOrOffline         uint64     `json:"stale_or_offline"`
	PresenceMissing        uint64     `json:"presence_missing"`
	LatestLastSeenAt       *time.Time `json:"latest_last_seen_at,omitempty"`
	FreshnessCutoffSeconds uint32     `json:"freshness_cutoff_seconds"`
}

type AnalyticsHealthStats struct {
	ActiveStreams       uint64     `json:"active_streams"`
	LatestReconciledAt  *time.Time `json:"latest_reconciled_at,omitempty"`
	LatestUpdatedAt     *time.Time `json:"latest_updated_at,omitempty"`
	UnpreparedStreamGap string     `json:"unprepared_stream_gap"`
}

type AccountSecurityStats struct {
	ActiveSessions         uint64     `json:"active_sessions"`
	UsersWithMFA           uint64     `json:"users_with_mfa"`
	ActiveAPIKeys          uint64     `json:"active_api_keys"`
	RecoveryCodesRemaining uint64     `json:"recovery_codes_remaining"`
	LastSecurityEventAt    *time.Time `json:"last_security_event_at,omitempty"`
}

type NetworkStats struct {
	NodesTotal      uint64               `json:"nodes_total"`
	NodesActive     uint64               `json:"nodes_active"`
	NodesOnline     uint64               `json:"nodes_online"`
	NodesStale      uint64               `json:"nodes_stale"`
	FreshnessCutoff uint32               `json:"freshness_cutoff_seconds"`
	Regions         []NetworkRegionStats `json:"regions"`
}

type NetworkRegionStats struct {
	Region      string `json:"region"`
	NodesTotal  uint64 `json:"nodes_total"`
	NodesOnline uint64 `json:"nodes_online"`
}

type AnalyticsStats analytics.Summary

func (stats AnalyticsStats) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		MetricVersion       uint16  `json:"metric_version"`
		RequestCount        string  `json:"request_count"`
		RequestBytes        string  `json:"request_bytes"`
		ResponseBytes       string  `json:"response_bytes"`
		TotalBytes          string  `json:"total_bytes"`
		AverageBandwidthBPS float64 `json:"average_bandwidth_bps"`
		Status2xx           string  `json:"status_2xx"`
		Status3xx           string  `json:"status_3xx"`
		Status4xx           string  `json:"status_4xx"`
		Status5xx           string  `json:"status_5xx"`
		SecurityEvents      string  `json:"security_events"`
		SecurityEventRows   string  `json:"security_event_rows"`
	}{
		MetricVersion:       stats.MetricVersion,
		RequestCount:        strconv.FormatUint(stats.RequestCount, 10),
		RequestBytes:        strconv.FormatUint(stats.RequestBytes, 10),
		ResponseBytes:       strconv.FormatUint(stats.ResponseBytes, 10),
		TotalBytes:          strconv.FormatUint(stats.TotalBytes, 10),
		AverageBandwidthBPS: stats.AverageBandwidthBPS,
		Status2xx:           strconv.FormatUint(stats.Status2xx, 10),
		Status3xx:           strconv.FormatUint(stats.Status3xx, 10),
		Status4xx:           strconv.FormatUint(stats.Status4xx, 10),
		Status5xx:           strconv.FormatUint(stats.Status5xx, 10),
		SecurityEvents:      strconv.FormatUint(stats.SecurityEvents, 10),
		SecurityEventRows:   strconv.FormatUint(stats.SecurityEventRows, 10),
	})
}

type AnalyticsOverview struct {
	Summary     AnalyticsStats          `json:"summary"`
	Trend       []AnalyticsTrendPoint   `json:"trend"`
	Top         []AnalyticsRankSnapshot `json:"top"`
	TopExtended []AnalyticsRankSnapshot `json:"top_extended,omitempty"`
	// FX36: busiest 5-minute bandwidth and blocked IPs (firewall + CC
	// auto-bans); omitted when the analytics store cannot provide them.
	PeakBandwidthBPS *string `json:"peak_bandwidth_bps,omitempty"`
	BlockedIPCount   *string `json:"blocked_ip_count,omitempty"`
	// SettlingMinutes：最近 N 分钟数据仍在结算（只作提示，不拦截展示）；无需提示时省略。
	SettlingMinutes *uint32 `json:"settling_minutes,omitempty"`
}

type AnalyticsTrendPoint struct {
	Hour                time.Time `json:"hour"`
	MetricVersion       uint16    `json:"metric_version"`
	RequestCount        string    `json:"request_count"`
	RequestBytes        string    `json:"request_bytes"`
	ResponseBytes       string    `json:"response_bytes"`
	TotalBytes          string    `json:"total_bytes"`
	AverageBandwidthBPS float64   `json:"average_bandwidth_bps"`
	Status2xx           string    `json:"status_2xx"`
	Status3xx           string    `json:"status_3xx"`
	Status4xx           string    `json:"status_4xx"`
	Status5xx           string    `json:"status_5xx"`
	SecurityEvents      string    `json:"security_events"`
}

type AnalyticsRankSnapshot struct {
	Dimension  string              `json:"dimension"`
	SnapshotAt time.Time           `json:"snapshot_at"`
	Items      []AnalyticsRankItem `json:"items"`
}

type AnalyticsRankItem struct {
	Key           string `json:"key"`
	RequestCount  string `json:"request_count"`
	ResponseBytes string `json:"response_bytes"`
	// Domain / URL ranks: the address parts (analytics.RankItem), so the
	// home page shows host:port and scheme://host:port/path like the
	// analytics page. Omitted when unknown.
	Host   string `json:"host,omitempty"`
	Port   uint16 `json:"port,omitempty"`
	Path   string `json:"path,omitempty"`
	Scheme string `json:"scheme,omitempty"`
}

func analyticsRankItem(item analytics.RankItem) AnalyticsRankItem {
	return AnalyticsRankItem{
		Key: item.Key, RequestCount: strconv.FormatUint(item.RequestCount, 10),
		ResponseBytes: strconv.FormatUint(item.ResponseBytes, 10),
		Host:          item.Host, Port: item.Port, Path: item.Path, Scheme: item.Scheme,
	}
}

type BalanceStats struct {
	Currency     string     `json:"currency"`
	BalanceMinor int64      `json:"balance_minor"`
	Revision     int64      `json:"revision"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

type TenantSubscriptionStats struct {
	Active uint64             `json:"active"`
	Items  []SubscriptionItem `json:"items"`
}

type SubscriptionItem struct {
	ID                uuid.UUID                            `json:"id"`
	Name              string                               `json:"name"`
	EndsAt            time.Time                            `json:"ends_at"`
	Timezone          string                               `json:"timezone"`
	SiteLimit         SubscriptionLimit                    `json:"site_limit"`
	DomainLimit       SubscriptionLimit                    `json:"domain_limit"`
	NodeLimit         SubscriptionLimit                    `json:"node_limit"`
	TrafficLimitBytes SubscriptionLimit                    `json:"traffic_limit_bytes"`
	TrafficProgress   Section[SubscriptionTrafficProgress] `json:"traffic_progress"`
}

type SubscriptionTrafficProgress struct {
	PeriodKey            string    `json:"period_key"`
	UsedBytes            string    `json:"used_bytes"`
	FinalizedThrough     time.Time `json:"finalized_through"`
	SourceWatermark      string    `json:"source_watermark"`
	SourceEvidenceSHA256 string    `json:"source_evidence_sha256"`
}

type SubscriptionLimit int64

func (limit SubscriptionLimit) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatInt(int64(limit), 10))
}

type TrafficPackageStats struct {
	Active         uint64 `json:"active"`
	GrantedBytes   string `json:"granted_bytes"`
	RemainingBytes string `json:"remaining_bytes"`
	UsedBytes      string `json:"used_bytes"`
}

type NoticeStats struct {
	Unread uint64       `json:"unread"`
	Items  []NoticeItem `json:"items"`
}

type NoticeItem struct {
	ID          uuid.UUID  `json:"id"`
	Title       string     `json:"title"`
	PublishedAt time.Time  `json:"published_at"`
	ReadAt      *time.Time `json:"read_at,omitempty"`
}

type Reader interface {
	Admin(context.Context, Actor, Query) (AdminResponse, error)
	Tenant(context.Context, Actor, Query) (TenantResponse, error)
}
