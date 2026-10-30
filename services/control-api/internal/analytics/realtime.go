package analytics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maximumRealtimeErrorPPM = uint64(10_000)
	maximumRealtimePoints   = 744
	maximumRealtimeTopItems = 10
)

var ErrRealtimeEvidenceUnavailable = errors.New("analytics realtime evidence unavailable")

type RealtimeRequest struct {
	Audience   Audience
	TenantID   string
	From       time.Time
	To         time.Time
	SiteID     string
	Host       string
	ListenPort uint16
	// AllowPartialCoverage lets the coverage panel (query_version=3) read settled
	// hours while other hours are still unfinalized. The result then reports
	// coverage_complete=false with the missing hours and skips reconciliation.
	AllowPartialCoverage bool
	// Live (query_version=4, the realtime monitor) reads the newest facts,
	// unsettled hours included, without the hourly settlement reconciliation.
	// It is a display read only: billing and reconciled panels never set it.
	Live bool
}

type RealtimeFilter struct {
	From       time.Time
	To         time.Time
	SiteID     string
	Host       string
	ListenPort uint16
	// ExcludedWindows are unsettled hour starts removed from every projection
	// so a partial result contains settled facts only.
	ExcludedWindows []time.Time
}

type RealtimeMetrics struct {
	Requests          uint64  `json:"requests"`
	TrafficBytes      uint64  `json:"traffic_bytes"`
	BandwidthBPS      float64 `json:"bandwidth_bps"`
	Connections       uint64  `json:"connections"`
	Status2xx         uint64  `json:"status_2xx"`
	Status3xx         uint64  `json:"status_3xx"`
	Status4xx         uint64  `json:"status_4xx"`
	Status5xx         uint64  `json:"status_5xx"`
	CacheHits         uint64  `json:"cache_hits"`
	CacheMisses       uint64  `json:"cache_misses"`
	Errors            uint64  `json:"errors"`
	AverageDurationUS float64 `json:"average_duration_us"`
	OriginConnectUS   float64 `json:"origin_connect_us"`
	OriginFirstByteUS float64 `json:"origin_first_byte_us"`
	OriginTotalUS     float64 `json:"origin_total_us"`
}

type RealtimePoint struct {
	Bucket             time.Time `json:"bucket"`
	Requests           uint64    `json:"requests"`
	TrafficBytes       uint64    `json:"traffic_bytes"`
	BandwidthBPS       float64   `json:"bandwidth_bps"`
	Connections        uint64    `json:"connections"`
	CacheHits          uint64    `json:"cache_hits"`
	CacheMisses        uint64    `json:"cache_misses"`
	CacheHitBytes      uint64    `json:"cache_hit_bytes"`
	Status4xx          uint64    `json:"status_4xx"`
	Status5xx          uint64    `json:"status_5xx"`
	OriginTotalUS      *float64  `json:"origin_total_us"`
	OriginTrafficBytes *uint64   `json:"origin_traffic_bytes"`
	OriginBandwidthBPS *float64  `json:"origin_bandwidth_bps"`
}

type RealtimeTopItem struct {
	Host         string `json:"host"`
	ListenPort   uint16 `json:"listen_port"`
	Requests     uint64 `json:"requests"`
	TrafficBytes uint64 `json:"traffic_bytes"`
}

type RealtimeEvidence struct {
	AccessSourceCount     uint64    `json:"access_source_count"`
	ConnectionSourceCount uint64    `json:"connection_source_count"`
	ExpectedEvents        uint64    `json:"expected_events"`
	ObservedEvents        uint64    `json:"observed_events"`
	ErrorPPM              uint64    `json:"error_ppm"`
	FinalizedThrough      time.Time `json:"finalized_through"`
	SourceWatermark       time.Time `json:"source_watermark"`
	CoverageFrom          time.Time `json:"coverage_from"`
	CoverageTo            time.Time `json:"coverage_to"`
	SnapshotAt            time.Time `json:"snapshot_at"`
	// Coverage over the enclosing hours, serialized only by query_version=3:
	// MissingWindows lists hour starts not finalized yet (empty when complete).
	CoverageComplete bool        `json:"-"`
	RequestedWindows uint16      `json:"-"`
	CoveredWindows   uint16      `json:"-"`
	MissingWindows   []time.Time `json:"-"`
	coverageVerified bool
}

type RealtimeResult struct {
	MetricVersion       uint16            `json:"metric_version"`
	SeriesBucketSeconds uint32            `json:"series_bucket_seconds"`
	Summary             RealtimeMetrics   `json:"summary"`
	Series              []RealtimePoint   `json:"series"`
	Top                 []RealtimeTopItem `json:"top"`
	Evidence            RealtimeEvidence  `json:"evidence"`
}

type realtimeQueryStore interface {
	Realtime(context.Context, Scope, RealtimeFilter) (RealtimeResult, error)
}

type RealtimeExpectedCountReader interface {
	ExpectedRealtimeEvidence(context.Context, Scope, RealtimeFilter) (RealtimeExpectedEvidence, error)
}

type RealtimeExpectedEvidence struct {
	TenantID                   string
	From                       time.Time
	To                         time.Time
	SiteID                     string
	Host                       string
	ListenPort                 uint16
	ExpectedEvents             uint64
	RequestedWindows           uint16
	CoveredWindows             uint16
	AccessSourcesExpected      uint64
	AccessSourcesFinalized     uint64
	ConnectionSourcesExpected  uint64
	ConnectionSourcesFinalized uint64
	FinalizedThrough           time.Time
	SourceWatermark            time.Time
	// MissingWindows is non-empty only for partial evidence: the hour starts
	// in [From,To) that are not covered and finalized.
	MissingWindows []time.Time
}

func (service *Service) Realtime(ctx context.Context, actor Actor, request RealtimeRequest) (RealtimeResult, error) {
	if ctx == nil {
		return RealtimeResult{}, ErrInvalidInput
	}
	scope, filter, err := authorizeQueryWithValidation(actor, QueryRequest{
		Audience: request.Audience, TenantID: request.TenantID, From: request.From, To: request.To, SiteID: request.SiteID,
	}, validateRankScopeFilter)
	if err != nil {
		return RealtimeResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return RealtimeResult{}, err
	}
	hosts, hostsValid := canonicalRealtimeHosts(request.Host)
	realtimeFilter := RealtimeFilter{
		From: filter.From, To: filter.To, SiteID: filter.SiteID,
		Host: hosts, ListenPort: request.ListenPort,
	}
	if !hostsValid || !validRealtimeFilter(realtimeFilter) {
		return RealtimeResult{}, ErrInvalidInput
	}
	coverage := realtimeCoverageFilter(realtimeFilter)
	if request.Live {
		return service.liveRealtime(ctx, scope, realtimeFilter, coverage)
	}
	if service.realtimeExpectedCounts == nil && (!coverage.From.Equal(realtimeFilter.From) || !coverage.To.Equal(realtimeFilter.To)) {
		return RealtimeResult{}, ErrRealtimeEvidenceUnavailable
	}
	store, ok := service.store.(realtimeQueryStore)
	if !ok {
		return RealtimeResult{}, ErrRealtimeEvidenceUnavailable
	}
	var expected RealtimeExpectedEvidence
	if service.realtimeExpectedCounts != nil {
		expected, err = service.realtimeExpectedCounts.ExpectedRealtimeEvidence(ctx, scope, realtimeFilter)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return RealtimeResult{}, ctxErr
		}
		if err != nil {
			return RealtimeResult{}, err
		}
		if len(expected.MissingWindows) > 0 && !request.AllowPartialCoverage ||
			!validRealtimeExpectedEvidence(expected, scope, realtimeFilter) {
			return RealtimeResult{}, ErrRealtimeEvidenceUnavailable
		}
		realtimeFilter.ExcludedWindows = expected.MissingWindows
	}
	if service.realtimeExpectedCounts != nil && expected.CoveredWindows == 0 {
		// No settled hour: return an empty result flagged as uncovered instead
		// of querying facts that cannot be reconciled.
		epoch := time.Unix(0, 0).UTC()
		result := RealtimeResult{MetricVersion: MetricVersion, SeriesBucketSeconds: realtimeBucketSeconds(realtimeFilter),
			Series: []RealtimePoint{}, Top: []RealtimeTopItem{}}
		result.Evidence = RealtimeEvidence{FinalizedThrough: epoch, SourceWatermark: epoch,
			CoverageFrom: coverage.From, CoverageTo: coverage.To, SnapshotAt: time.Now().UTC().Truncate(time.Millisecond),
			RequestedWindows: expected.RequestedWindows, MissingWindows: append([]time.Time{}, expected.MissingWindows...)}
		return result, nil
	}
	result, err := store.Realtime(ctx, scope, realtimeFilter)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return RealtimeResult{}, ctxErr
	}
	if err != nil {
		var storageError *HTTPError
		if errors.Is(err, ErrTransport) || errors.As(err, &storageError) {
			return RealtimeResult{}, fmt.Errorf("%w: analytics storage", ErrRealtimeEvidenceUnavailable)
		}
		return RealtimeResult{}, err
	}
	if service.realtimeExpectedCounts != nil && provenEmptyRealtimeEvidence(expected) &&
		(result.Evidence.ObservedEvents != 0 || result.Evidence.ConnectionSourceCount != 0 || result.Summary.Connections != 0) {
		// Activity without any rostered source cannot be reconciled.
		return RealtimeResult{}, ErrRealtimeEvidenceUnavailable
	}
	if service.realtimeExpectedCounts != nil {
		result.Evidence.ExpectedEvents = expected.ExpectedEvents
		result.Evidence.ErrorPPM = realtimeErrorPPM(expected.ExpectedEvents, result.Evidence.ObservedEvents)
		result.Evidence.FinalizedThrough = earliestRealtimeEvidenceTime(result.Evidence.FinalizedThrough, expected.FinalizedThrough)
		result.Evidence.SourceWatermark = earliestRealtimeEvidenceTime(result.Evidence.SourceWatermark, expected.SourceWatermark)
		result.Evidence.coverageVerified = true
		if ctxErr := ctx.Err(); ctxErr != nil {
			return RealtimeResult{}, ctxErr
		}
	}
	result.SeriesBucketSeconds = realtimeBucketSeconds(realtimeFilter)
	result.Evidence.CoverageFrom, result.Evidence.CoverageTo = coverage.From, coverage.To
	windows := uint16(coverage.To.Sub(coverage.From) / time.Hour)
	result.Evidence.RequestedWindows = windows
	result.Evidence.MissingWindows = append([]time.Time{}, realtimeFilter.ExcludedWindows...)
	result.Evidence.CoveredWindows = windows - uint16(len(result.Evidence.MissingWindows))
	result.Evidence.CoverageComplete = len(result.Evidence.MissingWindows) == 0
	if err := validateRealtimeResult(result, realtimeFilter); err != nil {
		return RealtimeResult{}, err
	}
	return result, nil
}

// liveRealtime serves the realtime monitor: every fact in the window as
// ingested so far. Nothing is reconciled, so the evidence claims no expected
// count, accuracy or finalization; the shape checks still hold.
func (service *Service) liveRealtime(ctx context.Context, scope Scope, filter, coverage RealtimeFilter) (RealtimeResult, error) {
	store, ok := service.store.(realtimeQueryStore)
	if !ok {
		return RealtimeResult{}, ErrRealtimeEvidenceUnavailable
	}
	result, err := store.Realtime(ctx, scope, filter)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return RealtimeResult{}, ctxErr
	}
	if err != nil {
		var storageError *HTTPError
		if errors.Is(err, ErrTransport) || errors.As(err, &storageError) {
			return RealtimeResult{}, fmt.Errorf("%w: analytics storage", ErrRealtimeEvidenceUnavailable)
		}
		return RealtimeResult{}, err
	}
	epoch := time.Unix(0, 0).UTC()
	windows := uint16(coverage.To.Sub(coverage.From) / time.Hour)
	result.SeriesBucketSeconds = realtimeBucketSeconds(filter)
	result.Evidence.ExpectedEvents, result.Evidence.ErrorPPM = 0, 0
	result.Evidence.FinalizedThrough, result.Evidence.SourceWatermark = epoch, epoch
	result.Evidence.CoverageFrom, result.Evidence.CoverageTo = coverage.From, coverage.To
	result.Evidence.RequestedWindows, result.Evidence.CoveredWindows = windows, windows
	result.Evidence.MissingWindows, result.Evidence.CoverageComplete = []time.Time{}, true
	if err := validateRealtimeShape(result, filter); err != nil {
		return RealtimeResult{}, err
	}
	if result.Evidence.AccessSourceCount != result.Summary.Requests || result.Evidence.ObservedEvents < result.Summary.Requests ||
		result.Evidence.ConnectionSourceCount == 0 && result.Summary.Connections != 0 {
		return RealtimeResult{}, ErrInvalidResponse
	}
	return result, nil
}

func validRealtimeExpectedEvidence(evidence RealtimeExpectedEvidence, scope Scope, filter RealtimeFilter) bool {
	filter = realtimeCoverageFilter(filter)
	windows := filter.To.Sub(filter.From) / time.Hour
	scopeMatches := scope.kind == scopeTenant && evidence.TenantID == scope.tenantID ||
		scope.kind == scopeAdmin && evidence.TenantID == ""
	if !scopeMatches || !evidence.From.Equal(filter.From) || !evidence.To.Equal(filter.To) || evidence.SiteID != filter.SiteID ||
		evidence.Host != filter.Host || evidence.ListenPort != filter.ListenPort || windows <= 0 || windows > maximumRealtimePoints+1 ||
		uint64(evidence.RequestedWindows) != uint64(windows) || !validRealtimeMissingWindows(evidence.MissingWindows, filter) ||
		int(evidence.CoveredWindows)+len(evidence.MissingWindows) != int(evidence.RequestedWindows) ||
		evidence.FinalizedThrough.Location() != time.UTC || evidence.SourceWatermark.Location() != time.UTC {
		return false
	}
	if evidence.CoveredWindows == 0 {
		// Nothing settled yet: only an all-zero aggregate is consistent.
		return evidence.ExpectedEvents == 0 && provenEmptyRealtimeEvidence(evidence) &&
			evidence.AccessSourcesFinalized == 0 && evidence.ConnectionSourcesFinalized == 0
	}
	// Settled hours carry the same complete-source rules as a fully settled range.
	settledThrough := realtimeSettledThrough(filter, evidence.MissingWindows)
	return (evidence.AccessSourcesExpected > 0 && evidence.ConnectionSourcesExpected > 0 || provenEmptyRealtimeEvidence(evidence)) &&
		evidence.AccessSourcesFinalized == evidence.AccessSourcesExpected &&
		evidence.ConnectionSourcesFinalized == evidence.ConnectionSourcesExpected &&
		!evidence.FinalizedThrough.Before(settledThrough) && !evidence.SourceWatermark.Before(settledThrough)
}

// Proven-empty evidence covers every requested window with recorded rosters
// that contain no listener and no reported activity for the filter.
func provenEmptyRealtimeEvidence(evidence RealtimeExpectedEvidence) bool {
	return evidence.ExpectedEvents == 0 && evidence.AccessSourcesExpected == 0 && evidence.ConnectionSourcesExpected == 0
}

func earliestRealtimeEvidenceTime(current, authority time.Time) time.Time {
	if !current.After(time.Unix(0, 0).UTC()) || authority.Before(current) {
		return authority
	}
	return current
}

func validRealtimeFilter(filter RealtimeFilter) bool {
	validationScope := Scope{kind: scopeTenant, tenantID: "00000000-0000-4000-8000-000000000001"}
	if err := validateScopeFilterGranularity(validationScope, Filter{From: filter.From, To: filter.To, SiteID: filter.SiteID}, time.Minute); err != nil {
		return false
	}
	if filter.To.Sub(filter.From) > 31*24*time.Hour {
		return false
	}
	if !filter.From.Equal(filter.From.Truncate(time.Minute)) || !filter.To.Equal(filter.To.Truncate(time.Minute)) {
		return false
	}
	hosts, ok := canonicalRealtimeHosts(filter.Host)
	return ok && hosts == filter.Host
}

// Coverage is independently reconciled over complete source windows. It never
// changes the requested interval used by summary, series, or ranking projections.
func realtimeCoverageFilter(filter RealtimeFilter) RealtimeFilter {
	filter.From = filter.From.Truncate(time.Hour)
	to := filter.To.Truncate(time.Hour)
	if !filter.To.Equal(to) {
		to = to.Add(time.Hour)
	}
	filter.To = to
	return filter
}

func realtimeBucketSeconds(filter RealtimeFilter) uint32 {
	minutes := int64(filter.To.Sub(filter.From) / time.Minute)
	return uint32((minutes+maximumRealtimePoints-1)/maximumRealtimePoints) * 60
}

func canonicalRealtimeHosts(value string) (string, bool) {
	hosts := strings.Fields(strings.ToLower(value))
	if len(hosts) > 64 {
		return "", false
	}
	seen := make(map[string]struct{}, len(hosts))
	canonical := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if !validRealtimeHost(host) {
			return "", false
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		canonical = append(canonical, host)
	}
	return strings.Join(canonical, " "), true
}

func validRealtimeHost(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") || strings.ContainsAny(host, "/:@") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return strings.ToLower(host) == host
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
				return false
			}
		}
	}
	return true
}

func validateRealtimeResult(result RealtimeResult, filter RealtimeFilter) error {
	if err := validateRealtimeShape(result, filter); err != nil {
		return err
	}
	return validateRealtimeEvidence(result, filter)
}

// validateRealtimeShape checks the facts themselves: buckets, sums, ranking.
func validateRealtimeShape(result RealtimeResult, filter RealtimeFilter) error {
	if !validRealtimeFilter(filter) || result.MetricVersion != MetricVersion || len(result.Series) > maximumRealtimePoints || len(result.Top) > maximumRealtimeTopItems ||
		!validRealtimeMetrics(result.Summary) {
		return ErrInvalidResponse
	}
	var seriesRequests, seriesTraffic uint64
	bucketDuration := time.Duration(realtimeBucketSeconds(filter)) * time.Second
	for index, point := range result.Series {
		if point.Bucket.Location() != time.UTC || point.Bucket.Before(filter.From) || !point.Bucket.Before(filter.To) ||
			!point.Bucket.Equal(point.Bucket.Truncate(time.Minute)) || index > 0 && !result.Series[index-1].Bucket.Before(point.Bucket) ||
			point.Bucket.Sub(filter.From)%bucketDuration != 0 ||
			math.IsNaN(point.BandwidthBPS) || math.IsInf(point.BandwidthBPS, 0) || point.BandwidthBPS < 0 ||
			point.CacheHits > point.Requests || point.CacheMisses > point.Requests-point.CacheHits || point.CacheHitBytes > point.TrafficBytes ||
			point.Status4xx > point.Requests || point.Status5xx > point.Requests-point.Status4xx ||
			point.OriginTotalUS != nil && (math.IsNaN(*point.OriginTotalUS) || math.IsInf(*point.OriginTotalUS, 0) || *point.OriginTotalUS < 0) ||
			point.OriginTrafficBytes != nil || point.OriginBandwidthBPS != nil ||
			seriesRequests > math.MaxUint64-point.Requests || seriesTraffic > math.MaxUint64-point.TrafficBytes {
			return ErrInvalidResponse
		}
		seriesRequests += point.Requests
		seriesTraffic += point.TrafficBytes
	}
	if seriesRequests != result.Summary.Requests || seriesTraffic != result.Summary.TrafficBytes {
		return ErrInvalidResponse
	}
	seenTop := make(map[string]struct{}, len(result.Top))
	for index, item := range result.Top {
		identity := item.Host + ":" + strconv.FormatUint(uint64(item.ListenPort), 10)
		if item.Host == "" || strings.ToLower(item.Host) != item.Host || item.Requests == 0 || item.Requests > result.Summary.Requests ||
			item.TrafficBytes > result.Summary.TrafficBytes ||
			index > 0 && (result.Top[index-1].TrafficBytes < item.TrafficBytes ||
				result.Top[index-1].TrafficBytes == item.TrafficBytes && (result.Top[index-1].Requests < item.Requests ||
					result.Top[index-1].Requests == item.Requests && (result.Top[index-1].Host > item.Host ||
						result.Top[index-1].Host == item.Host && result.Top[index-1].ListenPort >= item.ListenPort))) {
			return ErrInvalidResponse
		}
		if _, exists := seenTop[identity]; exists {
			return ErrInvalidResponse
		}
		seenTop[identity] = struct{}{}
	}
	return nil
}

// validateRealtimeEvidence checks the settlement reconciliation claims.
func validateRealtimeEvidence(result RealtimeResult, filter RealtimeFilter) error {
	evidence := &result.Evidence
	computed := realtimeErrorPPM(evidence.ExpectedEvents, evidence.ObservedEvents)
	if evidence.ErrorPPM != computed {
		return ErrInvalidResponse
	}
	coverage := realtimeCoverageFilter(filter)
	exactCoverage := coverage.From.Equal(filter.From) && coverage.To.Equal(filter.To)
	if evidence.AccessSourceCount != result.Summary.Requests || evidence.ObservedEvents < result.Summary.Requests ||
		exactCoverage && evidence.ObservedEvents != result.Summary.Requests {
		return ErrInvalidResponse
	}
	if !evidence.coverageVerified && (evidence.AccessSourceCount == 0 || evidence.ConnectionSourceCount == 0 || evidence.ExpectedEvents == 0) ||
		evidence.FinalizedThrough.Location() != time.UTC || evidence.SourceWatermark.Location() != time.UTC ||
		evidence.FinalizedThrough.Before(realtimeSettledThrough(coverage, filter.ExcludedWindows)) ||
		evidence.SourceWatermark.Before(realtimeSettledThrough(coverage, filter.ExcludedWindows)) ||
		!exactCoverage && !evidence.coverageVerified {
		return ErrRealtimeEvidenceUnavailable
	}
	if evidence.ConnectionSourceCount == 0 && result.Summary.Connections != 0 {
		return ErrInvalidResponse
	}
	if computed > maximumRealtimeErrorPPM {
		return ErrInvalidResponse
	}
	return nil
}

func validRealtimeMetrics(metrics RealtimeMetrics) bool {
	if math.IsNaN(metrics.BandwidthBPS) || math.IsInf(metrics.BandwidthBPS, 0) || metrics.BandwidthBPS < 0 ||
		math.IsNaN(metrics.AverageDurationUS) || math.IsInf(metrics.AverageDurationUS, 0) || metrics.AverageDurationUS < 0 ||
		math.IsNaN(metrics.OriginConnectUS) || math.IsInf(metrics.OriginConnectUS, 0) || metrics.OriginConnectUS < 0 ||
		math.IsNaN(metrics.OriginFirstByteUS) || math.IsInf(metrics.OriginFirstByteUS, 0) || metrics.OriginFirstByteUS < 0 ||
		math.IsNaN(metrics.OriginTotalUS) || math.IsInf(metrics.OriginTotalUS, 0) || metrics.OriginTotalUS < 0 {
		return false
	}
	if metrics.Status2xx > math.MaxUint64-metrics.Status3xx || metrics.Status2xx+metrics.Status3xx > math.MaxUint64-metrics.Status4xx ||
		metrics.Status2xx+metrics.Status3xx+metrics.Status4xx > math.MaxUint64-metrics.Status5xx ||
		metrics.CacheHits > math.MaxUint64-metrics.CacheMisses {
		return false
	}
	status := metrics.Status2xx + metrics.Status3xx + metrics.Status4xx + metrics.Status5xx
	return status <= metrics.Requests && metrics.CacheHits+metrics.CacheMisses <= metrics.Requests && metrics.Errors <= metrics.Requests &&
		metrics.OriginConnectUS <= metrics.OriginFirstByteUS && metrics.OriginFirstByteUS <= metrics.OriginTotalUS
}

func realtimeErrorPPM(expected, observed uint64) uint64 {
	if expected == 0 {
		if observed == 0 {
			return 0
		}
		return 1_000_000
	}
	delta := expected
	if observed <= expected {
		delta -= observed
	} else {
		delta = observed - expected
	}
	return uint64(math.Round(float64(delta) * 1_000_000 / float64(expected)))
}

type realtimeWireRow struct {
	Kind                  string   `json:"kind"`
	BucketMS              *int64   `json:"bucket_ms"`
	Host                  *string  `json:"host"`
	ListenPort            *uint16  `json:"listen_port"`
	Requests              *uint64  `json:"requests"`
	TrafficBytes          *uint64  `json:"traffic_bytes"`
	BandwidthBPS          *float64 `json:"bandwidth_bps"`
	Connections           *uint64  `json:"connections"`
	Status2xx             *uint64  `json:"status_2xx"`
	Status3xx             *uint64  `json:"status_3xx"`
	Status4xx             *uint64  `json:"status_4xx"`
	Status5xx             *uint64  `json:"status_5xx"`
	CacheHits             *uint64  `json:"cache_hits"`
	CacheMisses           *uint64  `json:"cache_misses"`
	Errors                *uint64  `json:"errors"`
	AverageDurationUS     *float64 `json:"average_duration_us"`
	OriginConnectUS       *float64 `json:"origin_connect_us"`
	OriginFirstByteUS     *float64 `json:"origin_first_byte_us"`
	OriginTotalUS         *float64 `json:"origin_total_us"`
	AccessSourceCount     *uint64  `json:"access_source_count"`
	ConnectionSourceCount *uint64  `json:"connection_source_count"`
	ExpectedEvents        *uint64  `json:"expected_events"`
	ObservedEvents        *uint64  `json:"observed_events"`
	FinalizedThroughMS    *int64   `json:"finalized_through_ms"`
	SourceWatermarkMS     *int64   `json:"source_watermark_ms"`
	CacheHitBytes         *uint64  `json:"cache_hit_bytes"`
}

// GROUPING SETS reads access facts once: the bounding-hour observed count and
// every exact-range projection share that scan, including during late ingestion.
// Expected counts come only from the independent PostgreSQL source authority.
const realtimeSQL = `WITH access_groups AS (
  SELECT multiIf(grouping(time_bucket,dimension_host,dimension_port)=7,'summary',
      grouping(time_bucket)=0,'series','top') kind,
    if(grouping(time_bucket)=0,toInt64(toUnixTimestamp64Milli(toDateTime64(time_bucket,3,'UTC'))),NULL) bucket_ms,
    if(grouping(dimension_host)=0,dimension_host,NULL) host,
    if(grouping(dimension_port)=0,dimension_port,NULL) listen_port,
    toUInt64(countIf(in_range)) requests,
    toUInt64(sumIf(toUInt128(request_bytes)+toUInt128(response_bytes),in_range)) traffic_bytes,
    traffic_bytes*8.0/if(kind='series',
      least(toFloat64({bucket_seconds:UInt32}),(toFloat64({to_ms:UInt64})-toFloat64(bucket_ms))/1000),
      toFloat64({duration_seconds:UInt64})) bandwidth_bps,
    toUInt64(0) connections,
    toUInt64(countIf(in_range AND status_code>=200 AND status_code<300)) status_2xx,
    toUInt64(countIf(in_range AND status_code>=300 AND status_code<400)) status_3xx,
    toUInt64(countIf(in_range AND status_code>=400 AND status_code<500)) status_4xx,
    toUInt64(countIf(in_range AND status_code>=500 AND status_code<600)) status_5xx,
    toUInt64(countIf(in_range AND lower(cache_status)='hit')) cache_hits,
    toUInt64(countIf(in_range AND lower(cache_status)='miss')) cache_misses,
    toUInt64(countIf(in_range AND (status_code>=500 OR upstream_result!=''))) errors,
    ifNull(avgOrNullIf(duration_us,in_range),0) average_duration_us,
    ifNull(avgOrNullIf(ifNull(origin_connect_us,0),in_range),0) origin_connect_us,
    ifNull(avgOrNullIf(ifNull(origin_first_byte_us,0),in_range),0) origin_first_byte_us,
    if(kind='summary',ifNull(avgOrNullIf(ifNull(origin_total_us,0),in_range),0),
      avgOrNullIf(origin_total_us,in_range)) origin_total_us,
    requests access_source_count,toUInt64(0) connection_source_count,toUInt64(0) expected_events,
    toUInt64(count()) observed_events,toInt64(0) finalized_through_ms,toInt64(0) source_watermark_ms,
    toUInt64(sumIf(toUInt128(request_bytes)+toUInt128(response_bytes),in_range AND lower(cache_status)='hit')) cache_hit_bytes
  FROM (
    SELECT *,host dimension_host,listen_port dimension_port,
      occurred_at>=fromUnixTimestamp64Milli({from_ms:UInt64},'UTC') AND
        occurred_at<fromUnixTimestamp64Milli({to_ms:UInt64},'UTC') in_range,
      toStartOfInterval(greatest(occurred_at,fromUnixTimestamp64Milli({from_ms:UInt64},'UTC')),toIntervalSecond({bucket_seconds:UInt32}),
        fromUnixTimestamp64Milli({from_ms:UInt64},'UTC'),'UTC') time_bucket
    FROM access_events FINAL WHERE metric_version=1
      AND ingested_at<=fromUnixTimestamp64Milli({snapshot_ms:UInt64},'UTC')
      AND occurred_at>=fromUnixTimestamp64Milli({coverage_from_ms:UInt64},'UTC')
      AND occurred_at<fromUnixTimestamp64Milli({coverage_to_ms:UInt64},'UTC')
      AND NOT has({excluded_hours_ms:Array(Int64)},toInt64(toUnixTimestamp(toStartOfHour(occurred_at,'UTC')))*1000)
      AND ({tenant_scoped:UInt8}=0 OR tenant_id={tenant_id:UUID}) AND ({has_site:UInt8}=0 OR site_id={site_id:UUID})
      AND ({has_host:UInt8}=0 OR has(splitByChar(' ',{host:String}),host)) AND ({has_port:UInt8}=0 OR listen_port={listen_port:UInt16})
  ) GROUP BY GROUPING SETS ((),(time_bucket),(dimension_host,dimension_port))
)
SELECT * EXCEPT(position) FROM (
  SELECT *,row_number() OVER (PARTITION BY kind ORDER BY traffic_bytes DESC,requests DESC,host,listen_port) position
  FROM access_groups
) WHERE kind='summary' OR (kind='series' AND requests>0) OR (kind='top' AND requests>0 AND position<=10)
UNION ALL
SELECT if(isNull(bucket_ms),'connection_summary','connection_series'),bucket_ms,NULL,NULL,NULL,NULL,NULL,
  toUInt64(sum(latest_connections)),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
  NULL,toUInt64(sum(receipts)),NULL,NULL,toInt64(ifNull(toUnixTimestamp64Milli(max(finalized_through)),0)),NULL,NULL
FROM (
  SELECT tenant_id,node_id,domain,listen_port,maxIf(connections,in_range) latest_connections,
    if(grouping(time_bucket)=0,toInt64(toUnixTimestamp64Milli(toDateTime64(time_bucket,3,'UTC'))),NULL) bucket_ms,
    countIf(in_range) receipts,max(finalized_through) finalized_through
  FROM (
    SELECT *,occurred_at>=fromUnixTimestamp64Milli({from_ms:UInt64},'UTC') AND
      occurred_at<fromUnixTimestamp64Milli({to_ms:UInt64},'UTC') in_range,
      toStartOfInterval(greatest(occurred_at,fromUnixTimestamp64Milli({from_ms:UInt64},'UTC')),toIntervalSecond({bucket_seconds:UInt32}),
      fromUnixTimestamp64Milli({from_ms:UInt64},'UTC'),'UTC') time_bucket
    FROM connections_ingest_receipts_v1 FINAL WHERE schema_version IN (1,2) AND state_rank>=2
      AND updated_at<=fromUnixTimestamp64Milli({snapshot_ms:UInt64},'UTC')
      AND occurred_at>=fromUnixTimestamp64Milli({coverage_from_ms:UInt64},'UTC')
      AND occurred_at<fromUnixTimestamp64Milli({coverage_to_ms:UInt64},'UTC')
      AND NOT has({excluded_hours_ms:Array(Int64)},toInt64(toUnixTimestamp(toStartOfHour(occurred_at,'UTC')))*1000)
      AND ({tenant_scoped:UInt8}=0 OR tenant_id={tenant_id:UUID}) AND ({has_site:UInt8}=0 OR site_id={site_id:UUID})
      AND ({has_host:UInt8}=0 OR has(splitByChar(' ',{host:String}),domain)) AND ({has_port:UInt8}=0 OR listen_port={listen_port:UInt16})
  ) GROUP BY GROUPING SETS ((tenant_id,node_id,domain,listen_port),(tenant_id,node_id,domain,listen_port,time_bucket))
) GROUP BY bucket_ms
HAVING isNull(bucket_ms) OR (bucket_ms>={from_ms:UInt64} AND bucket_ms<{to_ms:UInt64})
FORMAT JSONEachRow`

func (client *Client) Realtime(ctx context.Context, scope Scope, filter RealtimeFilter) (RealtimeResult, error) {
	if client == nil || ctx == nil || !validRealtimeFilter(filter) ||
		validateScopeFilterGranularity(scope, Filter{From: filter.From, To: filter.To, SiteID: filter.SiteID}, time.Minute) != nil {
		return RealtimeResult{}, ErrInvalidInput
	}
	tenantID, tenantScoped := nilUUIDValue, "0"
	if scope.kind == scopeTenant {
		tenantID, tenantScoped = scope.tenantID, "1"
	}
	coverage := realtimeCoverageFilter(filter)
	snapshotAt := time.Now().UTC().Truncate(time.Millisecond)
	parameters := url.Values{
		"param_from_ms": {strconv.FormatInt(filter.From.UnixMilli(), 10)}, "param_to_ms": {strconv.FormatInt(filter.To.UnixMilli(), 10)},
		"param_duration_seconds": {strconv.FormatInt(int64(filter.To.Sub(filter.From)/time.Second), 10)},
		"param_bucket_seconds":   {strconv.FormatUint(uint64(realtimeBucketSeconds(filter)), 10)},
		"param_coverage_from_ms": {strconv.FormatInt(coverage.From.UnixMilli(), 10)},
		"param_coverage_to_ms":   {strconv.FormatInt(coverage.To.UnixMilli(), 10)},
		"param_snapshot_ms":      {strconv.FormatInt(snapshotAt.UnixMilli(), 10)},
		"param_tenant_scoped":    {tenantScoped}, "param_tenant_id": {tenantID},
		"param_has_site": {booleanParameter(filter.SiteID != "")}, "param_site_id": {orNilUUID(filter.SiteID)},
		"param_has_host": {booleanParameter(filter.Host != "")}, "param_host": {filter.Host},
		"param_has_port": {booleanParameter(filter.ListenPort != 0)}, "param_listen_port": {strconv.FormatUint(uint64(filter.ListenPort), 10)},
		"param_excluded_hours_ms": {realtimeExcludedHoursParameter(filter.ExcludedWindows)},
	}
	rows, err := queryRows[realtimeWireRow](client, ctx, realtimeSQL, parameters, 2*maximumRealtimePoints+maximumRealtimeTopItems+2)
	if err != nil {
		return RealtimeResult{}, err
	}
	result, err := realtimeResultFromRows(rows)
	result.SeriesBucketSeconds = realtimeBucketSeconds(filter)
	result.Evidence.CoverageFrom, result.Evidence.CoverageTo = coverage.From, coverage.To
	result.Evidence.SnapshotAt = snapshotAt
	return result, err
}

func realtimeResultFromRows(rows []realtimeWireRow) (RealtimeResult, error) {
	result := RealtimeResult{MetricVersion: MetricVersion, Series: []RealtimePoint{}, Top: []RealtimeTopItem{}}
	seenSummary, seenConnectionSummary := false, false
	connectionSeries := make(map[int64]uint64)
	var connections, connectionSources uint64
	finalizedThrough := time.Unix(0, 0).UTC()
	for _, row := range rows {
		switch row.Kind {
		case "summary":
			if row.OriginTotalUS == nil {
				zero := float64(0)
				row.OriginTotalUS = &zero
			}
			if seenSummary || !rowMetricsPresent(row) || row.AccessSourceCount == nil || row.ObservedEvents == nil {
				return RealtimeResult{}, ErrInvalidResponse
			}
			seenSummary = true
			result.Summary = metricsFromWire(row)
			result.Evidence.AccessSourceCount = *row.AccessSourceCount
			result.Evidence.ObservedEvents = *row.ObservedEvents
		case "series":
			if row.BucketMS == nil || row.Requests == nil || row.TrafficBytes == nil || row.BandwidthBPS == nil || row.Connections == nil ||
				row.CacheHits == nil || row.CacheMisses == nil || row.CacheHitBytes == nil || row.Status4xx == nil || row.Status5xx == nil {
				return RealtimeResult{}, ErrInvalidResponse
			}
			result.Series = append(result.Series, RealtimePoint{Bucket: time.UnixMilli(*row.BucketMS).UTC(), Requests: *row.Requests, TrafficBytes: *row.TrafficBytes, BandwidthBPS: *row.BandwidthBPS, Connections: *row.Connections,
				CacheHits: *row.CacheHits, CacheMisses: *row.CacheMisses, CacheHitBytes: *row.CacheHitBytes,
				Status4xx: *row.Status4xx, Status5xx: *row.Status5xx, OriginTotalUS: row.OriginTotalUS})
		case "top":
			if row.Host == nil || row.ListenPort == nil || row.Requests == nil || row.TrafficBytes == nil {
				return RealtimeResult{}, ErrInvalidResponse
			}
			result.Top = append(result.Top, RealtimeTopItem{Host: *row.Host, ListenPort: *row.ListenPort, Requests: *row.Requests, TrafficBytes: *row.TrafficBytes})
		case "connection_summary":
			if seenConnectionSummary || row.Connections == nil || row.ConnectionSourceCount == nil || row.FinalizedThroughMS == nil {
				return RealtimeResult{}, ErrInvalidResponse
			}
			seenConnectionSummary = true
			connections, connectionSources = *row.Connections, *row.ConnectionSourceCount
			finalizedThrough = time.UnixMilli(*row.FinalizedThroughMS).UTC()
		case "connection_series":
			if row.BucketMS == nil || row.Connections == nil {
				return RealtimeResult{}, ErrInvalidResponse
			}
			if _, exists := connectionSeries[*row.BucketMS]; exists {
				return RealtimeResult{}, ErrInvalidResponse
			}
			connectionSeries[*row.BucketMS] = *row.Connections
		default:
			return RealtimeResult{}, ErrInvalidResponse
		}
	}
	if !seenSummary {
		return RealtimeResult{}, ErrInvalidResponse
	}
	result.Summary.Connections = connections
	result.Evidence.ConnectionSourceCount = connectionSources
	result.Evidence.FinalizedThrough = finalizedThrough
	result.Evidence.SourceWatermark = time.Unix(0, 0).UTC()
	result.Evidence.ErrorPPM = realtimeErrorPPM(0, result.Evidence.ObservedEvents)
	for index := range result.Series {
		result.Series[index].Connections = connectionSeries[result.Series[index].Bucket.UnixMilli()]
	}
	sort.Slice(result.Series, func(i, j int) bool { return result.Series[i].Bucket.Before(result.Series[j].Bucket) })
	sort.Slice(result.Top, func(i, j int) bool {
		if result.Top[i].TrafficBytes != result.Top[j].TrafficBytes {
			return result.Top[i].TrafficBytes > result.Top[j].TrafficBytes
		}
		if result.Top[i].Requests != result.Top[j].Requests {
			return result.Top[i].Requests > result.Top[j].Requests
		}
		if result.Top[i].Host != result.Top[j].Host {
			return result.Top[i].Host < result.Top[j].Host
		}
		return result.Top[i].ListenPort < result.Top[j].ListenPort
	})
	return result, nil
}

func rowMetricsPresent(row realtimeWireRow) bool {
	return row.Requests != nil && row.TrafficBytes != nil && row.BandwidthBPS != nil && row.Connections != nil &&
		row.Status2xx != nil && row.Status3xx != nil && row.Status4xx != nil && row.Status5xx != nil && row.CacheHits != nil &&
		row.CacheMisses != nil && row.Errors != nil && row.AverageDurationUS != nil && row.OriginConnectUS != nil &&
		row.OriginFirstByteUS != nil && row.OriginTotalUS != nil
}

func metricsFromWire(row realtimeWireRow) RealtimeMetrics {
	return RealtimeMetrics{Requests: *row.Requests, TrafficBytes: *row.TrafficBytes, BandwidthBPS: *row.BandwidthBPS,
		Connections: *row.Connections, Status2xx: *row.Status2xx, Status3xx: *row.Status3xx, Status4xx: *row.Status4xx,
		Status5xx: *row.Status5xx, CacheHits: *row.CacheHits, CacheMisses: *row.CacheMisses, Errors: *row.Errors,
		AverageDurationUS: *row.AverageDurationUS, OriginConnectUS: *row.OriginConnectUS,
		OriginFirstByteUS: *row.OriginFirstByteUS, OriginTotalUS: *row.OriginTotalUS}
}

func realtimeExcludedHoursParameter(windows []time.Time) string {
	encoded := make([]string, len(windows))
	for index, window := range windows {
		encoded[index] = strconv.FormatInt(window.UnixMilli(), 10)
	}
	return "[" + strings.Join(encoded, ",") + "]"
}

// realtimeSettledThrough is the end of the latest enclosing hour that is not
// excluded, or the zero time when every hour is excluded.
func realtimeSettledThrough(coverage RealtimeFilter, excluded []time.Time) time.Time {
	for end := coverage.To; end.After(coverage.From); end = end.Add(-time.Hour) {
		if !slices.ContainsFunc(excluded, func(window time.Time) bool { return window.Equal(end.Add(-time.Hour)) }) {
			return end
		}
	}
	return time.Time{}
}

func booleanParameter(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
func orNilUUID(value string) string {
	if value == "" {
		return nilUUIDValue
	}
	return strings.ToLower(value)
}
