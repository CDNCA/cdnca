package analytics

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHandlerQueryTimeout = 6 * time.Second
	defaultHandlerMaxResponse  = 1 << 20
	maximumHandlerQueryTimeout = 30 * time.Second
	maximumHandlerRawQuery     = 16 << 10
	maximumHandlerResponse     = 4 << 20
)

var (
	ErrInvalidHandlerConfig = errors.New("invalid analytics handler configuration")
	errHandlerResponseLimit = errors.New("analytics handler response too large")
	requestIDPattern        = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

type AuthenticateFunc func(*http.Request) (Actor, error)

type HandlerConfig struct {
	QueryTimeout     time.Duration
	MaxResponseBytes int
	Logger           *slog.Logger
}

type Handler struct {
	service          *Service
	authenticate     AuthenticateFunc
	queryTimeout     time.Duration
	maxResponseBytes int
	logger           *slog.Logger
}

type handlerRoute struct {
	audience  Audience
	operation string
	dimension RankDimension
}

type requestIDContextKey struct{}

type queryMetadata struct {
	From          string `json:"from"`
	To            string `json:"to"`
	Timezone      string `json:"timezone"`
	MetricVersion uint16 `json:"metric_version"`
}

type analyticsSummaryResponse struct {
	Data Summary       `json:"data"`
	Meta queryMetadata `json:"meta"`
}

type peakBandwidthResponse struct {
	Data PeakBandwidth `json:"data"`
	Meta queryMetadata `json:"meta"`
}

type blockedIPCountResponse struct {
	Data uint64        `json:"blocked_ip_count"`
	Meta queryMetadata `json:"meta"`
}

type blockedIPTrendResponse struct {
	Data []blockedIPTrendResponsePoint `json:"data"`
	Meta queryMetadata                 `json:"meta"`
}

type wafOverviewResponse struct {
	Data WAFOverview   `json:"data"`
	Meta queryMetadata `json:"meta"`
}

type blockedIPTrendResponsePoint struct {
	Hour           string `json:"hour"`
	BlockedIPCount uint64 `json:"blocked_ip_count"`
}

type trendResponse struct {
	Data []trendResponsePoint `json:"data"`
	Meta queryMetadata        `json:"meta"`
}

type trendResponsePoint struct {
	Hour                string  `json:"hour"`
	MetricVersion       uint16  `json:"metric_version"`
	RequestCount        uint64  `json:"request_count"`
	RequestBytes        uint64  `json:"request_bytes"`
	ResponseBytes       uint64  `json:"response_bytes"`
	TotalBytes          uint64  `json:"total_bytes"`
	AverageBandwidthBPS float64 `json:"average_bandwidth_bps"`
	Status2xx           uint64  `json:"status_2xx"`
	Status3xx           uint64  `json:"status_3xx"`
	Status4xx           uint64  `json:"status_4xx"`
	Status5xx           uint64  `json:"status_5xx"`
	SecurityEvents      uint64  `json:"security_events"`
	SecurityEventRows   uint64  `json:"security_event_rows"`
	CacheHitRequests    uint64  `json:"cache_hit_requests"`
	CacheHitBytes       uint64  `json:"cache_hit_bytes"`
	UniqueClientIPs     uint64  `json:"unique_client_ips"`
}

type rankResponse struct {
	Data      []RankItem    `json:"data"`
	Dimension RankDimension `json:"dimension"`
	Page      rankPageMeta  `json:"page"`
	Meta      queryMetadata `json:"meta"`
}

type rankPageMeta struct {
	NextCursor string `json:"next_cursor,omitempty"`
	SnapshotAt string `json:"snapshot_at"`
	// RetainedFrom: the ranking only covers [retained_from, to); older data
	// of this dimension has passed its retention (absent: whole range).
	RetainedFrom string `json:"retained_from,omitempty"`
	// Source is where the dimension is ranked from: "history" (hourly facts,
	// bandwidth_history_days) or "access_log" (access_logs_days).
	Source string `json:"source"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func NewHandler(service *Service, authenticate AuthenticateFunc, config HandlerConfig) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidHandlerConfig
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultHandlerQueryTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultHandlerMaxResponse
	}
	if config.QueryTimeout <= 0 || config.QueryTimeout > maximumHandlerQueryTimeout ||
		config.MaxResponseBytes < 512 || config.MaxResponseBytes > maximumHandlerResponse {
		return nil, ErrInvalidHandlerConfig
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Handler{
		service: service, authenticate: authenticate, queryTimeout: config.QueryTimeout,
		maxResponseBytes: config.MaxResponseBytes, logger: config.Logger,
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := RequestIDFromContext(request.Context())
	if requestID == "" && requestIDPattern.MatchString(request.Header.Get("X-Request-ID")) {
		requestID = request.Header.Get("X-Request-ID")
	}
	if requestID == "" {
		requestID = newRequestID()
	}
	request = request.WithContext(WithRequestID(request.Context(), requestID))
	writer.Header().Set("X-Request-ID", requestID)
	writer.Header().Set("Cache-Control", "no-store")
	if request.URL == nil || len(request.URL.RawQuery) > maximumHandlerRawQuery {
		handler.writeServiceError(writer, request, ErrInvalidInput)
		return
	}

	route, ok := resolveHandlerRoute(request.URL.Path)
	if !ok {
		handler.writeError(writer, request, http.StatusNotFound, "analytics_route_not_found", "analytics route was not found", nil)
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		handler.writeError(writer, request, http.StatusMethodNotAllowed, "analytics_method_not_allowed", "analytics route requires GET", nil)
		return
	}
	if err := validateHandlerRawQuery(request.URL.RawQuery); err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	parentContext := request.Context()
	ctx, cancel := context.WithTimeout(parentContext, handler.queryTimeout)
	defer cancel()
	request = request.WithContext(ctx)
	requestContextError := func() error {
		if err := parentContext.Err(); err != nil {
			return err
		}
		return ctx.Err()
	}
	if err := requestContextError(); err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	actor, err := handler.authenticate(request)
	if err != nil {
		if requestErr := requestContextError(); requestErr != nil {
			handler.writeServiceError(writer, request, requestErr)
			return
		}
		handler.writeError(writer, request, http.StatusUnauthorized, "analytics_authentication_required", "authentication is required", nil)
		return
	}
	if requestErr := requestContextError(); requestErr != nil {
		handler.writeServiceError(writer, request, requestErr)
		return
	}
	queryRequest, limit, cursor, err := parseHandlerQuery(request, route)
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	if requestErr := requestContextError(); requestErr != nil {
		handler.writeServiceError(writer, request, requestErr)
		return
	}
	switch route.operation {
	case "summary":
		result, err := handler.service.Summary(ctx, actor, queryRequest)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		if requestErr := requestContextError(); requestErr != nil {
			handler.writeServiceError(writer, request, requestErr)
			return
		}
		handler.writeResult(writer, request, analyticsSummaryResponse{Data: result, Meta: metadataFor(queryRequest)})
	case "blocked_ip_count":
		result, err := handler.service.BlockedIPCount(ctx, actor, queryRequest)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		if requestErr := requestContextError(); requestErr != nil {
			handler.writeServiceError(writer, request, requestErr)
			return
		}
		handler.writeResult(writer, request, blockedIPCountResponse{Data: result, Meta: metadataFor(queryRequest)})
	case "peak_bandwidth":
		result, err := handler.service.PeakBandwidth(ctx, actor, queryRequest)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		if requestErr := requestContextError(); requestErr != nil {
			handler.writeServiceError(writer, request, requestErr)
			return
		}
		handler.writeResult(writer, request, peakBandwidthResponse{Data: result, Meta: metadataFor(queryRequest)})
	case "blocked_ip_trend":
		result, err := handler.service.BlockedIPTrend(ctx, actor, queryRequest)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		if requestErr := requestContextError(); requestErr != nil {
			handler.writeServiceError(writer, request, requestErr)
			return
		}
		points := make([]blockedIPTrendResponsePoint, len(result))
		for index, point := range result {
			points[index] = blockedIPTrendResponsePoint{Hour: point.Hour.UTC().Format(time.RFC3339Nano), BlockedIPCount: point.BlockedIPCount}
		}
		handler.writeResult(writer, request, blockedIPTrendResponse{Data: points, Meta: metadataFor(queryRequest)})
	case "waf_overview":
		result, err := handler.service.WAFOverview(ctx, actor, queryRequest)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		if requestErr := requestContextError(); requestErr != nil {
			handler.writeServiceError(writer, request, requestErr)
			return
		}
		if result.Trend == nil {
			result.Trend = []WAFTrendPoint{}
		}
		handler.writeResult(writer, request, wafOverviewResponse{Data: result, Meta: metadataFor(queryRequest)})
	case "trend":
		result, err := handler.service.Trend(ctx, actor, queryRequest)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		if requestErr := requestContextError(); requestErr != nil {
			handler.writeServiceError(writer, request, requestErr)
			return
		}
		points := make([]trendResponsePoint, len(result))
		for index, point := range result {
			points[index] = responseTrendPoint(point)
		}
		handler.writeResult(writer, request, trendResponse{Data: points, Meta: metadataFor(queryRequest)})
	case "rank":
		result, err := handler.service.Rank(ctx, actor, queryRequest, route.dimension, limit, cursor)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		if requestErr := requestContextError(); requestErr != nil {
			handler.writeServiceError(writer, request, requestErr)
			return
		}
		if result.SnapshotAt.IsZero() {
			handler.writeServiceError(writer, request, ErrInvalidResponse)
			return
		}
		if result.Items == nil {
			result.Items = []RankItem{}
		}
		handler.writeResult(writer, request, rankResponse{
			Data: result.Items, Dimension: route.dimension,
			Page: rankPageMeta{NextCursor: result.NextCursor, SnapshotAt: result.SnapshotAt.UTC().Format(time.RFC3339Nano),
				RetainedFrom: formatOptionalTime(result.RetainedFrom), Source: rankSource(route.dimension)},
			Meta: metadataFor(queryRequest),
		})
	case "realtime":
		realtimeRequest := RealtimeRequest{
			Audience: route.audience, TenantID: queryRequest.TenantID, From: queryRequest.From, To: queryRequest.To,
			SiteID: queryRequest.SiteID, Host: request.URL.Query().Get("host"), ListenPort: uint16(limit),
			// Only query_version=3 clients understand coverage fields; cached
			// v1/v2 clients keep the strict all-hours-settled contract.
			AllowPartialCoverage: request.URL.Query().Get("query_version") == "3",
			Live:                 request.URL.Query().Get("query_version") == "4",
		}
		result, err := handler.service.Realtime(ctx, actor, realtimeRequest)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		if requestErr := requestContextError(); requestErr != nil {
			handler.writeServiceError(writer, request, requestErr)
			return
		}
		switch request.URL.Query().Get("query_version") {
		case "3":
			handler.writeResult(writer, request, realtimeCoverageResponseFor(result, metadataFor(queryRequest), 3))
		case "4":
			handler.writeResult(writer, request, realtimeCoverageResponseFor(result, metadataFor(queryRequest), 4))
		case "2":
			handler.writeResult(writer, request, realtimeMinuteResponse{Data: result,
				Meta: realtimeMinuteMetadata{queryMetadata: metadataFor(queryRequest), QueryVersion: 2}})
		default:
			handler.writeResult(writer, request, legacyRealtimeResponse(result, metadataFor(queryRequest)))
		}
	}
}

func validateHandlerRawQuery(rawQuery string) error {
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ErrInvalidInput
	}
	for _, values := range query {
		if len(values) != 1 {
			return ErrInvalidInput
		}
	}
	return nil
}

func WithRequestID(ctx context.Context, requestID string) context.Context {
	if !requestIDPattern.MatchString(requestID) {
		return ctx
	}
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

func RequestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	if !requestIDPattern.MatchString(requestID) {
		return ""
	}
	return requestID
}

func resolveHandlerRoute(path string) (handlerRoute, bool) {
	for _, prefix := range []struct {
		value    string
		audience Audience
	}{
		{value: "/v1/admin/analytics/", audience: AudiencePlatform},
		{value: "/v1/analytics/", audience: AudienceTenant},
	} {
		suffix, ok := strings.CutPrefix(path, prefix.value)
		if !ok {
			continue
		}
		switch suffix {
		case "summary":
			return handlerRoute{audience: prefix.audience, operation: "summary"}, true
		case "blocked-ip-count":
			return handlerRoute{audience: prefix.audience, operation: "blocked_ip_count"}, true
		case "blocked-ip-trend":
			return handlerRoute{audience: prefix.audience, operation: "blocked_ip_trend"}, true
		case "peak-bandwidth":
			return handlerRoute{audience: prefix.audience, operation: "peak_bandwidth"}, true
		case "waf-overview":
			return handlerRoute{audience: prefix.audience, operation: "waf_overview"}, true
		case "hourly-trend":
			return handlerRoute{audience: prefix.audience, operation: "trend"}, true
		case "site-realtime":
			return handlerRoute{audience: prefix.audience, operation: "realtime"}, true
		}
		dimension, ok := strings.CutPrefix(suffix, "top/")
		if !ok || dimension == "" || strings.ContainsRune(dimension, '/') {
			return handlerRoute{}, false
		}
		parsed, err := parseRankDimension(dimension)
		if err != nil {
			return handlerRoute{audience: prefix.audience, operation: "rank", dimension: RankDimension(dimension)}, true
		}
		return handlerRoute{audience: prefix.audience, operation: "rank", dimension: parsed}, true
	}
	return handlerRoute{}, false
}

func parseRankDimension(value string) (RankDimension, error) {
	dimension := RankDimension(value)
	switch dimension {
	case RankByURL, RankByIP, RankByDomain, RankByRegion, RankByCarrier, RankByJA4, RankByReferer,
		RankByProvince, RankByBrowser, RankByOS:
		return dimension, nil
	default:
		return dimension, ErrDimensionUnsupported
	}
}

func parseHandlerQuery(request *http.Request, route handlerRoute) (QueryRequest, uint16, string, error) {
	allowed := map[string]bool{
		"from": true, "to": true, "tenant_id": true, "site_id": true, "node_id": true,
	}
	if route.operation == "realtime" {
		allowed["host"] = true
		allowed["listen_port"] = true
		allowed["query_version"] = true
	}
	if route.operation == "rank" || route.operation == "waf_overview" {
		allowed["domain"] = true
	}
	if route.operation == "rank" {
		allowed["limit"] = true
		allowed["cursor"] = true
		allowed["listen_port"] = true
	}
	query := request.URL.Query()
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return QueryRequest{}, 0, "", ErrInvalidInput
		}
	}
	if tenantValues, present := query["tenant_id"]; present {
		if route.audience == AudienceTenant {
			return QueryRequest{}, 0, "", ErrScopeForbidden
		}
		if tenantValues[0] == "" {
			return QueryRequest{}, 0, "", ErrInvalidInput
		}
	}
	from, err := time.Parse(time.RFC3339, query.Get("from"))
	if err != nil {
		return QueryRequest{}, 0, "", ErrInvalidInput
	}
	to, err := time.Parse(time.RFC3339, query.Get("to"))
	if err != nil {
		return QueryRequest{}, 0, "", ErrInvalidInput
	}
	if route.operation == "realtime" {
		version, present := query["query_version"]
		if present && version[0] != "2" && version[0] != "3" && version[0] != "4" || !present &&
			(!from.Equal(from.Truncate(time.Hour)) || !to.Equal(to.Truncate(time.Hour))) {
			return QueryRequest{}, 0, "", ErrInvalidInput
		}
	}
	if route.operation == "rank" {
		if _, err := parseRankDimension(string(route.dimension)); err != nil {
			return QueryRequest{}, 0, "", err
		}
	}
	domain := strings.ToLower(strings.TrimSuffix(query.Get("domain"), "."))
	if route.operation == "rank" {
		var ok bool
		domain, ok = normalizeRankDomainFilter(query.Get("domain"))
		if !ok {
			return QueryRequest{}, 0, "", ErrInvalidInput
		}
	}
	requestFilter := QueryRequest{
		Audience: route.audience, TenantID: query.Get("tenant_id"), From: from.UTC(), To: to.UTC(),
		SiteID: query.Get("site_id"), Domain: domain, NodeID: query.Get("node_id"),
	}
	if route.operation == "realtime" || route.operation == "rank" {
		if requestFilter.NodeID != "" {
			if route.operation == "realtime" {
				return QueryRequest{}, 0, "", ErrInvalidInput
			}
		}
		port := uint64(0)
		if raw := query.Get("listen_port"); raw != "" {
			port, err = strconv.ParseUint(raw, 10, 16)
			if err != nil || port == 0 {
				return QueryRequest{}, 0, "", ErrInvalidInput
			}
		}
		if route.operation == "realtime" {
			return requestFilter, uint16(port), "", nil
		}
		requestFilter.ListenPort = uint16(port)
	}
	if route.operation != "rank" {
		return requestFilter, 0, "", nil
	}
	limit := uint64(20)
	if raw := query.Get("limit"); raw != "" {
		limit, err = strconv.ParseUint(raw, 10, 16)
		if err != nil || limit == 0 || limit > uint64(maxRankLimit) {
			return QueryRequest{}, 0, "", ErrInvalidInput
		}
	}
	cursor := query.Get("cursor")
	if len(cursor) > maxCursorSize {
		return QueryRequest{}, 0, "", ErrInvalidInput
	}
	return requestFilter, uint16(limit), cursor, nil
}

func metadataFor(request QueryRequest) queryMetadata {
	return queryMetadata{
		From: request.From.UTC().Format(time.RFC3339Nano), To: request.To.UTC().Format(time.RFC3339Nano),
		Timezone: "UTC", MetricVersion: MetricVersion,
	}
}

func responseTrendPoint(point TrendPoint) trendResponsePoint {
	return trendResponsePoint{
		Hour: point.Hour.UTC().Format(time.RFC3339Nano), MetricVersion: point.MetricVersion,
		RequestCount: point.RequestCount, RequestBytes: point.RequestBytes, ResponseBytes: point.ResponseBytes,
		TotalBytes: point.TotalBytes, AverageBandwidthBPS: point.AverageBandwidthBPS,
		Status2xx: point.Status2xx, Status3xx: point.Status3xx, Status4xx: point.Status4xx,
		Status5xx: point.Status5xx, SecurityEvents: point.SecurityEvents, SecurityEventRows: point.SecurityEventRows,
		CacheHitRequests: point.CacheHitRequests, CacheHitBytes: point.CacheHitBytes, UniqueClientIPs: point.UniqueClientIPs,
	}
}

func (handler *Handler) writeResult(writer http.ResponseWriter, request *http.Request, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		handler.writeServiceError(writer, request, ErrInvalidResponse)
		return
	}
	if len(encoded)+1 > handler.maxResponseBytes {
		handler.writeServiceError(writer, request, errHandlerResponseLimit)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(append(encoded, '\n'))
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, request *http.Request, err error) {
	status, code, message := publicAnalyticsError(err)
	handler.writeError(writer, request, status, code, message, err)
}

func (handler *Handler) writeError(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	code string,
	message string,
	_ error,
) {
	if status >= 500 {
		handler.logger.ErrorContext(request.Context(), "analytics query failed",
			"request_id", RequestIDFromContext(request.Context()), "code", code, "path", request.URL.Path,
		)
	}
	encoded, _ := json.Marshal(errorEnvelope{Error: apiError{
		Code: code, Message: message, RequestID: RequestIDFromContext(request.Context()),
	}})
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}

func publicAnalyticsError(err error) (int, string, string) {
	var storageError *HTTPError
	switch {
	case errors.Is(err, ErrInvalidInput):
		return http.StatusBadRequest, "analytics_invalid_request", "analytics query parameters are invalid"
	case errors.Is(err, ErrPermissionDenied):
		return http.StatusForbidden, "analytics_permission_denied", "analytics read permission is required"
	case errors.Is(err, ErrScopeForbidden):
		return http.StatusForbidden, "analytics_scope_forbidden", "analytics scope is not available to this identity"
	case errors.Is(err, ErrDimensionUnsupported):
		return http.StatusUnprocessableEntity, "analytics_dimension_unsupported", "analytics dimension is not supported"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "analytics_query_timeout", "analytics query timed out"
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout, "analytics_request_cancelled", "analytics request was cancelled"
	case errors.Is(err, ErrTransport):
		return http.StatusServiceUnavailable, "analytics_storage_unavailable", "analytics storage is unavailable"
	case errors.As(err, &storageError) && storageError.Retryable():
		return http.StatusServiceUnavailable, "analytics_storage_unavailable", "analytics storage is unavailable"
	case errors.As(err, &storageError):
		return http.StatusBadGateway, "analytics_storage_rejected", "analytics storage rejected the query"
	case errors.Is(err, ErrResponseTooLarge), errors.Is(err, errHandlerResponseLimit):
		return http.StatusBadGateway, "analytics_response_too_large", "analytics query response exceeded its limit"
	case errors.Is(err, ErrInvalidResponse):
		return http.StatusBadGateway, "analytics_storage_invalid_response", "analytics storage returned an invalid response"
	case errors.Is(err, ErrRealtimeEvidenceUnavailable):
		return http.StatusServiceUnavailable, "analytics_realtime_evidence_unavailable", "analytics realtime evidence is not finalized"
	default:
		return http.StatusInternalServerError, "analytics_internal_error", "analytics query could not be completed"
	}
}

func newRequestID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err == nil {
		return hex.EncodeToString(raw)
	}
	return "analytics-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func rankSource(dimension RankDimension) string {
	if HistoryRankable(dimension) {
		return "history"
	}
	return "access_log"
}
