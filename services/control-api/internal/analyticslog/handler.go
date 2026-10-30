package analyticslog

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
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHandlerTimeout     = 6 * time.Second
	defaultHandlerMaxResponse = 1 << 20
	maximumHandlerResponse    = 1 << 20
	maximumRawQueryBytes      = 8192
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

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
	// ipIntel adds the client address' carrier / region / ASN / IDC to
	// access and block rows (nil: rows go out without it).
	ipIntel IPIntelLookup
	// eventNames adds site_domain and rule_name to block rows (nil: "").
	eventNames EventNameLookup
	// nodeNames adds node_name to platform access rows (nil: "").
	nodeNames NodeNameLookup
}

// SetIPIntelLookup makes access and block log rows carry ip_intel.
func (handler *Handler) SetIPIntelLookup(lookup IPIntelLookup) { handler.ipIntel = lookup }

func (handler *Handler) lookupIPIntel(ctx context.Context, addresses []string) map[string]*IPInfo {
	if handler.ipIntel == nil || len(addresses) == 0 {
		return nil
	}
	return handler.ipIntel.Lookup(ctx, addresses)
}

type routeKind uint8

const (
	routeInvalid routeKind = iota
	routeAccess
	routeBlockEvent
	routeBlockStateUnsupported
	routeCCBan
	routeAccessExportCollection
	routeAccessExportItem
	routeAccessExportGrant
	routeAccessExportDownload
)

type handlerRoute struct {
	audience   Audience
	kind       routeKind
	resourceID string
}

type requestIDKey struct{}
type traceIDKey struct{}

type queryMetadata struct {
	From                   string `json:"from"`
	To                     string `json:"to"`
	Timezone               string `json:"timezone"`
	SnapshotAt             string `json:"snapshot_at,omitempty"`
	NextCursor             string `json:"next_cursor,omitempty"`
	Consistency            string `json:"consistency"`
	ReplacementConsistency string `json:"replacement_consistency"`
	Pagination             string `json:"pagination"`
}

type accessResponseItem struct {
	AccessLog
	OccurredAt string  `json:"occurred_at"`
	IPIntel    *IPInfo `json:"ip_intel,omitempty"`
	// NodeName names node_id on platform rows ("" when unknown); tenant rows omit it.
	NodeName *string `json:"node_name,omitempty"`
}

type blockEventResponseItem struct {
	BlockEvent
	OccurredAt string  `json:"occurred_at"`
	IPIntel    *IPInfo `json:"ip_intel,omitempty"`
	// SiteDomain and RuleName name site_id and rule_id ("" when unknown, P14).
	SiteDomain string `json:"site_domain"`
	RuleName   string `json:"rule_name"`
}

type accessResponse struct {
	Data []accessResponseItem `json:"data"`
	Meta queryMetadata        `json:"meta"`
}

type ccBanResponse struct {
	Data      []CCBan       `json:"data"`
	Truncated bool          `json:"truncated"`
	Meta      queryMetadata `json:"meta"`
}

type blockEventResponse struct {
	Data []blockEventResponseItem `json:"data"`
	Meta queryMetadata            `json:"meta"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	TraceID   string `json:"trace_id"`
}

func NewHandler(service *Service, authenticate AuthenticateFunc, config HandlerConfig) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultHandlerTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultHandlerMaxResponse
	}
	if config.QueryTimeout <= 0 || config.QueryTimeout > 30*time.Second || config.MaxResponseBytes < 512 ||
		config.MaxResponseBytes > maximumHandlerResponse {
		return nil, ErrInvalidConfiguration
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
	traceID := traceIDFromRequest(request, requestID)
	request = request.WithContext(withTraceID(request.Context(), traceID))
	writer.Header().Set("X-Request-ID", requestID)
	writer.Header().Set("X-Trace-ID", traceID)
	writer.Header().Set("Cache-Control", "no-store")

	route, ok := resolveRoute(request.URL.Path)
	if !ok || !routeAllowsMethod(route.kind, request.Method) {
		handler.writeError(writer, request, http.StatusNotFound, "analytics_logs_route_not_found", "analytics log route was not found")
		return
	}
	if request.Method == http.MethodGet && getRequestHasBody(request) {
		handler.writeServiceError(writer, request, ErrInvalidInput)
		return
	}
	actor, err := handler.authenticate(request)
	if err != nil {
		handler.writeError(writer, request, http.StatusUnauthorized, "analytics_logs_authentication_required", "authentication is required")
		return
	}
	if route.kind == routeBlockStateUnsupported {
		tenantID, err := parseUnsupportedScope(request, route.audience)
		if err == nil {
			err = handler.service.Unsupported(actor, route.audience, tenantID)
		}
		if err != nil {
			handler.writeServiceError(writer, request, err)
		}
		return
	}
	if route.kind >= routeAccessExportCollection {
		ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
		defer cancel()
		handler.serveAccessExport(writer, request.WithContext(ctx), actor, route)
		return
	}

	query, err := parseQuery(request, route)
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	request = request.WithContext(ctx)
	switch route.kind {
	case routeAccess:
		page, err := handler.service.ListAccess(ctx, actor, query)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		addresses := make([]string, len(page.Items))
		for index, item := range page.Items {
			addresses[index] = item.ClientIP
		}
		intel := handler.lookupIPIntel(ctx, addresses)
		var nodeNames map[string]string
		if route.audience == AudiencePlatform {
			nodeNames = handler.lookupNodeNames(ctx, page.Items)
		}
		items := make([]accessResponseItem, len(page.Items))
		for index, item := range page.Items {
			item.URIPath = safeURIPath(item.URIPath)
			items[index] = accessResponseItem{AccessLog: item, OccurredAt: item.OccurredAt.UTC().Format(time.RFC3339Nano),
				IPIntel: intel[item.ClientIP]}
			if nodeNames != nil {
				name := nodeNameOf(nodeNames, item.NodeID)
				items[index].NodeName = &name
			}
		}
		handler.writeResult(writer, request, accessResponse{Data: items, Meta: responseMeta(query.Filter, page.SnapshotAt, page.NextCursor)})
	case routeBlockEvent:
		page, err := handler.service.ListBlockEvents(ctx, actor, query)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		addresses := make([]string, len(page.Items))
		for index, item := range page.Items {
			addresses[index] = item.ClientIP
		}
		intel := handler.lookupIPIntel(ctx, addresses)
		tenantID := actor.TenantID
		if route.audience == AudiencePlatform {
			tenantID = query.TenantID
		}
		names := handler.lookupEventNames(ctx, strings.ToLower(tenantID), page.Items)
		items := make([]blockEventResponseItem, len(page.Items))
		for index, item := range page.Items {
			item.URIPath = safeURIPath(item.URIPath)
			items[index] = blockEventResponseItem{BlockEvent: item, OccurredAt: item.OccurredAt.UTC().Format(time.RFC3339Nano),
				IPIntel: intel[item.ClientIP], SiteDomain: names.Sites[strings.ToLower(item.SiteID)],
				RuleName: names.rule(item.PolicyID, item.RuleID)}
		}
		handler.writeResult(writer, request, blockEventResponse{Data: items, Meta: responseMeta(query.Filter, page.SnapshotAt, page.NextCursor)})
	case routeCCBan:
		page, err := handler.service.ListCCBans(ctx, actor, query)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		handler.writeResult(writer, request, ccBanResponse{Data: page.Items, Truncated: page.Truncated,
			Meta: responseMeta(query.Filter, page.SnapshotAt, "")})
	}
}

func routeAllowsMethod(kind routeKind, method string) bool {
	switch kind {
	case routeAccess, routeBlockEvent, routeBlockStateUnsupported, routeCCBan, routeAccessExportItem, routeAccessExportDownload:
		return method == http.MethodGet
	case routeAccessExportCollection:
		return method == http.MethodGet || method == http.MethodPost
	case routeAccessExportGrant:
		return method == http.MethodPost
	default:
		return false
	}
}

func getRequestHasBody(request *http.Request) bool {
	return request == nil || request.URL == nil || len(request.URL.RawQuery) > maximumRawQueryBytes ||
		request.ContentLength != 0 || len(request.TransferEncoding) != 0
}

func WithRequestID(ctx context.Context, requestID string) context.Context {
	if !requestIDPattern.MatchString(requestID) {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey{}, requestID)
}

func RequestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDKey{}).(string)
	if !requestIDPattern.MatchString(requestID) {
		return ""
	}
	return requestID
}

func withTraceID(ctx context.Context, traceID string) context.Context {
	if !requestIDPattern.MatchString(traceID) {
		return ctx
	}
	return context.WithValue(ctx, traceIDKey{}, traceID)
}

func traceIDFromContext(ctx context.Context) string {
	traceID, _ := ctx.Value(traceIDKey{}).(string)
	if !requestIDPattern.MatchString(traceID) {
		return ""
	}
	return traceID
}

func traceIDFromRequest(request *http.Request, fallback string) string {
	if traceID := traceIDFromContext(request.Context()); traceID != "" {
		return traceID
	}
	values := request.Header.Values("X-Trace-ID")
	if len(values) == 1 && requestIDPattern.MatchString(values[0]) {
		return values[0]
	}
	return fallback
}

func resolveRoute(path string) (handlerRoute, bool) {
	for _, prefix := range []struct {
		value    string
		audience Audience
	}{
		{value: "/v1/admin/analytics/logs/", audience: AudiencePlatform},
		{value: "/v1/analytics/logs/", audience: AudienceTenant},
	} {
		suffix, ok := strings.CutPrefix(path, prefix.value)
		if !ok {
			continue
		}
		switch suffix {
		case "access":
			return handlerRoute{audience: prefix.audience, kind: routeAccess}, true
		case "access/exports":
			return handlerRoute{audience: prefix.audience, kind: routeAccessExportCollection}, true
		case "block-events":
			return handlerRoute{audience: prefix.audience, kind: routeBlockEvent}, true
		case "cc-bans":
			return handlerRoute{audience: prefix.audience, kind: routeCCBan}, true
		case "blocks/current", "blocks/current-count", "blocks/history":
			return handlerRoute{audience: prefix.audience, kind: routeBlockStateUnsupported}, true
		default:
			parts := strings.Split(suffix, "/")
			if len(parts) >= 3 && parts[0] == "access" && parts[1] == "exports" && validUUID(parts[2]) {
				switch {
				case len(parts) == 3:
					return handlerRoute{audience: prefix.audience, kind: routeAccessExportItem, resourceID: parts[2]}, true
				case len(parts) == 4 && parts[3] == "download-grants":
					return handlerRoute{audience: prefix.audience, kind: routeAccessExportGrant, resourceID: parts[2]}, true
				case len(parts) == 4 && parts[3] == "download":
					return handlerRoute{audience: prefix.audience, kind: routeAccessExportDownload, resourceID: parts[2]}, true
				}
			}
			return handlerRoute{}, false
		}
	}
	return handlerRoute{}, false
}

func parseQuery(request *http.Request, route handlerRoute) (QueryRequest, error) {
	allowed := map[string]bool{
		"from": true, "to": true, "tenant_id": true, "site_id": true, "host": true, "node_id": true,
		"client_ip": true, "uri_path": true, "uri_path_match": true, "status_code": true, "country_code": true, "carrier": true,
		"ja4": true, "origin_connect_us_min": true, "origin_connect_us_max": true,
		"origin_first_byte_us_min": true, "origin_first_byte_us_max": true,
		"origin_total_us_min": true, "origin_total_us_max": true,
		"limit": true, "cursor": true,
	}
	if route.kind == routeAccess {
		allowed["method"] = true
		allowed["protocol"] = true
		allowed["cache_status"] = true
		allowed["upstream_result"] = true
		allowed["content_type"] = true
		allowed["user_agent"] = true
		allowed["request_bytes_min"] = true
		allowed["request_bytes_max"] = true
		allowed["response_bytes_min"] = true
		allowed["response_bytes_max"] = true
	}
	if route.kind == routeBlockEvent {
		allowed["action"] = true
		allowed["event_type"] = true
	}
	if route.kind == routeCCBan {
		allowed = map[string]bool{"from": true, "to": true, "tenant_id": true, "site_id": true, "client_ip": true, "limit": true}
	}
	query, err := parseRawQuery(request)
	if err != nil {
		return QueryRequest{}, err
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 || values[0] == "" {
			return QueryRequest{}, ErrInvalidInput
		}
	}
	if _, present := query["tenant_id"]; present && route.audience == AudienceTenant {
		return QueryRequest{}, ErrScopeForbidden
	}
	from, err := time.Parse(time.RFC3339Nano, query.Get("from"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	to, err := time.Parse(time.RFC3339Nano, query.Get("to"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	limit := uint64(DefaultLimit)
	if raw := query.Get("limit"); raw != "" {
		limit, err = strconv.ParseUint(raw, 10, 16)
		if err != nil || limit == 0 || limit > uint64(MaxLimit) {
			return QueryRequest{}, ErrInvalidInput
		}
	}
	filter := Filter{
		From: from.UTC(), To: to.UTC(), SiteID: query.Get("site_id"), Host: query.Get("host"), NodeID: query.Get("node_id"),
		ClientIP: query.Get("client_ip"), URIPath: query.Get("uri_path"), Method: query.Get("method"), Protocol: query.Get("protocol"),
		CacheStatus: query.Get("cache_status"), UpstreamResult: query.Get("upstream_result"), ContentType: query.Get("content_type"),
		UserAgent:   query.Get("user_agent"),
		CountryCode: query.Get("country_code"), Carrier: query.Get("carrier"),
		JA4: query.Get("ja4"), Action: query.Get("action"), EventType: query.Get("event_type"),
	}
	if filter.Action != "" && !slices.Contains(SecurityLogActions, filter.Action) {
		return QueryRequest{}, ErrInvalidInput
	}
	filter.OriginConnectUSMin, err = parseOptionalUint64(query.Get("origin_connect_us_min"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	filter.OriginConnectUSMax, err = parseOptionalUint64(query.Get("origin_connect_us_max"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	filter.OriginFirstByteUSMin, err = parseOptionalUint64(query.Get("origin_first_byte_us_min"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	filter.OriginFirstByteUSMax, err = parseOptionalUint64(query.Get("origin_first_byte_us_max"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	filter.OriginTotalUSMin, err = parseOptionalUint64(query.Get("origin_total_us_min"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	filter.OriginTotalUSMax, err = parseOptionalUint64(query.Get("origin_total_us_max"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	filter.RequestBytesMin, err = parseOptionalUint64(query.Get("request_bytes_min"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	filter.RequestBytesMax, err = parseOptionalUint64(query.Get("request_bytes_max"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	filter.ResponseBytesMin, err = parseOptionalUint64(query.Get("response_bytes_min"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	filter.ResponseBytesMax, err = parseOptionalUint64(query.Get("response_bytes_max"))
	if err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	if filter.URIPathPrefix, err = parseURIPathMatch(query.Get("uri_path_match")); err != nil {
		return QueryRequest{}, ErrInvalidInput
	}
	if raw := query.Get("status_code"); raw != "" {
		status, err := strconv.ParseUint(raw, 10, 16)
		if err != nil {
			return QueryRequest{}, ErrInvalidInput
		}
		filter.StatusCode = uint16(status)
		filter.HasStatus = true
	}
	return QueryRequest{
		Audience: route.audience, TenantID: query.Get("tenant_id"), Filter: filter,
		Limit: uint16(limit), Cursor: query.Get("cursor"),
	}, nil
}

// parseURIPathMatch maps uri_path_match (exact|prefix, default exact) to the
// prefix flag.
func parseURIPathMatch(value string) (bool, error) {
	switch value {
	case "", "exact":
		return false, nil
	case "prefix":
		return true, nil
	default:
		return false, ErrInvalidInput
	}
}

func parseOptionalUint64(value string) (*uint64, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return nil, ErrInvalidInput
	}
	return &parsed, nil
}

func parseUnsupportedScope(request *http.Request, audience Audience) (string, error) {
	query, err := parseRawQuery(request)
	if err != nil {
		return "", err
	}
	for key, values := range query {
		if key != "tenant_id" || len(values) != 1 || values[0] == "" {
			return "", ErrInvalidInput
		}
	}
	if _, present := query["tenant_id"]; present && audience == AudienceTenant {
		return "", ErrScopeForbidden
	}
	return query.Get("tenant_id"), nil
}

func parseRawQuery(request *http.Request) (url.Values, error) {
	if request == nil || request.URL == nil || len(request.URL.RawQuery) > maximumRawQueryBytes {
		return nil, ErrInvalidInput
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return query, nil
}

func responseMeta(filter Filter, snapshotAt time.Time, nextCursor string) queryMetadata {
	metadata := queryMetadata{
		From: filter.From.UTC().Format(time.RFC3339Nano), To: filter.To.UTC().Format(time.RFC3339Nano), Timezone: "UTC",
		Consistency: "snapshot", ReplacementConsistency: "latest_event_id_at_snapshot", Pagination: "keyset",
	}
	if !snapshotAt.IsZero() {
		metadata.SnapshotAt = snapshotAt.UTC().Format(time.RFC3339Nano)
	}
	metadata.NextCursor = nextCursor
	return metadata
}

func (handler *Handler) writeResult(writer http.ResponseWriter, request *http.Request, value any) {
	if err := request.Context().Err(); err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		handler.writeServiceError(writer, request, ErrInvalidResponse)
		return
	}
	if err := request.Context().Err(); err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	if len(encoded)+1 > handler.maxResponseBytes {
		handler.writeServiceError(writer, request, ErrResponseTooLarge)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(append(encoded, '\n'))
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, request *http.Request, err error) {
	status, code, message := publicError(err)
	handler.writeError(writer, request, status, code, message)
}

func (handler *Handler) writeError(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	traceID := traceIDFromRequest(request, RequestIDFromContext(request.Context()))
	request = request.WithContext(withTraceID(request.Context(), traceID))
	writer.Header().Set("X-Trace-ID", traceID)
	if status >= 500 {
		handler.logger.ErrorContext(request.Context(), "analytics log query failed",
			"request_id", RequestIDFromContext(request.Context()), "trace_id", traceID,
			"code", code, "path", request.URL.Path)
	}
	encoded, _ := json.Marshal(errorEnvelope{Error: apiError{
		Code: code, Message: message, RequestID: RequestIDFromContext(request.Context()), TraceID: traceID,
	}})
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}

func publicError(err error) (int, string, string) {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return http.StatusBadRequest, "analytics_logs_invalid_request", "analytics log query parameters are invalid"
	case errors.Is(err, ErrPermissionDenied):
		return http.StatusForbidden, "analytics_logs_permission_denied", "analytics log read permission is required"
	case errors.Is(err, ErrScopeForbidden):
		return http.StatusForbidden, "analytics_logs_scope_forbidden", "analytics log scope is not available to this identity"
	case errors.Is(err, ErrCapabilityUnsupported):
		return http.StatusUnprocessableEntity, "analytics_logs_capability_unsupported", "analytics log capability is not supported by the current schema"
	case errors.Is(err, ErrConflict):
		return http.StatusConflict, "analytics_log_export_idempotency_conflict", "the idempotency key is already bound to another export"
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, "analytics_log_export_not_found", "the analytics log export was not found"
	case errors.Is(err, ErrExpired):
		return http.StatusGone, "analytics_log_export_grant_rejected", "the analytics log export grant is unavailable"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "analytics_logs_query_timeout", "analytics log query timed out"
	case errors.Is(err, ErrStorageUnavailable), errors.Is(err, ErrInvalidResponse), errors.Is(err, ErrResponseTooLarge):
		return http.StatusServiceUnavailable, "analytics_logs_storage_unavailable", "analytics log storage is unavailable"
	default:
		return http.StatusServiceUnavailable, "analytics_logs_unavailable", "analytics log query could not be completed"
	}
}

func newRequestID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err == nil {
		return hex.EncodeToString(raw)
	}
	return "analytics-logs-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
}
