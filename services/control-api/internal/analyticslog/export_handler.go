package analyticslog

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxExportRequestBytes = 16 << 10

type exportFilterBody struct {
	From                 string  `json:"from"`
	To                   string  `json:"to"`
	SiteID               string  `json:"site_id,omitempty"`
	Host                 string  `json:"host,omitempty"`
	NodeID               string  `json:"node_id,omitempty"`
	ClientIP             string  `json:"client_ip,omitempty"`
	URIPath              string  `json:"uri_path,omitempty"`
	URIPathMatch         string  `json:"uri_path_match,omitempty"`
	StatusCode           *uint16 `json:"status_code,omitempty"`
	CountryCode          string  `json:"country_code,omitempty"`
	Carrier              string  `json:"carrier,omitempty"`
	Method               string  `json:"method,omitempty"`
	Protocol             string  `json:"protocol,omitempty"`
	CacheStatus          string  `json:"cache_status,omitempty"`
	UpstreamResult       string  `json:"upstream_result,omitempty"`
	ContentType          string  `json:"content_type,omitempty"`
	UserAgent            string  `json:"user_agent,omitempty"`
	RequestBytesMin      *uint64 `json:"request_bytes_min,omitempty"`
	RequestBytesMax      *uint64 `json:"request_bytes_max,omitempty"`
	ResponseBytesMin     *uint64 `json:"response_bytes_min,omitempty"`
	ResponseBytesMax     *uint64 `json:"response_bytes_max,omitempty"`
	JA4                  string  `json:"ja4,omitempty"`
	OriginConnectUSMin   *uint64 `json:"origin_connect_us_min,omitempty"`
	OriginConnectUSMax   *uint64 `json:"origin_connect_us_max,omitempty"`
	OriginFirstByteUSMin *uint64 `json:"origin_first_byte_us_min,omitempty"`
	OriginFirstByteUSMax *uint64 `json:"origin_first_byte_us_max,omitempty"`
	OriginTotalUSMin     *uint64 `json:"origin_total_us_min,omitempty"`
	OriginTotalUSMax     *uint64 `json:"origin_total_us_max,omitempty"`
}

// exportFilterSummary 把冻结的导出请求文档还原成与创建请求同一字段的原查询条件（LOG-02），
// 申请记录据此展示原条件；文档版本不认识就不给摘要。
func exportFilterSummary(stored []byte) (exportFilterBody, bool) {
	var document struct {
		Version int     `json:"version"`
		Filter  *Filter `json:"filter"`
	}
	if json.Unmarshal(stored, &document) != nil || document.Version != 1 || document.Filter == nil {
		return exportFilterBody{}, false
	}
	filter := document.Filter
	summary := exportFilterBody{
		From: filter.From.UTC().Format(time.RFC3339Nano), To: filter.To.UTC().Format(time.RFC3339Nano),
		SiteID: filter.SiteID, Host: filter.Host, NodeID: filter.NodeID, ClientIP: filter.ClientIP, URIPath: filter.URIPath,
		CountryCode: filter.CountryCode, Carrier: filter.Carrier, Method: filter.Method, Protocol: filter.Protocol,
		CacheStatus: filter.CacheStatus, UpstreamResult: filter.UpstreamResult, ContentType: filter.ContentType,
		UserAgent: filter.UserAgent, RequestBytesMin: filter.RequestBytesMin, RequestBytesMax: filter.RequestBytesMax,
		ResponseBytesMin: filter.ResponseBytesMin, ResponseBytesMax: filter.ResponseBytesMax, JA4: filter.JA4,
		OriginConnectUSMin: filter.OriginConnectUSMin, OriginConnectUSMax: filter.OriginConnectUSMax,
		OriginFirstByteUSMin: filter.OriginFirstByteUSMin, OriginFirstByteUSMax: filter.OriginFirstByteUSMax,
		OriginTotalUSMin: filter.OriginTotalUSMin, OriginTotalUSMax: filter.OriginTotalUSMax,
	}
	if filter.URIPathPrefix {
		summary.URIPathMatch = "prefix"
	}
	if filter.HasStatus {
		status := filter.StatusCode
		summary.StatusCode = &status
	}
	return summary, true
}

type exportCreateBody struct {
	Filter exportFilterBody `json:"filter"`
}

func (handler *Handler) serveAccessExport(writer http.ResponseWriter, request *http.Request, actor Actor, route handlerRoute) {
	if handler.service.exports == nil {
		handler.writeServiceError(writer, request, ErrCapabilityUnsupported)
		return
	}
	if route.kind == routeAccessExportCollection && request.Method == http.MethodGet {
		handler.serveAccessExportList(writer, request, actor, route)
		return
	}
	tenantID, err := parseExportScope(request, route.audience)
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	switch route.kind {
	case routeAccessExportCollection:
		idempotencyValues := request.Header.Values("Idempotency-Key")
		if len(idempotencyValues) != 1 || !exportIdempotencyPattern.MatchString(idempotencyValues[0]) {
			handler.writeServiceError(writer, request, ErrInvalidInput)
			return
		}
		idempotencyKey := idempotencyValues[0]
		body, err := decodeExportCreate(request)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		job, replayed, err := handler.service.exports.Create(request.Context(), actor, QueryRequest{
			Audience: route.audience, TenantID: tenantID, Filter: body,
			Limit: 1,
		}, idempotencyKey)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Idempotency-Replayed", map[bool]string{true: "true", false: "false"}[replayed])
		writer.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(writer).Encode(job)
	case routeAccessExportItem:
		job, err := handler.service.exports.Get(request.Context(), actor, route.audience, tenantID, route.resourceID)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		handler.writeResult(writer, request, job)
	case routeAccessExportGrant:
		if request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
			handler.writeServiceError(writer, request, ErrInvalidInput)
			return
		}
		grant, err := handler.service.exports.Grant(request.Context(), actor, route.audience, tenantID, route.resourceID)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(writer).Encode(grant)
	case routeAccessExportDownload:
		values := request.Header.Values("X-Analytics-Download-Token")
		if len(values) != 1 || strings.TrimSpace(values[0]) != values[0] {
			handler.writeServiceError(writer, request, ErrExpired)
			return
		}
		download, err := handler.service.exports.Consume(request.Context(), actor, route.audience, tenantID, route.resourceID, values[0])
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
		writer.Header().Set("Content-Disposition", `attachment; filename="`+download.Filename+`"`)
		writer.Header().Set("Digest", "sha-256="+download.SHA256)
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(download.Content)
	}
}

// serveAccessExportList 列出当前账号的申请记录；带 from/to 等查询条件时只返回
// 该查询范围上的最新一代申请（LOG-01：日志视图重新登录后找回原申请）。
func (handler *Handler) serveAccessExportList(writer http.ResponseWriter, request *http.Request, actor Actor, route handlerRoute) {
	tenantID, filter, scoped, err := parseExportListScope(request, route.audience)
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	var jobs []AccessExport
	if scoped {
		jobs, err = handler.service.exports.FindByScope(request.Context(), actor, QueryRequest{
			Audience: route.audience, TenantID: tenantID, Filter: filter, Limit: 1,
		})
	} else {
		jobs, err = handler.service.exports.List(request.Context(), actor, route.audience, tenantID)
	}
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	handler.writeResult(writer, request, struct {
		Data []AccessExport `json:"data"`
	}{Data: jobs})
}

// parseExportListScope 只有 tenant_id 时是普通列表；带查询条件时按访问日志列表
// 同一套参数解析（不接受 limit/cursor），scoped=true。
func parseExportListScope(request *http.Request, audience Audience) (string, Filter, bool, error) {
	query, err := parseRawQuery(request)
	if err != nil {
		return "", Filter{}, false, err
	}
	scoped := false
	for key := range query {
		if key == "limit" || key == "cursor" {
			return "", Filter{}, false, ErrInvalidInput
		}
		if key != "tenant_id" {
			scoped = true
		}
	}
	if !scoped {
		tenantID, err := parseExportScope(request, audience)
		return tenantID, Filter{}, false, err
	}
	parsed, err := parseQuery(request, handlerRoute{audience: audience, kind: routeAccess})
	if err != nil {
		return "", Filter{}, false, err
	}
	tenantID := strings.ToLower(parsed.TenantID)
	if audience == AudiencePlatform && !validUUID(tenantID) {
		return "", Filter{}, false, ErrInvalidInput
	}
	return tenantID, parsed.Filter, true, nil
}

func parseExportScope(request *http.Request, audience Audience) (string, error) {
	query, err := parseRawQuery(request)
	if err != nil {
		return "", err
	}
	for key, values := range query {
		if key != "tenant_id" || len(values) != 1 || values[0] == "" {
			return "", ErrInvalidInput
		}
	}
	if audience == AudienceTenant {
		if query.Has("tenant_id") {
			return "", ErrScopeForbidden
		}
		return "", nil
	}
	if !validUUID(strings.ToLower(query.Get("tenant_id"))) {
		return "", ErrInvalidInput
	}
	return strings.ToLower(query.Get("tenant_id")), nil
}

func decodeExportCreate(request *http.Request) (Filter, error) {
	if request.Body == nil || request.ContentLength > maxExportRequestBytes {
		return Filter{}, ErrInvalidInput
	}
	reader := io.LimitReader(request.Body, maxExportRequestBytes+1)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var body exportCreateBody
	if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Filter{}, ErrInvalidInput
	}
	from, fromErr := time.Parse(time.RFC3339Nano, body.Filter.From)
	to, toErr := time.Parse(time.RFC3339Nano, body.Filter.To)
	if fromErr != nil || toErr != nil {
		return Filter{}, ErrInvalidInput
	}
	filter := Filter{
		From: from.UTC(), To: to.UTC(), SiteID: body.Filter.SiteID, Host: body.Filter.Host, NodeID: body.Filter.NodeID,
		ClientIP: body.Filter.ClientIP, URIPath: body.Filter.URIPath, CountryCode: body.Filter.CountryCode,
		Carrier: body.Filter.Carrier, Method: body.Filter.Method, Protocol: body.Filter.Protocol,
		CacheStatus: body.Filter.CacheStatus, UpstreamResult: body.Filter.UpstreamResult,
		ContentType: body.Filter.ContentType, UserAgent: body.Filter.UserAgent,
		RequestBytesMin: body.Filter.RequestBytesMin, RequestBytesMax: body.Filter.RequestBytesMax,
		ResponseBytesMin: body.Filter.ResponseBytesMin, ResponseBytesMax: body.Filter.ResponseBytesMax,
		JA4: body.Filter.JA4, OriginConnectUSMin: body.Filter.OriginConnectUSMin,
		OriginConnectUSMax: body.Filter.OriginConnectUSMax, OriginFirstByteUSMin: body.Filter.OriginFirstByteUSMin,
		OriginFirstByteUSMax: body.Filter.OriginFirstByteUSMax, OriginTotalUSMin: body.Filter.OriginTotalUSMin,
		OriginTotalUSMax: body.Filter.OriginTotalUSMax,
	}
	prefix, err := parseURIPathMatch(body.Filter.URIPathMatch)
	if err != nil {
		return Filter{}, ErrInvalidInput
	}
	filter.URIPathPrefix = prefix
	if body.Filter.StatusCode != nil {
		filter.HasStatus = true
		filter.StatusCode = *body.Filter.StatusCode
	}
	if validateFilter(filter) != nil || filter.HasStatus && filter.StatusCode == 0 {
		return Filter{}, ErrInvalidInput
	}
	return normalizeFilter(filter), nil
}
