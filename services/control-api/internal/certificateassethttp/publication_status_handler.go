package certificateassethttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	publicationStatusPrefix       = "/v1/certificate-publications"
	defaultPublicationStatusLimit = 50
	maxPublicationStatusLimit     = 200
)

type PublicationStatusReader interface {
	List(
		context.Context,
		certificateasset.Actor,
		uuid.UUID,
		certificateasset.PublicationStatusFilter,
		certificateasset.PublicationStatusCursor,
		int,
	) (certificateasset.PublicationStatusPage, error)
	Get(
		context.Context,
		certificateasset.Actor,
		uuid.UUID,
		uuid.UUID,
		int64,
	) (certificateasset.PublicationStatusDetail, error)
}

type PublicationStatusHTTPDependencies struct {
	Reader              PublicationStatusReader
	CursorCodec         *certificateasset.PublicationCursorCodec
	AuthenticateSession AuthenticateSessionFunc
}

type PublicationStatusHandler struct {
	reader       PublicationStatusReader
	cursorCodec  *certificateasset.PublicationCursorCodec
	authenticate AuthenticateSessionFunc
}

type publicationStatusRoute struct {
	detail          bool
	siteID          uuid.UUID
	bindingRevision int64
}

type publicationStatusQuery struct {
	targetScopeID string
	filter        certificateasset.PublicationStatusFilter
	limit         int
	cursor        string
}

type publicationStatusListResponse struct {
	Items      []certificateasset.PublicationStatus `json:"items"`
	SnapshotAt time.Time                            `json:"snapshot_at"`
	NextCursor string                               `json:"next_cursor,omitempty"`
}

func NewPublicationStatusHandler(
	dependencies PublicationStatusHTTPDependencies,
) (*PublicationStatusHandler, error) {
	if dependencies.Reader == nil || dependencies.CursorCodec == nil ||
		dependencies.AuthenticateSession == nil {
		return nil, errInvalidDependencies
	}
	return &PublicationStatusHandler{
		reader: dependencies.Reader, cursorCodec: dependencies.CursorCodec,
		authenticate: dependencies.AuthenticateSession,
	}, nil
}

func (handler *PublicationStatusHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(response.Header())
	if handler == nil || request == nil || request.URL == nil {
		http.NotFound(response, request)
		return
	}
	requestID := responseRequestID(request)
	response.Header().Set("X-Request-ID", requestID)
	matched, ok := matchPublicationStatusRoute(request.URL.Path)
	if !ok || request.URL.RawPath != "" || request.URL.Fragment != "" {
		writeError(response, requestID, http.StatusNotFound,
			"certificate_publication_not_found", "证书发布状态接口不存在")
		return
	}
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeError(response, requestID, http.StatusMethodNotAllowed,
			"certificate_publication_method_not_allowed", "请求方法不受支持")
		return
	}
	if request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		writeError(response, requestID, http.StatusBadRequest,
			"certificate_publication_invalid_request", "读取请求不能包含正文")
		return
	}
	rawSession, err := strictBearer(request)
	if err != nil || hasUntrustedIdentityHeaders(request) {
		writeError(response, requestID, http.StatusUnauthorized,
			"authentication_required", "需要有效的租户会话")
		return
	}
	session, err := handler.authenticate(request.Context(), rawSession)
	if err != nil || session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil ||
		session.Principal.ScopeID == uuid.Nil {
		writeError(response, requestID, http.StatusUnauthorized,
			"authentication_required", "需要有效的租户会话")
		return
	}
	principal := session.Principal
	if principal.ScopeKind != certificateasset.ScopeTenant && principal.ScopeKind != certificateasset.ScopePlatform {
		writeError(response, requestID, http.StatusForbidden,
			"certificate_publication_permission_denied", "当前作用域不能读取租户证书发布状态")
		return
	}

	query, err := parsePublicationStatusQuery(request.URL.RawQuery, matched.detail)
	if err != nil {
		writePublicationStatusError(response, requestID, err)
		return
	}
	tenantScopeID, err := publicationStatusTenantScope(principal, query.targetScopeID)
	if err != nil {
		writePublicationStatusError(response, requestID, err)
		return
	}
	if !hasPermission(principal, "certificates.read") {
		writeError(response, requestID, http.StatusForbidden,
			"certificate_publication_permission_denied", "当前账号缺少证书读取权限")
		return
	}
	actor := certificateasset.Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
	}
	if matched.detail {
		handler.get(response, request, requestID, actor, tenantScopeID, matched)
		return
	}
	handler.list(response, request, requestID, actor, tenantScopeID, query)
}

func (handler *PublicationStatusHandler) list(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	actor certificateasset.Actor,
	tenantScopeID uuid.UUID,
	query publicationStatusQuery,
) {
	var cursor certificateasset.PublicationStatusCursor
	var err error
	if query.cursor != "" {
		cursor, err = handler.cursorCodec.Decode(query.cursor, actor, tenantScopeID, query.filter)
		if err != nil {
			writeError(response, requestID, http.StatusBadRequest,
				"certificate_publication_invalid_cursor", "分页游标无效或已不适用于当前筛选条件")
			return
		}
	}
	page, err := handler.reader.List(
		request.Context(), actor, tenantScopeID, query.filter, cursor, query.limit,
	)
	if err != nil {
		writePublicationStatusError(response, requestID, err)
		return
	}
	if page.Items == nil {
		page.Items = []certificateasset.PublicationStatus{}
	}
	result := publicationStatusListResponse{Items: page.Items, SnapshotAt: page.SnapshotAt}
	if page.NextCursor != nil {
		result.NextCursor, err = handler.cursorCodec.Encode(actor, tenantScopeID, query.filter, *page.NextCursor)
		if err != nil {
			writeError(response, requestID, http.StatusInternalServerError,
				"certificate_publication_internal_error", "证书发布状态服务暂时不可用")
			return
		}
	}
	writePublicationStatusJSON(response, http.StatusOK, result)
}

func (handler *PublicationStatusHandler) get(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	actor certificateasset.Actor,
	tenantScopeID uuid.UUID,
	matched publicationStatusRoute,
) {
	detail, err := handler.reader.Get(
		request.Context(), actor, tenantScopeID, matched.siteID, matched.bindingRevision,
	)
	if err != nil {
		writePublicationStatusError(response, requestID, err)
		return
	}
	if detail.History == nil {
		detail.History = []certificateasset.PublicationStatusEvent{}
	}
	writePublicationStatusJSON(response, http.StatusOK, detail)
}

func matchPublicationStatusRoute(path string) (publicationStatusRoute, bool) {
	if path == publicationStatusPrefix {
		return publicationStatusRoute{}, true
	}
	if !strings.HasPrefix(path, publicationStatusPrefix+"/") || strings.HasSuffix(path, "/") ||
		strings.Contains(path, "//") {
		return publicationStatusRoute{}, false
	}
	parts := strings.Split(strings.TrimPrefix(path, publicationStatusPrefix+"/"), "/")
	if len(parts) != 3 || parts[1] != "revisions" {
		return publicationStatusRoute{}, false
	}
	siteID, err := strictUUID(parts[0])
	if err != nil {
		return publicationStatusRoute{}, false
	}
	revision, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != parts[2] {
		return publicationStatusRoute{}, false
	}
	return publicationStatusRoute{detail: true, siteID: siteID, bindingRevision: revision}, true
}

func parsePublicationStatusQuery(raw string, detail bool) (publicationStatusQuery, error) {
	query := publicationStatusQuery{limit: defaultPublicationStatusLimit}
	if raw == "" {
		return query, nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return publicationStatusQuery{}, certificateasset.ErrInvalidInput
	}
	allowed := map[string]bool{"target_scope_id": true}
	if !detail {
		allowed["state"], allowed["operation"], allowed["site_id"] = true, true, true
		allowed["limit"], allowed["cursor"] = true, true
	}
	for name, candidates := range values {
		if !allowed[name] || len(candidates) != 1 || candidates[0] == "" {
			return publicationStatusQuery{}, certificateasset.ErrInvalidInput
		}
	}
	query.targetScopeID = values.Get("target_scope_id")
	if detail {
		return query, nil
	}
	query.filter.State = values.Get("state")
	query.filter.Operation = values.Get("operation")
	if rawSiteID := values.Get("site_id"); rawSiteID != "" {
		query.filter.SiteID, err = strictUUID(rawSiteID)
		if err != nil {
			return publicationStatusQuery{}, certificateasset.ErrInvalidInput
		}
	}
	if !validPublicationStatusHTTPFilter(query.filter) {
		return publicationStatusQuery{}, certificateasset.ErrInvalidInput
	}
	if rawLimit := values.Get("limit"); rawLimit != "" {
		query.limit, err = strconv.Atoi(rawLimit)
		if err != nil || query.limit < 1 || query.limit > maxPublicationStatusLimit ||
			strconv.Itoa(query.limit) != rawLimit {
			return publicationStatusQuery{}, certificateasset.ErrInvalidInput
		}
	}
	query.cursor = values.Get("cursor")
	return query, nil
}

func validPublicationStatusHTTPFilter(filter certificateasset.PublicationStatusFilter) bool {
	if filter.Operation != "" && filter.Operation != "publish" && filter.Operation != "unpublish" {
		return false
	}
	switch filter.State {
	case "", "pending", "leased", "retry_wait", "succeeded", "permanent_failed":
		return true
	default:
		return false
	}
}

func publicationStatusTenantScope(principal identity.Principal, rawTarget string) (uuid.UUID, error) {
	if rawTarget == "" {
		if principal.ScopeKind == certificateasset.ScopeTenant && principal.TenantID != nil &&
			*principal.TenantID != uuid.Nil {
			return principal.ScopeID, nil
		}
		return uuid.Nil, certificateasset.ErrInvalidInput
	}
	target, err := strictUUID(rawTarget)
	if err != nil {
		return uuid.Nil, certificateasset.ErrInvalidInput
	}
	if principal.ScopeKind == certificateasset.ScopeTenant {
		if principal.TenantID == nil || *principal.TenantID == uuid.Nil || target != principal.ScopeID {
			return uuid.Nil, certificateasset.ErrPermissionDenied
		}
		return target, nil
	}
	if principal.ScopeKind != certificateasset.ScopePlatform {
		return uuid.Nil, certificateasset.ErrPermissionDenied
	}
	return target, nil
}

func writePublicationStatusError(response http.ResponseWriter, requestID string, err error) {
	status, code, message := http.StatusInternalServerError,
		"certificate_publication_internal_error", "证书发布状态服务暂时不可用"
	switch {
	case errors.Is(err, certificateasset.ErrInvalidPublicationCursor):
		status, code, message = http.StatusBadRequest,
			"certificate_publication_invalid_cursor", "分页游标无效或已不适用于当前筛选条件"
	case errors.Is(err, certificateasset.ErrInvalidInput):
		status, code, message = http.StatusBadRequest,
			"certificate_publication_invalid_request", "证书发布状态请求无效"
	case errors.Is(err, certificateasset.ErrPermissionDenied):
		status, code, message = http.StatusForbidden,
			"certificate_publication_permission_denied", "当前账号缺少证书发布状态权限"
	case errors.Is(err, certificateasset.ErrNotFound):
		status, code, message = http.StatusNotFound,
			"certificate_publication_not_found", "证书发布状态不存在"
	}
	writeError(response, requestID, status, code, message)
}

func writePublicationStatusJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
