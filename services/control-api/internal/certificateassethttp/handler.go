package certificateassethttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	assetPrefix                  = "/v1/certificate-assets"
	sitePrefix                   = "/v1/sites"
	siteCertificateBindingSuffix = "certificate-binding"
	maxRequestBytes              = 384 << 10
)

var (
	errInvalidDependencies = errors.New("invalid certificate asset HTTP dependencies")
	errAuthentication      = errors.New("certificate asset authentication required")
	errInvalidRequest      = errors.New("invalid certificate asset HTTP request")
	errRequestTooLarge     = errors.New("certificate asset HTTP request too large")
	metadataPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type Service interface {
	ListPage(context.Context, certificateasset.Actor, certificateasset.ListRequest) (certificateasset.ListResult, error)
	Get(context.Context, certificateasset.Actor, uuid.UUID, uuid.UUID) (certificateasset.Asset, []certificateasset.Version, error)
	GetSiteBinding(context.Context, certificateasset.Actor, uuid.UUID, uuid.UUID) (certificateasset.Binding, certificateasset.Version, error)
	Import(context.Context, certificateasset.Actor, certificateasset.ImportRequest) (certificateasset.ImportResult, error)
	Activate(context.Context, certificateasset.Actor, certificateasset.ActivateRequest) (certificateasset.Version, error)
	ListBindings(context.Context, certificateasset.Actor, uuid.UUID, uuid.UUID) ([]certificateasset.Binding, error)
	Bind(context.Context, certificateasset.Actor, certificateasset.BindRequest) (certificateasset.Binding, error)
	Unbind(context.Context, certificateasset.Actor, certificateasset.UnbindRequest) (certificateasset.Binding, error)
	Delete(context.Context, certificateasset.Actor, certificateasset.DeleteRequest) (certificateasset.Asset, error)
	SetAutoRenew(context.Context, certificateasset.Actor, certificateasset.SetAutoRenewRequest) (certificateasset.Asset, error)
	SetDisabled(context.Context, certificateasset.Actor, certificateasset.SetDisabledRequest) (certificateasset.Asset, error)
	Download(context.Context, certificateasset.Actor, certificateasset.DownloadRequest) (certificateasset.Download, error)
}

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

type Dependencies struct {
	Service             Service
	AuthenticateSession AuthenticateSessionFunc
	// OpaqueResolver unwraps ACME-issued private keys for 下载证书; without
	// it only uploaded certificates can be downloaded.
	OpaqueResolver certificateasset.OpaquePublicationResolver
}

type Handler struct {
	service      Service
	authenticate AuthenticateSessionFunc
	resolver     certificateasset.OpaquePublicationResolver
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type assetList struct {
	Items  []certificateasset.Asset    `json:"items"`
	Total  int64                       `json:"total"`
	Counts certificateasset.ListCounts `json:"counts"`
}

type assetDetail struct {
	Asset    certificateasset.Asset     `json:"asset"`
	Versions []certificateasset.Version `json:"versions"`
}

type bindingList struct {
	Items []certificateasset.Binding `json:"items"`
}

type siteBindingDetail struct {
	Binding certificateasset.Binding `json:"binding"`
	Version certificateasset.Version `json:"version"`
}

type uploadBody struct {
	Name           *string    `json:"name"`
	Remark         *string    `json:"remark"`
	OwnerUserID    *uuid.UUID `json:"owner_user_id"`
	CertificatePEM *string    `json:"certificate_pem"`
	PrivateKeyPEM  *string    `json:"private_key_pem"`
}

type revisionBody struct {
	ExpectedRevision *int64 `json:"expected_revision"`
}

type bindBody struct {
	SiteID           *uuid.UUID `json:"site_id"`
	VersionID        *uuid.UUID `json:"version_id"`
	ExpectedRevision *int64     `json:"expected_revision"`
	Default          *bool      `json:"default"`
}

type autoRenewBody struct {
	Enabled          *bool  `json:"enabled"`
	ExpectedRevision *int64 `json:"expected_revision"`
}

type disabledBody struct {
	Disabled         *bool  `json:"disabled"`
	ExpectedRevision *int64 `json:"expected_revision"`
}

type deleteBody struct {
	ExpectedRevision *int64 `json:"expected_revision"`
}

type route struct {
	action    string
	assetID   uuid.UUID
	versionID uuid.UUID
	siteID    uuid.UUID
	methods   string
}

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if dependencies.Service == nil || dependencies.AuthenticateSession == nil {
		return nil, errInvalidDependencies
	}
	return &Handler{service: dependencies.Service, authenticate: dependencies.AuthenticateSession,
		resolver: dependencies.OpaqueResolver}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(response.Header())
	if handler == nil || request == nil || request.URL == nil {
		http.NotFound(response, request)
		return
	}
	requestID := responseRequestID(request)
	response.Header().Set("X-Request-ID", requestID)
	matched, ok := matchRoute(request.URL.Path)
	if !ok || request.URL.RawPath != "" || request.URL.Fragment != "" {
		writeError(response, requestID, http.StatusNotFound, "certificate_asset_not_found", "证书资产接口不存在")
		return
	}
	if !methodAllowed(request.Method, matched.methods) {
		response.Header().Set("Allow", matched.methods)
		writeError(response, requestID, http.StatusMethodNotAllowed, "certificate_asset_method_not_allowed", "请求方法不受支持")
		return
	}
	matched = matched.resolved(request.Method)
	rawSession, err := strictBearer(request)
	if err != nil || hasUntrustedIdentityHeaders(request) {
		writeError(response, requestID, http.StatusUnauthorized, "authentication_required", "需要有效的租户会话")
		return
	}
	session, err := handler.authenticate(request.Context(), rawSession)
	if err != nil || session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		writeError(response, requestID, http.StatusUnauthorized, "authentication_required", "需要有效的租户会话")
		return
	}
	principal := session.Principal
	query, err := strictQuery(request, matched.action == "list")
	if err != nil {
		writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "查询参数无效")
		return
	}
	var tenantScopeID uuid.UUID
	if matched.action != "list" || principal.ScopeKind != certificateasset.ScopePlatform || query.Has("target_scope_id") {
		tenantScopeID, err = targetTenantScope(query, principal)
	}
	if err != nil {
		status, code, message := http.StatusBadRequest, "certificate_asset_invalid_request", "目标租户作用域无效"
		if errors.Is(err, certificateasset.ErrPermissionDenied) {
			status, code, message = http.StatusForbidden, "certificate_asset_permission_denied", "当前作用域不能操作目标租户证书"
		}
		writeError(response, requestID, status, code, message)
		return
	}
	if principal.ScopeKind != certificateasset.ScopeTenant && principal.ScopeKind != certificateasset.ScopePlatform {
		writeError(response, requestID, http.StatusForbidden, "certificate_asset_permission_denied", "当前作用域不能操作租户证书")
		return
	}
	permission := "certificates.read"
	if matched.action != "list" && matched.action != "get" && matched.action != "list_bindings" &&
		matched.action != "get_site_binding" {
		permission = "certificates.manage"
	}
	if !hasPermission(principal, permission) {
		writeError(response, requestID, http.StatusForbidden, "certificate_asset_permission_denied", "当前账号缺少证书权限")
		return
	}
	actor := certificateasset.Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID,
		ScopeKind: principal.ScopeKind, SessionID: session.SessionID,
	}
	handler.dispatch(response, request, requestID, matched, actor, tenantScopeID, query)
}

func (handler *Handler) dispatch(response http.ResponseWriter, request *http.Request, requestID string, matched route, actor certificateasset.Actor, tenantScopeID uuid.UUID, query url.Values) {
	switch matched.action {
	case "list":
		if request.ContentLength > 0 {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "读取请求不能包含正文")
			return
		}
		listRequest, err := assetListRequest(query, tenantScopeID)
		if err != nil {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "查询参数无效")
			return
		}
		result, err := handler.service.ListPage(request.Context(), actor, listRequest)
		if result.Items == nil {
			result.Items = []certificateasset.Asset{}
		}
		writeValue(response, requestID, http.StatusOK, assetList{Items: result.Items, Total: result.Total, Counts: result.Counts}, err)
	case "get":
		if request.ContentLength > 0 {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "读取请求不能包含正文")
			return
		}
		asset, versions, err := handler.service.Get(request.Context(), actor, tenantScopeID, matched.assetID)
		if versions == nil {
			versions = []certificateasset.Version{}
		}
		if err == nil {
			response.Header().Set("ETag", quotedRevision(asset.Revision))
		}
		writeValue(response, requestID, http.StatusOK, assetDetail{Asset: asset, Versions: versions}, err)
	case "get_site_binding":
		if request.ContentLength > 0 {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "读取请求不能包含正文")
			return
		}
		binding, version, err := handler.service.GetSiteBinding(
			request.Context(), actor, tenantScopeID, matched.siteID,
		)
		if errors.Is(err, certificateasset.ErrNotFound) {
			writeError(response, requestID, http.StatusNotFound,
				"certificate_site_binding_not_found", "网站尚未绑定证书")
			return
		}
		writeValue(response, requestID, http.StatusOK, siteBindingDetail{
			Binding: binding, Version: version,
		}, err)
	case "upload":
		key, ok := validateWriteHeaders(response, request, requestID)
		if !ok {
			return
		}
		var body uploadBody
		if err := decodeBody(request, &body); err != nil {
			writeDecodeError(response, requestID, err)
			return
		}
		if body.Name == nil || body.CertificatePEM == nil || body.PrivateKeyPEM == nil ||
			strings.TrimSpace(*body.Name) == "" || len(*body.CertificatePEM) == 0 || len(*body.PrivateKeyPEM) == 0 ||
			len(*body.CertificatePEM) > certificateasset.MaxCertificatePEMBytes ||
			len(*body.PrivateKeyPEM) > certificateasset.MaxPrivateKeyPEMBytes {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "证书上传字段无效")
			return
		}
		result, err := handler.service.Import(request.Context(), actor, certificateasset.ImportRequest{
			TenantScopeID: tenantScopeID, Name: *body.Name, Source: certificateasset.SourceUploaded,
			Remark: optionalText(body.Remark), OwnerUserID: body.OwnerUserID,
			CertificatePEM: []byte(*body.CertificatePEM), PrivateKeyPEM: []byte(*body.PrivateKeyPEM),
			IdempotencyKey: key, RequestID: requestID,
		})
		if result.Replayed {
			response.Header().Set("Idempotency-Replayed", "true")
		}
		if err == nil {
			response.Header().Set("ETag", quotedRevision(result.Asset.Revision))
		}
		writeValue(response, requestID, http.StatusCreated, assetDetail{Asset: result.Asset, Versions: []certificateasset.Version{result.Version}}, err)
	case "activate":
		key, ok := validateWriteHeaders(response, request, requestID)
		if !ok {
			return
		}
		var body revisionBody
		if err := decodeBody(request, &body); err != nil {
			writeDecodeError(response, requestID, err)
			return
		}
		if body.ExpectedRevision == nil || *body.ExpectedRevision < 1 {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "激活字段无效")
			return
		}
		version, err := handler.service.Activate(request.Context(), actor, certificateasset.ActivateRequest{
			TenantScopeID: tenantScopeID, AssetID: matched.assetID, VersionID: matched.versionID,
			ExpectedRevision: *body.ExpectedRevision, IdempotencyKey: key, RequestID: requestID,
		})
		writeValue(response, requestID, http.StatusOK, version, err)
	case "list_bindings":
		if request.ContentLength > 0 {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "读取请求不能包含正文")
			return
		}
		items, err := handler.service.ListBindings(request.Context(), actor, tenantScopeID, matched.assetID)
		if items == nil {
			items = []certificateasset.Binding{}
		}
		writeValue(response, requestID, http.StatusOK, bindingList{Items: items}, err)
	case "bind":
		key, ok := validateWriteHeaders(response, request, requestID)
		if !ok {
			return
		}
		var body bindBody
		if err := decodeBody(request, &body); err != nil {
			writeDecodeError(response, requestID, err)
			return
		}
		if body.SiteID == nil || *body.SiteID == uuid.Nil || body.VersionID == nil || *body.VersionID == uuid.Nil ||
			body.ExpectedRevision == nil || *body.ExpectedRevision < 0 || body.Default == nil {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "绑定字段无效")
			return
		}
		binding, err := handler.service.Bind(request.Context(), actor, certificateasset.BindRequest{
			TenantScopeID: tenantScopeID, SiteID: *body.SiteID, AssetID: matched.assetID,
			VersionID: *body.VersionID, ExpectedRevision: *body.ExpectedRevision, Default: *body.Default,
			IdempotencyKey: key, RequestID: requestID,
		})
		writeValue(response, requestID, http.StatusOK, binding, err)
	case "unbind":
		key, ok := validateWriteHeaders(response, request, requestID)
		if !ok {
			return
		}
		var body revisionBody
		if err := decodeBody(request, &body); err != nil {
			writeDecodeError(response, requestID, err)
			return
		}
		if body.ExpectedRevision == nil || *body.ExpectedRevision < 1 {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "解绑字段无效")
			return
		}
		binding, err := handler.service.Unbind(request.Context(), actor, certificateasset.UnbindRequest{
			TenantScopeID: tenantScopeID, SiteID: matched.siteID, ExpectedRevision: *body.ExpectedRevision,
			IdempotencyKey: key, RequestID: requestID,
		})
		writeValue(response, requestID, http.StatusOK, binding, err)
	case "delete":
		key, ok := validateWriteHeaders(response, request, requestID)
		if !ok {
			return
		}
		var body deleteBody
		if err := decodeBody(request, &body); err != nil {
			writeDecodeError(response, requestID, err)
			return
		}
		if body.ExpectedRevision == nil || *body.ExpectedRevision < 1 {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "删除字段无效")
			return
		}
		asset, err := handler.service.Delete(request.Context(), actor, certificateasset.DeleteRequest{
			TenantScopeID: tenantScopeID, AssetID: matched.assetID, ExpectedRevision: *body.ExpectedRevision,
			IdempotencyKey: key, RequestID: requestID,
		})
		writeValue(response, requestID, http.StatusOK, asset, err)
	case "auto_renew":
		key, ok := validateWriteHeaders(response, request, requestID)
		if !ok {
			return
		}
		var body autoRenewBody
		if err := decodeBody(request, &body); err != nil {
			writeDecodeError(response, requestID, err)
			return
		}
		if body.Enabled == nil || body.ExpectedRevision == nil || *body.ExpectedRevision < 1 {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "自动续签字段无效")
			return
		}
		asset, err := handler.service.SetAutoRenew(request.Context(), actor, certificateasset.SetAutoRenewRequest{
			TenantScopeID: tenantScopeID, AssetID: matched.assetID, Enabled: *body.Enabled,
			ExpectedRevision: *body.ExpectedRevision, IdempotencyKey: key, RequestID: requestID,
		})
		if err == nil {
			response.Header().Set("ETag", quotedRevision(asset.Revision))
		}
		writeValue(response, requestID, http.StatusOK, asset, err)
	case "disabled":
		key, ok := validateWriteHeaders(response, request, requestID)
		if !ok {
			return
		}
		var body disabledBody
		if err := decodeBody(request, &body); err != nil {
			writeDecodeError(response, requestID, err)
			return
		}
		if body.Disabled == nil || body.ExpectedRevision == nil || *body.ExpectedRevision < 1 {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "禁用字段无效")
			return
		}
		asset, err := handler.service.SetDisabled(request.Context(), actor, certificateasset.SetDisabledRequest{
			TenantScopeID: tenantScopeID, AssetID: matched.assetID, Disabled: *body.Disabled,
			ExpectedRevision: *body.ExpectedRevision, IdempotencyKey: key, RequestID: requestID,
		})
		if err == nil {
			response.Header().Set("ETag", quotedRevision(asset.Revision))
		}
		writeValue(response, requestID, http.StatusOK, asset, err)
	case "download":
		if request.ContentLength > 0 {
			writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "读取请求不能包含正文")
			return
		}
		material, err := handler.service.Download(request.Context(), actor, certificateasset.DownloadRequest{
			TenantScopeID: tenantScopeID, AssetID: matched.assetID, RequestID: requestID,
			OpaqueResolver: handler.resolver,
		})
		if err != nil {
			writeServiceError(response, requestID, err)
			return
		}
		writeDownload(response, material)
	}
}

func matchRoute(path string) (route, bool) {
	if strings.HasPrefix(path, sitePrefix+"/") && !strings.HasSuffix(path, "/") && !strings.Contains(path, "//") {
		parts := strings.Split(strings.TrimPrefix(path, sitePrefix+"/"), "/")
		if len(parts) == 2 && parts[1] == siteCertificateBindingSuffix {
			siteID, err := strictUUID(parts[0])
			if err == nil {
				return route{action: "get_site_binding", siteID: siteID, methods: "GET"}, true
			}
		}
		return route{}, false
	}
	if path == assetPrefix {
		return route{action: "collection", methods: "GET, POST"}, true
	}
	if !strings.HasPrefix(path, assetPrefix+"/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return route{}, false
	}
	parts := strings.Split(strings.TrimPrefix(path, assetPrefix+"/"), "/")
	assetID, err := strictUUID(parts[0])
	if err != nil {
		return route{}, false
	}
	if len(parts) == 1 {
		return route{action: "item", assetID: assetID, methods: "GET, DELETE"}, true
	}
	if len(parts) == 4 && parts[1] == "versions" && parts[3] == "activate" {
		versionID, err := strictUUID(parts[2])
		if err != nil {
			return route{}, false
		}
		return route{action: parts[3], assetID: assetID, versionID: versionID, methods: "POST"}, true
	}
	if len(parts) == 2 && parts[1] == "auto-renew" {
		return route{action: "auto_renew", assetID: assetID, methods: "PATCH"}, true
	}
	if len(parts) == 2 && parts[1] == "disabled" {
		return route{action: "disabled", assetID: assetID, methods: "PATCH"}, true
	}
	if len(parts) == 2 && parts[1] == "download" {
		return route{action: "download", assetID: assetID, methods: "GET"}, true
	}
	if len(parts) == 2 && parts[1] == "bindings" {
		return route{action: "bindings", assetID: assetID, methods: "GET, POST"}, true
	}
	if len(parts) == 3 && parts[1] == "bindings" {
		siteID, err := strictUUID(parts[2])
		if err != nil {
			return route{}, false
		}
		return route{action: "unbind", assetID: assetID, siteID: siteID, methods: "DELETE"}, true
	}
	return route{}, false
}

func methodAllowed(method, allowed string) bool {
	for _, candidate := range strings.Split(allowed, ", ") {
		if candidate == method {
			return true
		}
	}
	return false
}

func (matched route) resolved(method string) route {
	if matched.action == "collection" {
		matched.action = map[bool]string{true: "list", false: "upload"}[method == http.MethodGet]
	}
	if matched.action == "item" {
		matched.action = map[bool]string{true: "get", false: "delete"}[method == http.MethodGet]
	}
	if matched.action == "bindings" {
		matched.action = map[bool]string{true: "list_bindings", false: "bind"}[method == http.MethodGet]
	}
	return matched
}

func strictQuery(request *http.Request, list bool) (url.Values, error) {
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return nil, errInvalidRequest
	}
	allowed := map[string]bool{"target_scope_id": true}
	if list {
		allowed["page"], allowed["limit"], allowed["search"], allowed["status"] = true, true, true, true
		for _, key := range listFilterKeys {
			allowed[key] = true
		}
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 || !utf8.ValidString(entries[0]) {
			return nil, errInvalidRequest
		}
	}
	return values, nil
}

func targetTenantScope(query url.Values, principal identity.Principal) (uuid.UUID, error) {
	values, present := query["target_scope_id"]
	if !present {
		if principal.ScopeKind == certificateasset.ScopeTenant && principal.TenantID != nil &&
			*principal.TenantID != uuid.Nil {
			return principal.ScopeID, nil
		}
		return uuid.Nil, errInvalidRequest
	}
	target, err := strictUUID(values[0])
	if err != nil {
		return uuid.Nil, errInvalidRequest
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

func assetListRequest(query url.Values, tenantScopeID uuid.UUID) (certificateasset.ListRequest, error) {
	request := certificateasset.ListRequest{TenantScopeID: tenantScopeID, Page: 1, Limit: 10}
	for key, target := range map[string]*int{"page": &request.Page, "limit": &request.Limit} {
		values, present := query[key]
		if !present {
			continue
		}
		value, err := strconv.Atoi(values[0])
		if err != nil || value < 1 || (key == "limit" && value > 100) || strconv.Itoa(value) != values[0] {
			return certificateasset.ListRequest{}, errInvalidRequest
		}
		*target = value
	}
	if values, present := query["search"]; present {
		request.Search = values[0]
		if request.Search == "" || strings.TrimSpace(request.Search) != request.Search || len(request.Search) > 128 ||
			strings.ContainsFunc(request.Search, unicode.IsControl) {
			return certificateasset.ListRequest{}, errInvalidRequest
		}
	}
	if values, present := query["status"]; present {
		request.Status = values[0]
		if !slices.Contains(certificateasset.ListStatuses, request.Status) {
			return certificateasset.ListRequest{}, errInvalidRequest
		}
	}
	filters, err := assetListFilters(query)
	if err != nil {
		return certificateasset.ListRequest{}, err
	}
	request.Filters = filters
	return request, nil
}

func optionalText(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// listFilterKeys are the advanced search query parameters (CERT-05).
var listFilterKeys = []string{"domain", "domains", "user", "certificate_id", "name", "remark",
	"source", "dns_provider_id", "expiry", "auto_renew", "issue", "sync"}

// assetListFilters reads the advanced search; a present parameter must not
// be empty. domains is comma separated.
func assetListFilters(query url.Values) (certificateasset.ListFilters, error) {
	var filters certificateasset.ListFilters
	text := map[string]*string{
		"domain": &filters.Domain, "user": &filters.User, "certificate_id": &filters.CertificateID,
		"name": &filters.Name, "remark": &filters.Remark, "source": &filters.Source,
		"expiry": &filters.Expiry, "issue": &filters.Issue, "sync": &filters.Sync,
	}
	for key, target := range text {
		if values, present := query[key]; present {
			if values[0] == "" {
				return filters, errInvalidRequest
			}
			*target = values[0]
		}
	}
	if values, present := query["domains"]; present {
		filters.Domains = strings.Split(values[0], ",")
	}
	if values, present := query["dns_provider_id"]; present {
		id, err := strictUUID(values[0])
		if err != nil {
			return filters, err
		}
		filters.DNSProviderID = &id
	}
	if values, present := query["auto_renew"]; present {
		if values[0] != "true" && values[0] != "false" {
			return filters, errInvalidRequest
		}
		value := values[0] == "true"
		filters.AutoRenew = &value
	}
	return filters, nil
}

func strictUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, errInvalidRequest
	}
	return parsed, nil
}

func strictBearer(request *http.Request) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || strings.Contains(values[0], ",") {
		return "", errAuthentication
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || len(token) >= 8192 || strings.ContainsFunc(token, unicode.IsSpace) {
		return "", errAuthentication
	}
	return token, nil
}

func hasUntrustedIdentityHeaders(request *http.Request) bool {
	for _, name := range []string{"X-Actor-ID", "X-Actor-Scope", "X-User-ID", "X-Scope-ID", "X-Scope-Kind", "X-Tenant-ID", "X-Role", "X-Roles", "X-Permission", "X-Permissions"} {
		if len(request.Header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func hasPermission(principal identity.Principal, permission string) bool {
	for _, candidate := range principal.Permissions {
		if candidate == permission {
			return true
		}
	}
	return false
}

func validateWriteHeaders(response http.ResponseWriter, request *http.Request, requestID string) (string, bool) {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		writeError(response, requestID, http.StatusUnsupportedMediaType, "certificate_asset_unsupported_media_type", "请求正文必须使用 application/json")
		return "", false
	}
	mediaType, params, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) {
		writeError(response, requestID, http.StatusUnsupportedMediaType, "certificate_asset_unsupported_media_type", "请求正文必须使用 application/json")
		return "", false
	}
	keys := request.Header.Values("Idempotency-Key")
	if len(keys) != 1 || !metadataPattern.MatchString(keys[0]) {
		writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_idempotency_key", "Idempotency-Key 无效")
		return "", false
	}
	requestIDs := request.Header.Values("X-Request-ID")
	if len(requestIDs) != 1 || requestIDs[0] != requestID || !metadataPattern.MatchString(requestIDs[0]) {
		writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "X-Request-ID 无效")
		return "", false
	}
	return keys[0], true
}

func decodeBody(request *http.Request, output any) error {
	if request.ContentLength > maxRequestBytes {
		return errRequestTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBytes+1))
	if err != nil {
		return errInvalidRequest
	}
	if len(data) > maxRequestBytes {
		return errRequestTooLarge
	}
	if !utf8.Valid(data) || uniqueJSONObject(data) != nil {
		return errInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errInvalidRequest
	}
	return nil
}

func uniqueJSONObject(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errInvalidRequest
	}
	if err := consumeObject(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidRequest
	}
	return nil
}

func consumeObject(decoder *json.Decoder) error {
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return errInvalidRequest
		}
		if _, duplicate := seen[key]; duplicate {
			return errInvalidRequest
		}
		seen[key] = struct{}{}
		if err := consumeJSONValue(decoder); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errInvalidRequest
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errInvalidRequest
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return consumeObject(decoder)
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidRequest
		}
		return nil
	default:
		return errInvalidRequest
	}
}

func responseRequestID(request *http.Request) string {
	values := request.Header.Values("X-Request-ID")
	if len(values) == 1 && metadataPattern.MatchString(values[0]) {
		return values[0]
	}
	return "certificate-asset-http"
}

func quotedRevision(revision int64) string {
	return `"` + strconv.FormatInt(revision, 10) + `"`
}

func writeDecodeError(response http.ResponseWriter, requestID string, err error) {
	if errors.Is(err, errRequestTooLarge) {
		writeError(response, requestID, http.StatusRequestEntityTooLarge, "certificate_asset_request_too_large", "请求正文过大")
		return
	}
	writeError(response, requestID, http.StatusBadRequest, "certificate_asset_invalid_request", "请求正文无效")
}

func writeValue(response http.ResponseWriter, requestID string, status int, value any, err error) {
	if err != nil {
		writeServiceError(response, requestID, err)
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeServiceError(response http.ResponseWriter, requestID string, err error) {
	status, code, message := http.StatusInternalServerError, "certificate_asset_internal_error", "证书服务暂时不可用"
	switch {
	case errors.Is(err, certificateasset.ErrInvalidCertificatePEM):
		status, code, message = http.StatusBadRequest, "certificate_asset_invalid_certificate_pem", "证书 PEM 无效"
	case errors.Is(err, certificateasset.ErrInvalidPrivateKeyPEM):
		status, code, message = http.StatusBadRequest, "certificate_asset_invalid_private_key_pem", "私钥 PEM 无效"
	case errors.Is(err, certificateasset.ErrKeyMismatch):
		status, code, message = http.StatusBadRequest, "certificate_asset_key_mismatch", "证书与私钥不匹配"
	case errors.Is(err, certificateasset.ErrInvalidInput), errors.Is(err, certificateasset.ErrInvalidSAN),
		errors.Is(err, certificateasset.ErrCertificateExpired), errors.Is(err, certificateasset.ErrCertificateNotYetValid),
		errors.Is(err, certificateasset.ErrWeakPublicKey), errors.Is(err, certificateasset.ErrWeakSignature),
		errors.Is(err, certificateasset.ErrCertificateAuthority), errors.Is(err, certificateasset.ErrServerAuthRequired),
		errors.Is(err, certificateasset.ErrChainOrder), errors.Is(err, certificateasset.ErrChainIncomplete):
		status, code, message = http.StatusBadRequest, "certificate_asset_invalid_request", "证书上传字段无效"
	case errors.Is(err, certificateasset.ErrPermissionDenied):
		status, code, message = http.StatusForbidden, "certificate_asset_permission_denied", "当前账号缺少证书权限"
	case errors.Is(err, certificateasset.ErrNotFound), errors.Is(err, certificateasset.ErrDeleted):
		status, code, message = http.StatusNotFound, "certificate_asset_not_found", "证书资产不存在"
	case errors.Is(err, certificateasset.ErrRevisionConflict):
		status, code, message = http.StatusConflict, "certificate_asset_revision_conflict", "证书资产已被其他操作修改"
	case errors.Is(err, certificateasset.ErrIdempotencyConflict):
		status, code, message = http.StatusConflict, "certificate_asset_idempotency_conflict", "幂等键已用于不同请求"
	case errors.Is(err, certificateasset.ErrAutoRenewUnsupported):
		status, code, message = http.StatusConflict, "certificate_asset_auto_renew_unsupported", "手动上传的证书不能自动续签"
	case errors.Is(err, certificateasset.ErrAssetDisabled):
		status, code, message = http.StatusConflict, "certificate_asset_disabled", "证书已禁用，请先启用"
	case errors.Is(err, certificateasset.ErrDownloadUnavailable):
		status, code, message = http.StatusConflict, "certificate_asset_download_unavailable", "证书没有可下载的有效版本"
	case errors.Is(err, certificateasset.ErrReferenced):
		status, code, message = http.StatusConflict, "certificate_asset_referenced", "证书仍被网站引用"
	case errors.Is(err, certificateasset.ErrInvalidTransition):
		status, code, message = http.StatusConflict, "certificate_asset_invalid_transition", "当前状态不允许此操作"
	case errors.Is(err, certificateasset.ErrDomainNotCovered):
		status, code, message = http.StatusConflict, "certificate_asset_domain_not_covered", "证书不包含网站域名"
	case errors.Is(err, certificateasset.ErrEnvelopeUnavailable):
		status, code, message = http.StatusServiceUnavailable, "certificate_asset_envelope_unavailable", "私钥加密服务暂不可用"
	}
	writeError(response, requestID, status, code, message)
}

func writeError(response http.ResponseWriter, requestID string, status int, code, message string) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(errorEnvelope{Error: apiError{Code: code, Message: message, RequestID: requestID}})
}

func setSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
}
