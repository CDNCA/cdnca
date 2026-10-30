package regioncataloghttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
	"github.com/google/uuid"
)

const Route = "/v1/regions"

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

var errPreconditionRequired = errors.New("region catalog precondition is required")

type Catalog interface {
	List(context.Context, regioncatalog.Actor, regioncatalog.ListRequest) (regioncatalog.Page, error)
	Get(context.Context, regioncatalog.Actor, string) (regioncatalog.Region, error)
	Create(context.Context, regioncatalog.Actor, regioncatalog.CreateRequest) (regioncatalog.Region, bool, error)
	Update(context.Context, regioncatalog.Actor, regioncatalog.UpdateRequest) (regioncatalog.Region, bool, error)
	Delete(context.Context, regioncatalog.Actor, regioncatalog.DeleteRequest) (bool, error)
}

type AuthenticateFunc func(context.Context, string) (identity.AuthenticatedSession, error)

type Handler struct {
	catalog      Catalog
	authenticate AuthenticateFunc
}

type regionBody struct {
	Name         string `json:"name"`
	CountryCode  string `json:"country_code"`
	ProvinceCode string `json:"province_code"`
	Description  string `json:"description"`
	L2CheckPort  int    `json:"l2_check_port"`
	Sort         int    `json:"sort"`
}

func NewHandler(catalog Catalog, authenticate AuthenticateFunc) (*Handler, error) {
	if catalog == nil || authenticate == nil {
		return nil, errors.New("region catalog HTTP dependencies are required")
	}
	return &Handler{catalog: catalog, authenticate: authenticate}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	requestID := regionRequestID(request)
	setHeaders(response.Header(), requestID)
	if handler == nil || request == nil || request.URL == nil || request.URL.Fragment != "" {
		writeError(response, requestID, http.StatusNotFound, "regions_not_found", "区域目录不存在")
		return
	}
	id, item := itemID(request.URL.Path)
	if request.URL.Path != Route && !item {
		writeError(response, requestID, http.StatusNotFound, "regions_not_found", "区域目录不存在")
		return
	}

	actor, ok := handler.actor(response, request, requestID)
	if !ok {
		return
	}
	manage := request.Method == http.MethodPost || request.Method == http.MethodPatch ||
		request.Method == http.MethodPut || request.Method == http.MethodDelete
	if !allowed(actor, manage) {
		message := "没有区域目录读取权限"
		if manage {
			message = "没有区域目录管理权限"
		}
		writeError(response, requestID, http.StatusForbidden, "regions_permission_denied", message)
		return
	}

	if request.URL.Path == Route {
		handler.collection(response, request, requestID, actor)
		return
	}
	handler.item(response, request, requestID, actor, id)
}

func (handler *Handler) collection(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	actor regioncatalog.Actor,
) {
	switch request.Method {
	case http.MethodGet:
		input, ok := listInput(request)
		if !ok {
			writeError(response, requestID, http.StatusBadRequest, "regions_validation_error", "区域目录查询参数无效")
			return
		}
		page, err := handler.catalog.List(request.Context(), actor, input)
		if err != nil {
			writeCatalogError(response, requestID, err)
			return
		}
		writeJSON(response, http.StatusOK, page)
	case http.MethodPost:
		if len(request.URL.Query()) != 0 {
			writeError(response, requestID, http.StatusBadRequest, "regions_validation_error", "区域目录请求参数无效")
			return
		}
		key, ok := idempotencyKey(request)
		if !ok {
			writeError(response, requestID, http.StatusBadRequest, "regions_validation_error", "Idempotency-Key 格式无效")
			return
		}
		var body regionBody
		if err := decodeBody(response, request, &body); err != nil {
			writeError(response, requestID, http.StatusBadRequest, "regions_validation_error", "区域字段无效")
			return
		}
		result, replayed, err := handler.catalog.Create(request.Context(), actor, regioncatalog.CreateRequest{
			Name: body.Name, CountryCode: body.CountryCode, ProvinceCode: body.ProvinceCode, Description: body.Description,
			L2CheckPort: body.L2CheckPort, Sort: body.Sort, IdempotencyKey: key, RequestID: requestID,
		})
		if err != nil {
			writeCatalogError(response, requestID, err)
			return
		}
		response.Header().Set("Location", Route+"/"+result.ID)
		writeRegion(response, http.StatusCreated, result, replayed)
	default:
		response.Header().Set("Allow", "GET, POST")
		writeError(response, requestID, http.StatusMethodNotAllowed, "regions_method_not_allowed", "请求方法不受支持")
	}
}

func (handler *Handler) item(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	actor regioncatalog.Actor,
	id string,
) {
	if len(request.URL.Query()) != 0 {
		writeError(response, requestID, http.StatusBadRequest, "regions_validation_error", "区域目录请求参数无效")
		return
	}
	switch request.Method {
	case http.MethodGet:
		if !emptyBody(request) {
			writeError(response, requestID, http.StatusBadRequest, "regions_validation_error", "区域详情请求正文必须为空")
			return
		}
		result, err := handler.catalog.Get(request.Context(), actor, id)
		if err != nil {
			writeCatalogError(response, requestID, err)
			return
		}
		writeRegion(response, http.StatusOK, result, false)
	case http.MethodPatch, http.MethodPut:
		key, ok := idempotencyKey(request)
		if !ok {
			writeError(response, requestID, http.StatusBadRequest, "regions_validation_error", "Idempotency-Key 格式无效")
			return
		}
		revision, err := expectedRevision(request)
		if err != nil {
			writeCatalogError(response, requestID, err)
			return
		}
		var body regionBody
		if err := decodeBody(response, request, &body); err != nil {
			writeError(response, requestID, http.StatusBadRequest, "regions_validation_error", "区域字段无效")
			return
		}
		result, replayed, err := handler.catalog.Update(request.Context(), actor, regioncatalog.UpdateRequest{
			ID: id, ExpectedRevision: revision, Name: body.Name, CountryCode: body.CountryCode,
			ProvinceCode: body.ProvinceCode, Description: body.Description, L2CheckPort: body.L2CheckPort, Sort: body.Sort, IdempotencyKey: key, RequestID: requestID,
		})
		if err != nil {
			writeCatalogError(response, requestID, err)
			return
		}
		writeRegion(response, http.StatusOK, result, replayed)
	case http.MethodDelete:
		if !emptyBody(request) {
			writeError(response, requestID, http.StatusBadRequest, "regions_validation_error", "删除区域请求正文必须为空")
			return
		}
		key, ok := idempotencyKey(request)
		if !ok {
			writeError(response, requestID, http.StatusBadRequest, "regions_validation_error", "Idempotency-Key 格式无效")
			return
		}
		revision, err := expectedRevision(request)
		if err != nil {
			writeCatalogError(response, requestID, err)
			return
		}
		replayed, err := handler.catalog.Delete(request.Context(), actor, regioncatalog.DeleteRequest{
			ID: id, ExpectedRevision: revision, IdempotencyKey: key, RequestID: requestID,
		})
		if err != nil {
			writeCatalogError(response, requestID, err)
			return
		}
		if replayed {
			response.Header().Set("Idempotent-Replay", "true")
		}
		response.WriteHeader(http.StatusNoContent)
	default:
		response.Header().Set("Allow", "GET, PATCH, PUT, DELETE")
		writeError(response, requestID, http.StatusMethodNotAllowed, "regions_method_not_allowed", "请求方法不受支持")
	}
}

func (handler *Handler) actor(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) (regioncatalog.Actor, bool) {
	rawToken, ok := bearer(request)
	if !ok {
		writeError(response, requestID, http.StatusUnauthorized, "regions_unauthenticated", "需要有效的平台管理员会话")
		return regioncatalog.Actor{}, false
	}
	session, err := handler.authenticate(request.Context(), rawToken)
	if err != nil || session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		writeError(response, requestID, http.StatusUnauthorized, "regions_unauthenticated", "需要有效的平台管理员会话")
		return regioncatalog.Actor{}, false
	}
	principal := session.Principal
	if principal.ScopeKind != "platform" || principal.TenantID != nil {
		writeError(response, requestID, http.StatusForbidden, "regions_permission_denied", "区域目录只允许平台作用域访问")
		return regioncatalog.Actor{}, false
	}
	return regioncatalog.Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
		Permissions: append([]string(nil), principal.Permissions...),
	}, true
}

func allowed(actor regioncatalog.Actor, manage bool) bool {
	permission := regioncatalog.PermissionRead
	if manage {
		permission = regioncatalog.PermissionManage
	}
	return slices.Contains(actor.Permissions, permission) || slices.Contains(actor.Permissions, "platform.admin")
}

func listInput(request *http.Request) (regioncatalog.ListRequest, bool) {
	allowedKeys := map[string]bool{"limit": true, "search": true, "page": true, "page_size": true}
	for key, values := range request.URL.Query() {
		if !allowedKeys[key] || len(values) != 1 {
			return regioncatalog.ListRequest{}, false
		}
	}
	if !emptyBody(request) {
		return regioncatalog.ListRequest{}, false
	}
	query := request.URL.Query()
	if query.Has("limit") && (query.Has("page") || query.Has("page_size")) {
		return regioncatalog.ListRequest{}, false
	}
	search := strings.TrimSpace(query.Get("search"))
	if utf8.RuneCountInString(search) > 128 || strings.IndexFunc(search, unicode.IsControl) >= 0 {
		return regioncatalog.ListRequest{}, false
	}
	if query.Has("page") || query.Has("page_size") {
		page, ok := positiveQueryInt(query.Get("page"), 1, 1<<31-1)
		if query.Get("page") == "" {
			page, ok = 1, true
		}
		if !ok {
			return regioncatalog.ListRequest{}, false
		}
		pageSize, ok := positiveQueryInt(query.Get("page_size"), 1, 300)
		if query.Get("page_size") == "" {
			pageSize, ok = 10, true
		}
		if !ok {
			return regioncatalog.ListRequest{}, false
		}
		return regioncatalog.ListRequest{Search: search, Paginated: true, Page: page, PageSize: pageSize}, true
	}
	limit := 50
	if raw := query.Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 || value > 300 || strconv.Itoa(value) != raw {
			return regioncatalog.ListRequest{}, false
		}
		limit = value
	}
	return regioncatalog.ListRequest{Limit: limit, Search: search}, true
}

func positiveQueryInt(raw string, minimum, maximum int) (int, bool) {
	value, err := strconv.Atoi(raw)
	return value, err == nil && value >= minimum && value <= maximum && strconv.Itoa(value) == raw
}

func itemID(path string) (string, bool) {
	prefix := Route + "/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	id := strings.TrimPrefix(path, prefix)
	if id == "" || strings.Contains(id, "/") || id[0] == '0' || len(id) > 19 {
		return "", false
	}
	parsed, err := strconv.ParseInt(id, 10, 64)
	return id, err == nil && parsed > 0 && strconv.FormatInt(parsed, 10) == id
}

func idempotencyKey(request *http.Request) (string, bool) {
	values := request.Header.Values("Idempotency-Key")
	return request.Header.Get("Idempotency-Key"), len(values) == 1 && idempotencyPattern.MatchString(values[0])
}

func expectedRevision(request *http.Request) (int64, error) {
	values := request.Header.Values("If-Match")
	if len(values) == 0 {
		return 0, errPreconditionRequired
	}
	if len(values) != 1 {
		return 0, regioncatalog.ErrInvalidInput
	}
	value := values[0]
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' || strings.TrimSpace(value) != value {
		return 0, regioncatalog.ErrInvalidInput
	}
	revision, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != value[1:len(value)-1] {
		return 0, regioncatalog.ErrInvalidInput
	}
	return revision, nil
}

func decodeBody(response http.ResponseWriter, request *http.Request, target any) error {
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return regioncatalog.ErrInvalidInput
	}
	request.Body = http.MaxBytesReader(response, request.Body, 64<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return regioncatalog.ErrInvalidInput
	}
	return nil
}

func emptyBody(request *http.Request) bool {
	if request.Body == nil {
		return true
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, 1))
	return err == nil && len(payload) == 0
}

func bearer(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 8192 {
		return "", false
	}
	return parts[1], true
}

func writeRegion(response http.ResponseWriter, status int, value regioncatalog.Region, replayed bool) {
	response.Header().Set("ETag", `"`+strconv.FormatInt(value.Revision, 10)+`"`)
	if replayed {
		response.Header().Set("Idempotent-Replay", "true")
	}
	writeJSON(response, status, value)
}

func writeCatalogError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, errPreconditionRequired):
		writeError(response, requestID, http.StatusPreconditionRequired, "regions_precondition_required", "必须提供 If-Match 修订值")
	case errors.Is(err, regioncatalog.ErrInvalidInput):
		writeError(response, requestID, http.StatusBadRequest, "regions_validation_error", "区域目录请求参数无效")
	case errors.Is(err, regioncatalog.ErrUnauthenticated):
		writeError(response, requestID, http.StatusUnauthorized, "regions_unauthenticated", "需要有效的平台管理员会话")
	case errors.Is(err, regioncatalog.ErrPermissionDenied):
		writeError(response, requestID, http.StatusForbidden, "regions_permission_denied", "没有区域目录操作权限")
	case errors.Is(err, regioncatalog.ErrNotFound):
		writeError(response, requestID, http.StatusNotFound, "regions_not_found", "区域不存在")
	case errors.Is(err, regioncatalog.ErrNameConflict):
		writeError(response, requestID, http.StatusConflict, "regions_name_conflict", "区域名称已存在")
	case errors.Is(err, regioncatalog.ErrIdempotencyConflict):
		writeError(response, requestID, http.StatusConflict, "regions_idempotency_conflict", "幂等键已用于不同的区域请求")
	case errors.Is(err, regioncatalog.ErrInUse):
		writeError(response, requestID, http.StatusConflict, "regions_in_use", "区域正在被节点使用，不能重命名或删除")
	case errors.Is(err, regioncatalog.ErrRevisionConflict):
		writeError(response, requestID, http.StatusPreconditionFailed, "regions_revision_conflict", "区域已被其他操作修改")
	default:
		writeError(response, requestID, http.StatusServiceUnavailable, "regions_unavailable", "区域目录服务暂时不可用")
	}
}

func regionRequestID(request *http.Request) string {
	if request != nil {
		if value := strings.TrimSpace(request.Header.Get("X-Request-ID")); requestIDPattern.MatchString(value) {
			return value
		}
	}
	return uuid.NewString()
}

func setHeaders(header http.Header, requestID string) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Request-ID", requestID)
}

func writeError(response http.ResponseWriter, requestID string, status int, code, message string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{
		"code": code, "message": message, "request_id": requestID,
	}})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
