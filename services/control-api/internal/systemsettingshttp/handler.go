package systemsettingshttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemsettings"
	"github.com/google/uuid"
)

const (
	route       = "/v1/admin/system-settings"
	publicRoute = "/v1/system-settings/public"
	// cspHostsRoute is read by the web container's nginx (auth_request)
	// before it serves index.html; it carries no session. The answer is the
	// configured 全站JS report hosts, which every tenant page already exposes.
	cspHostsRoute  = "/v1/system-settings/csp-hosts"
	cspHostsHeader = "X-Cdnca-Global-Js-Hosts"
	// cspPluginOriginsHeader (PA-19) carries the page origins of the ui_page
	// plugins enabled on this installation, for frame-src only.
	cspPluginOriginsHeader = "X-Cdnca-Plugin-Ui-Origins"
)

// PluginOriginsFunc returns the enabled ui_page plugin origins as CSP
// sources ("https://host ..."), "" when none.
type PluginOriginsFunc func(context.Context) (string, error)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Service interface {
	Get(context.Context, systemsettings.Actor) (systemsettings.Document, error)
	Save(context.Context, systemsettings.Actor, systemsettings.SaveRequest) (systemsettings.Document, error)
	Public(context.Context) (systemsettings.PublicSettings, error)
	CSPReportHosts(context.Context) (string, error)
}

type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

type Handler struct {
	service          Service
	pluginOrigins    PluginOriginsFunc
	authenticate     AuthenticateFunc
	timeout          time.Duration
	maxRequestBytes  int64
	maxResponseBytes int
}

func New(service Service, authenticate AuthenticateFunc) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, errors.New("system settings HTTP dependencies are required")
	}
	return &Handler{service: service, authenticate: authenticate, timeout: 15 * time.Second, maxRequestBytes: 512 << 10, maxResponseBytes: 1 << 20}, nil
}

// WithPluginOrigins adds the enabled ui_page plugin origins to the CSP host
// answer (PA-19). A lookup failure drops them, so the page is served with
// no plugin frame source rather than not at all.
func (h *Handler) WithPluginOrigins(origins PluginOriginsFunc) *Handler {
	h.pluginOrigins = origins
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setHeaders(w.Header())
	if h == nil || r == nil || r.URL == nil {
		http.NotFound(w, r)
		return
	}
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if !metadataPattern.MatchString(requestID) {
		requestID = "system-settings-http"
	}
	w.Header().Set("X-Request-ID", requestID)
	if r.URL.Path == cspHostsRoute {
		h.serveCSPHosts(w, r, requestID)
		return
	}
	// 登录页没有会话也要显示系统名称。完全不带 Authorization 时只回品牌白名单；
	// 带了 Authorization 但无效仍按下面走 401，不悄悄降级。
	if r.URL.Path == publicRoute && len(r.Header.Values("Authorization")) == 0 {
		h.servePublic(w, r, requestID, true)
		return
	}
	raw, ok := bearer(r)
	if !ok {
		h.error(w, requestID, http.StatusUnauthorized, "system_settings_unauthenticated", "需要有效的管理员会话")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	r = r.WithContext(ctx)
	session, err := h.authenticate(r, raw)
	if err != nil {
		h.error(w, requestID, http.StatusUnauthorized, "system_settings_unauthenticated", "需要有效的管理员会话")
		return
	}
	if session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		h.error(w, requestID, http.StatusUnauthorized, "system_settings_unauthenticated", "需要有效的管理员会话")
		return
	}
	if r.URL.Path == publicRoute {
		h.servePublic(w, r, requestID, false)
		return
	}
	actor, ok := actorFromSession(session)
	if !ok {
		h.error(w, requestID, http.StatusForbidden, "system_settings_permission_denied", "没有系统配置操作权限")
		return
	}
	if r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.Path != route {
		h.error(w, requestID, http.StatusNotFound, "system_settings_not_found", "系统配置资源不存在")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !emptyBody(r.Body) {
			h.error(w, requestID, http.StatusBadRequest, "system_settings_validation_error", "读取请求不能包含正文")
			return
		}
		value, err := h.service.Get(r.Context(), actor)
		h.writeResult(w, requestID, value, err)
		return
	case http.MethodPut:
		h.put(w, r, requestID, actor)
	default:
		w.Header().Set("Allow", "GET, PUT")
		h.error(w, requestID, http.StatusMethodNotAllowed, "system_settings_method_not_allowed", "请求方法不受支持")
	}
}

// servePublic 给任意有效会话（管理员或租户用户）返回系统名称/标题、购买说明与全站 JS；
// anonymous 时只返回系统名称与标题。
func (h *Handler) servePublic(w http.ResponseWriter, r *http.Request, requestID string, anonymous bool) {
	if r.URL.RawQuery != "" || r.URL.Fragment != "" {
		h.error(w, requestID, http.StatusNotFound, "system_settings_not_found", "系统配置资源不存在")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.error(w, requestID, http.StatusMethodNotAllowed, "system_settings_method_not_allowed", "请求方法不受支持")
		return
	}
	if !emptyBody(r.Body) {
		h.error(w, requestID, http.StatusBadRequest, "system_settings_validation_error", "读取请求不能包含正文")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	value, err := h.service.Public(ctx)
	if err != nil {
		h.error(w, requestID, http.StatusServiceUnavailable, "system_settings_unavailable", "系统配置服务暂时不可用")
		return
	}
	if anonymous {
		h.json(w, http.StatusOK, value.PublicBranding)
		return
	}
	h.json(w, http.StatusOK, value)
}

func (h *Handler) serveCSPHosts(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.URL.RawQuery != "" || r.URL.Fragment != "" {
		h.error(w, requestID, http.StatusNotFound, "system_settings_not_found", "系统配置资源不存在")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.error(w, requestID, http.StatusMethodNotAllowed, "system_settings_method_not_allowed", "请求方法不受支持")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	hosts, err := h.service.CSPReportHosts(ctx)
	if err != nil {
		h.error(w, requestID, http.StatusServiceUnavailable, "system_settings_unavailable", "系统配置服务暂时不可用")
		return
	}
	w.Header().Set(cspHostsHeader, hosts)
	if h.pluginOrigins != nil {
		if origins, err := h.pluginOrigins(ctx); err == nil {
			w.Header().Set(cspPluginOriginsHeader, origins)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request, requestID string, actor systemsettings.Actor) {
	if len(r.Header.Values("X-Request-ID")) != 1 || r.Header.Get("X-Request-ID") != requestID ||
		len(r.Header.Values("Idempotency-Key")) != 1 || !metadataPattern.MatchString(r.Header.Get("Idempotency-Key")) {
		h.error(w, requestID, http.StatusBadRequest, "system_settings_validation_error", "写入请求元数据无效")
		return
	}
	expected, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		h.error(w, requestID, http.StatusBadRequest, "system_settings_validation_error", "If-Match 无效")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.maxRequestBytes)
	var body struct {
		Value systemsettings.Settings `json:"value"`
	}
	if err := decodeStrict(r.Body, &body); err != nil {
		h.error(w, requestID, http.StatusBadRequest, "system_settings_validation_error", "系统配置字段无效")
		return
	}
	value, err := h.service.Save(r.Context(), actor, systemsettings.SaveRequest{ExpectedRevision: expected, Value: body.Value, IdempotencyKey: r.Header.Get("Idempotency-Key"), RequestID: requestID})
	h.writeResult(w, requestID, value, err)
}

func (h *Handler) writeResult(w http.ResponseWriter, requestID string, value systemsettings.Document, err error) {
	if err != nil {
		status, code, message := http.StatusInternalServerError, "system_settings_unavailable", "系统配置服务暂时不可用"
		switch {
		case errors.Is(err, systemsettings.ErrInvalidInput):
			status, code, message = http.StatusBadRequest, "system_settings_validation_error", "系统配置字段无效"
		case errors.Is(err, systemsettings.ErrPermissionDenied):
			status, code, message = http.StatusForbidden, "system_settings_permission_denied", "没有系统配置操作权限"
		case errors.Is(err, systemsettings.ErrRevisionConflict):
			status, code, message = http.StatusConflict, "system_settings_revision_conflict", "系统配置 revision 已变化，请刷新后重试"
		case errors.Is(err, systemsettings.ErrIdempotencyConflict):
			status, code, message = http.StatusConflict, "system_settings_idempotency_conflict", "Idempotency-Key 已用于不同请求"
		case errors.Is(err, systemsettings.ErrUnavailable):
			status = http.StatusServiceUnavailable
		}
		body := map[string]any{"code": code, "message": message, "request_id": requestID}
		if located, ok := fielderr.As(err); ok && status == http.StatusBadRequest {
			body["details"] = map[string]string{"field": located.Field, "reason": located.Reason}
		}
		h.json(w, status, map[string]any{"error": body})
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(value.Revision, 10)+`"`)
	if value.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	h.json(w, http.StatusOK, value)
}

func actorFromSession(session identity.AuthenticatedSession) (systemsettings.Actor, bool) {
	p := session.Principal
	if session.SessionID == uuid.Nil || p.UserID == uuid.Nil || p.ScopeID == uuid.Nil || p.ScopeKind != "platform" || p.TenantID != nil {
		return systemsettings.Actor{}, false
	}
	return systemsettings.Actor{UserID: p.UserID, ScopeID: p.ScopeID, ScopeKind: p.ScopeKind}, true
}

func bearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 8192 {
		return "", false
	}
	return parts[1], true
}

func parseIfMatch(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, errors.New("invalid If-Match")
	}
	raw := value[1 : len(value)-1]
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return 0, errors.New("invalid If-Match")
	}
	return strconv.ParseInt(raw, 10, 64)
}

func decodeStrict(r io.Reader, target any) error {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}
func emptyBody(r io.ReadCloser) bool {
	if r == nil {
		return true
	}
	b, err := io.ReadAll(io.LimitReader(r, 1))
	return err == nil && len(b) == 0
}
func setHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
}
func (h *Handler) error(w http.ResponseWriter, id string, status int, code, message string) {
	h.json(w, status, map[string]any{"error": map[string]string{"code": code, "message": message, "request_id": id}})
}
func (h *Handler) json(w http.ResponseWriter, status int, value any) {
	b, err := json.Marshal(value)
	if err != nil || len(b)+1 > h.maxResponseBytes {
		status = http.StatusInternalServerError
		b = []byte(`{"error":{"code":"system_settings_unavailable","message":"系统配置服务暂时不可用"}}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
