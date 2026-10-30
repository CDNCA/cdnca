package systemcleanuphttp

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

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemcleanup"
	"github.com/google/uuid"
)

const route = "/v1/admin/system-cleanup-settings"

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Service interface {
	Get(context.Context, systemcleanup.Actor) (systemcleanup.Document, error)
	Save(context.Context, systemcleanup.Actor, systemcleanup.SaveRequest) (systemcleanup.Document, error)
}
type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)
type Handler struct {
	service          Service
	authenticate     AuthenticateFunc
	timeout          time.Duration
	maxRequestBytes  int64
	maxResponseBytes int
}

func New(service Service, authenticate AuthenticateFunc) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, errors.New("system cleanup HTTP dependencies are required")
	}
	return &Handler{service: service, authenticate: authenticate, timeout: 15 * time.Second, maxRequestBytes: 64 << 10, maxResponseBytes: 256 << 10}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setHeaders(w.Header())
	if h == nil || r == nil || r.URL == nil {
		http.NotFound(w, r)
		return
	}
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if !metadataPattern.MatchString(requestID) {
		requestID = "system-cleanup-settings-http"
	}
	w.Header().Set("X-Request-ID", requestID)
	raw, ok := bearer(r)
	if !ok {
		h.error(w, requestID, 401, "system_cleanup_settings_unauthenticated", "需要有效的管理员会话")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	r = r.WithContext(ctx)
	session, err := h.authenticate(r, raw)
	if err != nil {
		h.error(w, requestID, 401, "system_cleanup_settings_unauthenticated", "需要有效的管理员会话")
		return
	}
	if session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		h.error(w, requestID, http.StatusUnauthorized, "system_cleanup_settings_unauthenticated", "需要有效的管理员会话")
		return
	}
	actor, ok := actorFromSession(session)
	if !ok {
		h.error(w, requestID, http.StatusForbidden, "system_cleanup_settings_permission_denied", "没有数据清理配置操作权限")
		return
	}
	if r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.Path != route {
		h.error(w, requestID, 404, "system_cleanup_settings_not_found", "数据清理资源不存在")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !emptyBody(r.Body) {
			h.error(w, requestID, 400, "system_cleanup_settings_validation_error", "读取请求不能包含正文")
			return
		}
		value, err := h.service.Get(r.Context(), actor)
		h.writeResult(w, requestID, value, err)
	case http.MethodPut:
		h.put(w, r, requestID, actor)
	default:
		w.Header().Set("Allow", "GET, PUT")
		h.error(w, requestID, 405, "system_cleanup_settings_method_not_allowed", "请求方法不受支持")
	}
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request, requestID string, actor systemcleanup.Actor) {
	if len(r.Header.Values("X-Request-ID")) != 1 || r.Header.Get("X-Request-ID") != requestID || len(r.Header.Values("Idempotency-Key")) != 1 || !metadataPattern.MatchString(r.Header.Get("Idempotency-Key")) {
		h.error(w, requestID, 400, "system_cleanup_settings_validation_error", "写入请求元数据无效")
		return
	}
	expected, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		h.error(w, requestID, 400, "system_cleanup_settings_validation_error", "If-Match 无效")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.maxRequestBytes)
	var body struct {
		Value systemcleanup.Settings `json:"value"`
	}
	if err := decodeStrict(r.Body, &body); err != nil {
		h.error(w, requestID, 400, "system_cleanup_settings_validation_error", "数据清理字段无效")
		return
	}
	value, err := h.service.Save(r.Context(), actor, systemcleanup.SaveRequest{ExpectedRevision: expected, Value: body.Value, IdempotencyKey: r.Header.Get("Idempotency-Key"), RequestID: requestID})
	h.writeResult(w, requestID, value, err)
}

func (h *Handler) writeResult(w http.ResponseWriter, requestID string, value systemcleanup.Document, err error) {
	if err != nil {
		status, code, message := 500, "system_cleanup_settings_unavailable", "数据清理服务暂时不可用"
		switch {
		case errors.Is(err, systemcleanup.ErrInvalidInput):
			status, code, message = 400, "system_cleanup_settings_validation_error", "数据清理字段无效"
		case errors.Is(err, systemcleanup.ErrPermissionDenied):
			status, code, message = 403, "system_cleanup_settings_permission_denied", "没有数据清理配置操作权限"
		case errors.Is(err, systemcleanup.ErrRevisionConflict):
			status, code, message = 409, "system_cleanup_settings_revision_conflict", "数据清理配置 revision 已变化，请刷新后重试"
		case errors.Is(err, systemcleanup.ErrIdempotencyConflict):
			status, code, message = 409, "system_cleanup_settings_idempotency_conflict", "Idempotency-Key 已用于不同请求"
		case errors.Is(err, systemcleanup.ErrUnavailable):
			status = http.StatusServiceUnavailable
		}
		h.error(w, requestID, status, code, message)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(value.Revision, 10)+`"`)
	if value.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	h.json(w, 200, value)
}

func actorFromSession(session identity.AuthenticatedSession) (systemcleanup.Actor, bool) {
	p := session.Principal
	if session.SessionID == uuid.Nil || p.UserID == uuid.Nil || p.ScopeID == uuid.Nil || p.ScopeKind != "platform" || p.TenantID != nil {
		return systemcleanup.Actor{}, false
	}
	return systemcleanup.Actor{UserID: p.UserID, ScopeID: p.ScopeID, ScopeKind: p.ScopeKind}, true
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
		status = 500
		b = []byte(`{"error":{"code":"system_cleanup_settings_unavailable","message":"数据清理服务暂时不可用"}}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
