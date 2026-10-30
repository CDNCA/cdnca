package systemmailsettingshttp

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
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"github.com/google/uuid"
)

const route = "/v1/admin/system-mail-settings"

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Service interface {
	Get(context.Context, systemmailsettings.Actor) (systemmailsettings.Document, error)
	Save(context.Context, systemmailsettings.Actor, systemmailsettings.SaveRequest) (systemmailsettings.Document, error)
}

// Tester sends a test mail through the provider on the page (optional).
type Tester interface {
	Test(context.Context, systemmailsettings.Actor, systemmailsettings.TestRequest, systemmailsettings.TestSender) (systemmailsettings.TestResult, error)
}

type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

type Handler struct {
	service      Service
	authenticate AuthenticateFunc
	timeout      time.Duration
	sendTest     systemmailsettings.TestSender
}

// WithTestSender enables POST /v1/admin/system-mail-settings/tests.
func (h *Handler) WithTestSender(send systemmailsettings.TestSender) *Handler {
	h.sendTest = send
	return h
}

func New(service Service, authenticate AuthenticateFunc) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, errors.New("system mail settings HTTP dependencies are required")
	}
	return &Handler{service: service, authenticate: authenticate, timeout: 15 * time.Second}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setHeaders(w.Header())
	if h == nil || r == nil || r.URL == nil {
		http.NotFound(w, r)
		return
	}
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if !metadataPattern.MatchString(requestID) {
		requestID = "system-mail-settings-http"
	}
	w.Header().Set("X-Request-ID", requestID)
	raw, ok := bearer(r)
	if !ok {
		h.error(w, requestID, http.StatusUnauthorized, "system_mail_settings_unauthenticated", "需要有效的管理员会话")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	session, err := h.authenticate(r.WithContext(ctx), raw)
	if err != nil {
		h.error(w, requestID, http.StatusUnauthorized, "system_mail_settings_unauthenticated", "需要有效的管理员会话")
		return
	}
	if session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		h.error(w, requestID, http.StatusUnauthorized, "system_mail_settings_unauthenticated", "需要有效的管理员会话")
		return
	}
	actor, ok := actorFromSession(session)
	if !ok {
		h.error(w, requestID, http.StatusForbidden, "system_mail_settings_permission_denied", "没有发信配置操作权限")
		return
	}
	if r.URL.RawQuery == "" && r.URL.Fragment == "" && r.URL.Path == route+"/tests" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			h.error(w, requestID, http.StatusMethodNotAllowed, "system_mail_settings_method_not_allowed", "请求方法不受支持")
			return
		}
		h.test(w, r.WithContext(ctx), requestID, actor)
		return
	}
	if r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.Path != route {
		h.error(w, requestID, http.StatusNotFound, "system_mail_settings_not_found", "发信配置资源不存在")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !emptyBody(r.Body) {
			h.error(w, requestID, http.StatusBadRequest, "system_mail_settings_validation_error", "读取请求不能包含正文")
			return
		}
		value, err := h.service.Get(ctx, actor)
		h.writeResult(w, requestID, value, err)
	case http.MethodPut:
		h.put(w, r.WithContext(ctx), requestID, actor)
	default:
		w.Header().Set("Allow", "GET, PUT")
		h.error(w, requestID, http.StatusMethodNotAllowed, "system_mail_settings_method_not_allowed", "请求方法不受支持")
	}
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request, requestID string, actor systemmailsettings.Actor) {
	if len(r.Header.Values("X-Request-ID")) != 1 || r.Header.Get("X-Request-ID") != requestID || len(r.Header.Values("Idempotency-Key")) != 1 || !metadataPattern.MatchString(r.Header.Get("Idempotency-Key")) {
		h.error(w, requestID, http.StatusBadRequest, "system_mail_settings_validation_error", "写入请求元数据无效")
		return
	}
	expected, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		h.error(w, requestID, http.StatusBadRequest, "system_mail_settings_validation_error", "If-Match 无效")
		return
	}
	var body struct {
		Value systemmailsettings.Settings `json:"value"`
		// Write-only native SMS credential; omitted or empty keeps the stored one.
		SMSAccessKeySecret string `json:"sms_access_key_secret,omitempty"`
		// Write-only official mail service credential; omitted keeps it.
		MailSecret string `json:"mail_secret,omitempty"`
	}
	if err := decodeStrict(http.MaxBytesReader(w, r.Body, 128<<10), &body); err != nil {
		h.error(w, requestID, http.StatusBadRequest, "system_mail_settings_validation_error", "发信配置字段无效")
		return
	}
	value, err := h.service.Save(r.Context(), actor, systemmailsettings.SaveRequest{ExpectedRevision: expected, Value: body.Value, SMSAccessKeySecret: body.SMSAccessKeySecret, MailSecret: body.MailSecret, IdempotencyKey: r.Header.Get("Idempotency-Key"), RequestID: requestID})
	h.writeResult(w, requestID, value, err)
}

// test sends one test mail with the settings on the page (not saved).
func (h *Handler) test(w http.ResponseWriter, r *http.Request, requestID string, actor systemmailsettings.Actor) {
	tester, ok := h.service.(Tester)
	if !ok || h.sendTest == nil {
		h.error(w, requestID, http.StatusServiceUnavailable, "system_mail_settings_test_unavailable", "发送测试邮件需要启用通知运行时")
		return
	}
	var body struct {
		Value      systemmailsettings.Settings `json:"value"`
		MailSecret string                      `json:"mail_secret,omitempty"`
		To         string                      `json:"to"`
	}
	if err := decodeStrict(http.MaxBytesReader(w, r.Body, 128<<10), &body); err != nil {
		h.error(w, requestID, http.StatusBadRequest, "system_mail_settings_validation_error", "测试邮件字段无效")
		return
	}
	result, err := tester.Test(r.Context(), actor, systemmailsettings.TestRequest{Value: body.Value, MailSecret: body.MailSecret,
		To: body.To, RequestID: requestID}, h.sendTest)
	if err != nil {
		h.writeResult(w, requestID, systemmailsettings.Document{}, err)
		return
	}
	h.json(w, http.StatusOK, result)
}

func (h *Handler) writeResult(w http.ResponseWriter, requestID string, value systemmailsettings.Document, err error) {
	if err != nil {
		status, code, message := http.StatusInternalServerError, "system_mail_settings_unavailable", "发信配置服务暂时不可用"
		switch {
		case errors.Is(err, systemmailsettings.ErrInvalidInput):
			status, code, message = http.StatusBadRequest, "system_mail_settings_validation_error", "发信配置字段无效"
		case errors.Is(err, systemmailsettings.ErrModuleNotLicensed):
			status, code, message = http.StatusForbidden, "system_mail_settings_module_not_licensed", "授权未包含所选的官方邮件服务"
		case errors.Is(err, systemmailsettings.ErrPermissionDenied):
			status, code, message = http.StatusForbidden, "system_mail_settings_permission_denied", "没有发信配置操作权限"
		case errors.Is(err, systemmailsettings.ErrRevisionConflict):
			status, code, message = http.StatusConflict, "system_mail_settings_revision_conflict", "发信配置 revision 已变化，请刷新后重试"
		case errors.Is(err, systemmailsettings.ErrIdempotencyConflict):
			status, code, message = http.StatusConflict, "system_mail_settings_idempotency_conflict", "Idempotency-Key 已用于不同请求"
		case errors.Is(err, systemmailsettings.ErrUnavailable):
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

func actorFromSession(session identity.AuthenticatedSession) (systemmailsettings.Actor, bool) {
	p := session.Principal
	if session.SessionID == uuid.Nil || p.UserID == uuid.Nil || p.ScopeID == uuid.Nil || p.ScopeKind != "platform" || p.TenantID != nil {
		return systemmailsettings.Actor{}, false
	}
	return systemmailsettings.Actor{UserID: p.UserID, ScopeID: p.ScopeID, ScopeKind: p.ScopeKind}, true
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
	if err != nil {
		status = http.StatusInternalServerError
		b = []byte(`{"error":{"code":"system_mail_settings_unavailable","message":"发信配置服务暂时不可用"}}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
