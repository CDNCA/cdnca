package systemconfighttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
)

const (
	categoryPrefix             = "/v1/admin/system-configuration/categories/"
	revisionPrefix             = "/v1/admin/system-configuration/revisions/"
	defaultRequestBytes  int64 = 64 << 10
	defaultResponseBytes       = 1 << 20
	defaultTimeout             = 15 * time.Second
)

var (
	ErrInvalidDependencies = errors.New("invalid system configuration HTTP dependencies")
	ErrUnauthenticated     = errors.New("system configuration authentication required")
	ErrUnavailable         = errors.New("system configuration HTTP unavailable")
	metadataPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type CategoryService interface {
	GetActiveCategory(context.Context, systemconfig.Actor, string) (systemconfig.CategoryDocument, error)
	SaveCategory(context.Context, systemconfig.Actor, systemconfig.SaveCategoryRequest) (systemconfig.CategoryDocument, error)
}

type LifecycleService interface {
	PreflightRevision(context.Context, systemconfig.Actor, systemconfig.PreflightRevisionRequest) (systemconfig.Revision, error)
	ActivateRevision(context.Context, systemconfig.Actor, systemconfig.ActivateRequest) (systemconfig.Revision, error)
	ActivationStatus(context.Context, systemconfig.Actor, int64) ([]systemconfig.ActivationStatus, error)
}

type RollbackService interface {
	RollbackRevision(context.Context, systemconfig.Actor, systemconfig.RollbackRequest) (systemconfig.Revision, error)
}

type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

type HandlerConfig struct {
	Timeout          time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int
}

type Handler struct {
	service          CategoryService
	lifecycle        LifecycleService
	authenticate     AuthenticateFunc
	timeout          time.Duration
	maxRequestBytes  int64
	maxResponseBytes int
}

type valueEnvelope struct {
	Value json.RawMessage `json:"value"`
}

type secretValue struct {
	ErrorPageStorage secretIntent `json:"error_page_storage"`
}

type secretIntent struct {
	Intent      string                                `json:"intent"`
	Replacement *systemconfig.SecretEnvelopeReference `json:"replacement,omitempty"`
}

func NewHandler(service CategoryService, authenticate AuthenticateFunc, config HandlerConfig) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidDependencies
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultRequestBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultResponseBytes
	}
	if config.Timeout <= 0 || config.Timeout > 30*time.Second ||
		config.MaxRequestBytes < 1024 || config.MaxRequestBytes > 1<<20 ||
		config.MaxResponseBytes < 512 || config.MaxResponseBytes > 4<<20 {
		return nil, ErrInvalidDependencies
	}
	lifecycle, _ := service.(LifecycleService)
	return &Handler{service: service, lifecycle: lifecycle, authenticate: authenticate, timeout: config.Timeout,
		maxRequestBytes: config.MaxRequestBytes, maxResponseBytes: config.MaxResponseBytes}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer.Header())
	if handler == nil || request == nil || request.URL == nil {
		http.NotFound(writer, request)
		return
	}
	requestID := requestIdentifier(request)
	writer.Header().Set("X-Request-ID", requestID)
	rawSession, err := bearerSession(request)
	if err != nil || hasUntrustedIdentityHeaders(request) {
		handler.writeError(writer, requestID, http.StatusUnauthorized,
			"system_configuration_unauthenticated", "需要有效的管理员会话")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	request = request.WithContext(ctx)
	session, err := handler.authenticate(request, rawSession)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, ErrUnauthenticated) {
			handler.writeError(writer, requestID, http.StatusUnauthorized,
				"system_configuration_unauthenticated", "需要有效的管理员会话")
		} else {
			slog.Error("system configuration authentication failed",
				"stage", "authenticate", "request_id", requestID,
				"error_chain", systemConfigurationErrorChain(err))
			handler.writeError(writer, requestID, http.StatusInternalServerError,
				"system_configuration_unavailable", "系统配置服务暂时不可用")
		}
		return
	}
	actor, ok := actorFromSession(session)
	if !ok {
		handler.writeError(writer, requestID, http.StatusUnauthorized,
			"system_configuration_unauthenticated", "需要有效的管理员会话")
		return
	}
	if request.URL.RawQuery != "" || request.URL.Fragment != "" || len(request.URL.Path) > 512 {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "请求格式无效")
		return
	}
	if revision, action, matched := resolveRevisionAction(request.URL.Path); matched {
		handler.revisionAction(writer, request, requestID, actor, revision, action)
		return
	}
	category, matched := resolveCategory(request.URL.Path)
	if !matched || !knownCategory(category) {
		handler.writeError(writer, requestID, http.StatusNotFound,
			"system_configuration_category_not_found", "系统配置分类不存在")
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodPut {
		writer.Header().Set("Allow", "GET, PUT")
		handler.writeError(writer, requestID, http.StatusMethodNotAllowed,
			"system_configuration_method_not_allowed", "请求方法不受支持")
		return
	}
	if request.Method == http.MethodGet {
		handler.get(writer, request, requestID, actor, category)
		return
	}
	handler.put(writer, request, requestID, actor, category)
}

func (handler *Handler) revisionAction(writer http.ResponseWriter, request *http.Request, requestID string,
	actor systemconfig.Actor, revision int64, action string,
) {
	slog.Info("system configuration revision request",
		"stage", "revision_action", "action", action, "method", request.Method,
		"revision", revision, "request_id", requestID)
	if action == "rollback" {
		handler.rollbackRevision(writer, request, requestID, actor, revision)
		return
	}
	if handler.lifecycle == nil {
		handler.writeError(writer, requestID, http.StatusServiceUnavailable,
			"system_configuration_publication_unavailable", "系统配置发布服务暂时不可用")
		return
	}
	if action == "publications" {
		if request.Method != http.MethodGet || request.ContentLength > 0 {
			writer.Header().Set("Allow", "GET")
			handler.writeError(writer, requestID, http.StatusMethodNotAllowed,
				"system_configuration_method_not_allowed", "请求方法不受支持")
			return
		}
		items, err := handler.lifecycle.ActivationStatus(request.Context(), actor, revision)
		if err != nil {
			handler.writeServiceError(writer, requestID, err)
			return
		}
		handler.writeJSON(writer, requestID, http.StatusOK, map[string]any{"revision": revision, "publications": items})
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		handler.writeError(writer, requestID, http.StatusMethodNotAllowed,
			"system_configuration_method_not_allowed", "请求方法不受支持")
		return
	}
	key, ok := handler.writeMetadata(writer, request, requestID)
	if !ok {
		return
	}
	if action == "preflight" {
		if mediaType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]); mediaType != "application/json" {
			handler.writeError(writer, requestID, http.StatusBadRequest,
				"system_configuration_validation_error", "请求正文必须使用 application/json")
			return
		}
		request.Body = http.MaxBytesReader(nil, request.Body, handler.maxRequestBytes)
		var body struct {
			SnapshotSHA256            string    `json:"snapshot_sha256"`
			ExpectedPendingCategories *[]string `json:"expected_pending_categories"`
		}
		if err := decodeStrict(request.Body, &body); err != nil {
			handler.writeError(writer, requestID, http.StatusBadRequest,
				"system_configuration_validation_error", "系统配置预检参数无效")
			return
		}
		result, err := handler.lifecycle.PreflightRevision(request.Context(), actor, systemconfig.PreflightRevisionRequest{
			Revision: revision, SnapshotSHA256: body.SnapshotSHA256,
			ExpectedPendingCategories: body.ExpectedPendingCategories, IdempotencyKey: key, RequestID: requestID,
		})
		if err != nil {
			handler.writeServiceError(writer, requestID, err)
			return
		}
		handler.writeJSON(writer, requestID, http.StatusOK, revisionEnvelope(result))
		return
	}
	// The body is optional; when present it carries the categories the
	// operator confirmed the activation makes effective.
	var activation struct {
		ExpectedPendingCategories *[]string `json:"expected_pending_categories"`
	}
	if request.ContentLength != 0 {
		if mediaType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]); mediaType != "application/json" {
			handler.writeError(writer, requestID, http.StatusBadRequest,
				"system_configuration_validation_error", "请求正文必须使用 application/json")
			return
		}
		request.Body = http.MaxBytesReader(nil, request.Body, handler.maxRequestBytes)
		if err := decodeStrict(request.Body, &activation); err != nil {
			handler.writeError(writer, requestID, http.StatusBadRequest,
				"system_configuration_validation_error", "系统配置激活参数无效")
			return
		}
	}
	expectedActive, err := parseIfMatch(request)
	if err != nil {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "If-Match 必须是带引号的非负 revision")
		return
	}
	slog.Info("system configuration activation dispatch",
		"stage", "activate_dispatch", "revision", revision,
		"expected_active_revision", expectedActive, "request_id", requestID)
	result, err := handler.lifecycle.ActivateRevision(request.Context(), actor, systemconfig.ActivateRequest{
		Revision: revision, ExpectedActiveRevision: expectedActive,
		ExpectedPendingCategories: activation.ExpectedPendingCategories, IdempotencyKey: key, RequestID: requestID,
	})
	if err != nil {
		slog.Error("system configuration activation returned an error",
			"stage", "activate_error", "revision", revision, "request_id", requestID,
			"error_class", systemConfigurationErrorClass(err),
			"error_chain", systemConfigurationErrorChain(err))
		handler.writeServiceError(writer, requestID, err)
		return
	}
	slog.Info("system configuration activation returned successfully",
		"stage", "activate_success", "revision", revision, "request_id", requestID)
	handler.writeJSON(writer, requestID, http.StatusOK, revisionEnvelope(result))
}

func (handler *Handler) rollbackRevision(writer http.ResponseWriter, request *http.Request, requestID string,
	actor systemconfig.Actor, targetRevision int64,
) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		handler.writeError(writer, requestID, http.StatusMethodNotAllowed,
			"system_configuration_method_not_allowed", "请求方法不受支持")
		return
	}
	service, ok := handler.service.(RollbackService)
	if !ok {
		handler.writeError(writer, requestID, http.StatusServiceUnavailable,
			"system_configuration_rollback_unavailable", "系统配置回滚服务暂时不可用")
		return
	}
	key, ok := handler.writeMetadata(writer, request, requestID)
	if !ok {
		return
	}
	expectedHead, err := parseIfMatch(request)
	if err != nil {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "If-Match 必须是带引号的非负 revision")
		return
	}
	if mediaType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]); mediaType != "application/json" {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "请求正文必须使用 application/json")
		return
	}
	request.Body = http.MaxBytesReader(nil, request.Body, handler.maxRequestBytes)
	var body struct {
		ExpectedActiveRevision int64 `json:"expected_active_revision"`
	}
	if err := decodeStrict(request.Body, &body); err != nil || body.ExpectedActiveRevision < 1 {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "系统配置回滚参数无效")
		return
	}
	result, err := service.RollbackRevision(request.Context(), actor, systemconfig.RollbackRequest{
		TargetRevision: targetRevision, ExpectedHeadRevision: expectedHead,
		ExpectedActiveRevision: body.ExpectedActiveRevision, IdempotencyKey: key, RequestID: requestID,
	})
	if err != nil {
		switch {
		case errors.Is(err, systemconfig.ErrNotFound):
			handler.writeError(writer, requestID, http.StatusNotFound,
				"system_configuration_revision_not_found", "目标系统配置 revision 不存在")
		case errors.Is(err, systemconfig.ErrInvalidTransition):
			handler.writeError(writer, requestID, http.StatusConflict,
				"system_configuration_invalid_transition", "目标 revision 不是可回滚的已生效历史版本")
		default:
			handler.writeServiceError(writer, requestID, err)
		}
		return
	}
	if result.Revision < 1 || result.Status != systemconfig.StatusDraft ||
		result.SourceRevision == nil || *result.SourceRevision != targetRevision {
		handler.writeError(writer, requestID, http.StatusInternalServerError,
			"system_configuration_unavailable", "系统配置服务暂时不可用")
		return
	}
	writer.Header().Set("ETag", quotedRevision(result.Revision))
	if result.Replayed {
		writer.Header().Set("Idempotency-Replayed", "true")
	}
	handler.writeJSON(writer, requestID, http.StatusOK, map[string]any{
		"revision": result.Revision, "status": result.Status,
		"snapshot_sha256": result.SnapshotSHA256, "source_revision": *result.SourceRevision,
		"replayed": result.Replayed,
	})
}

func revisionEnvelope(result systemconfig.Revision) map[string]any {
	return map[string]any{
		"revision": result.Revision, "status": result.Status,
		"snapshot_sha256": result.SnapshotSHA256, "replayed": result.Replayed,
	}
}

func (handler *Handler) writeMetadata(writer http.ResponseWriter, request *http.Request, requestID string) (string, bool) {
	if !metadataPattern.MatchString(strings.TrimSpace(request.Header.Get("X-Request-ID"))) ||
		requestID != strings.TrimSpace(request.Header.Get("X-Request-ID")) {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "X-Request-ID 无效")
		return "", false
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if len(request.Header.Values("Idempotency-Key")) != 1 || !metadataPattern.MatchString(key) {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "Idempotency-Key 无效")
		return "", false
	}
	return key, true
}

func (handler *Handler) get(writer http.ResponseWriter, request *http.Request, requestID string,
	actor systemconfig.Actor, category string,
) {
	if request.ContentLength > 0 {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "读取请求不能包含正文")
		return
	}
	document, err := handler.service.GetActiveCategory(request.Context(), actor, category)
	if err != nil {
		handler.writeServiceError(writer, requestID, err)
		return
	}
	writer.Header().Set("ETag", quotedRevision(document.HeadRevision))
	handler.writeJSON(writer, requestID, http.StatusOK, document)
}

func (handler *Handler) put(writer http.ResponseWriter, request *http.Request, requestID string,
	actor systemconfig.Actor, category string,
) {
	if !metadataPattern.MatchString(strings.TrimSpace(request.Header.Get("X-Request-ID"))) ||
		requestID != strings.TrimSpace(request.Header.Get("X-Request-ID")) {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "X-Request-ID 无效")
		return
	}
	key := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if len(request.Header.Values("Idempotency-Key")) != 1 || !metadataPattern.MatchString(key) {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "Idempotency-Key 无效")
		return
	}
	expected, err := parseIfMatch(request)
	if err != nil {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "If-Match 必须是带引号的非负 revision")
		return
	}
	if mediaType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]); mediaType != "application/json" {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "请求正文必须使用 application/json")
		return
	}
	change, err := handler.decodeChange(request, category)
	if err != nil {
		handler.writeError(writer, requestID, http.StatusBadRequest,
			"system_configuration_validation_error", "系统配置字段无效")
		return
	}
	document, err := handler.service.SaveCategory(request.Context(), actor, systemconfig.SaveCategoryRequest{
		Category: category, ExpectedHeadRevision: expected, Change: change,
		IdempotencyKey: key, RequestID: requestID,
	})
	if err != nil {
		handler.writeServiceError(writer, requestID, err)
		return
	}
	writer.Header().Set("ETag", quotedRevision(document.HeadRevision))
	if document.Replayed {
		writer.Header().Set("Idempotency-Replayed", "true")
	}
	handler.writeJSON(writer, requestID, http.StatusOK, document)
}

func (handler *Handler) decodeChange(request *http.Request, category string) (systemconfig.CategoryChange, error) {
	request.Body = http.MaxBytesReader(nil, request.Body, handler.maxRequestBytes)
	var envelope valueEnvelope
	if err := decodeStrict(request.Body, &envelope); err != nil || len(envelope.Value) == 0 ||
		bytes.Equal(bytes.TrimSpace(envelope.Value), []byte("null")) {
		return systemconfig.CategoryChange{}, errors.New("invalid category body")
	}
	switch category {
	case systemconfig.CategoryNginx:
		var value systemconfig.NginxLimits
		if err := decodeStrict(bytes.NewReader(envelope.Value), &value); err != nil {
			return systemconfig.CategoryChange{}, err
		}
		return systemconfig.CategoryChange{Nginx: &value}, nil
	case systemconfig.CategoryDefaults:
		var value systemconfig.DefaultReferences
		if err := decodeStrict(bytes.NewReader(envelope.Value), &value); err != nil {
			return systemconfig.CategoryChange{}, err
		}
		return systemconfig.CategoryChange{Defaults: &value}, nil
	case systemconfig.CategoryResources:
		var value systemconfig.ResourceLimits
		if err := decodeStrict(bytes.NewReader(envelope.Value), &value); err != nil {
			return systemconfig.CategoryChange{}, err
		}
		return systemconfig.CategoryChange{Resources: &value}, nil
	case systemconfig.CategoryErrorPages:
		var value []systemconfig.ErrorPageMetadata
		if err := decodeStrict(bytes.NewReader(envelope.Value), &value); err != nil {
			return systemconfig.CategoryChange{}, err
		}
		return systemconfig.CategoryChange{ErrorPages: &value}, nil
	case systemconfig.CategorySecrets:
		var value secretValue
		if err := decodeStrict(bytes.NewReader(envelope.Value), &value); err != nil {
			return systemconfig.CategoryChange{}, err
		}
		if (value.ErrorPageStorage.Intent == systemconfig.SecretIntentClear && value.ErrorPageStorage.Replacement != nil) ||
			(value.ErrorPageStorage.Intent == systemconfig.SecretIntentReplace && value.ErrorPageStorage.Replacement == nil) ||
			(value.ErrorPageStorage.Intent != systemconfig.SecretIntentClear &&
				value.ErrorPageStorage.Intent != systemconfig.SecretIntentReplace) {
			return systemconfig.CategoryChange{}, errors.New("invalid secret intent")
		}
		return systemconfig.CategoryChange{Secret: &systemconfig.SecretChange{
			Intent: value.ErrorPageStorage.Intent, Replacement: value.ErrorPageStorage.Replacement,
		}}, nil
	case systemconfig.CategoryNodeMonitoring:
		var value systemconfig.NodeMonitoringConfiguration
		if err := decodeStrict(bytes.NewReader(envelope.Value), &value); err != nil {
			return systemconfig.CategoryChange{}, err
		}
		return systemconfig.CategoryChange{NodeMonitoring: &value}, nil
	case systemconfig.CategoryDDoSProtection:
		var value edgeconfig.DDoSProtection
		if err := decodeStrict(bytes.NewReader(envelope.Value), &value); err != nil {
			return systemconfig.CategoryChange{}, err
		}
		return systemconfig.CategoryChange{DDoSProtection: &value}, nil
	case systemconfig.CategoryAccessLogFields:
		var value edgeconfig.AccessLogFields
		if err := decodeStrict(bytes.NewReader(envelope.Value), &value); err != nil {
			return systemconfig.CategoryChange{}, err
		}
		return systemconfig.CategoryChange{AccessLogFields: &value}, nil
	default:
		return systemconfig.CategoryChange{}, errors.New("invalid category")
	}
}

func decodeStrict(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}

func resolveCategory(path string) (string, bool) {
	if !strings.HasPrefix(path, categoryPrefix) {
		return "", false
	}
	category := strings.TrimPrefix(path, categoryPrefix)
	return category, category != "" && !strings.Contains(category, "/")
}

func resolveRevisionAction(path string) (int64, string, bool) {
	if !strings.HasPrefix(path, revisionPrefix) {
		return 0, "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, revisionPrefix), "/")
	if len(parts) != 2 || (parts[1] != "preflight" && parts[1] != "activate" &&
		parts[1] != "publications" && parts[1] != "rollback") {
		return 0, "", false
	}
	revision, err := strconv.ParseInt(parts[0], 10, 64)
	return revision, parts[1], err == nil && revision > 0
}

func knownCategory(category string) bool {
	for _, candidate := range systemconfig.Categories() {
		if category == candidate {
			return true
		}
	}
	return false
}

func bearerSession(request *http.Request) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return "", ErrUnauthenticated
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 8192 {
		return "", ErrUnauthenticated
	}
	return parts[1], nil
}

func hasUntrustedIdentityHeaders(request *http.Request) bool {
	for _, name := range []string{"X-User-ID", "X-Scope-ID", "X-Scope-Kind", "X-Role", "X-Roles", "X-Permission", "X-Permissions"} {
		if len(request.Header.Values(name)) > 0 {
			return true
		}
	}
	return false
}

func actorFromSession(session identity.AuthenticatedSession) (systemconfig.Actor, bool) {
	principal := session.Principal
	if session.SessionID == uuid.Nil || principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil ||
		(principal.ScopeKind != "platform" && principal.ScopeKind != "tenant") ||
		(principal.ScopeKind == "platform" && principal.TenantID != nil) ||
		(principal.ScopeKind == "tenant" && principal.TenantID == nil) {
		return systemconfig.Actor{}, false
	}
	return systemconfig.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}, true
}

func parseIfMatch(request *http.Request) (int64, error) {
	values := request.Header.Values("If-Match")
	if len(values) != 1 {
		return 0, errors.New("invalid If-Match")
	}
	value := strings.TrimSpace(values[0])
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, errors.New("invalid If-Match")
	}
	raw := value[1 : len(value)-1]
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return 0, errors.New("invalid If-Match")
	}
	revision, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || revision < 0 {
		return 0, errors.New("invalid If-Match")
	}
	return revision, nil
}

func requestIdentifier(request *http.Request) string {
	value := strings.TrimSpace(request.Header.Get("X-Request-ID"))
	if metadataPattern.MatchString(value) {
		return value
	}
	return "system-configuration-http"
}

func quotedRevision(revision int64) string {
	return `"` + strconv.FormatInt(revision, 10) + `"`
}

func setSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, requestID string, err error) {
	slog.Error("system configuration service error",
		"stage", "write_service_error", "request_id", requestID,
		"error_class", systemConfigurationErrorClass(err),
		"error_chain", systemConfigurationErrorChain(err))
	status, code, message := http.StatusInternalServerError,
		"system_configuration_unavailable", "系统配置服务暂时不可用"
	switch {
	case errors.Is(err, systemconfig.ErrRegionOverrideUnsupported):
		status, code, message = http.StatusBadRequest, "system_configuration_region_override_unsupported",
			"该配置项在建站时取值，不支持按区域覆盖；默认配置只有 GZIP 开关与压缩类型可按区域设置"
	case errors.Is(err, systemconfig.ErrInvalidInput):
		status, code, message = http.StatusBadRequest, "system_configuration_validation_error", "系统配置字段无效"
	case errors.Is(err, systemconfig.ErrPermissionDenied):
		status, code, message = http.StatusForbidden, "system_configuration_permission_denied", "没有系统配置操作权限"
	case errors.Is(err, systemconfig.ErrNotFound):
		status, code, message = http.StatusNotFound, "system_configuration_active_not_found", "尚无已生效的系统配置"
	case errors.Is(err, systemconfig.ErrRevisionConflict):
		status, code, message = http.StatusConflict, "system_configuration_revision_conflict", "系统配置 revision 已变化，请刷新后重试"
	case errors.Is(err, systemconfig.ErrPendingCategoriesChanged):
		status, code, message = http.StatusConflict, "system_configuration_pending_categories_changed", "本次将一并生效的配置分类已变化，请刷新后重新确认"
	case errors.Is(err, systemconfig.ErrIdempotencyConflict):
		status, code, message = http.StatusConflict, "system_configuration_idempotency_conflict", "Idempotency-Key 已用于不同请求"
	case errors.Is(err, systemconfig.ErrEntitlementDenied):
		status, code, message = http.StatusUnprocessableEntity, "system_configuration_entitlement_denied", "当前授权不允许扩张系统配置"
	case errors.Is(err, systemconfig.ErrPublicationFailed):
		status, code, message = http.StatusUnprocessableEntity, "system_configuration_publication_failed", "边缘配置生成或发布失败，原生效版本保持不变"
	}
	handler.writeError(writer, requestID, status, code, message)
}

func systemConfigurationErrorClass(err error) string {
	switch {
	case errors.Is(err, systemconfig.ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, systemconfig.ErrPermissionDenied):
		return "permission_denied"
	case errors.Is(err, systemconfig.ErrNotFound):
		return "not_found"
	case errors.Is(err, systemconfig.ErrRevisionConflict):
		return "revision_conflict"
	case errors.Is(err, systemconfig.ErrPendingCategoriesChanged):
		return "pending_categories_changed"
	case errors.Is(err, systemconfig.ErrIdempotencyConflict):
		return "idempotency_conflict"
	case errors.Is(err, systemconfig.ErrEntitlementDenied):
		return "entitlement_denied"
	case errors.Is(err, systemconfig.ErrPublicationFailed):
		return "publication_failed"
	default:
		return "internal"
	}
}

func systemConfigurationErrorChain(err error) string {
	if err == nil {
		return ""
	}
	chain := make([]string, 0, 3)
	for current := err; current != nil; current = errors.Unwrap(current) {
		chain = append(chain, fmt.Sprintf("%T", current))
	}
	return strings.Join(chain, " -> ")
}

func (handler *Handler) writeError(writer http.ResponseWriter, requestID string, status int, code, message string) {
	handler.writeJSON(writer, requestID, status, map[string]any{"error": map[string]string{
		"code": code, "message": message, "request_id": requestID,
	}})
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, requestID string, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > handler.maxResponseBytes {
		encoded, _ = json.Marshal(map[string]any{"error": map[string]string{
			"code": "system_configuration_unavailable", "message": "系统配置服务暂时不可用", "request_id": requestID,
		}})
		status = http.StatusInternalServerError
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}
