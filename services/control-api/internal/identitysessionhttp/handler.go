package identitysessionhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ifMatchPattern = regexp.MustCompile(`^"([1-9][0-9]*)"$`)
	bearerPattern  = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

type SessionStore interface {
	List(context.Context, ListRequest) (ListResult, error)
	Revoke(context.Context, RevokeRequest) (RevokeResult, error)
}

type Handler struct {
	store        SessionStore
	authenticate AuthenticateSessionFunc
	routes       *http.ServeMux
}

type sessionFamilyView struct {
	FamilyID     uuid.UUID  `json:"family_id"`
	DeviceLabel  string     `json:"device_label"`
	IPPrefix     string     `json:"ip_prefix,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   time.Time  `json:"last_used_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	Current      bool       `json:"current"`
	Active       bool       `json:"active"`
	SessionCount int64      `json:"session_count"`
	Revision     int64      `json:"revision"`
}

type listResponse struct {
	Items      []sessionFamilyView `json:"items"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type revokeResponse struct {
	FamilyID  uuid.UUID `json:"family_id"`
	Revision  int64     `json:"revision"`
	RevokedAt time.Time `json:"revoked_at"`
	Current   bool      `json:"current"`
	Replayed  bool      `json:"replayed,omitempty"`
}

type errorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

type errorResponse struct {
	Error errorDetail `json:"error"`
}

func NewRuntimeHandler(pool *pgxpool.Pool, identityService *identity.Service, now Clock) (http.Handler, error) {
	if !poolConfigured(pool) || identityService == nil || !identityService.Configured() {
		return nil, ErrUnavailable
	}
	if now == nil {
		now = time.Now
	}
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, now), now)
	if err != nil {
		return nil, err
	}
	return NewHandler(store, identityService.AuthenticateSession)
}

func NewHandler(store SessionStore, authenticate AuthenticateSessionFunc) (*Handler, error) {
	if nilPort(store) || authenticate == nil {
		return nil, ErrUnavailable
	}
	handler := &Handler{store: store, authenticate: authenticate, routes: http.NewServeMux()}
	handler.routes.HandleFunc("/v1/identity/sessions", handler.listSessions)
	handler.routes.HandleFunc("/v1/identity/session-families/{family_id}", handler.revokeFamily)
	handler.routes.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		handler.writeError(response, request, http.StatusNotFound, "identity_session_not_found", "接口不存在")
	})
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID, _ := requestID(request)
	if requestID != "" {
		response.Header().Set("X-Request-ID", requestID)
	}
	handler.routes.ServeHTTP(response, request)
}

func (handler *Handler) listSessions(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		handler.writeError(response, request, http.StatusMethodNotAllowed, "identity_session_method_not_allowed", "请求方法不受支持")
		return
	}
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	limit, cursor, err := parseListQuery(request.URL.Query())
	if err != nil {
		handler.writeStoreError(response, request, err)
		return
	}
	result, err := handler.store.List(request.Context(), ListRequest{Actor: actor, Limit: limit, Cursor: cursor})
	if err != nil {
		handler.writeStoreError(response, request, err)
		return
	}
	view := listResponse{Items: make([]sessionFamilyView, len(result.Items)), NextCursor: result.NextCursor}
	for index, item := range result.Items {
		view.Items[index] = sessionFamilyView{FamilyID: item.FamilyID, DeviceLabel: item.DeviceLabel,
			IPPrefix: item.IPPrefix, CreatedAt: item.CreatedAt.UTC(), LastUsedAt: item.LastUsedAt.UTC(),
			ExpiresAt: item.ExpiresAt.UTC(), RevokedAt: utcPointer(item.RevokedAt), Current: item.Current,
			Active: item.Active, SessionCount: item.SessionCount, Revision: item.Revision}
	}
	handler.writeJSON(response, http.StatusOK, view)
}

func (handler *Handler) revokeFamily(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodDelete {
		response.Header().Set("Allow", http.MethodDelete)
		handler.writeError(response, request, http.StatusMethodNotAllowed, "identity_session_method_not_allowed", "请求方法不受支持")
		return
	}
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	if request.URL.RawQuery != "" || !emptyBody(request) {
		handler.writeStoreError(response, request, ErrInvalidInput)
		return
	}
	familyID, err := strictUUID(request.PathValue("family_id"))
	if err != nil {
		handler.writeStoreError(response, request, err)
		return
	}
	expectedRevision, err := parseIfMatch(request.Header.Values("If-Match"))
	if err != nil {
		handler.writeStoreError(response, request, err)
		return
	}
	idempotencyKey, err := singleHeader(request, "Idempotency-Key")
	if err != nil || !writeIdentityPattern.MatchString(idempotencyKey) {
		handler.writeStoreError(response, request, ErrInvalidInput)
		return
	}
	requestID, err := requestID(request)
	if err != nil {
		handler.writeStoreError(response, request, err)
		return
	}
	result, err := handler.store.Revoke(request.Context(), RevokeRequest{Actor: actor, FamilyID: familyID,
		ExpectedRevision: expectedRevision, IdempotencyKey: idempotencyKey, RequestID: requestID})
	if err != nil {
		handler.writeStoreError(response, request, err)
		return
	}
	response.Header().Set("ETag", fmt.Sprintf(`"%d"`, result.Revision))
	handler.writeJSON(response, http.StatusOK, revokeResponse{FamilyID: result.FamilyID, Revision: result.Revision,
		RevokedAt: result.RevokedAt.UTC(), Current: result.Current, Replayed: result.Replayed})
}

func (handler *Handler) actor(response http.ResponseWriter, request *http.Request) (Actor, bool) {
	if _, err := requestID(request); err != nil {
		handler.writeStoreError(response, request, err)
		return Actor{}, false
	}
	authorization, err := singleHeader(request, "Authorization")
	if err != nil || !strings.HasPrefix(authorization, "Bearer ") {
		handler.writeStoreError(response, request, ErrUnauthenticated)
		return Actor{}, false
	}
	token := strings.TrimPrefix(authorization, "Bearer ")
	if len(token) > 4096 || !bearerPattern.MatchString(token) || strings.ContainsAny(token, " \t\r\n") {
		handler.writeStoreError(response, request, ErrUnauthenticated)
		return Actor{}, false
	}
	session, err := handler.authenticate(request.Context(), token)
	if err != nil || session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil ||
		session.Principal.ScopeID == uuid.Nil ||
		(session.Principal.ScopeKind != "tenant" && session.Principal.ScopeKind != "platform") {
		handler.writeStoreError(response, request, ErrUnauthenticated)
		return Actor{}, false
	}
	return Actor{SessionID: session.SessionID, ScopeID: session.Principal.ScopeID,
		UserID: session.Principal.UserID, ScopeKind: session.Principal.ScopeKind}, true
}

func parseListQuery(query url.Values) (int, string, error) {
	for name, values := range query {
		if name != "limit" && name != "cursor" || len(values) != 1 {
			return 0, "", ErrInvalidInput
		}
	}
	limit := defaultListLimit
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || strconv.Itoa(parsed) != raw || parsed < 1 || parsed > maxListLimit {
			return 0, "", ErrInvalidInput
		}
		limit = parsed
	}
	cursor := query.Get("cursor")
	if len(cursor) > 2048 || strings.ContainsAny(cursor, "\x00\r\n \t") {
		return 0, "", ErrInvalidInput
	}
	return limit, cursor, nil
}

func parseIfMatch(values []string) (int64, error) {
	if len(values) != 1 {
		return 0, ErrInvalidInput
	}
	matches := ifMatchPattern.FindStringSubmatch(values[0])
	if len(matches) != 2 {
		return 0, ErrInvalidInput
	}
	value, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil || value < 1 || strconv.FormatInt(value, 10) != matches[1] {
		return 0, ErrInvalidInput
	}
	return value, nil
}

func requestID(request *http.Request) (string, error) {
	value, err := singleHeader(request, "X-Request-ID")
	if err != nil {
		return "", ErrInvalidInput
	}
	parsed, err := strictUUID(value)
	if err != nil {
		return "", ErrInvalidInput
	}
	return parsed.String(), nil
}

func strictUUID(raw string) (uuid.UUID, error) {
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return uuid.Nil, ErrInvalidInput
	}
	return value, nil
}

func singleHeader(request *http.Request, name string) (string, error) {
	values := request.Header.Values(name)
	if len(values) != 1 || values[0] == "" || values[0] != strings.TrimSpace(values[0]) ||
		strings.ContainsAny(values[0], "\x00\r\n") {
		return "", ErrInvalidInput
	}
	return values[0], nil
}

func emptyBody(request *http.Request) bool {
	if request.Body == nil || request.Body == http.NoBody {
		return true
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, 1))
	return err == nil && len(raw) == 0
}

func (handler *Handler) writeStoreError(response http.ResponseWriter, request *http.Request, err error) {
	status, code, message := http.StatusInternalServerError, "identity_session_internal_error", "会话服务暂时不可用"
	switch {
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrInvalidCursor):
		status, code, message = http.StatusBadRequest, "identity_session_validation_error", "请求参数无效"
	case errors.Is(err, ErrUnauthenticated), errors.Is(err, identity.ErrInvalidSession):
		status, code, message = http.StatusUnauthorized, "identity_session_unauthenticated", "登录状态无效或已过期"
	case errors.Is(err, ErrNotFound):
		status, code, message = http.StatusNotFound, "identity_session_not_found", "会话设备不存在"
	case errors.Is(err, ErrRevisionConflict):
		status, code, message = http.StatusConflict, "identity_session_revision_conflict", "会话状态已变化，请刷新后重试"
	case errors.Is(err, ErrIdempotencyConflict):
		status, code, message = http.StatusConflict, "identity_session_idempotency_conflict", "幂等键已用于不同请求"
	case errors.Is(err, ErrAlreadyRevoked):
		status, code, message = http.StatusConflict, "identity_session_already_revoked", "该设备会话已撤销"
	case errors.Is(err, ErrUnavailable):
		status, code, message = http.StatusServiceUnavailable, "identity_session_unavailable", "会话服务暂时不可用"
	}
	handler.writeError(response, request, status, code, message)
}

func (handler *Handler) writeError(response http.ResponseWriter, request *http.Request, status int, code, message string) {
	requestID, _ := requestID(request)
	handler.writeJSON(response, status, errorResponse{Error: errorDetail{Code: code, Message: message, RequestID: requestID}})
}

func (handler *Handler) writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func utcPointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC()
	return &result
}

func poolConfigured(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return pool.Config() != nil
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Ptr && reflected.IsNil()
}
