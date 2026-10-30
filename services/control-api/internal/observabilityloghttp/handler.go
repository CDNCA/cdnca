package observabilityloghttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/observabilitylog"
	"github.com/google/uuid"
)

const (
	maxBodyBytes   = 8 << 10
	maxExportBytes = 8 << 20
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var actorDisplayIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)
type ClientIPFunc func(*http.Request) string

type Dependencies struct {
	Domain              observabilitylog.Domain
	AuthenticateSession AuthenticateSessionFunc
	ResolveClientIP     ClientIPFunc
}

type Handler struct {
	domain       observabilitylog.Domain
	authenticate AuthenticateSessionFunc
	clientIP     ClientIPFunc
}

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if dependencies.Domain == nil || dependencies.AuthenticateSession == nil || dependencies.ResolveClientIP == nil {
		return nil, observabilitylog.ErrInvalidConfig
	}
	return &Handler{domain: dependencies.Domain, authenticate: dependencies.AuthenticateSession, clientIP: dependencies.ResolveClientIP}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := request.Header.Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	response.Header().Set("X-Request-ID", requestID)
	rawSession, err := strictBearer(request)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "authentication_required", requestID)
		return
	}
	session, err := handler.authenticate(request.Context(), rawSession)
	if err != nil || session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		writeError(response, http.StatusUnauthorized, "authentication_required", requestID)
		return
	}
	actor := observabilitylog.Actor{UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID,
		ScopeKind: session.Principal.ScopeKind, SessionID: session.SessionID, Permissions: session.Principal.Permissions,
		RequestID: requestID, SourceIP: handler.clientIP(request)}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/v1/observability/logs":
		query, err := parseQuery(request.URL.Query())
		if err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		if err := authorizeTarget(actor, query.TargetScopeID, false); err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		if query.CaptureAuditBoundary {
			boundary, err := handler.domain.CaptureAuditBoundary(request.Context(), actor, platformTargetScope(actor, query.TargetScopeID))
			if err != nil {
				writeDomainError(response, requestID, err)
				return
			}
			writeJSON(response, http.StatusOK, observabilitylog.Page{Items: []observabilitylog.Fact{},
				SnapshotAt: boundary.SnapshotAt, AuditBoundary: boundary.Token})
			return
		}
		page, err := handler.domain.List(request.Context(), actor, query)
		if err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		writeJSON(response, http.StatusOK, page)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/observability/logs/export":
		query, err := parseQuery(request.URL.Query())
		if err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		if err := authorizeTarget(actor, query.TargetScopeID, false); err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		if query.CaptureAuditBoundary || query.AfterAuditBoundary != "" {
			writeDomainError(response, requestID, observabilitylog.ErrInvalidInput)
			return
		}
		artifact, err := handler.domain.Export(request.Context(), actor, query)
		if err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		if !validExportArtifact(artifact) {
			writeDomainError(response, requestID, observabilitylog.ErrUnavailable)
			return
		}
		response.Header().Set("Content-Type", "text/csv; charset=utf-8")
		response.Header().Set("Content-Disposition", `attachment; filename="observability-logs.csv"`)
		response.Header().Set("X-Content-SHA256", artifact.SHA256)
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(artifact.Content)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/observability/frontend-events":
		target, err := parseFrontendTarget(request.URL.Query())
		if err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		if err := authorizeTarget(actor, target, true); err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		if actor.ScopeKind == observabilitylog.ScopePlatform {
			actor.ScopeID = platformTargetScope(actor, target)
		}
		var input observabilitylog.FrontendInput
		if err := decodeJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, "observability_logs_invalid_request", requestID)
			return
		}
		if err := handler.domain.RecordFrontend(request.Context(), actor, input); err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		response.WriteHeader(http.StatusAccepted)
	default:
		writeError(response, http.StatusNotFound, "observability_logs_not_found", requestID)
	}
}

func authorizeTarget(actor observabilitylog.Actor, target *uuid.UUID, requireExplicitTarget bool) error {
	switch actor.ScopeKind {
	case observabilitylog.ScopeTenant:
		if target != nil || !hasPermission(actor.Permissions, "identity.self.read") {
			return observabilitylog.ErrPermissionDenied
		}
	case observabilitylog.ScopePlatform:
		if !hasPermission(actor.Permissions, "platform.admin") || (target != nil && *target == uuid.Nil) {
			return observabilitylog.ErrPermissionDenied
		}
		if target == nil && requireExplicitTarget {
			// Frontend events are written into a concrete scope, so the writer must name it;
			// reads fall back to the administrator's own platform scope.
			return observabilitylog.ErrInvalidInput
		}
	default:
		return observabilitylog.ErrPermissionDenied
	}
	return nil
}

func hasPermission(permissions []string, expected string) bool {
	for _, permission := range permissions {
		if permission == expected {
			return true
		}
	}
	return false
}

// platformTargetScope resolves the audit boundary scope for a platform actor that did
// not name one: its own platform scope.
func platformTargetScope(actor observabilitylog.Actor, target *uuid.UUID) uuid.UUID {
	if target != nil {
		return *target
	}
	return actor.ScopeID
}

func parseFrontendTarget(values url.Values) (*uuid.UUID, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 || len(values["target_scope_id"]) != 1 {
		return nil, observabilitylog.ErrInvalidInput
	}
	raw := values.Get("target_scope_id")
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return nil, observabilitylog.ErrInvalidInput
	}
	return &value, nil
}

func validExportArtifact(artifact observabilitylog.ExportArtifact) bool {
	if len(artifact.Content) > maxExportBytes || !sha256Pattern.MatchString(artifact.SHA256) {
		return false
	}
	digest := sha256.Sum256(artifact.Content)
	return artifact.SHA256 == hex.EncodeToString(digest[:])
}

func parseQuery(values url.Values) (observabilitylog.Query, error) {
	allowed := map[string]bool{"target_scope_id": true, "kind": true, "result": true, "action": true, "source_ip": true,
		"from": true, "to": true, "limit": true, "cursor": true, "audit_boundary": true,
		"after_audit_boundary": true, "actor_user_id": true, "actor_user_display_id": true, "action_verb": true, "resource_type": true,
		"resource_id": true, "change": true, "category": true}
	for key := range values {
		if !allowed[key] {
			return observabilitylog.Query{}, observabilitylog.ErrInvalidInput
		}
	}
	for _, key := range []string{"target_scope_id", "action", "action_verb", "category", "resource_type", "resource_id", "change",
		"source_ip", "from", "to", "limit", "cursor", "audit_boundary", "after_audit_boundary", "actor_user_id", "actor_user_display_id"} {
		if len(values[key]) > 1 {
			return observabilitylog.Query{}, observabilitylog.ErrInvalidInput
		}
	}
	var query observabilitylog.Query
	if raw := values.Get("target_scope_id"); raw != "" {
		value, err := uuid.Parse(raw)
		if err != nil || value.String() != raw {
			return query, observabilitylog.ErrInvalidInput
		}
		query.TargetScopeID = &value
	}
	if raw := values.Get("actor_user_id"); raw != "" {
		value, err := uuid.Parse(raw)
		if err != nil || value == uuid.Nil || value.String() != raw {
			return query, observabilitylog.ErrInvalidInput
		}
		query.AuditActorUserID = &value
	}
	if raw := values.Get("actor_user_display_id"); raw != "" {
		if !actorDisplayIDPattern.MatchString(raw) || query.AuditActorUserID != nil {
			return query, observabilitylog.ErrInvalidInput
		}
		query.ActorUserDisplayID = raw
	}
	if raw := values.Get("audit_boundary"); raw != "" {
		if raw != "capture" || len(values) != 2 || query.TargetScopeID == nil {
			return query, observabilitylog.ErrInvalidInput
		}
		query.CaptureAuditBoundary = true
	}
	query.AfterAuditBoundary = values.Get("after_audit_boundary")
	if len(query.AfterAuditBoundary) > 4096 || query.AfterAuditBoundary != "" && (query.AuditActorUserID == nil || query.ActorUserDisplayID != "") ||
		query.CaptureAuditBoundary && query.AfterAuditBoundary != "" {
		return query, observabilitylog.ErrInvalidInput
	}
	for _, raw := range values["kind"] {
		for _, value := range strings.Split(raw, ",") {
			if value == "" {
				return query, observabilitylog.ErrInvalidInput
			}
			query.Kinds = append(query.Kinds, observabilitylog.Kind(value))
		}
	}
	for _, raw := range values["result"] {
		for _, value := range strings.Split(raw, ",") {
			if value == "" {
				return query, observabilitylog.ErrInvalidInput
			}
			query.ResultCodes = append(query.ResultCodes, value)
		}
	}
	if query.AfterAuditBoundary != "" {
		for _, kind := range query.Kinds {
			if kind == observabilitylog.KindNotification {
				return query, observabilitylog.ErrInvalidInput
			}
		}
	}
	query.Action, query.ActionVerb, query.Category = values.Get("action"), values.Get("action_verb"), values.Get("category")
	query.ResourceType, query.ResourceID, query.Change = values.Get("resource_type"), values.Get("resource_id"), values.Get("change")
	query.SourceIP, query.Cursor = values.Get("source_ip"), values.Get("cursor")
	var err error
	if raw := values.Get("from"); raw != "" {
		query.From, err = timeValue(raw)
		if err != nil {
			return query, err
		}
	}
	if raw := values.Get("to"); raw != "" {
		query.To, err = timeValue(raw)
		if err != nil {
			return query, err
		}
	}
	if raw := values.Get("limit"); raw != "" {
		query.Limit, err = strconv.Atoi(raw)
		if err != nil {
			return query, observabilitylog.ErrInvalidInput
		}
	}
	return query, nil
}

func timeValue(raw string) (time.Time, error) {
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || value.Location() != time.UTC {
		return time.Time{}, observabilitylog.ErrInvalidInput
	}
	return value, nil
}

func strictBearer(request *http.Request) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", errors.New("authentication required")
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || len(token) >= 8192 || strings.ContainsFunc(token, unicode.IsSpace) {
		return "", errors.New("authentication required")
	}
	return token, nil
}

func decodeJSON(request *http.Request, output any) error {
	mediaType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(params) != 0 {
		return observabilitylog.ErrInvalidInput
	}
	limited := &io.LimitedReader{R: request.Body, N: maxBodyBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return observabilitylog.ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || limited.N == 0 {
		return observabilitylog.ErrInvalidInput
	}
	return nil
}

func writeDomainError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, observabilitylog.ErrInvalidCursor):
		// 游标失效（会话轮转、条件变化、篡改）单独给稳定码，前端据此清游标并从第一页重查（A18）。
		writeError(response, http.StatusBadRequest, "observability_logs_cursor_expired", requestID)
	case errors.Is(err, observabilitylog.ErrInvalidInput):
		writeError(response, http.StatusBadRequest, "observability_logs_invalid_request", requestID)
	case errors.Is(err, observabilitylog.ErrPermissionDenied):
		writeError(response, http.StatusForbidden, "permission_denied", requestID)
	default:
		writeError(response, http.StatusServiceUnavailable, "observability_logs_unavailable", requestID)
	}
}

func writeError(response http.ResponseWriter, status int, code, requestID string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{"code": code, "request_id": requestID}})
}
func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
