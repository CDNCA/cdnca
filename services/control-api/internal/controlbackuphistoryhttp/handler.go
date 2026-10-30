package controlbackuphistoryhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackuphistory"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

type Dependencies struct {
	Reader              controlbackuphistory.Reader
	AuthenticateSession AuthenticateSessionFunc
}

type Handler struct {
	reader       controlbackuphistory.Reader
	authenticate AuthenticateSessionFunc
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if dependencies.AuthenticateSession == nil {
		return nil, errors.New("backup history authentication is not configured")
	}
	return &Handler{reader: dependencies.Reader, authenticate: dependencies.AuthenticateSession}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := request.Header.Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	response.Header().Set("X-Request-ID", requestID)
	if request.Method != http.MethodGet || request.URL.Path != "/v1/admin/system-backup-runs" {
		writeError(response, http.StatusNotFound, "backup_history_not_found", requestID)
		return
	}
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
	if session.Principal.ScopeKind != "platform" || !hasPermission(session.Principal.Permissions, "platform.admin") {
		writeError(response, http.StatusForbidden, "permission_denied", requestID)
		return
	}
	if handler.reader == nil {
		writeError(response, http.StatusServiceUnavailable, "backup_history_unavailable", requestID)
		return
	}
	query, err := parseQuery(request.URL.Query())
	if err != nil {
		writeError(response, http.StatusBadRequest, "backup_history_invalid_request", requestID)
		return
	}
	page, err := handler.reader.List(request.Context(), query)
	if err != nil {
		status, code := http.StatusServiceUnavailable, "backup_history_unavailable"
		if errors.Is(err, controlbackuphistory.ErrInvalidInput) || errors.Is(err, controlbackuphistory.ErrInvalidCursor) {
			status, code = http.StatusBadRequest, "backup_history_invalid_request"
		}
		writeError(response, status, code, requestID)
		return
	}
	writeJSON(response, http.StatusOK, page)
}

func parseQuery(values url.Values) (controlbackuphistory.Query, error) {
	allowed := map[string]bool{"backup_id": true, "state": true, "from": true, "to": true, "limit": true, "cursor": true}
	for key, items := range values {
		if !allowed[key] || len(items) != 1 || items[0] == "" {
			return controlbackuphistory.Query{}, controlbackuphistory.ErrInvalidInput
		}
	}
	query := controlbackuphistory.Query{BackupID: values.Get("backup_id"), State: values.Get("state"), Cursor: values.Get("cursor")}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || strconv.Itoa(limit) != raw || limit != 10 && limit != 30 && limit != 100 && limit != 300 {
			return controlbackuphistory.Query{}, controlbackuphistory.ErrInvalidInput
		}
		query.Limit = limit
	}
	for raw, destination := range map[string]*time.Time{"from": &query.From, "to": &query.To} {
		if value := values.Get(raw); value != "" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil || parsed.Location() != time.UTC {
				return controlbackuphistory.Query{}, controlbackuphistory.ErrInvalidInput
			}
			*destination = parsed
		}
	}
	return query, nil
}

func strictBearer(request *http.Request) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", errors.New("authentication required")
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || len(token) >= 8192 || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("authentication required")
	}
	return token, nil
}

func hasPermission(permissions []string, expected string) bool {
	for _, permission := range permissions {
		if permission == expected {
			return true
		}
	}
	return false
}

func writeError(response http.ResponseWriter, status int, code, requestID string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{"code": code, "request_id": requestID}})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
