// Package statuspagehttp serves the status page:
//
//	GET    /v1/status-page/public                          public view (no session; cached 30 s, 60/min per source)
//	GET    /v1/admin/status-page                           editor view
//	PUT    /v1/admin/status-page                           save settings and components (If-Match revision)
//	POST   /v1/admin/status-page/incidents                 open an incident or schedule maintenance
//	POST   /v1/admin/status-page/incidents/{id}/updates    post a progress update
//	DELETE /v1/admin/status-page/incidents/{id}            delete an incident
package statuspagehttp

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
	"github.com/cdnca/cdnca/services/control-api/internal/statuspage"
	"github.com/google/uuid"
)

const (
	PublicRoute   = "/v1/status-page/public"
	AdminRoute    = "/v1/admin/status-page"
	incidentsPath = AdminRoute + "/incidents"
	bodyLimit     = 64 << 10
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

type Handler struct {
	service      *statuspage.Service
	authenticate AuthenticateFunc
	sourceIP     func(*http.Request) string
	cache        *publicCache
	limiter      *sourceLimiter
}

// New builds the handler. sourceIP returns the client address behind the
// trusted proxies; the public route is rate limited by it.
func New(service *statuspage.Service, authenticate AuthenticateFunc, sourceIP func(*http.Request) string) (*Handler, error) {
	if service == nil || authenticate == nil || sourceIP == nil {
		return nil, errors.New("status page HTTP dependencies are required")
	}
	return &Handler{
		service: service, authenticate: authenticate, sourceIP: sourceIP,
		cache:   &publicCache{build: service.Public, now: time.Now},
		limiter: &sourceLimiter{counts: map[string]int{}, now: time.Now, maximum: limitPerSource},
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("X-Content-Type-Options", "nosniff")
	requestID := r.Header.Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = "status-page-" + uuid.NewString()
	}
	header.Set("X-Request-ID", requestID)
	if r.URL.Path == PublicRoute {
		h.public(w, r, requestID)
		return
	}
	header.Set("Cache-Control", "no-store")
	actor, ok := h.actor(w, r, requestID)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	path := r.URL.Path
	switch {
	case path == AdminRoute && r.Method == http.MethodGet:
		view, err := h.service.Admin(ctx, actor)
		h.respond(w, requestID, http.StatusOK, view, err)
	case path == AdminRoute && r.Method == http.MethodPut:
		revision, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), `"`), 10, 64)
		if err != nil || revision < 1 {
			writeError(w, requestID, http.StatusPreconditionRequired, "status_page_revision_required")
			return
		}
		var request statuspage.SaveRequest
		if !decode(w, r, requestID, &request) {
			return
		}
		request.ExpectedRevision = revision
		view, err := h.service.Save(ctx, actor, request)
		h.respond(w, requestID, http.StatusOK, view, err)
	case path == incidentsPath && r.Method == http.MethodPost:
		var input statuspage.IncidentInput
		if !decode(w, r, requestID, &input) {
			return
		}
		item, err := h.service.CreateIncident(ctx, actor, input)
		h.respond(w, requestID, http.StatusCreated, item, err)
	case strings.HasPrefix(path, incidentsPath+"/"):
		h.incident(ctx, w, r, requestID, actor, strings.TrimPrefix(path, incidentsPath+"/"))
	default:
		header.Set("Allow", "GET, PUT, POST, DELETE")
		writeError(w, requestID, http.StatusMethodNotAllowed, "status_page_method_not_allowed")
	}
}

func (h *Handler) incident(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string,
	actor statuspage.Actor, rest string) {
	raw, action, _ := strings.Cut(rest, "/")
	id, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, requestID, http.StatusNotFound, "status_page_not_found")
		return
	}
	switch {
	case action == "updates" && r.Method == http.MethodPost:
		var input statuspage.UpdateInput
		if !decode(w, r, requestID, &input) {
			return
		}
		item, err := h.service.AddUpdate(ctx, actor, id, input)
		h.respond(w, requestID, http.StatusOK, item, err)
	case action == "" && r.Method == http.MethodDelete:
		err := h.service.DeleteIncident(ctx, actor, id)
		if err == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.respond(w, requestID, 0, nil, err)
	default:
		writeError(w, requestID, http.StatusMethodNotAllowed, "status_page_method_not_allowed")
	}
}

func (h *Handler) actor(w http.ResponseWriter, r *http.Request, requestID string) (statuspage.Actor, bool) {
	values := r.Header.Values("Authorization")
	parts := []string{}
	if len(values) == 1 {
		parts = strings.Fields(values[0])
	}
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 8192 {
		writeError(w, requestID, http.StatusUnauthorized, "status_page_unauthenticated")
		return statuspage.Actor{}, false
	}
	session, err := h.authenticate(r, parts[1])
	if err != nil || session.SessionID == uuid.Nil {
		writeError(w, requestID, http.StatusUnauthorized, "status_page_unauthenticated")
		return statuspage.Actor{}, false
	}
	p := session.Principal
	if p.UserID == uuid.Nil || p.ScopeID == uuid.Nil || p.ScopeKind != "platform" || p.TenantID != nil {
		writeError(w, requestID, http.StatusForbidden, "status_page_permission_denied")
		return statuspage.Actor{}, false
	}
	return statuspage.Actor{UserID: p.UserID, ScopeID: p.ScopeID, RequestID: requestID}, true
}

func decode(w http.ResponseWriter, r *http.Request, requestID string, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, bodyLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, requestID, http.StatusBadRequest, "status_page_validation_error")
		return false
	}
	return true
}

func (h *Handler) respond(w http.ResponseWriter, requestID string, status int, value any, err error) {
	if err == nil {
		writeJSON(w, status, value)
		return
	}
	for _, mapping := range []struct {
		target error
		status int
		code   string
	}{
		{statuspage.ErrInvalidInput, http.StatusBadRequest, "status_page_validation_error"},
		{statuspage.ErrTooManyComponents, http.StatusBadRequest, "status_page_too_many_components"},
		{statuspage.ErrDuplicateComponent, http.StatusConflict, "status_page_duplicate_component"},
		{statuspage.ErrLineGroupNotFound, http.StatusBadRequest, "status_page_line_group_not_found"},
		{statuspage.ErrUnknownComponentRef, http.StatusBadRequest, "status_page_unknown_component"},
		{statuspage.ErrIncidentTransition, http.StatusConflict, "status_page_incident_closed"},
		{statuspage.ErrRevisionConflict, http.StatusPreconditionFailed, "status_page_revision_conflict"},
		{statuspage.ErrPermissionDenied, http.StatusForbidden, "status_page_permission_denied"},
		{statuspage.ErrNotFound, http.StatusNotFound, "status_page_not_found"},
	} {
		if errors.Is(err, mapping.target) {
			writeError(w, requestID, mapping.status, mapping.code)
			return
		}
	}
	writeError(w, requestID, http.StatusServiceUnavailable, "status_page_unavailable")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, requestID string, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "request_id": requestID}})
}
