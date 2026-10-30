package gatewayregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const maxBodyBytes = 32 << 10

// BindAttemptsPerMinute bounds POST /v1/gateway-bindings/complete per source
// address (the route is public; the token is the credential).
const BindAttemptsPerMinute = 10

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

// Patterns are the routes the control-api server forwards here.
var Patterns = []string{
	"GET /v1/admin/gateways",
	"POST /v1/admin/gateways",
	"POST /v1/admin/gateways/{id}/binding-token",
	"POST /v1/admin/gateways/{id}/disable",
	"POST /v1/admin/gateways/{id}/enable",
	"DELETE /v1/admin/gateways/{id}",
	"POST /v1/gateway-bindings/complete",
	"PUT /v1/admin/gateways/{id}/allowed-ips",
	"GET /v1/admin/gateway-settings",
	"PUT /v1/admin/gateway-settings",
}

type Handler struct {
	service      *Service
	authenticate AuthenticateSessionFunc
	mux          *http.ServeMux
	limiter      *windowLimiter
}

func NewHandler(service *Service, authenticate AuthenticateSessionFunc) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidInput
	}
	h := &Handler{service: service, authenticate: authenticate, mux: http.NewServeMux(),
		limiter: &windowLimiter{limit: BindAttemptsPerMinute, window: time.Minute, now: service.config.Now, seen: map[string][]time.Time{}}}
	h.mux.HandleFunc(Patterns[0], h.list)
	h.mux.HandleFunc(Patterns[1], h.create)
	h.mux.HandleFunc(Patterns[2], h.token)
	h.mux.HandleFunc(Patterns[3], func(w http.ResponseWriter, r *http.Request) { h.setDisabled(w, r, true) })
	h.mux.HandleFunc(Patterns[4], func(w http.ResponseWriter, r *http.Request) { h.setDisabled(w, r, false) })
	h.mux.HandleFunc(Patterns[5], h.delete)
	h.mux.HandleFunc(Patterns[6], h.bind)
	h.mux.HandleFunc(Patterns[7], h.allowedIPs)
	h.mux.HandleFunc(Patterns[8], h.settings)
	h.mux.HandleFunc(Patterns[9], h.updateSettings)
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) actor(w http.ResponseWriter, r *http.Request) (Actor, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || values[0][7:] == "" ||
		strings.TrimSpace(values[0][7:]) != values[0][7:] {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return Actor{}, false
	}
	session, err := h.authenticate(r.Context(), values[0][7:])
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return Actor{}, false
	}
	p := session.Principal
	if p.UserID == uuid.Nil || session.SessionID == uuid.Nil || p.ScopeKind != "platform" || p.TenantID != nil ||
		identity.Authorize(p, PermissionManage) != nil {
		writeError(w, http.StatusForbidden, "permission_denied")
		return Actor{}, false
	}
	return Actor{UserID: p.UserID, ScopeID: p.ScopeID, IP: apikeycredential.ClientIP(r.Context())}, true
}

func pathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil || id.String() != r.PathValue("id") {
		writeError(w, http.StatusNotFound, "gateway_not_found")
		return uuid.Nil, false
	}
	return id, true
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.actor(w, r); !ok {
		return
	}
	gateways, err := h.service.List(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": gateways, "installation_id": h.service.InstallationID(),
		"standalone_access_open": h.service.config.Endpoints.ControlInternalAddress != ""})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	var input CreateInput
	if !decode(w, r, &input) {
		return
	}
	created, err := h.service.Create(r.Context(), actor, input)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	created, err := h.service.IssueToken(r.Context(), actor, id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, created)
}

func (h *Handler) setDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.service.SetDisabled(r.Context(), actor, id, disabled); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.service.Delete(r.Context(), actor, id); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) allowedIPs(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var input struct {
		AllowedIPs []string `json:"allowed_ips"`
	}
	if !decode(w, r, &input) {
		return
	}
	ips, err := h.service.SetAllowedIPs(r.Context(), actor, id, input.AllowedIPs)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowed_ips": ips})
}

func (h *Handler) settings(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.actor(w, r); !ok {
		return
	}
	settings, err := h.service.Settings(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.Header().Set("ETag", SettingsETag(settings))
	writeJSON(w, http.StatusOK, settings)
}

// updateSettings requires If-Match with the ETag of the GET the form was
// loaded from (G1): a missing one is 428, a stale one 409.
func (h *Handler) updateSettings(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	ifMatch := r.Header.Values("If-Match")
	if len(ifMatch) != 1 || strings.TrimSpace(ifMatch[0]) == "" {
		writeError(w, http.StatusPreconditionRequired, "precondition_required")
		return
	}
	var input Settings
	if !decode(w, r, &input) {
		return
	}
	settings, err := h.service.UpdateSettings(r.Context(), actor, strings.TrimSpace(ifMatch[0]), input)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.Header().Set("ETag", SettingsETag(settings))
	writeJSON(w, http.StatusOK, settings)
}

// bind is public: the binding token in the body is the credential.
func (h *Handler) bind(w http.ResponseWriter, r *http.Request) {
	ip := apikeycredential.ClientIP(r.Context())
	if !h.limiter.allow(ip) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	var request BindRequest
	if !decode(w, r, &request) {
		return
	}
	result, err := h.service.Bind(r.Context(), request, ip)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 || !strings.HasPrefix(strings.ToLower(contentTypes[0]), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.More() {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPermissionDenied):
		writeError(w, http.StatusForbidden, "permission_denied")
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "gateway_not_found")
	case errors.Is(err, ErrNameTaken):
		writeError(w, http.StatusConflict, "gateway_name_taken")
	case errors.Is(err, ErrSettingsChanged):
		writeError(w, http.StatusConflict, "gateway_settings_changed")
	case errors.Is(err, ErrConflict):
		writeError(w, http.StatusConflict, "gateway_state_conflict")
	case errors.Is(err, ErrInvalidToken):
		writeError(w, http.StatusUnauthorized, "gateway_binding_token_invalid")
	case errors.Is(err, ErrRemoteAccessDisabled):
		writeError(w, http.StatusConflict, "gateway_remote_access_disabled")
	case errors.Is(err, ErrInvalidInput):
		writeError(w, http.StatusUnprocessableEntity, "invalid_input")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error")
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// writeError writes the control-api ErrorEnvelope.
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": http.StatusText(status),
		"request_id": uuid.NewString()}})
}

// windowLimiter is a per-key sliding window (bounded map: old keys expire).
type windowLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	seen   map[string][]time.Time
}

func (l *windowLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.seen) > 4096 {
		for k, times := range l.seen {
			if len(times) == 0 || now.Sub(times[len(times)-1]) >= l.window {
				delete(l.seen, k)
			}
		}
	}
	kept := l.seen[key][:0]
	for _, at := range l.seen[key] {
		if now.Sub(at) < l.window {
			kept = append(kept, at)
		}
	}
	if len(kept) >= l.limit {
		l.seen[key] = kept
		return false
	}
	l.seen[key] = append(kept, now)
	return true
}
