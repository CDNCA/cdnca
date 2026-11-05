package poolmon

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// Route is the admin read of the pool monitor.
const Route = "/v1/admin/system-db-pool"

// authenticateWait bounds the session check: it reads the database, which is
// slow exactly while the pool is saturated; the pool figures themselves come
// from memory.
const authenticateWait = 5 * time.Second

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// AuthenticateFunc checks a bearer session (identity.Service.AuthenticateSession).
type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

// View is the monitor read by the handler.
type View interface{ Snapshot() Snapshot }

// Handler serves GET /v1/admin/system-db-pool: this process's pool now, the
// last hour every 10 seconds, the resident connections and the alert state,
// to platform members holding control.upgrades.read or platform.admin (the
// maintenance page). Read-only, no audit.
type Handler struct {
	view         View
	authenticate AuthenticateFunc
}

func NewHandler(view View, authenticate AuthenticateFunc) *Handler {
	return &Handler{view: view, authenticate: authenticate}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := r.Header.Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = "system-db-pool"
	}
	w.Header().Set("X-Request-ID", requestID)
	if r.URL.Path != Route {
		writeError(w, requestID, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, requestID, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	scheme, raw, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(raw) == "" {
		writeError(w, requestID, http.StatusUnauthorized, "authentication_required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authenticateWait)
	defer cancel()
	session, err := h.authenticate(r.WithContext(ctx), strings.TrimSpace(raw))
	if err != nil {
		writeError(w, requestID, http.StatusUnauthorized, "authentication_required")
		return
	}
	principal := session.Principal
	if principal.ScopeKind != "platform" || principal.TenantID != nil ||
		!slices.ContainsFunc(recipientPermissions, func(p string) bool { return slices.Contains(principal.Permissions, p) }) {
		writeError(w, requestID, http.StatusForbidden, "permission_denied")
		return
	}
	writeJSON(w, http.StatusOK, h.view.Snapshot())
}

func writeError(w http.ResponseWriter, requestID string, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": code, "request_id": requestID}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
