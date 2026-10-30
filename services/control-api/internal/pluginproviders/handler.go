package pluginproviders

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// Routes (platform administrators):
//
//	GET  /v1/admin/plugin-providers                      list with contract results
//	POST /v1/admin/plugin-providers/{plugin_id}/contract run the installation contract now
//	POST /v1/admin/plugin-providers/{plugin_id}/enable   enable (contract must have passed); a
//	     payment plugin needs {"risk_acknowledged":true,"step_up_token":"..."} (MFA step-up
//	     audience/action plugin.provider.enable_payment for the installation's tenant)
//	POST /v1/admin/plugin-providers/{plugin_id}/disable  disable
const (
	ListRoute = "/v1/admin/plugin-providers"

	PermissionRead   = "plugin_installations.read"
	PermissionManage = "plugin_installations.manage"
)

var pluginIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)

// AuthenticateFunc resolves the caller's session (Bearer token).
type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

type Handler struct {
	service      *Service
	authenticate AuthenticateFunc
	mux          *http.ServeMux
}

func NewHandler(service *Service, authenticate AuthenticateFunc) (*Handler, error) {
	if service == nil || service.Store == nil || authenticate == nil {
		return nil, errors.New("plugin provider HTTP dependencies are required")
	}
	handler := &Handler{service: service, authenticate: authenticate, mux: http.NewServeMux()}
	handler.mux.HandleFunc("GET "+ListRoute, handler.list)
	handler.mux.HandleFunc("POST "+ListRoute+"/{plugin_id}/{action}", handler.mutate)
	return handler, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(w, r)
}

// principal admits platform administrators holding permission (or
// platform.admin).
func (h *Handler) principal(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, bool) {
	session, ok := h.session(w, r, permission)
	return session.Principal, ok
}

func (h *Handler) session(w http.ResponseWriter, r *http.Request, permission string) (identity.AuthenticatedSession, bool) {
	scheme, raw, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(raw) == "" {
		writeError(w, r, http.StatusUnauthorized, "authentication_required")
		return identity.AuthenticatedSession{}, false
	}
	session, err := h.authenticate(r, strings.TrimSpace(raw))
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "authentication_required")
		return identity.AuthenticatedSession{}, false
	}
	principal := session.Principal
	if principal.ScopeKind != "platform" || principal.TenantID != nil ||
		!slices.Contains(principal.Permissions, permission) && !slices.Contains(principal.Permissions, "platform.admin") {
		writeError(w, r, http.StatusForbidden, "permission_denied")
		return identity.AuthenticatedSession{}, false
	}
	return session, true
}

type enableBody struct {
	RiskAcknowledged bool   `json:"risk_acknowledged"`
	StepUpToken      string `json:"step_up_token"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.principal(w, r, PermissionRead); !ok {
		return
	}
	providers, err := h.service.Store.List(r.Context())
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "plugin_provider_unavailable")
		return
	}
	if providers == nil {
		providers = []Provider{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": providers})
}

func (h *Handler) mutate(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r, PermissionManage)
	if !ok {
		return
	}
	principal := session.Principal
	pluginID, action := r.PathValue("plugin_id"), r.PathValue("action")
	if !pluginIDPattern.MatchString(pluginID) || len(pluginID) > 128 {
		writeError(w, r, http.StatusNotFound, "plugin_provider_not_found")
		return
	}
	actor := Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, RequestID: r.Header.Get("X-Request-ID"),
		SourceIP: clientIP(r)}
	ctx := context.WithoutCancel(r.Context())
	var provider Provider
	var err error
	switch action {
	case "contract":
		provider, err = h.service.RunContract(ctx, actor, pluginID)
	case "enable":
		var body enableBody
		if r.ContentLength != 0 {
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&body) != nil || len(body.StepUpToken) > 4096 {
				writeError(w, r, http.StatusBadRequest, "invalid_request")
				return
			}
		}
		provider, err = h.service.Enable(ctx, actor, pluginID, PaymentEnable{SessionID: session.SessionID,
			StepUpToken: strings.TrimSpace(body.StepUpToken), RiskAcknowledged: body.RiskAcknowledged})
	case "disable":
		provider, err = h.service.Store.SetEnabled(ctx, actor, pluginID, false)
	default:
		writeError(w, r, http.StatusNotFound, "not_found")
		return
	}
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, provider)
	case errors.Is(err, ErrNotFound):
		writeError(w, r, http.StatusNotFound, "plugin_provider_not_found")
	case errors.Is(err, ErrContractNeeded):
		writeError(w, r, http.StatusConflict, "plugin_provider_contract_not_passed")
	case errors.Is(err, ErrRiskNotAcknowledged), errors.Is(err, ErrConfirmationRequired):
		writeError(w, r, http.StatusUnprocessableEntity, "plugin_provider_risk_not_acknowledged")
	case errors.Is(err, ErrStepUpRequired):
		writeError(w, r, http.StatusForbidden, "plugin_provider_step_up_required")
	case errors.Is(err, ErrNotUsable):
		writeError(w, r, http.StatusConflict, "plugin_provider_not_active")
	case errors.Is(err, ErrConflict):
		writeError(w, r, http.StatusConflict, "plugin_provider_changed")
	default:
		writeError(w, r, http.StatusServiceUnavailable, "plugin_provider_unavailable")
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": code,
		"request_id": r.Header.Get("X-Request-ID")}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
