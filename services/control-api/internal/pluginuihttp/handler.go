package pluginuihttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	PagesRoute      = "/v1/plugin-ui/pages"
	SigningKeyRoute = "/v1/plugin-ui/signing-key"
	proxyRoute      = "/v1/plugin-ui/{plugin_id}/proxy"
)

var (
	pluginIDPattern  = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// AuthenticateFunc resolves the caller's session (Bearer token).
type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

// ModulesFunc returns the module codes the verified lease grants.
type ModulesFunc func(context.Context) ([]string, error)

// SiteChecker reports whether the principal may act on site.
type SiteChecker interface {
	CanAccessSite(ctx context.Context, principal identity.Principal, siteID uuid.UUID) (bool, error)
}

// Auditor records one audit event in its own transaction.
type Auditor interface {
	Record(context.Context, audit.Event) error
}

type Config struct {
	Store        Store
	Authenticate AuthenticateFunc
	Modules      ModulesFunc
	Sites        SiteChecker
	Auditor      Auditor
	// Signer is nil when the installation key is not configured: pages
	// still mount, the proxy answers plugin_ui_proxy_unavailable.
	Signer    *Signer
	Forwarder Forwarder
	Now       func() time.Time
}

type Handler struct {
	config  Config
	limiter *limiter
	mux     *http.ServeMux
}

func New(config Config) (*Handler, error) {
	if config.Store == nil || config.Authenticate == nil || config.Modules == nil || config.Sites == nil ||
		config.Auditor == nil {
		return nil, errors.New("plugin ui HTTP dependencies are required")
	}
	if config.Forwarder == nil {
		config.Forwarder = newPublicForwarder()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	handler := &Handler{config: config, limiter: &limiter{window: time.Minute, limit: 120}, mux: http.NewServeMux()}
	handler.mux.HandleFunc("GET "+PagesRoute, handler.pages)
	handler.mux.HandleFunc("POST "+proxyRoute, handler.proxy)
	handler.mux.HandleFunc("GET "+SigningKeyRoute, handler.signingKey)
	return handler, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(w, r)
}

type session struct {
	principal identity.Principal
	role      string
	modules   []string
}

func (h *Handler) session(w http.ResponseWriter, r *http.Request) (session, bool) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, raw, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(raw) == "" {
		h.error(w, r, http.StatusUnauthorized, "plugin_ui_unauthenticated")
		return session{}, false
	}
	authenticated, err := h.config.Authenticate(r, strings.TrimSpace(raw))
	if err != nil || authenticated.Principal.UserID == uuid.Nil || authenticated.Principal.ScopeID == uuid.Nil {
		h.error(w, r, http.StatusUnauthorized, "plugin_ui_unauthenticated")
		return session{}, false
	}
	modules, err := h.config.Modules(r.Context())
	if err != nil {
		modules = nil // no lease: module-gated pages stay hidden
	}
	role := "user"
	if authenticated.Principal.ScopeKind == "platform" {
		role = "admin"
	}
	return session{principal: authenticated.Principal, role: role, modules: modules}, true
}

func (h *Handler) pages(w http.ResponseWriter, r *http.Request) {
	current, ok := h.session(w, r)
	if !ok {
		return
	}
	plugins, err := h.config.Store.ActivePlugins(r.Context())
	if err != nil {
		h.error(w, r, http.StatusServiceUnavailable, "plugin_ui_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": PagesFor(plugins, current.role, current.principal.Permissions,
		current.modules)})
}

// SigningKey is the installation public key a plugin backend verifies
// proxied calls with (public material only).
type SigningKey struct {
	InstallationID  uuid.UUID `json:"installation_id"`
	KeyID           string    `json:"key_id"`
	Algorithm       string    `json:"algorithm"`
	PublicKey       string    `json:"public_key"`
	SignatureDomain string    `json:"signature_domain"`
}

// signingKey shows the installation public key to whoever confirms or
// manages plugin installations, so the administrator can hand it to a
// plugin backend (reads change nothing: not audited).
func (h *Handler) signingKey(w http.ResponseWriter, r *http.Request) {
	current, ok := h.session(w, r)
	if !ok {
		return
	}
	allowed := false
	for _, permission := range current.principal.Permissions {
		allowed = allowed || permission == "plugin_installations.read" || permission == "plugin_installations.manage" ||
			permission == "platform.admin" && current.principal.ScopeKind == "platform"
	}
	switch {
	case !allowed:
		h.error(w, r, http.StatusForbidden, "permission_denied")
	case h.config.Signer == nil:
		h.error(w, r, http.StatusServiceUnavailable, "plugin_ui_proxy_unavailable")
	default:
		signer := *h.config.Signer
		writeJSON(w, http.StatusOK, SigningKey{InstallationID: signer.InstallationID, KeyID: signer.KeyID(),
			Algorithm: "Ed25519", PublicKey: signer.PublicKey(), SignatureDomain: ProxySignatureDomain})
	}
}

func (h *Handler) proxy(w http.ResponseWriter, r *http.Request) {
	current, ok := h.session(w, r)
	if !ok {
		return
	}
	pluginID := r.PathValue("plugin_id")
	if !pluginIDPattern.MatchString(pluginID) {
		h.error(w, r, http.StatusNotFound, "plugin_ui_not_found")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxProxyRequestBytes))
	if err != nil {
		h.error(w, r, http.StatusRequestEntityTooLarge, "plugin_ui_request_too_large")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request ProxyRequest
	if err := decoder.Decode(&request); err != nil || !validProxyRequest(request) {
		h.error(w, r, http.StatusBadRequest, "plugin_ui_request_invalid")
		return
	}
	plugins, err := h.config.Store.ActivePlugins(r.Context())
	if err != nil {
		h.error(w, r, http.StatusServiceUnavailable, "plugin_ui_unavailable")
		return
	}
	var plugin *ActivePlugin
	for index := range plugins {
		if plugins[index].Declaration.PluginID == pluginID {
			plugin = &plugins[index]
		}
	}
	deny := func(status int, code string) {
		h.audit(r, current, "plugin.ui_page.proxy", pluginID, "denied", map[string]any{"plugin_id": pluginID,
			"page_id": request.PageID, "method": request.Method, "path": request.Path, "reason_code": code})
		h.error(w, r, status, code)
	}
	// The page must be one this principal can open: the page gates
	// (role, permission, module) gate its API calls too.
	visible := false
	if plugin != nil {
		for _, page := range PagesFor([]ActivePlugin{*plugin}, current.role, current.principal.Permissions, current.modules) {
			visible = visible || page.PageID == request.PageID
		}
	}
	switch {
	case plugin == nil || !visible:
		deny(http.StatusNotFound, "plugin_ui_not_found")
		return
	case plugin.Declaration.APIBaseURL == "":
		deny(http.StatusNotFound, "plugin_ui_api_not_declared")
		return
	case h.config.Signer == nil:
		deny(http.StatusServiceUnavailable, "plugin_ui_proxy_unavailable")
		return
	case !h.limiter.allow(pluginID+"/"+current.principal.UserID.String(), h.config.Now()):
		deny(http.StatusTooManyRequests, "plugin_ui_rate_limited")
		return
	}
	if request.SiteID != nil {
		allowed, err := h.config.Sites.CanAccessSite(r.Context(), current.principal, *request.SiteID)
		if err != nil {
			h.error(w, r, http.StatusServiceUnavailable, "plugin_ui_unavailable")
			return
		}
		if !allowed {
			deny(http.StatusForbidden, "plugin_ui_site_denied")
			return
		}
	}
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if !requestIDPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	callContext := Context{PluginID: pluginID, PageID: request.PageID, UserID: current.principal.UserID,
		DisplayName: current.principal.DisplayName, Role: current.role, TenantScopeID: current.principal.ScopeID,
		SiteID: request.SiteID, Locale: locale(r), RequestID: requestID, IssuedAt: h.config.Now().UTC().Truncate(time.Second)}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	response, err := forward(ctx, h.config.Forwarder, *h.config.Signer, plugin.Declaration.APIBaseURL, request, callContext)
	payload := map[string]any{"plugin_id": pluginID, "page_id": request.PageID, "method": request.Method,
		"path": request.Path}
	if request.SiteID != nil {
		payload["site_id"] = request.SiteID.String()
	}
	if err != nil {
		payload["reason_code"] = "plugin_ui_backend_unavailable"
		h.audit(r, current, "plugin.ui_page.proxy", pluginID, "failure", payload)
		h.error(w, r, http.StatusBadGateway, "plugin_ui_backend_unavailable")
		return
	}
	// Reads are not audited (they change nothing here); every write the
	// plugin backend is asked to make on the user's behalf is.
	if request.Method != http.MethodGet {
		payload["status"] = response.Status
		result := "success"
		if response.Status >= 400 {
			result = "failure"
		}
		h.audit(r, current, "plugin.ui_page.proxy", pluginID, result, payload)
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) audit(r *http.Request, current session, action, pluginID, result string, payload map[string]any) {
	userID := current.principal.UserID
	payload["ip"] = clientIP(r)
	_ = h.config.Auditor.Record(context.WithoutCancel(r.Context()), audit.Event{ScopeID: current.principal.ScopeID,
		ActorUserID: &userID, Action: action, ResourceType: "plugin_ui_page", ResourceID: pluginID,
		RequestID: "plugin-ui." + uuid.NewString(), Result: result, Payload: payload})
}

func (h *Handler) error(w http.ResponseWriter, r *http.Request, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": code,
		"request_id": r.Header.Get("X-Request-ID")}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func locale(r *http.Request) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language"))), "en") {
		return "en-US"
	}
	return "zh-CN"
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// PostgresSites is the production SiteChecker: platform principals reach
// every site, tenant principals the sites of their own scope.
type PostgresSites struct{ Pool *pgxpool.Pool }

func (sites PostgresSites) CanAccessSite(ctx context.Context, principal identity.Principal, siteID uuid.UUID) (bool, error) {
	var ok bool
	err := sites.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sites WHERE id=$1 AND ($2 OR scope_id=$3))`,
		siteID, principal.ScopeKind == "platform", principal.ScopeID).Scan(&ok)
	return ok, err
}

// PostgresAuditor writes one event per transaction.
type PostgresAuditor struct {
	Pool *pgxpool.Pool
	Log  *audit.Log
}

func (auditor PostgresAuditor) Record(ctx context.Context, event audit.Event) error {
	tx, err := auditor.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := auditor.Log.Append(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
