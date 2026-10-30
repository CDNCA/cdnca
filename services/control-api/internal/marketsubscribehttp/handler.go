// Package marketsubscribehttp exposes the subscriber side of the node market
// to platform administrators: list supplies, bind them to sites, preview and
// apply a site revision on every leaf. Mounting is up to internal/httpapi.
package marketsubscribehttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsubscribe"
	"github.com/google/uuid"
)

const maxBody = 256 << 10

var segmentPattern = regexp.MustCompile(`^[0-9a-f-]{36}$`)

// Patterns are the routes this handler serves, for mounting on a shared mux.
var Patterns = []string{
	"GET /v1/admin/market/supplies",
	"PUT /v1/admin/sites/{site}/market-supplies/{supply}",
	"DELETE /v1/admin/sites/{site}/market-supplies/{supply}",
	"POST /v1/admin/sites/{site}/market-rollout/preview",
	"POST /v1/admin/sites/{site}/market-rollout/apply",
}

type Service interface {
	Supplies(ctx context.Context) ([]marketsubscribe.Supply, error)
	Bind(ctx context.Context, siteID, supplyID uuid.UUID, role string, priority int) error
	Unbind(ctx context.Context, siteID, supplyID uuid.UUID) error
	Preview(ctx context.Context, siteID uuid.UUID, revision int64, cfg siteconf.Config) (marketsubscribe.Result, error)
	Apply(ctx context.Context, siteID uuid.UUID, revision int64, cfg siteconf.Config) (marketsubscribe.Result, error)
}

// Caller is the authenticated console session making a market request.
type Caller struct {
	UserID      uuid.UUID
	ScopeID     uuid.UUID
	ScopeKind   string // "platform" or "tenant"
	Permissions []string
}

func (c Caller) has(codes ...string) bool {
	for _, code := range codes {
		if slices.Contains(c.Permissions, code) {
			return true
		}
	}
	return false
}

// Authenticate resolves the request's session; the caller supplies it.
type Authenticate func(*http.Request) (Caller, error)

// Marketplace permission codes (migration 296, buildout §4.1). Until the next
// release the old platform gate (sites.manage / platform.admin) still passes.
const (
	PermissionBrowse   = "marketplace.browse"
	PermissionPurchase = "marketplace.purchase"
	PermissionSell     = "marketplace.sell"
)

type access int

const (
	// accessSites is the supply/site binding API: it edits sites.
	accessSites access = iota
	accessBrowse
	accessPurchase
	accessSell
	// accessAdvisoryRead/Ack also admit tenants that install plugins: each
	// access scope acknowledges a plugin advisory on its own.
	accessAdvisoryRead
	accessAdvisoryAck
	// accessPluginRead is the plugin catalogue and detail (read-only): a
	// tenant confirming an installation looks its plugin up (q=plugin_id)
	// and reads the signed ui_page menus/origin before consenting.
	accessPluginRead
)

func (a access) allows(c Caller) bool {
	legacy := c.ScopeKind == "platform" && c.has("sites.manage", "platform.admin")
	switch a {
	case accessSites:
		return legacy
	case accessBrowse:
		return legacy || c.ScopeKind == "platform" && c.has(PermissionBrowse, PermissionPurchase, PermissionSell)
	case accessPurchase:
		return legacy || c.ScopeKind == "platform" && c.has(PermissionPurchase)
	case accessSell:
		return legacy || c.ScopeKind == "platform" && c.has(PermissionSell)
	case accessAdvisoryRead, accessPluginRead:
		return accessBrowse.allows(c) || c.ScopeKind == "tenant" && c.has("plugin_installations.read", "plugin_installations.manage")
	case accessAdvisoryAck:
		return accessPurchase.allows(c) || c.ScopeKind == "tenant" && c.has("plugin_installations.manage")
	}
	return false
}

type handlerFunc func(http.ResponseWriter, *http.Request, Caller)

type Handler struct {
	svc          Service
	authenticate Authenticate
	mux          *http.ServeMux
}

// New serves the supply/site routes when svc is set; with a nil svc (node
// market off) only what WithMember/WithBuyer add is served.
func New(svc Service, authenticate Authenticate) *Handler {
	h := &Handler{svc: svc, authenticate: authenticate, mux: http.NewServeMux()}
	if svc == nil {
		return h
	}
	handlers := []handlerFunc{h.supplies, h.bind, h.unbind, h.rollout(false), h.rollout(true)}
	for i, pattern := range Patterns {
		// Listing supplies is a read every market role needs (renewal,
		// selection); binding and rollout edit sites and keep the old gate.
		need := accessSites
		if i == 0 {
			need = accessBrowse
		}
		h.handle(pattern, need, handlers[i])
	}
	return h
}

// handle registers pattern behind its access check; every route answers 403
// before any market call when the session lacks the permission.
func (h *Handler) handle(pattern string, need access, next handlerFunc) {
	h.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		caller, err := h.authenticate(r)
		if err != nil || !need.allows(caller) {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		next(w, r, caller)
	})
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

func (h *Handler) supplies(w http.ResponseWriter, r *http.Request, _ Caller) {
	items, err := h.svc.Supplies(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) bind(w http.ResponseWriter, r *http.Request, _ Caller) {
	site, supply, ok := ids(w, r)
	if !ok {
		return
	}
	var body struct {
		Role     string `json:"role"`
		Priority int    `json:"priority"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := h.svc.Bind(r.Context(), site, supply, body.Role, body.Priority); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) unbind(w http.ResponseWriter, r *http.Request, _ Caller) {
	site, supply, ok := ids(w, r)
	if !ok {
		return
	}
	if err := h.svc.Unbind(r.Context(), site, supply); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) rollout(commit bool) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, _ Caller) {
		site, err := uuid.Parse(r.PathValue("site"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_site")
			return
		}
		var body struct {
			Revision int64           `json:"revision"`
			Config   siteconf.Config `json:"config"`
		}
		if !decode(w, r, &body) || body.Revision < 1 {
			if body.Revision < 1 {
				writeError(w, http.StatusBadRequest, "invalid_revision")
			}
			return
		}
		run := h.svc.Preview
		if commit {
			run = h.svc.Apply
		}
		result, err := run(r.Context(), site, body.Revision, body.Config)
		if errors.Is(err, marketsubscribe.ErrReceiptPending) {
			// Leaves answered but not every receipt was saved: not applied,
			// not failed. The body says which leaves (state receipt_pending).
			writeJSON(w, http.StatusAccepted, result)
			return
		}
		if err != nil {
			h.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, marketsubscribe.ErrInvalid), errors.Is(err, siteconf.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid")
	case errors.Is(err, marketsubscribe.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, marketsubscribe.ErrNoMarketBinding), errors.Is(err, marketsubscribe.ErrNoLeaves),
		errors.Is(err, marketsubscribe.ErrStaleRevision), errors.Is(err, marketsubscribe.ErrSitePackageUnavailable),
		errors.Is(err, marketsubscribe.ErrRevisionConflict):
		writeError(w, http.StatusConflict, conflictCode(err))
	default:
		writeError(w, http.StatusInternalServerError, "internal")
	}
}

func conflictCode(err error) string {
	switch {
	case errors.Is(err, marketsubscribe.ErrNoMarketBinding):
		return "no_market_binding"
	case errors.Is(err, marketsubscribe.ErrNoLeaves):
		return "no_active_leaf"
	case errors.Is(err, marketsubscribe.ErrSitePackageUnavailable):
		return "site_package_unavailable"
	case errors.Is(err, marketsubscribe.ErrRevisionConflict):
		return "revision_conflict"
	default:
		return "stale_revision"
	}
}

func ids(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	site, err1 := uuid.Parse(r.PathValue("site"))
	supply, err2 := uuid.Parse(r.PathValue("supply"))
	if err1 != nil || err2 != nil {
		writeError(w, http.StatusBadRequest, "invalid_id")
		return uuid.Nil, uuid.Nil, false
	}
	return site, supply, true
}

func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
