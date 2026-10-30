package marketsubscribehttp

import (
	"context"
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/marketsubscribe"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

// MC12 E2: roll a saved site out by choosing it. The server compiles the
// revision from the site (marketsubscribe.PlanSite); the console no longer
// sends a revision number or a config.

// SiteRolloutPatterns are the site-based rollout routes.
var SiteRolloutPatterns = []string{
	"GET /v1/admin/sites/{site}/market-supplies",
	"POST /v1/admin/sites/{site}/market-rollout/site-preview",
	"POST /v1/admin/sites/{site}/market-rollout/site-apply",
	// fix-mktsiteconf7 §1: each leaf's receipt and node delivery after an apply.
	"GET /v1/admin/sites/{site}/market-rollout/leaves",
}

// SiteRollout is the part of the service that compiles from saved sites.
type SiteRollout interface {
	SiteBindings(ctx context.Context, siteID uuid.UUID) ([]marketsubscribe.SiteBinding, error)
	SiteLeaves(ctx context.Context, siteID uuid.UUID) ([]marketsubscribe.LeafStatus, error)
	PreviewSite(ctx context.Context, actor site.Actor, siteID uuid.UUID) (marketsubscribe.SiteRolloutResult, error)
	ApplySite(ctx context.Context, actor site.Actor, siteID uuid.UUID, siteVersion int64, digest string) (marketsubscribe.SiteRolloutResult, error)
}

// WithSiteRollout serves SiteRolloutPatterns behind the site binding gate.
func (h *Handler) WithSiteRollout(svc SiteRollout) *Handler {
	h.handle(SiteRolloutPatterns[0], accessSites, func(w http.ResponseWriter, r *http.Request, _ Caller) {
		id, ok := siteParam(w, r)
		if !ok {
			return
		}
		items, err := svc.SiteBindings(r.Context(), id)
		if err != nil {
			h.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	h.handle(SiteRolloutPatterns[1], accessSites, func(w http.ResponseWriter, r *http.Request, c Caller) {
		id, ok := siteParam(w, r)
		if !ok {
			return
		}
		var body struct{}
		if !decode(w, r, &body) {
			return
		}
		out, err := svc.PreviewSite(r.Context(), c.siteActor(), id)
		h.siteResult(w, out, err)
	})
	h.handle(SiteRolloutPatterns[2], accessSites, func(w http.ResponseWriter, r *http.Request, c Caller) {
		id, ok := siteParam(w, r)
		if !ok {
			return
		}
		var body struct {
			SiteVersion int64  `json:"site_version"`
			Digest      string `json:"digest"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.SiteVersion < 1 || len(body.Digest) != 64 {
			writeError(w, http.StatusBadRequest, "invalid_body")
			return
		}
		out, err := svc.ApplySite(r.Context(), c.siteActor(), id, body.SiteVersion, body.Digest)
		h.siteResult(w, out, err)
	})
	h.handle(SiteRolloutPatterns[3], accessSites, func(w http.ResponseWriter, r *http.Request, _ Caller) {
		id, ok := siteParam(w, r)
		if !ok {
			return
		}
		items, err := svc.SiteLeaves(r.Context(), id)
		if err != nil {
			h.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	return h
}

func (c Caller) siteActor() site.Actor {
	return site.Actor{UserID: c.UserID, ScopeID: c.ScopeID, ScopeKind: c.ScopeKind}
}

// siteResult answers the plan with the leaves' result; a site saved since
// the preview is a 409 carrying the fresh plan, so the page can re-check it.
func (h *Handler) siteResult(w http.ResponseWriter, out marketsubscribe.SiteRolloutResult, err error) {
	if errors.Is(err, marketsubscribe.ErrSiteChanged) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "site_changed", "plan": out.Plan})
		return
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func siteParam(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("site"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_site")
		return uuid.Nil, false
	}
	return id, true
}
