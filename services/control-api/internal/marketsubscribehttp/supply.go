package marketsubscribehttp

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupplyguard"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

// Seller supply composition (ADR 0012 ML-09): the seller picks nodes, this
// controller keeps them as a hidden line group whose id is the offer
// component's node_pool_ref, and lists the node plugins every picked node
// has (ML-02/ML-11: only those may be included in the offer).

// SupplyPatterns are the routes WithSupplyGroups serves.
var SupplyPatterns = []string{
	"POST /v1/admin/market/supply-groups",
	"GET /v1/admin/market/supply-groups/{id}",
	"PUT /v1/admin/market/supply-groups/{id}",
	"DELETE /v1/admin/market/supply-groups/{id}",
	"POST /v1/admin/market/supply-plugins",
	// u4g: display names of plugin codes (a resale's upstream snapshot keeps codes only).
	"POST /v1/admin/market/plugin-names",
}

// SupplyGroups is *marketsupply.SupplyGroups.
type SupplyGroups interface {
	Put(ctx context.Context, actor marketsupply.SupplyActor, w marketsupply.SupplyGroupWrite) (marketsupply.SupplyGroup, error)
	Get(ctx context.Context, actor marketsupply.SupplyActor, id uuid.UUID) (marketsupply.SupplyGroup, error)
	Delete(ctx context.Context, actor marketsupply.SupplyActor, id uuid.UUID, revision int64, key, requestID string) error
	GroupPlugins(ctx context.Context, actor marketsupply.SupplyActor, id uuid.UUID) ([]marketsupply.SupplyPlugin, error)
	SupplyPlugins(ctx context.Context, platform uuid.UUID, nodeIDs []uuid.UUID) ([]marketsupply.SupplyPlugin, error)
	PluginNames(ctx context.Context, codes []string) ([]marketsupply.SupplyPlugin, error)
}

type supplyGroupView struct {
	marketsupply.SupplyGroup
	// NodePoolRef is what the offer component carries (own_pool).
	NodePoolRef string                      `json:"node_pool_ref"`
	Plugins     []marketsupply.SupplyPlugin `json:"plugins"`
}

// WithSupplyGroups serves SupplyPatterns behind the seller permission.
func (h *Handler) WithSupplyGroups(groups SupplyGroups) *Handler {
	h.handle(SupplyPatterns[0], accessSell, h.putSupplyGroup(groups, false))
	h.handle(SupplyPatterns[1], accessSell, func(w http.ResponseWriter, r *http.Request, c Caller) {
		id, ok := supplyID(w, r)
		if !ok {
			return
		}
		h.writeSupplyGroup(w, r, groups, c, http.StatusOK, func() (marketsupply.SupplyGroup, error) {
			return groups.Get(r.Context(), supplyActor(c), id)
		})
	})
	h.handle(SupplyPatterns[2], accessSell, h.putSupplyGroup(groups, true))
	h.handle(SupplyPatterns[3], accessSell, func(w http.ResponseWriter, r *http.Request, c Caller) {
		id, ok := supplyID(w, r)
		if !ok {
			return
		}
		key, ok := idempotencyKey(w, r)
		if !ok {
			return
		}
		revision, err := strconv.ParseInt(r.URL.Query().Get("revision"), 10, 64)
		if err != nil || revision < 1 || len(r.URL.Query()) != 1 {
			writeError(w, http.StatusBadRequest, "invalid_query")
			return
		}
		if err := groups.Delete(r.Context(), supplyActor(c), id, revision, key, "supply-"+uuid.NewString()); err != nil {
			supplyFail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	h.handle(SupplyPatterns[4], accessSell, func(w http.ResponseWriter, r *http.Request, c Caller) {
		var body struct {
			NodeIDs []uuid.UUID `json:"node_ids"`
		}
		if !decode(w, r, &body) {
			return
		}
		plugins, err := groups.SupplyPlugins(r.Context(), c.ScopeID, body.NodeIDs)
		if err != nil {
			supplyFail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": plugins})
	})
	h.handle(SupplyPatterns[5], accessSell, func(w http.ResponseWriter, r *http.Request, c Caller) {
		var body struct {
			Codes []string `json:"codes"`
		}
		if !decode(w, r, &body) {
			return
		}
		names, err := groups.PluginNames(r.Context(), body.Codes)
		if err != nil {
			supplyFail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": names})
	})
	return h
}

func (h *Handler) putSupplyGroup(groups SupplyGroups, update bool) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, c Caller) {
		var id uuid.UUID
		if update {
			var ok bool
			if id, ok = supplyID(w, r); !ok {
				return
			}
		}
		key, ok := idempotencyKey(w, r)
		if !ok {
			return
		}
		var body marketsupply.SupplyGroupWrite
		if !decode(w, r, &body) {
			return
		}
		if update != (body.ExpectedRevision > 0) {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		body.GroupID, body.IdempotencyKey, body.RequestID = id, key, "supply-"+uuid.NewString()
		status := http.StatusOK
		if !update {
			status = http.StatusCreated
		}
		h.writeSupplyGroup(w, r, groups, c, status, func() (marketsupply.SupplyGroup, error) {
			return groups.Put(r.Context(), supplyActor(c), body)
		})
	}
}

func (h *Handler) writeSupplyGroup(w http.ResponseWriter, r *http.Request, groups SupplyGroups, c Caller, status int,
	load func() (marketsupply.SupplyGroup, error),
) {
	group, err := load()
	if err != nil {
		supplyFail(w, err)
		return
	}
	plugins, err := groups.GroupPlugins(r.Context(), supplyActor(c), group.ID)
	if err != nil {
		supplyFail(w, err)
		return
	}
	writeJSON(w, status, supplyGroupView{SupplyGroup: group, NodePoolRef: group.ID.String(), Plugins: plugins})
}

func supplyActor(c Caller) marketsupply.SupplyActor {
	return marketsupply.SupplyActor{UserID: c.UserID, ScopeID: c.ScopeID}
}

func supplyID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || !segmentPattern.MatchString(r.PathValue("id")) {
		writeError(w, http.StatusBadRequest, "invalid_id")
		return uuid.Nil, false
	}
	return id, true
}

func idempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) != 1 || !keyValue.MatchString(values[0]) {
		writeError(w, http.StatusBadRequest, "idempotency_key_required")
		return "", false
	}
	return values[0], true
}

func supplyFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, marketsupply.ErrSupplyNodeUnusable):
		writeError(w, http.StatusUnprocessableEntity, "node_unusable")
	case errors.Is(err, marketsupply.ErrSupplyInvalid):
		writeError(w, http.StatusBadRequest, "invalid")
	case errors.Is(err, marketsupply.ErrSupplyNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, marketsupply.ErrSupplyForbidden):
		writeError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, nodescheduler.ErrMarketSupplyInUse):
		writeSupplyInUse(w, err)
	case errors.Is(err, marketsupply.ErrSupplyConflict):
		writeError(w, http.StatusConflict, "conflict")
	default:
		writeError(w, http.StatusInternalServerError, "internal")
	}
}

// writeSupplyInUse answers 409 supply_in_use; a refusal for leaving normal
// subscribers without an online node (ML-18) also carries the counts.
func writeSupplyInUse(w http.ResponseWriter, err error) {
	var inUse *marketsupplyguard.InUseError
	if !errors.As(err, &inUse) {
		writeError(w, http.StatusConflict, "supply_in_use")
		return
	}
	writeJSON(w, http.StatusConflict, map[string]any{"error": "supply_in_use",
		"online_available": inUse.OnlineAvailable, "normal_subscriptions": inUse.NormalSubscriptions})
}
