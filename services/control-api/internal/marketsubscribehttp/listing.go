package marketsubscribehttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupplyguard"
	"github.com/google/uuid"
)

// Batch listing (批量选择节点批量设置上线售卖).
// The console fills one offer template and picks nodes; this controller makes
// the items — one offer per node, or one offer over all of them — each as
// ML-09's hidden supply group plus a market offer relayed as is (the market
// protocol is unchanged). Every item reports its own result; submitting the
// same nodes with the same template again returns what was made.

// ListingPatterns are the routes WithListing serves.
var ListingPatterns = []string{
	"POST /v1/admin/market/listing-batches",
	"GET /v1/admin/market/listing-templates",
	"POST /v1/admin/market/listing-templates",
	"PUT /v1/admin/market/listing-templates/{id}",
	"DELETE /v1/admin/market/listing-templates/{id}",
	"POST /v1/admin/market/supply-node-removals",
}

const (
	maxBatchItems = 200
	itemLease     = 2 * time.Minute
)

// ListingSupply is the part of *marketsupply.SupplyGroups batches use.
type ListingSupply interface {
	SupplyGroups
}

type batchRequest struct {
	// Mode: "single" (one offer per node) or "multi" (one offer, all nodes).
	Mode    string      `json:"mode"`
	NodeIDs []uuid.UUID `json:"node_ids"`
	// Offer is the market offer body (POST /v1/offers) without components:
	// each item adds its own own_pool component. For single-node items its
	// name gets " · <node>" appended.
	Offer json.RawMessage `json:"offer"`
	// Publish lists each new offer (draft otherwise).
	Publish bool `json:"publish"`
}

// BatchResult is one item of a batch.
type BatchResult struct {
	NodeIDs []uuid.UUID `json:"node_ids"`
	// Status: created (new offer), existing (the same item was made before),
	// failed (Error/Detail say why), in_progress (another submission is making it).
	Status  string     `json:"status"`
	GroupID *uuid.UUID `json:"group_id,omitempty"`
	OfferID *uuid.UUID `json:"offer_id,omitempty"`
	// Published is the market status after publishing (listed / pending_review).
	Published string `json:"published,omitempty"`
	// RemovedPlugins: template plugins the item's nodes do not have, left out.
	RemovedPlugins []string        `json:"removed_plugins"`
	Error          string          `json:"error,omitempty"`
	Detail         json.RawMessage `json:"detail,omitempty"`
}

// WithListing serves ListingPatterns behind the seller permission; offers are
// relayed through forwarder.
func (h *Handler) WithListing(supply ListingSupply, store ListingStore, forwarder Forwarder) *Handler {
	h.handle(ListingPatterns[0], accessSell, func(w http.ResponseWriter, r *http.Request, c Caller) {
		var body batchRequest
		if !decode(w, r, &body) {
			return
		}
		offer, ok := batchOffer(body)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		groups := [][]uuid.UUID{}
		if body.Mode == "multi" {
			groups = append(groups, sortedIDs(body.NodeIDs))
		} else {
			for _, id := range body.NodeIDs {
				groups = append(groups, []uuid.UUID{id})
			}
		}
		b := batch{supply: supply, store: store, forwarder: forwarder, caller: c, publish: body.Publish}
		results := make([]BatchResult, len(groups))
		for i, nodes := range groups {
			results[i] = b.item(r.Context(), nodes, offer, body.Mode == "single")
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": results})
	})
	h.handle(ListingPatterns[1], accessSell, func(w http.ResponseWriter, r *http.Request, c Caller) {
		items, err := store.Templates(r.Context(), c.ScopeID)
		if err != nil {
			listingFail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": nonNilTemplates(items)})
	})
	putTemplate := func(update bool) handlerFunc {
		return func(w http.ResponseWriter, r *http.Request, c Caller) {
			var body ListingTemplate
			if update {
				id, ok := supplyID(w, r)
				if !ok {
					return
				}
				body.ID = id
			}
			var in struct {
				Name     string          `json:"name"`
				Body     json.RawMessage `json:"body"`
				Revision int64           `json:"revision"`
			}
			if !decode(w, r, &in) {
				return
			}
			body.Name, body.Body, body.Revision = strings.TrimSpace(in.Name), in.Body, in.Revision
			if body.Name == "" || len([]rune(body.Name)) > 64 || len(body.Body) > 32<<10 || !isObject(body.Body) ||
				update != (body.Revision > 0) {
				writeError(w, http.StatusBadRequest, "invalid")
				return
			}
			saved, err := store.PutTemplate(r.Context(), c.ScopeID, c.UserID, body)
			if err != nil {
				listingFail(w, err)
				return
			}
			status := http.StatusOK
			if !update {
				status = http.StatusCreated
			}
			writeJSON(w, status, saved)
		}
	}
	h.handle(ListingPatterns[2], accessSell, putTemplate(false))
	h.handle(ListingPatterns[3], accessSell, putTemplate(true))
	h.handle(ListingPatterns[4], accessSell, func(w http.ResponseWriter, r *http.Request, c Caller) {
		id, ok := supplyID(w, r)
		if !ok {
			return
		}
		var revision int64
		if _, err := fmt.Sscan(r.URL.Query().Get("revision"), &revision); err != nil || revision < 1 || len(r.URL.Query()) != 1 {
			writeError(w, http.StatusBadRequest, "invalid_query")
			return
		}
		if err := store.DeleteTemplate(r.Context(), c.ScopeID, id, revision); err != nil {
			listingFail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	h.handle(ListingPatterns[5], accessSell, h.removeSupplyNodes(supply))
	return h
}

// batchOffer checks the template: a JSON object with a name and no
// components of its own (the items add them).
func batchOffer(body batchRequest) (map[string]json.RawMessage, bool) {
	ids := slices.Clone(body.NodeIDs)
	if body.Mode != "single" && body.Mode != "multi" || len(ids) == 0 || len(ids) > maxBatchItems ||
		slices.Contains(ids, uuid.Nil) || len(slices.Compact(sortedIDs(ids))) != len(ids) {
		return nil, false
	}
	var offer map[string]json.RawMessage
	if json.Unmarshal(body.Offer, &offer) != nil || offer == nil {
		return nil, false
	}
	if _, has := offer["components"]; has {
		return nil, false
	}
	var name string
	if json.Unmarshal(offer["name"], &name) != nil || strings.TrimSpace(name) == "" {
		return nil, false
	}
	return offer, true
}

type batch struct {
	supply    ListingSupply
	store     ListingStore
	forwarder Forwarder
	caller    Caller
	publish   bool
}

func (b batch) item(ctx context.Context, nodes []uuid.UUID, template map[string]json.RawMessage, perNode bool) BatchResult {
	result := BatchResult{NodeIDs: nodes, RemovedPlugins: []string{}}
	fail := func(code string, detail json.RawMessage) BatchResult {
		result.Status, result.Error, result.Detail = "failed", code, detail
		return result
	}
	offer := map[string]json.RawMessage{}
	for k, v := range template {
		offer[k] = v
	}
	var name string
	_ = json.Unmarshal(offer["name"], &name)
	name = strings.TrimSpace(name)

	// Plugins: only what every node of the item has (ML-09 intersection).
	var tags map[string]json.RawMessage
	_ = json.Unmarshal(offer["tags"], &tags)
	var wanted []string
	_ = json.Unmarshal(tags["plugins"], &wanted)
	if len(wanted) > 0 {
		available, err := b.supply.SupplyPlugins(ctx, b.caller.ScopeID, nodes)
		if err != nil {
			return fail(supplyCode(err), nil)
		}
		kept := []string{}
		for _, code := range wanted {
			if slices.ContainsFunc(available, func(p marketsupply.SupplyPlugin) bool { return p.Code == code }) {
				kept = append(kept, code)
			} else {
				result.RemovedPlugins = append(result.RemovedPlugins, code)
			}
		}
		if len(kept) == 0 {
			delete(tags, "plugins")
		} else {
			tags["plugins"], _ = json.Marshal(kept)
		}
		offer["tags"], _ = json.Marshal(tags)
	}

	nodeKey := nodeSetKey(nodes)
	groupName := name
	if perNode {
		groupName = name + " · " + nodes[0].String()[:8]
	}
	digest := itemDigest(nodeKey, offer)
	stored, err := b.store.ClaimItem(ctx, b.caller.ScopeID, b.caller.UserID, digest, itemLease)
	switch {
	case errors.Is(err, ErrItemBusy):
		result.Status = "in_progress"
		return result
	case err != nil:
		return fail("internal", nil)
	}
	if stored.OfferID != nil {
		result.Status, result.GroupID, result.OfferID = "existing", stored.GroupID, stored.OfferID
		// B19/B20: the offer was made before (maybe as a draft, maybe its
		// publish failed). With publish asked, publish that same offer; the
		// market refuses (409) what is already listed or in review.
		if b.publish {
			b.publishOffer(ctx, &result, true)
		}
		return result
	}
	release := func() { _ = b.store.ReleaseItem(context.WithoutCancel(ctx), b.caller.ScopeID, digest) }

	// The group key depends on the node set only: a retry with another
	// template reuses the group made for these nodes.
	groupKey := "listing-" + nodeKey[:40]
	group, err := b.supply.Put(ctx, supplyActor(b.caller), marketsupply.SupplyGroupWrite{Name: groupName, NodeIDs: nodes,
		IdempotencyKey: groupKey, RequestID: "listing-" + uuid.NewString()})
	if errors.Is(err, marketsupply.ErrSupplyConflict) {
		// Same key, other name: the group exists, reuse it.
		group, err = b.supply.Get(ctx, supplyActor(b.caller), marketsupply.CreatedGroupID(b.caller.UserID, groupKey))
	}
	if err != nil {
		release()
		return fail(supplyCode(err), nil)
	}
	result.GroupID = &group.ID
	if err := b.store.SaveItem(ctx, b.caller.ScopeID, digest, BatchItem{GroupID: &group.ID}); err != nil {
		release()
		return fail("internal", nil)
	}

	offer["name"], _ = json.Marshal(groupName)
	offer["components"], _ = json.Marshal([]map[string]string{{"kind": "own_pool", "node_pool_ref": group.ID.String()}})
	raw, _ := json.Marshal(offer)
	status, response, err := b.forwarder.Forward(ctx, http.MethodPost, "/v1/offers", "", raw)
	if err != nil || status >= 500 {
		release()
		return fail("market_unavailable", nil)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		release()
		return fail(marketCode(response), marketDetail(response))
	}
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	if json.Unmarshal(response, &created) != nil || created.ID == uuid.Nil {
		release()
		return fail("market_response_invalid", nil)
	}
	result.OfferID = &created.ID
	if err := b.store.SaveItem(ctx, b.caller.ScopeID, digest, BatchItem{GroupID: &group.ID, OfferID: &created.ID}); err != nil {
		// The offer exists but is not recorded: report it, a resubmission
		// would list the item again.
		result.Status = "created"
		result.Error = "record_failed"
		return result
	}
	result.Status = "created"
	if b.publish {
		b.publishOffer(ctx, &result, false)
	}
	return result
}

// publishOffer lists result.OfferID. A failure leaves the offer a draft and
// says why (publish_*); resubmitting the item retries it on the same offer.
// existing: the offer may have been published by an earlier submission, so
// the market's conflict (not a draft any more) is no error.
func (b batch) publishOffer(ctx context.Context, result *BatchResult, existing bool) {
	status, response, err := b.forwarder.Forward(ctx, http.MethodPost, "/v1/offers/"+result.OfferID.String()+"/publish", "", nil)
	var published struct {
		Status string `json:"status"`
	}
	switch {
	case err != nil || status >= 500:
		result.Error = "publish_market_unavailable"
	case existing && status == http.StatusConflict:
	case status != http.StatusOK || json.Unmarshal(response, &published) != nil:
		result.Error, result.Detail = "publish_"+marketCode(response), marketDetail(response)
	default:
		result.Published = published.Status
	}
}

// removeSupplyNodes takes nodes out of every supply group of this seller
// that has them. ADR 0012 §18.4 / U3: while a group has normal subscribers
// at least one online, usable node must stay. That rule is the shared
// marketsupplyguard check run inside Put (nodescheduler putGroup), so it
// uses the market slot states (stopped/cancelled subscriptions do not
// count); a refused group reports supply_keeps_online_node. A group cannot
// drop to no nodes.
func (h *Handler) removeSupplyNodes(supply ListingSupply) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, c Caller) {
		var body struct {
			GroupIDs []uuid.UUID `json:"group_ids"`
			NodeIDs  []uuid.UUID `json:"node_ids"`
		}
		if !decode(w, r, &body) || len(body.GroupIDs) == 0 || len(body.GroupIDs) > maxBatchItems ||
			len(body.NodeIDs) == 0 || len(body.NodeIDs) > 256 {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		type outcome struct {
			GroupID  uuid.UUID   `json:"group_id"`
			Status   string      `json:"status"` // updated | unchanged | failed
			Removed  []uuid.UUID `json:"removed"`
			Revision int64       `json:"revision,omitempty"`
			Error    string      `json:"error,omitempty"`
		}
		results := []outcome{}
		for _, id := range sortedIDs(slices.Compact(sortedIDs(body.GroupIDs))) {
			res := outcome{GroupID: id, Removed: []uuid.UUID{}}
			results = append(results, func() outcome {
				group, err := supply.Get(r.Context(), supplyActor(c), id)
				if err != nil {
					res.Status, res.Error = "failed", supplyCode(err)
					return res
				}
				keep := []uuid.UUID{}
				for _, n := range group.Nodes {
					if slices.Contains(body.NodeIDs, n.NodeID) {
						res.Removed = append(res.Removed, n.NodeID)
					} else {
						keep = append(keep, n.NodeID)
					}
				}
				if len(res.Removed) == 0 {
					res.Status, res.Revision = "unchanged", group.Revision
					return res
				}
				if len(keep) == 0 {
					res.Status, res.Error = "failed", "supply_needs_node"
					return res
				}
				updated, err := supply.Put(r.Context(), supplyActor(c), marketsupply.SupplyGroupWrite{GroupID: id,
					ExpectedRevision: group.Revision, Name: group.Name, NodeIDs: keep,
					IdempotencyKey: fmt.Sprintf("listing-remove-%s-%d", id, group.Revision), RequestID: "listing-" + uuid.NewString()})
				if err != nil {
					res.Status, res.Error = "failed", supplyCode(err)
					return res
				}
				res.Status, res.Revision = "updated", updated.Revision
				return res
			}())
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": results})
	}
}

func sortedIDs(ids []uuid.UUID) []uuid.UUID {
	out := slices.Clone(ids)
	slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	return out
}

func nodeSetKey(nodes []uuid.UUID) string {
	h := sha256.New()
	_, _ = h.Write([]byte("cdnca.market.listing-nodes/v1\x00"))
	for _, n := range sortedIDs(nodes) {
		_, _ = h.Write(n[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// itemDigest binds the node set and the final offer body (canonical JSON:
// encoding/json sorts map keys).
func itemDigest(nodeKey string, offer map[string]json.RawMessage) []byte {
	canonical := map[string]any{}
	for k, v := range offer {
		var value any
		_ = json.Unmarshal(v, &value)
		canonical[k] = value
	}
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256([]byte("cdnca.market.listing-item/v1\x00" + nodeKey + "\x00" + string(raw)))
	return sum[:]
}

func isObject(raw json.RawMessage) bool {
	var v map[string]any
	return json.Unmarshal(raw, &v) == nil && v != nil
}

// marketCode is the market's error code ("error" field), or request_failed.
func marketCode(raw []byte) string {
	var body struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &body) != nil || body.Error == "" || !tokenValue.MatchString(body.Error) {
		return "request_failed"
	}
	return body.Error
}

// marketDetail passes the market's refusal body (floor, plugins) through.
func marketDetail(raw []byte) json.RawMessage {
	if !json.Valid(raw) || len(raw) > 4096 {
		return nil
	}
	return raw
}

func supplyCode(err error) string {
	var inUse *marketsupplyguard.InUseError
	switch {
	case errors.As(err, &inUse):
		return "supply_keeps_online_node"
	case errors.Is(err, marketsupply.ErrSupplyNodeUnusable):
		return "node_unusable"
	case errors.Is(err, marketsupply.ErrSupplyInvalid):
		return "invalid"
	case errors.Is(err, marketsupply.ErrSupplyNotFound):
		return "not_found"
	case errors.Is(err, marketsupply.ErrSupplyForbidden):
		return "forbidden"
	case errors.Is(err, marketsupply.ErrSupplyConflict):
		return "conflict"
	}
	return "internal"
}

func listingFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrListingConflict):
		writeError(w, http.StatusConflict, "conflict")
	default:
		storeFail(w, err)
	}
}

func nonNilTemplates(items []ListingTemplate) []ListingTemplate {
	if items == nil {
		return []ListingTemplate{}
	}
	return items
}
