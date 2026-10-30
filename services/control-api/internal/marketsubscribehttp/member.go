package marketsubscribehttp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/cdnca/cdnca/libs/marketproto/pluginkind"
)

// Forwarder relays one member API request to the market with this
// controller's installation certificate (marketclient.Client.Forward).
type Forwarder interface {
	Forward(ctx context.Context, method, path, idempotencyKey string, body []byte) (int, []byte, error)
}

// memberRoute is one market member API call the admin console may make on
// behalf of this controller, as "METHOD /v1/admin/market/<x>" → "/v1/<x>".
type memberRoute struct {
	upstream string
	access   access
	// query lists the query parameters passed through, each with its pattern.
	query map[string]*regexp.Regexp
	// keyed writes need the Idempotency-Key header (marketplace-openapi);
	// legacy node-market writes carry idempotency_key in the body instead.
	keyed bool
	// compat fills ?compat= with this controller's version unless the
	// caller asked for all versions (§5.3 "自动按本主控版本过滤").
	compat bool
}

var (
	textValue   = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,64}$`)
	tokenValue  = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	cursorValue = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`) // length checked in forward
	limitValue  = regexp.MustCompile(`^([1-9]|[1-9][0-9]|1[0-9][0-9]|200)$`)
	amountValue = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)
	scoreValue  = regexp.MustCompile(`^(0|[0-2](\.[0-9]{1,3})?|3(\.0{1,3})?)$`)
	versionArg  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$`)
	// pluginKind accepts exactly the market 030 kinds (single source: libs/marketproto/pluginkind).
	pluginKind = regexp.MustCompile(`^(` + strings.Join(pluginkind.All, "|") + `)$`)
	keyValue   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	oneValue   = regexp.MustCompile(`^1$`)
	currency   = regexp.MustCompile(`^[A-Z]{3}$`)
	page       = map[string]*regexp.Regexp{"cursor": cursorValue, "limit": limitValue}
)

func with(base map[string]*regexp.Regexp, extra map[string]*regexp.Regexp) map[string]*regexp.Regexp {
	out := map[string]*regexp.Regexp{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

var memberRoutes = map[string]memberRoute{
	// Existing node market (docs/marketplace).
	"GET /v1/admin/market/member": {upstream: "/v1/members/me", access: accessBrowse},
	"GET /v1/admin/market/offers": {upstream: "/v1/offers", access: accessBrowse, query: map[string]*regexp.Regexp{
		"mine": oneValue, "region": textValue, "carrier": textValue, "billing_model": tokenValue,
		"max_price": amountValue, "min_score": scoreValue, "settlement_mode": regexp.MustCompile(`^(direct|escrow)$`),
		"cursor": cursorValue, "limit": limitValue}},
	"POST /v1/admin/market/offers": {upstream: "/v1/offers", access: accessSell},
	// Node plugins an offer of these components may include, checked before
	// submitting the offer (ADR 0012, ML-02/ML-09); read-only, no key.
	"POST /v1/admin/market/offers/plugin-options": {upstream: "/v1/offers/plugin-options", access: accessSell},
	"POST /v1/admin/market/offers/{id}/publish":   {upstream: "/v1/offers/{id}/publish", access: accessSell},
	"GET /v1/admin/market/offers/{id}/quality":    {upstream: "/v1/offers/{id}/quality", access: accessBrowse},
	"POST /v1/admin/market/subscriptions":         {upstream: "/v1/subscriptions", access: accessPurchase},
	"GET /v1/admin/market/supply-targets":         {upstream: "/v1/supply-targets", access: accessBrowse},
	// MARKET-03: the agreements the operator published (latest version with text); read-only.
	"GET /v1/admin/market/agreements":            {upstream: "/v1/agreements", access: accessBrowse},
	"PUT /v1/admin/market/ledger/credit-terms":   {upstream: "/v1/ledger/credit-terms", access: accessSell},
	"GET /v1/admin/market/commission/statements": {upstream: "/v1/commission/statements", access: accessSell},
	"GET /v1/admin/market/ledger/balance": {upstream: "/v1/ledger/balance", access: accessBrowse, query: map[string]*regexp.Regexp{
		"buyer_id": textValue, "seller_id": textValue, "currency": textValue}},

	// ADR 0012 listing page (ML-11): the platform floor (ML-13), this
	// controller's node admissions (line grade) and an offer's subscribers
	// with their usage, holds and node overloads (§9.4). The market answers
	// 501 market_feature_unavailable until it mounts the last two.
	"GET /v1/admin/market/supply-limits-policy":    {upstream: "/v1/supply-limits-policy", access: accessBrowse},
	"GET /v1/admin/market/node-admissions":         {upstream: "/v1/node-admissions", access: accessSell, query: page},
	"GET /v1/admin/market/offers/{id}/subscribers": {upstream: "/v1/offers/{id}/subscribers", access: accessSell, query: page},

	// ADR 0012 subscriber pages (ML-12): an offer's node groups and effective
	// thresholds (§9.2), one subscription's limits, usage series, holds and
	// slot states (§9.3), the nodes out of scheduling (ML-06), and the escrow
	// prepaid balance, arrears and alert line plus the per-seller direct
	// balances (ADR 0015 §12; the alert line is served at /v1/ledger/alerts).
	"GET /v1/admin/market/offers/{id}/nodes":         {upstream: "/v1/offers/{id}/nodes", access: accessBrowse},
	"GET /v1/admin/market/subscriptions/{id}/limits": {upstream: "/v1/subscriptions/{id}/limits", access: accessBrowse, query: map[string]*regexp.Regexp{"hours": regexp.MustCompile(`^([1-9]|[1-9][0-9]|1[0-5][0-9]|16[0-8])$`)}},
	"GET /v1/admin/market/supply-unscheduled":        {upstream: "/v1/supply-unscheduled", access: accessBrowse},
	"GET /v1/admin/market/prepaid":                   {upstream: "/v1/prepaid", access: accessBrowse, query: map[string]*regexp.Regexp{"currency": currency}},
	"PUT /v1/admin/market/prepaid/alert":             {upstream: "/v1/ledger/alerts", access: accessPurchase},

	// Direct top-ups (ADR 0015 §3.4): the subscriber pays a seller's own
	// merchant account; the seller's controller books it and the market
	// credits the buyer's balance with that seller.
	"GET /v1/admin/market/direct-pay/sellers": {upstream: "/v1/direct-pay/sellers", access: accessBrowse,
		query: map[string]*regexp.Regexp{"seller_id": textValue}},
	"POST /v1/admin/market/direct-topups": {upstream: "/v1/direct-topups", access: accessPurchase, keyed: true},
	"GET /v1/admin/market/direct-topups": {upstream: "/v1/direct-topups", access: accessBrowse,
		query: with(page, map[string]*regexp.Regexp{"as": regexp.MustCompile(`^(buyer|seller)$`)})},
	"GET /v1/admin/market/direct-topups/{id}": {upstream: "/v1/direct-topups/{id}", access: accessBrowse},
	// ADR 0012 ML-16 (§15, §18.1–18.2): who subscribes to me across offers
	// (visibility "a"), my private note on a row, and the suspended slots as
	// buyer or seller. No seller route pauses, stops or tightens (U2/U3).
	"GET /v1/admin/market/seller/subscribers": {upstream: "/v1/seller/subscribers", access: accessSell,
		query: with(page, map[string]*regexp.Regexp{"offer_id": segmentPattern})},
	"PUT /v1/admin/market/seller/subscribers/note": {upstream: "/v1/seller/subscribers/note", access: accessSell},
	"GET /v1/admin/market/holds":                   {upstream: "/v1/holds", access: accessBrowse, query: page},
	"GET /v1/admin/market/seller/holds":            {upstream: "/v1/seller/holds", access: accessSell, query: page},

	// ADR 0012 ML-17 (§18.3): stop complaints on a subscriber row. Answers
	// carry the outcome and the caller's own target reference only (U5).
	"POST /v1/admin/market/supply-complaints":               {upstream: "/v1/supply-complaints", access: accessSell},
	"GET /v1/admin/market/supply-complaints":                {upstream: "/v1/supply-complaints", access: accessSell, query: page},
	"GET /v1/admin/market/supply-complaints/{id}":           {upstream: "/v1/supply-complaints/{id}", access: accessSell},
	"POST /v1/admin/market/supply-complaints/{id}/withdraw": {upstream: "/v1/supply-complaints/{id}/withdraw", access: accessSell},

	// Plugin market (buyer.yaml, M2).
	"GET /v1/admin/market/plugins": {upstream: "/v1/plugins", access: accessPluginRead, compat: true, query: with(page, map[string]*regexp.Regexp{
		"q": textValue, "kind": pluginKind, "applies_to": regexp.MustCompile(`^(admin|user|site)$`),
		"compat": versionArg, "price": regexp.MustCompile(`^(free|paid)$`), "sort": regexp.MustCompile(`^(popular|newest|name)$`)})},
	"GET /v1/admin/market/plugins/{id}":          {upstream: "/v1/plugins/{id}", access: accessPluginRead},
	"GET /v1/admin/market/licenses":              {upstream: "/v1/licenses", access: accessBrowse, query: page},
	"POST /v1/admin/market/licenses/{id}/cancel": {upstream: "/v1/licenses/{id}/cancel", access: accessPurchase, keyed: true},
	"POST /v1/admin/market/licenses/{id}/resume": {upstream: "/v1/licenses/{id}/resume", access: accessPurchase, keyed: true},
	// PL-RENEWAL-01: renew a past-due or expired subscription on the same licence.
	"POST /v1/admin/market/licenses/{id}/renew": {upstream: "/v1/licenses/{id}/renew", access: accessPurchase, keyed: true},

	// Orders (buyer.yaml, M1): plugin plans, node offers and prepaid top-ups
	// (kind=prepaid_topup, platform market).
	"POST /v1/admin/market/orders":     {upstream: "/v1/orders", access: accessPurchase, keyed: true},
	"GET /v1/admin/market/orders/{id}": {upstream: "/v1/orders/{id}", access: accessBrowse},

	// Plugin purchase from the market prepaid balance (buyer.yaml, M2).
	"POST /v1/admin/market/plugin-purchases": {upstream: "/v1/plugin-purchases", access: accessPurchase, keyed: true},
	// Download (PA-27): a live licence of this installation, or the free plan's licence; else 402 purchase_required.
	"POST /v1/admin/market/plugin-downloads": {upstream: "/v1/plugin-downloads", access: accessPurchase},

	// Node subscriptions, usage statements, SLA and disputes (buyer.yaml, M4).
	// ML-11b batch delist (stops new sales; sold subscriptions keep their
	// snapshot) and limits: not mounted by the market yet, so they answer
	// 501 market_feature_unavailable until it does.
	"PUT /v1/admin/market/offers/{id}/terms":                 {upstream: "/v1/offers/{id}/terms", access: accessSell, keyed: true},
	"POST /v1/admin/market/offers/{id}/delist":               {upstream: "/v1/offers/{id}/delist", access: accessSell, keyed: true},
	"PUT /v1/admin/market/offers/{id}/limits":                {upstream: "/v1/offers/{id}/limits", access: accessSell, keyed: true},
	"GET /v1/admin/market/subscriptions/{id}":                {upstream: "/v1/subscriptions/{id}", access: accessBrowse},
	"PUT /v1/admin/market/subscriptions/{id}/selection":      {upstream: "/v1/subscriptions/{id}/selection", access: accessPurchase, keyed: true},
	"PUT /v1/admin/market/subscriptions/{id}/renewal-policy": {upstream: "/v1/subscriptions/{id}/renewal-policy", access: accessPurchase, keyed: true},
	"POST /v1/admin/market/subscriptions/{id}/cancel":        {upstream: "/v1/subscriptions/{id}/cancel", access: accessPurchase, keyed: true},
	// ADR 0012 §24 (ML-31): liability-free cancel after T1 zero-online minutes; 409 outage_not_eligible otherwise.
	"POST /v1/admin/market/subscriptions/{id}/outage-cancel": {upstream: "/v1/subscriptions/{id}/outage-cancel", access: accessPurchase, keyed: true},
	"GET /v1/admin/market/usage-statements": {upstream: "/v1/usage-statements", access: accessBrowse,
		query: with(page, map[string]*regexp.Regexp{"status": regexp.MustCompile(`^[a-z_]{1,32}$`), "as": regexp.MustCompile(`^(buyer|seller)$`)})},
	"POST /v1/admin/market/usage-statements/{id}/accept":  {upstream: "/v1/usage-statements/{id}/accept", access: accessPurchase, keyed: true},
	"POST /v1/admin/market/usage-statements/{id}/dispute": {upstream: "/v1/usage-statements/{id}/dispute", access: accessPurchase, keyed: true},
	"POST /v1/admin/market/sla-breaches/{id}/dispute":     {upstream: "/v1/sla-breaches/{id}/dispute", access: accessPurchase, keyed: true},
	"GET /v1/admin/market/disputes/{id}":                  {upstream: "/v1/disputes/{id}", access: accessBrowse},
	"POST /v1/admin/market/disputes/{id}/withdraw":        {upstream: "/v1/disputes/{id}/withdraw", access: accessPurchase, keyed: true},
	"POST /v1/admin/market/disputes/{id}/escalate":        {upstream: "/v1/disputes/{id}/escalate", access: accessPurchase, keyed: true},

	// Buyer disputes across both markets and opening one on a plugin order
	// (buyer.yaml, M1 mktgaps2). license_id answers 503 until the plugin
	// market resolves licences to orders.
	"GET /v1/admin/market/disputes": {upstream: "/v1/disputes", access: accessBrowse, query: with(page, map[string]*regexp.Regexp{
		"status":       regexp.MustCompile(`^(awaiting_seller|under_review|resolved_buyer|resolved_seller|resolved_split|withdrawn|closed)$`),
		"subject_kind": regexp.MustCompile(`^(order|plugin_order|usage_statement|sla_breach)$`)})},
	"POST /v1/admin/market/disputes": {upstream: "/v1/disputes", access: accessPurchase, keyed: true},
}

// WithMember also serves the member routes through forwarder. version is this
// controller's release, used to filter the plugin catalogue by compatibility.
func (h *Handler) WithMember(forwarder Forwarder, version string) *Handler {
	if !versionArg.MatchString(version) || version == "development" {
		version = ""
	}
	for pattern, route := range memberRoutes {
		h.handle(pattern, route.access, h.forward(forwarder, route, version))
	}
	// The one binary member route: checked and re-served here (preview.go).
	return h.withPluginPreview(forwarder)
}

func (h *Handler) forward(forwarder Forwarder, route memberRoute, version string) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, _ Caller) {
		path := route.upstream
		if strings.Contains(path, "{id}") {
			id := r.PathValue("id")
			if !segmentPattern.MatchString(id) {
				writeError(w, http.StatusBadRequest, "invalid_id")
				return
			}
			path = strings.Replace(path, "{id}", id, 1)
		}
		query := url.Values{}
		allVersions := false
		for key, values := range r.URL.Query() {
			if route.compat && key == "all_versions" && len(values) == 1 && values[0] == "1" {
				allVersions = true
				continue
			}
			pattern := route.query[key]
			if pattern == nil || len(values) != 1 || len(values[0]) > 1024 || !pattern.MatchString(values[0]) {
				writeError(w, http.StatusBadRequest, "invalid_query")
				return
			}
			query.Set(key, values[0])
		}
		if route.compat && !allVersions && version != "" && query.Get("compat") == "" {
			query.Set("compat", version)
		}
		if len(query) > 0 {
			path += "?" + query.Encode()
		}
		key := ""
		if route.keyed {
			keys := r.Header.Values("Idempotency-Key")
			if len(keys) != 1 || !keyValue.MatchString(keys[0]) {
				writeError(w, http.StatusBadRequest, "idempotency_key_required")
				return
			}
			key = keys[0]
		}
		var body []byte
		if r.Method != http.MethodGet {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
			if err != nil || len(raw) > 0 && !json.Valid(raw) {
				writeError(w, http.StatusBadRequest, "invalid_body")
				return
			}
			body = raw
		}
		status, raw, err := forwarder.Forward(r.Context(), r.Method, path, key, body)
		if err != nil {
			writeError(w, http.StatusBadGateway, "market_unavailable")
			return
		}
		if (status == http.StatusNotFound || status == http.StatusMethodNotAllowed) && !json.Valid(raw) {
			// The market has not mounted this entry yet (a later market task).
			writeError(w, http.StatusNotImplemented, "market_feature_unavailable")
			return
		}
		if status == http.StatusUnauthorized || status >= 500 {
			// The market's view of our certificate must not log the admin out.
			status = http.StatusBadGateway
		}
		if len(raw) > 0 && !json.Valid(raw) {
			writeError(w, http.StatusBadGateway, "market_response_invalid")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = w.Write(raw)
	}
}

// MemberPatterns are the member and buyer routes, for mounting on a shared mux.
func MemberPatterns() []string {
	out := make([]string, 0, len(memberRoutes)+len(buyerPatterns))
	for pattern := range memberRoutes {
		out = append(out, pattern)
	}
	out = append(out, SupplyPatterns...)
	out = append(out, ListingPatterns...)
	return append(out, buyerPatterns...)
}
