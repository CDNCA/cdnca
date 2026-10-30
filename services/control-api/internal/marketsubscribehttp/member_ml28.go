package marketsubscribehttp

import "regexp"

// ADR 0012 ML-28 pages need two market member surfaces no relay row carried
// yet: same-site automatic pauses (ML-24, market httpapi nodeactions.go) and
// the direct-settlement commission prepaid account (ML-27, market httpapi
// commission_prepaid.go). Kept in its own file so the ML-16/17/31 rows in
// member.go merge without conflicts. Top-ups use POST /v1/admin/market/orders
// with kind=commission_topup.
func init() {
	rfc3339 := regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$`)
	for pattern, route := range map[string]memberRoute{
		// Owner (purchase side) and suppliers on the path both read; the market
		// lets only a supplier that switched site_auto_pause on resume.
		"GET /v1/admin/market/site-pauses": {upstream: "/v1/site-pauses", access: accessBrowse,
			query: map[string]*regexp.Regexp{"open": regexp.MustCompile(`^(true|false)$`)}},
		"POST /v1/admin/market/site-pauses/{id}/resume": {upstream: "/v1/site-pauses/{id}/resume", access: accessSell},

		"GET /v1/admin/market/commission/prepaid": {upstream: "/v1/commission/prepaid", access: accessSell,
			query: map[string]*regexp.Regexp{"currency": currency}},
		"PUT /v1/admin/market/commission/prepaid":       {upstream: "/v1/commission/prepaid", access: accessSell},
		"PUT /v1/admin/market/commission/prepaid/alert": {upstream: "/v1/commission/prepaid/alert", access: accessSell},
		"GET /v1/admin/market/commission/prepaid/deductions": {upstream: "/v1/commission/prepaid/deductions", access: accessSell,
			query: map[string]*regexp.Regexp{"from": rfc3339, "to": rfc3339, "cursor": cursorValue, "limit": limitValue}},
	} {
		if _, exists := memberRoutes[pattern]; exists {
			panic("marketsubscribehttp: duplicate member route " + pattern)
		}
		memberRoutes[pattern] = route
	}
}
