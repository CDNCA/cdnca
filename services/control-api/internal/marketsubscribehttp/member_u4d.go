package marketsubscribehttp

import "regexp"

// u4d (C22): subscription feedback tickets (market httpapi feedback.go). The
// buyer side needs purchase to write and browse to read; the seller side
// needs sell. Kept in its own file so member.go merges without conflicts.
func init() {
	states := map[string]*regexp.Regexp{"state": regexp.MustCompile(`^(open|in_progress|resolved|closed)$`),
		"subscription": regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)}
	for pattern, route := range map[string]memberRoute{
		"POST /v1/admin/market/subscriptions/{id}/feedback":   {upstream: "/v1/subscriptions/{id}/feedback", access: accessPurchase, keyed: true},
		"GET /v1/admin/market/buyer/feedback":                 {upstream: "/v1/buyer/feedback", access: accessBrowse, query: with(page, states)},
		"GET /v1/admin/market/buyer/feedback/{id}":            {upstream: "/v1/buyer/feedback/{id}", access: accessBrowse},
		"POST /v1/admin/market/buyer/feedback/{id}/messages":  {upstream: "/v1/buyer/feedback/{id}/messages", access: accessPurchase, keyed: true},
		"POST /v1/admin/market/buyer/feedback/{id}/escalate":  {upstream: "/v1/buyer/feedback/{id}/escalate", access: accessPurchase, keyed: true},
		"GET /v1/admin/market/seller/feedback":                {upstream: "/v1/seller/feedback", access: accessSell, query: with(page, states)},
		"GET /v1/admin/market/seller/feedback/{id}":           {upstream: "/v1/seller/feedback/{id}", access: accessSell},
		"POST /v1/admin/market/seller/feedback/{id}/messages": {upstream: "/v1/seller/feedback/{id}/messages", access: accessSell, keyed: true},
	} {
		if _, exists := memberRoutes[pattern]; exists {
			panic("marketsubscribehttp: duplicate member route " + pattern)
		}
		memberRoutes[pattern] = route
	}
}
