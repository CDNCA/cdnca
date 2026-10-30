package marketsubscribehttp

var memberRoutes = map[string]memberRoute{
	"GET /v1/admin/market/member": {upstream: "/v1/members/me", access: accessBrowse},
}
