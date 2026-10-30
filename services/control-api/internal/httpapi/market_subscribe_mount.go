package httpapi

import (
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/marketsubscribehttp"
)

// mountMarketSubscribe exposes the node market subscriber API; the handler
// does its own platform-admin authorization.
func mountMarketSubscribe(mux *http.ServeMux, handler http.Handler) {
	for _, pattern := range append(append(append([]string{}, marketsubscribehttp.Patterns...), marketsubscribehttp.SiteRolloutPatterns...),
		marketsubscribehttp.MemberPatterns()...) {
		mux.Handle(pattern, handler)
	}
}
