package httpapi

import (
	"context"
	"net/http"
)

// runtimeFeaturesResponse is GET /v1/runtime-features: which optional runtimes
// this control plane mounted. Each flag is derived from the mounted handler,
// so a menu hidden by it is exactly a route set that would answer 404.
type runtimeFeaturesResponse struct {
	CacheControl   bool `json:"cache_control"`
	CustomRBAC     bool `json:"custom_rbac"`
	PluginWebhooks bool `json:"plugin_webhooks"`
	// ApprovalCenter: the platform approval center is turned on (settings in
	// 系统设置); its menu is hidden while it is off.
	ApprovalCenter bool `json:"approval_center"`
	// Market: node market and plugin store (menus hidden when off).
	Market bool `json:"market"`
	// PackageAutoRenew: always false in the community edition (no package
	// commerce); the field stays so the web client keeps its menu contract.
	PackageAutoRenew bool `json:"package_auto_renew"`
	// OriginAuth: origin authentication routes mounted (ORIGIN_AUTH_RUNTIME_ENABLED);
	// the /site/origin-auth/* menus are hidden while it is off.
	OriginAuth bool `json:"origin_auth"`
}

func (s *Server) runtimeFeatures(ctx context.Context) runtimeFeaturesResponse {
	return runtimeFeaturesResponse{
		CacheControl:   s.cacheControlHandler != nil,
		CustomRBAC:     s.customRBACHandler != nil,
		PluginWebhooks: s.pluginWebhookHandler != nil,
		ApprovalCenter: s.approvalCenterEnabled(ctx),
		Market:         s.marketRuntime && s.marketSubscribeHandler != nil,
		OriginAuth:     s.originAuthHandler != nil,
	}
}

func (s *Server) handleRuntimeFeatures(w http.ResponseWriter, r *http.Request) {
	if _, err := s.authenticatedSessionPrincipal(r); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]runtimeFeaturesResponse{"features": s.runtimeFeatures(r.Context())})
}
