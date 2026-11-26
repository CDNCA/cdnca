package httpapi

import (
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
)

func packageRuntimeError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, packageaddon.ErrQuotaExceeded):
		return http.StatusConflict, "package_resource_quota_exceeded", true
	case errors.Is(err, packageaddon.ErrFeatureDenied):
		return http.StatusForbidden, "package_feature_denied", true
	case errors.Is(err, packageaddon.ErrSubscriptionInactive):
		return http.StatusConflict, "package_subscription_inactive", true
	case errors.Is(err, packageaddon.ErrWAFInUse):
		return http.StatusConflict, "package_addon_waf_in_use", true
	case errors.Is(err, packageaddon.ErrInUse):
		return http.StatusConflict, "package_addon_in_use", true
	default:
		return 0, "", false
	}
}

// packageQuotaExceededDetails names the resource a package_resource_quota_exceeded
// refusal is for (sites, domains, root_domains or http_ports of a site write; stream_ports of a stream write): used is
// the subscription's usage before the change, requested what it would add.
type packageQuotaExceededDetails struct {
	Resource  string `json:"resource"`
	Limit     int64  `json:"limit"`
	Used      int64  `json:"used"`
	Requested int64  `json:"requested"`
}

// packageQuotaDetails is nil for a refusal that does not name its resource.
func packageQuotaDetails(err error) *packageQuotaExceededDetails {
	var refusal *packageaddon.QuotaExceededError
	if !errors.As(err, &refusal) {
		return nil
	}
	return &packageQuotaExceededDetails{Resource: refusal.Resource, Limit: refusal.Limit, Used: refusal.Used, Requested: refusal.Requested}
}
