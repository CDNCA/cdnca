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
