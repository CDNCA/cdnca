package site

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func checkPackageSiteChange(ctx context.Context, tx pgx.Tx, scopeID, ownerID, siteID uuid.UUID, fields SiteFields, at time.Time) error {
	if fields.PackageSubscriptionID == nil {
		return nil
	}
	limits, err := packageaddon.LockRuntimeLimits(ctx, tx, scopeID, *fields.PackageSubscriptionID, at)
	if err != nil {
		return err
	}
	if limits.OwnerUserID != ownerID {
		return ErrPermissionDenied
	}
	if err := packageaddon.CheckSiteSecurityUsage(ctx, tx, scopeID, siteID, limits); err != nil {
		return err
	}
	ports := make([]int64, 0, len(fields.HTTPPorts)+len(fields.HTTPSPorts))
	for _, values := range [][]string{fields.HTTPPorts, fields.HTTPSPorts} {
		for _, value := range values {
			port, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return ErrInvalidInput
			}
			ports = append(ports, port)
		}
	}
	return packageaddon.CheckSiteChange(ctx, tx, scopeID, *fields.PackageSubscriptionID, siteID, fields.Domains, ports, at)
}

// packageContraction reports a write that leaves the site disabled, keeps its
// subscription binding and adds no domain or port. Such a write takes nothing
// from the package, so an expired or suspended subscription must not block it
// (PJ-C01: taking a site offline is a safe exit, not an expansion).
func packageContraction(current, proposed SiteFields) bool {
	if proposed.Enabled || !sameSubscription(current.PackageSubscriptionID, proposed.PackageSubscriptionID) {
		return false
	}
	return len(addedDomains(current.Domains, proposed.Domains)) == 0 &&
		len(addedDomains(current.HTTPPorts, proposed.HTTPPorts)) == 0 &&
		len(addedDomains(current.HTTPSPorts, proposed.HTTPSPorts)) == 0
}

func sameSubscription(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

// batchPackageFailure maps a package admission refusal to a batch item code;
// ok=false means the error is not a per-item refusal and aborts the batch.
func batchPackageFailure(err error) (string, bool) {
	switch {
	case errors.Is(err, packageaddon.ErrSubscriptionInactive):
		return "package_subscription_inactive", true
	case errors.Is(err, packageaddon.ErrQuotaExceeded):
		return "package_resource_quota_exceeded", true
	case errors.Is(err, packageaddon.ErrFeatureDenied):
		return "package_feature_denied", true
	case errors.Is(err, ErrPermissionDenied):
		return "permission_denied", true
	default:
		return "", false
	}
}

// Omitting a binding on an ordinary edit preserves the current subscription.
// A replacement must identify its product or subscription explicitly.
func preservePackageBinding(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, fields *SiteFields) (uuid.UUID, error) {
	var ownerID uuid.UUID
	var subscriptionID, productID *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT owner_user_id,package_subscription_id,package_id FROM sites WHERE scope_id=$1 AND id=$2`, scopeID, siteID).Scan(&ownerID, &subscriptionID, &productID)
	if err == nil && fields.PackageSubscriptionID == nil && fields.PackageID == nil {
		fields.PackageSubscriptionID, fields.PackageID = subscriptionID, productID
	}
	return ownerID, err
}
