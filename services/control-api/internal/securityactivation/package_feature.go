package securityactivation

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// checkBindingPackageFeature checks the package grants the library the
// candidate claims (bundleID's publication: another library after a rebind,
// sec-rebind). A detach withdraws the feature and needs no grant.
func checkBindingPackageFeature(ctx context.Context, tx pgx.Tx, scopeID, siteID, bindingID, bundleID uuid.UUID, version int64, at time.Time) error {
	var policyID uuid.UUID
	var detach bool
	if err := tx.QueryRow(ctx, `SELECT publication.policy_id,publication.detach FROM security_policy_publications publication
		JOIN security_policy_site_bindings binding ON binding.id=publication.binding_id
		WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2 AND binding.id=$3 AND publication.id=$4`,
		scopeID, siteID, bindingID, bundleID).Scan(&policyID, &detach); err != nil {
		return err
	}
	if detach {
		return nil
	}
	policy, err := loadPolicyVersion(ctx, tx, scopeID, policyID, version)
	if err != nil {
		return err
	}
	return securitybinding.CheckSitePolicyFeature(ctx, tx, scopeID, siteID, policy, at)
}
