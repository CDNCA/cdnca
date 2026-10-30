package acmehttp01

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeedge"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/jackc/pgx/v5"
)

type Authorizer struct {
	trust *entitlementguard.TrustStore
	clock func() time.Time
}

func NewAuthorizer(trust *entitlementguard.TrustStore, clock func() time.Time) (*Authorizer, error) {
	if trust == nil {
		return nil, ErrInvalidConfig
	}
	if clock == nil {
		clock = time.Now
	}
	return &Authorizer{trust: trust, clock: clock}, nil
}

func (a *Authorizer) AuthorizeOverlay(ctx context.Context, tx pgx.Tx, request acmeedge.EntitlementRequest) (acmeedge.EntitlementDecision, error) {
	if ctx == nil || tx == nil {
		return acmeedge.EntitlementDecision{}, ErrInvalidConfig
	}
	// cdncaCE: the community entitlement has no domain or node limit.
	return acmeedge.EntitlementDecision{LocallyVerified: true, Status: string(entitlement.StatusValid),
		EvaluatedAt: a.clock().UTC(), Allowed: true}, nil
}

func (a *Authorizer) authorizeLeaseOverlay(ctx context.Context, tx pgx.Tx, request acmeedge.EntitlementRequest) (acmeedge.EntitlementDecision, error) {
	if ctx == nil || tx == nil {
		return acmeedge.EntitlementDecision{}, ErrInvalidConfig
	}
	var installationID string
	var serial *int64
	var encoded []byte
	err := tx.QueryRow(ctx, `
		SELECT installation.installation_id,installation.current_serial,lease.signed_lease
		FROM control_installation_entitlement installation
		LEFT JOIN entitlement_cached_leases lease ON lease.serial=installation.current_serial
		WHERE installation.singleton=true
		FOR UPDATE OF installation`).Scan(&installationID, &serial, &encoded)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (serial == nil || len(encoded) == 0) {
		return acmeedge.EntitlementDecision{}, entitlementguard.ErrUnavailable
	}
	if err != nil {
		return acmeedge.EntitlementDecision{}, err
	}
	signed, err := entitlement.Decode(encoded)
	if err != nil {
		return acmeedge.EntitlementDecision{}, entitlementguard.ErrInvalid
	}
	evaluatedAt := a.clock().UTC()
	verified, err := a.trust.Verify(signed, entitlement.VerifyOptions{
		Now: evaluatedAt, ExpectedAudience: entitlement.ControlAudience,
		ExpectedInstallationID: installationID,
	})
	if err != nil {
		return acmeedge.EntitlementDecision{}, entitlementguard.ErrInvalid
	}
	decision := acmeedge.EntitlementDecision{
		LocallyVerified: true, InGrace: verified.Status == entitlement.StatusGrace,
		Status: string(verified.Status), LeaseSerial: verified.Lease.Serial, EvaluatedAt: evaluatedAt,
	}
	if verified.Status != entitlement.StatusValid && verified.Status != entitlement.StatusGrace ||
		!verified.Lease.HasFeature(entitlementguard.FeatureSitesManage) ||
		!verified.Lease.HasFeature(entitlementguard.FeatureNodesManage) {
		return decision, nil
	}
	domainLimit, hasDomains := verified.Lease.Quota(entitlementguard.QuotaDomainsCount)
	nodeLimit, hasNodes := verified.Lease.Quota(entitlementguard.QuotaNodesCount)
	if !hasDomains || !hasNodes {
		return decision, nil
	}
	var activeDomains, allocatedNodes int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sites WHERE deleted_at IS NULL AND enabled=true`).Scan(&activeDomains); err != nil {
		return acmeedge.EntitlementDecision{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM nodes WHERE admin_state <> 'retired'`).Scan(&allocatedNodes); err != nil {
		return acmeedge.EntitlementDecision{}, err
	}
	decision.Allowed = activeDomains <= domainLimit && allocatedNodes <= nodeLimit && int64(request.NodeCount) <= nodeLimit
	return decision, nil
}
