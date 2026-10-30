package entitlementguard

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Guard struct {
	auditor *audit.Log
	trust   *TrustStore
	now     func() time.Time
}

type resourceCheck struct {
	AuditScopeID uuid.UUID
	ActorUserID  uuid.UUID
	ResourceID   uuid.UUID
	RequestID    string
	Operation    string
	ResourceType string
	Feature      string
	Quota        string
	Delta        int64
	Count        func(context.Context, pgx.Tx) (int64, error)
}

func NewGuard(pool *pgxpool.Pool, now func() time.Time, trust *TrustStore) *Guard {
	if now == nil {
		now = time.Now
	}
	return &Guard{auditor: audit.New(pool), trust: trust, now: now}
}

// leaseUsable is the single rule for create/publish/feature checks: a lease in
// grace keeps the control plane fully usable while the license service is
// unreachable; expired, revoked, not-yet-valid and
// missing leases are denied. Control upgrades (ReadValidVersion) still require
// a valid lease.
func leaseUsable(status entitlement.Status) bool {
	return status == entitlement.StatusValid || status == entitlement.StatusGrace
}

func (g *Guard) ReadValidVersion(ctx context.Context, tx pgx.Tx) (VersionGrant, error) {
	var installationID string
	var serial *int64
	var encodedLease []byte
	var cachedStatus *string
	err := tx.QueryRow(ctx, `
		SELECT installation.installation_id, installation.current_serial, lease.signed_lease, lease.status
		FROM control_installation_entitlement installation
		LEFT JOIN entitlement_cached_leases lease ON lease.serial = installation.current_serial
		WHERE installation.singleton = true`,
	).Scan(&installationID, &serial, &encodedLease, &cachedStatus)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (serial == nil || len(encodedLease) == 0 || g.trust == nil)) {
		return VersionGrant{}, ErrUnavailable
	}
	if err != nil {
		return VersionGrant{}, err
	}
	signed, err := entitlement.Decode(encodedLease)
	if err != nil {
		return VersionGrant{}, ErrInvalid
	}
	verified, err := g.trust.Verify(signed, entitlement.VerifyOptions{
		Now:                    g.now(),
		ExpectedAudience:       entitlement.ControlAudience,
		ExpectedInstallationID: installationID,
	})
	if err != nil || verified.Lease.Serial != uint64(*serial) {
		return VersionGrant{}, ErrInvalid
	}
	grant := VersionGrant{
		Serial:     verified.Lease.Serial,
		Channel:    verified.Lease.Version.Channel,
		MinVersion: verified.Lease.Version.Min,
		MaxVersion: verified.Lease.Version.Max,
	}
	if cachedStatus != nil && *cachedStatus == string(entitlement.StatusRevoked) {
		return grant, ErrStateDenied
	}
	// B17: same revocation LKG as CheckFeature and the installation lock; a
	// serial named by the accepted list is revoked, a missing or invalid list
	// cannot prove it is not.
	revocation, err := loadRevocationLKGTx(ctx, tx, g.trust, g.now().UTC(),
		verified.Lease.CustomerID, installationID, verified.Lease.LicenseID)
	if errors.Is(err, ErrRevocationUnavailable) {
		return grant, ErrUnavailable
	}
	if errors.Is(err, ErrRevocationInvalid) || errors.Is(err, ErrRevocationExpired) {
		return grant, ErrInvalid
	}
	if err != nil {
		return VersionGrant{}, err
	}
	verified, err = g.trust.Verify(signed, entitlement.VerifyOptions{
		Now: g.now(), ExpectedAudience: entitlement.ControlAudience,
		ExpectedInstallationID: installationID, RevokedSerials: revocation.RevokedSerials,
	})
	if err != nil {
		return grant, ErrInvalid
	}
	if verified.Status != entitlement.StatusValid {
		return grant, ErrStateDenied
	}
	return grant, nil
}

// ReadValidFeatures returns the feature codes of the installation's current
// lease when it verifies through the trust chain and is valid or in grace now.
// Any other state (no lease, invalid, expired, revoked) grants nothing: callers that
// recheck what the license service delivered (artifactsync) treat it as "no
// paid feature", never as an error that keeps a previous grant.
func (g *Guard) ReadValidFeatures(ctx context.Context, tx pgx.Tx) (map[string]bool, error) {
	if tx == nil {
		return communityFeatures(), nil
	}
	return communityFeaturesWithPurchases(ctx, tx, g.now())
}

func (g *Guard) readValidLeaseFeatures(ctx context.Context, tx pgx.Tx) (map[string]bool, error) {
	features := map[string]bool{}
	var installationID string
	var serial *int64
	var encodedLease []byte
	var cachedStatus *string
	err := tx.QueryRow(ctx, `
		SELECT installation.installation_id, installation.current_serial, lease.signed_lease, lease.status
		FROM control_installation_entitlement installation
		LEFT JOIN entitlement_cached_leases lease ON lease.serial = installation.current_serial
		WHERE installation.singleton = true`,
	).Scan(&installationID, &serial, &encodedLease, &cachedStatus)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (serial == nil || len(encodedLease) == 0 || g.trust == nil) {
		return features, nil
	}
	if err != nil {
		return nil, err
	}
	signed, err := entitlement.Decode(encodedLease)
	if err != nil {
		return features, nil
	}
	verified, err := g.trust.Verify(signed, entitlement.VerifyOptions{
		Now: g.now(), ExpectedAudience: entitlement.ControlAudience, ExpectedInstallationID: installationID,
	})
	if err != nil || !leaseUsable(verified.Status) || verified.Lease.Serial != uint64(*serial) ||
		cachedStatus != nil && *cachedStatus == string(entitlement.StatusRevoked) {
		return features, nil
	}
	// Same revocation check as CheckFeature: a missing or invalid revocation
	// list, or a revoked serial, grants nothing.
	revocation, err := loadRevocationLKGTx(ctx, tx, g.trust, g.now().UTC(),
		verified.Lease.CustomerID, installationID, verified.Lease.LicenseID)
	if err != nil {
		return features, nil
	}
	verified, err = g.trust.Verify(signed, entitlement.VerifyOptions{
		Now: g.now(), ExpectedAudience: entitlement.ControlAudience, ExpectedInstallationID: installationID,
		RevokedSerials: revocation.RevokedSerials,
	})
	if err != nil || !leaseUsable(verified.Status) {
		return features, nil
	}
	for _, feature := range verified.Lease.Features {
		features[feature.Code] = true
	}
	return features, nil
}

func (g *Guard) CheckSiteChange(ctx context.Context, tx pgx.Tx, check SiteCheck) error {
	delta := check.ExpansionDelta
	if delta == 0 {
		delta = check.Delta
	}
	if delta < 0 || delta > 100 {
		return fmt.Errorf("invalid site entitlement delta")
	}
	return g.check(ctx, tx, resourceCheck{
		AuditScopeID: check.AuditScopeID,
		ActorUserID:  check.ActorUserID,
		ResourceID:   check.ResourceID,
		RequestID:    check.RequestID,
		Operation:    check.Operation,
		ResourceType: "site",
		Feature:      FeatureSitesManage,
		Quota:        QuotaDomainsCount,
		Delta:        delta,
		Count:        activeDomainCount,
	})
}

func (g *Guard) CheckNodeCreate(ctx context.Context, tx pgx.Tx, check NodeCheck) error {
	return g.check(ctx, tx, resourceCheck{
		AuditScopeID: check.AuditScopeID,
		ActorUserID:  check.ActorUserID,
		ResourceID:   check.ResourceID,
		RequestID:    check.RequestID,
		Operation:    check.Operation,
		ResourceType: "node",
		Feature:      FeatureNodesManage,
		Quota:        QuotaNodesCount,
		Delta:        1,
		Count:        allocatedNodeCount,
	})
}

func (g *Guard) CheckFeature(ctx context.Context, tx pgx.Tx, check FeatureCheck) (FeatureDecision, error) {
	return g.checkFeature(ctx, tx, check, true)
}

// CheckBuiltInNodeMonitoring uses the same locked, signed lease and revocation
// checks as paid features, but monitoring is included in every valid license.
func (g *Guard) CheckBuiltInNodeMonitoring(ctx context.Context, tx pgx.Tx, check BuiltInNodeMonitoringCheck) (FeatureDecision, error) {
	return g.checkFeature(ctx, tx, FeatureCheck{
		TargetScopeID: check.TargetScopeID,
		ActorScopeID:  check.ActorScopeID,
		ActorUserID:   check.ActorUserID,
		ResourceType:  check.ResourceType,
		ResourceID:    check.ResourceID,
		RequestID:     check.RequestID,
		Operation:     check.Operation,
		Feature:       "builtin.node_monitoring",
	}, false)
}

func (g *Guard) checkFeature(ctx context.Context, tx pgx.Tx, check FeatureCheck, requireFeature bool) (FeatureDecision, error) {
	if tx == nil || check.TargetScopeID == uuid.Nil || check.ActorScopeID == uuid.Nil ||
		check.ActorUserID == uuid.Nil || check.ResourceID == uuid.Nil || check.ResourceType == "" ||
		check.RequestID == "" || check.Operation == "" || check.Feature == "" {
		return FeatureDecision{}, fmt.Errorf("entitlement feature check is invalid")
	}
	if (check.Quota == "") != (check.Count == nil) {
		return FeatureDecision{}, fmt.Errorf("entitlement quota and Count must be configured together")
	}
	if !requireFeature {
		check.Feature = ""
	}
	return g.communityFeatureDecision(ctx, tx, check)
}

func (g *Guard) checkLeaseFeature(ctx context.Context, tx pgx.Tx, check FeatureCheck, requireFeature bool) (FeatureDecision, error) {
	if (check.Quota == "") != (check.Count == nil) {
		return FeatureDecision{}, fmt.Errorf("entitlement quota and Count must be configured together")
	}
	decision := FeatureDecision{
		TargetScopeID: check.TargetScopeID,
		ActorScopeID:  check.ActorScopeID,
		ActorUserID:   check.ActorUserID,
		ResourceType:  check.ResourceType,
		ResourceID:    check.ResourceID,
		RequestID:     check.RequestID,
		Operation:     check.Operation,
		Feature:       check.Feature,
		Quota:         check.Quota,
	}
	if check.Quota != "" {
		decision.Limit = -1
	}

	var installationID string
	var serial *int64
	var encodedLease []byte
	var cachedStatus *string
	err := tx.QueryRow(ctx, `
		SELECT installation.installation_id, installation.current_serial,
		       lease.signed_lease, lease.status
		FROM control_installation_entitlement installation
		LEFT JOIN entitlement_cached_leases lease ON lease.serial = installation.current_serial
		WHERE installation.singleton = true
		FOR UPDATE OF installation`,
	).Scan(&installationID, &serial, &encodedLease, &cachedStatus)
	evaluatedAt := g.now().UTC()
	decision.EvaluatedAt = evaluatedAt
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (serial == nil || len(encodedLease) == 0)) {
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, ErrUnavailable, StatusUninstalled, "lease_unavailable")
	}
	if err != nil {
		return FeatureDecision{}, err
	}
	decision.LeaseSerial = uint64(*serial)
	decision.LeaseSHA256 = sha256.Sum256(encodedLease)
	if g.trust == nil {
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, ErrUnavailable, StatusInvalid, "trust_anchor_unavailable")
	}

	signed, err := entitlement.Decode(encodedLease)
	if err != nil {
		if updateErr := updateValidationState(ctx, tx, StatusInvalid, "invalid_envelope", evaluatedAt); updateErr != nil {
			return FeatureDecision{}, updateErr
		}
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, ErrInvalid, StatusInvalid, "invalid_envelope")
	}
	verified, err := g.trust.Verify(signed, entitlement.VerifyOptions{
		Now:                    evaluatedAt,
		ExpectedAudience:       entitlement.ControlAudience,
		ExpectedInstallationID: installationID,
	})
	if err != nil {
		code := verificationErrorCode(err)
		if updateErr := updateValidationState(ctx, tx, StatusInvalid, code, evaluatedAt); updateErr != nil {
			return FeatureDecision{}, updateErr
		}
		denial := ErrInvalid
		status := StatusInvalid
		if errors.Is(err, entitlement.ErrNotYetValid) {
			denial = ErrStateDenied
			status = "not_yet_valid"
		}
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, denial, status, code)
	}
	if verified.Lease.Serial != uint64(*serial) {
		if updateErr := updateValidationState(ctx, tx, StatusInvalid, "lease_serial_mismatch", evaluatedAt); updateErr != nil {
			return FeatureDecision{}, updateErr
		}
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, ErrInvalid, StatusInvalid, "lease_serial_mismatch")
	}
	decision.LeaseSerial = verified.Lease.Serial
	decision.NotBefore = time.Unix(verified.Lease.NotBefore, 0).UTC()
	decision.ExpiresAt = time.Unix(verified.Lease.ExpiresAt, 0).UTC()
	decision.GraceUntil = time.Unix(verified.Lease.GraceUntil, 0).UTC()
	// A stale revocation list is kept as last-known-good (user decision
	// 2026-10-21); the lease grace window below bounds how long it is used.
	revocation, revocationErr := loadRevocationLKGTx(ctx, tx, g.trust, evaluatedAt,
		verified.Lease.CustomerID, installationID, verified.Lease.LicenseID)
	if revocationErr != nil {
		denial, reason := revocationDenial(revocationErr)
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, denial, string(verified.Status), reason)
	}
	decision.RevocationRevision = revocation.Revision
	decision.RevocationSHA256 = revocation.ArtifactSHA256
	decision.RevocationKeyID = revocation.KeyID
	decision.RevocationIssuedAt = revocation.IssuedAt
	decision.RevocationExpiresAt = revocation.ExpiresAt
	verified, err = g.trust.Verify(signed, entitlement.VerifyOptions{
		Now: evaluatedAt, ExpectedAudience: entitlement.ControlAudience,
		ExpectedInstallationID: installationID, RevokedSerials: revocation.RevokedSerials,
	})
	if err != nil {
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, ErrRevocationInvalid,
			StatusInvalid, "revocation_state_invalid")
	}

	status := verified.Status
	if cachedStatus != nil && *cachedStatus == string(entitlement.StatusRevoked) {
		status = entitlement.StatusRevoked
	}
	if err := updateValidationState(ctx, tx, string(status), "", evaluatedAt); err != nil {
		return FeatureDecision{}, err
	}
	if !leaseUsable(status) {
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, ErrStateDenied, string(status), "lease_"+string(status))
	}
	if requireFeature && !verified.Lease.HasFeature(check.Feature) {
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, ErrFeatureDenied, string(status), "feature_missing")
	}
	if check.Quota == "" {
		return decision, nil
	}
	limit, found := verified.Lease.Quota(check.Quota)
	if !found {
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, ErrQuotaDenied, string(status), "quota_missing")
	}
	decision.Limit = limit
	if check.Count != nil {
		current, countErr := check.Count(ctx, tx)
		if countErr != nil {
			return FeatureDecision{}, countErr
		}
		if current < 0 {
			return FeatureDecision{}, fmt.Errorf("entitlement quota count must not be negative")
		}
		decision.Current = current
	}
	if limit == 0 || decision.Current >= limit {
		return FeatureDecision{}, g.denyFeature(ctx, tx, decision, ErrQuotaExceeded, string(status), "quota_exceeded")
	}
	return decision, nil
}

func (g *Guard) check(ctx context.Context, tx pgx.Tx, check resourceCheck) error {
	// cdncaCE: unlimited community quotas; base features are always granted.
	return nil
}

func (g *Guard) checkLease(ctx context.Context, tx pgx.Tx, check resourceCheck) error {

	var installationID string
	var serial *int64
	var encodedLease []byte
	var cachedStatus *string
	err := tx.QueryRow(ctx, `
		SELECT installation.installation_id, installation.current_serial, lease.signed_lease, lease.status
		FROM control_installation_entitlement installation
		LEFT JOIN entitlement_cached_leases lease ON lease.serial = installation.current_serial
		WHERE installation.singleton = true
		FOR UPDATE OF installation`,
	).Scan(&installationID, &serial, &encodedLease, &cachedStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		current, countErr := check.Count(ctx, tx)
		if countErr != nil {
			return countErr
		}
		return g.deny(ctx, tx, check, ErrUnavailable, StatusUninstalled, 0, current, -1, "lease_unavailable")
	}
	if err != nil {
		return err
	}
	// The singleton row serializes global quota changes. Count only after the
	// lock is acquired so a waiter observes sites committed by the lock holder.
	current, err := check.Count(ctx, tx)
	if err != nil {
		return err
	}
	if serial == nil || len(encodedLease) == 0 {
		return g.deny(ctx, tx, check, ErrUnavailable, StatusUninstalled, 0, current, -1, "lease_unavailable")
	}
	if g.trust == nil {
		return g.deny(ctx, tx, check, ErrUnavailable, StatusInvalid, uint64(*serial), current, -1, "trust_anchor_unavailable")
	}
	checkedAt := g.now()

	signed, err := entitlement.Decode(encodedLease)
	if err != nil {
		if updateErr := updateValidationState(ctx, tx, StatusInvalid, "invalid_envelope", checkedAt); updateErr != nil {
			return updateErr
		}
		return g.deny(ctx, tx, check, ErrUnavailable, StatusInvalid, uint64(*serial), current, -1, "invalid_envelope")
	}
	verified, err := g.trust.Verify(signed, entitlement.VerifyOptions{
		Now:                    checkedAt,
		ExpectedAudience:       entitlement.ControlAudience,
		ExpectedInstallationID: installationID,
	})
	if err != nil {
		code := verificationErrorCode(err)
		if updateErr := updateValidationState(ctx, tx, StatusInvalid, code, checkedAt); updateErr != nil {
			return updateErr
		}
		return g.deny(ctx, tx, check, ErrUnavailable, StatusInvalid, uint64(*serial), current, -1, code)
	}
	// A serial marked revoked by an accepted revocation list is denied like in
	// checkFeature, even when its time window alone would be valid or grace.
	if cachedStatus != nil && *cachedStatus == string(entitlement.StatusRevoked) {
		verified.Status = entitlement.StatusRevoked
	}
	if err := updateValidationState(ctx, tx, string(verified.Status), "", checkedAt); err != nil {
		return err
	}
	if !leaseUsable(verified.Status) {
		return g.deny(ctx, tx, check, ErrStateDenied, string(verified.Status), verified.Lease.Serial, current, quotaLimit(verified.Lease, check.Quota), "lease_"+string(verified.Status))
	}
	if !verified.Lease.HasFeature(check.Feature) {
		return g.deny(ctx, tx, check, ErrFeatureDenied, string(verified.Status), verified.Lease.Serial, current, quotaLimit(verified.Lease, check.Quota), "feature_missing")
	}
	limit, found := verified.Lease.Quota(check.Quota)
	if !found {
		return g.deny(ctx, tx, check, ErrQuotaDenied, string(verified.Status), verified.Lease.Serial, current, -1, "quota_missing")
	}
	// Only an operation that adds usage can exceed the quota. Editing a site
	// that already exists (Delta 0) stays allowed after the lease quota is
	// lowered below the current usage; lease state and feature still apply.
	if check.Delta > 0 && current+check.Delta > limit {
		return g.deny(ctx, tx, check, ErrQuotaExceeded, string(verified.Status), verified.Lease.Serial, current, limit, "quota_exceeded")
	}
	return nil
}

func (g *Guard) deny(
	ctx context.Context,
	tx pgx.Tx,
	check resourceCheck,
	denial error,
	status string,
	serial uint64,
	current int64,
	limit int64,
	reason string,
) error {
	if err := g.auditor.Append(ctx, tx, audit.Event{
		ScopeID:      check.AuditScopeID,
		ActorUserID:  &check.ActorUserID,
		Action:       "entitlement.guard.reject",
		ResourceType: check.ResourceType,
		ResourceID:   check.ResourceID.String(),
		RequestID:    check.RequestID,
		Result:       "denied",
		Payload: map[string]any{
			"operation":    check.Operation,
			"request_id":   check.RequestID,
			"lease_serial": serial,
			"state":        status,
			"feature":      check.Feature,
			"quota":        check.Quota,
			"current":      current,
			"limit":        limit,
			"reason":       reason,
		},
	}); err != nil {
		return err
	}
	return denial
}

func (g *Guard) denyFeature(
	ctx context.Context,
	tx pgx.Tx,
	decision FeatureDecision,
	denial error,
	status string,
	reason string,
) error {
	leaseSHA256 := ""
	if decision.LeaseSHA256 != ([32]byte{}) {
		leaseSHA256 = fmt.Sprintf("%x", decision.LeaseSHA256)
	}
	revocationSHA256 := ""
	if decision.RevocationSHA256 != ([32]byte{}) {
		revocationSHA256 = fmt.Sprintf("%x", decision.RevocationSHA256)
	}
	if err := g.auditor.Append(ctx, tx, audit.Event{
		ScopeID:      decision.TargetScopeID,
		ActorUserID:  &decision.ActorUserID,
		Action:       "entitlement.guard.reject",
		ResourceType: decision.ResourceType,
		ResourceID:   decision.ResourceID.String(),
		RequestID:    decision.RequestID,
		Result:       "denied",
		Payload: map[string]any{
			"target_scope_id":       decision.TargetScopeID.String(),
			"actor_scope_id":        decision.ActorScopeID.String(),
			"actor_user_id":         decision.ActorUserID.String(),
			"operation":             decision.Operation,
			"request_id":            decision.RequestID,
			"lease_serial":          decision.LeaseSerial,
			"lease_sha256":          leaseSHA256,
			"revocation_revision":   decision.RevocationRevision,
			"revocation_sha256":     revocationSHA256,
			"revocation_key_id":     decision.RevocationKeyID,
			"revocation_issued_at":  featureDecisionTime(decision.RevocationIssuedAt),
			"revocation_expires_at": featureDecisionTime(decision.RevocationExpiresAt),
			"state":                 status,
			"feature":               decision.Feature,
			"quota":                 decision.Quota,
			"current":               decision.Current,
			"limit":                 decision.Limit,
			"evaluated_at":          decision.EvaluatedAt.Format(time.RFC3339Nano),
			"not_before":            featureDecisionTime(decision.NotBefore),
			"expires_at":            featureDecisionTime(decision.ExpiresAt),
			"grace_until":           featureDecisionTime(decision.GraceUntil),
			"reason":                reason,
		},
	}); err != nil {
		return err
	}
	return denial
}

func revocationDenial(err error) (error, string) {
	switch {
	case errors.Is(err, ErrRevocationUnavailable):
		return ErrRevocationUnavailable, "revocation_state_unavailable"
	case errors.Is(err, ErrRevocationExpired):
		return ErrRevocationExpired, "revocation_state_expired"
	default:
		return ErrRevocationInvalid, "revocation_state_invalid"
	}
}

func featureDecisionTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

// activeDomainCount counts active domains across every tenant: the lease is
// issued to the whole control installation, so domains.count is one global
// budget (docs/runbooks/control-entitlement.md). Counting only the target
// scope would let each tenant consume the full licensed quota on its own.
// Callers hold the singleton installation row lock, so concurrent creates in
// different tenants serialize on this count.
func activeDomainCount(ctx context.Context, tx pgx.Tx) (int64, error) {
	var current int64
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM (
			SELECT DISTINCT ON (fact.site_id,fact.canonical_domain)
				fact.scope_id,fact.site_id,fact.action
			FROM site_domain_facts fact
			ORDER BY fact.site_id,fact.canonical_domain,fact.global_sequence DESC
		) current_domain
		JOIN sites site ON site.scope_id=current_domain.scope_id AND site.id=current_domain.site_id
		WHERE current_domain.action='activate'
		  AND site.deleted_at IS NULL AND site.enabled=true`,
	).Scan(&current); err != nil {
		return 0, err
	}
	return current, nil
}

func allocatedNodeCount(ctx context.Context, tx pgx.Tx) (int64, error) {
	var current int64
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM nodes
		JOIN access_scopes ON access_scopes.id = nodes.scope_id
		WHERE access_scopes.kind = 'platform' AND nodes.admin_state <> 'retired'`,
	).Scan(&current); err != nil {
		return 0, err
	}
	return current, nil
}

func updateValidationState(ctx context.Context, tx pgx.Tx, status, errorCode string, now time.Time) error {
	var errorValue any
	if errorCode != "" {
		errorValue = errorCode
	}
	_, err := tx.Exec(ctx, `
		UPDATE control_installation_entitlement
		SET last_status = $1, last_error_code = $2, last_verified_at = $3, updated_at = $3
		WHERE singleton = true`, status, errorValue, now.UTC())
	return err
}

func verificationErrorCode(err error) string {
	switch {
	case errors.Is(err, entitlement.ErrUnknownKey):
		return "unknown_key"
	case errors.Is(err, entitlement.ErrInvalidSignature):
		return "invalid_signature"
	case errors.Is(err, entitlement.ErrAudienceMismatch):
		return "audience_mismatch"
	case errors.Is(err, entitlement.ErrInstallationMismatch):
		return "installation_mismatch"
	case errors.Is(err, entitlement.ErrNotYetValid):
		return "not_yet_valid"
	case errors.Is(err, ErrKeyOutsideWindow):
		return "signing_key_outside_window"
	case errors.Is(err, ErrSignerRevoked):
		return "signer_revoked"
	default:
		return "verification_failed"
	}
}

func quotaLimit(lease entitlement.Lease, quota string) int64 {
	limit, found := lease.Quota(quota)
	if !found {
		return -1
	}
	return limit
}
