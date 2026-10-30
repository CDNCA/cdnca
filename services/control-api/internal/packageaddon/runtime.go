package packageaddon

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrQuotaExceeded        = errors.New("package resource quota exceeded")
	ErrFeatureDenied        = errors.New("package feature is not available")
	ErrSubscriptionInactive = errors.New("package subscription is not active")
)

// RuntimeLimits is the current immutable base entitlement plus active addon
// snapshots. A numeric limit of -1 is unlimited. Catalog edits never change it.
type RuntimeLimits struct {
	OwnerUserID uuid.UUID `json:"-"`
	Domains     int64     `json:"domains"`
	RootDomains int64     `json:"root_domains"`
	HTTPPorts   int64     `json:"http_ports"`
	StreamPorts int64     `json:"stream_ports"`
	CustomCC    bool      `json:"custom_cc"`
	WAF         bool      `json:"waf"`
}

// LockRuntimeLimits serializes resource admissions with addon changes and
// subscription changes. Call it inside the resource mutation transaction, after
// acquiring the existing IAM scope locks and before counting resource usage.
func LockRuntimeLimits(ctx context.Context, tx pgx.Tx, tenantScopeID, subscriptionID uuid.UUID, at time.Time) (RuntimeLimits, error) {
	var limits RuntimeLimits
	if tenantScopeID == uuid.Nil || subscriptionID == uuid.Nil || at.IsZero() {
		return limits, ErrInvalid
	}
	// Lock first, then read in a new statement. Under READ COMMITTED a FOR UPDATE
	// that waited only re-evaluates the locked row; rows joined in the same
	// statement keep the pre-wait snapshot, so a concurrently committed
	// entitlement revocation would still read as active.
	var locked uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM package_subscriptions
		WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`, tenantScopeID, subscriptionID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return RuntimeLimits{}, ErrSubscriptionInactive
	}
	if err != nil {
		return RuntimeLimits{}, err
	}
	var lifecycle, entitlement string
	var startsAt, endsAt time.Time
	err = tx.QueryRow(ctx, `SELECT s.lifecycle_status,s.starts_at,s.ends_at,
		coalesce(e.entitlement_status,''),o.owner_user_id
		FROM package_subscriptions s
		JOIN package_subscription_state_versions o ON o.subscription_id=s.id
		  AND o.tenant_scope_id=s.tenant_scope_id AND o.revision=s.revision
		LEFT JOIN package_subscription_entitlement_versions e ON e.subscription_id=s.id
		  AND e.revision=package_subscription_effective_entitlement_revision(s.id,$3)
		WHERE s.tenant_scope_id=$1 AND s.id=$2`, tenantScopeID, subscriptionID, at).
		Scan(&lifecycle, &startsAt, &endsAt, &entitlement, &limits.OwnerUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return RuntimeLimits{}, ErrSubscriptionInactive
	}
	if err != nil {
		return RuntimeLimits{}, err
	}
	if lifecycle != "active" || entitlement != "active" || at.Before(startsAt) || !at.Before(endsAt) {
		return RuntimeLimits{}, ErrSubscriptionInactive
	}
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT package_addon_effective_limits($1,$2)`, subscriptionID, at).Scan(&raw); err != nil {
		return RuntimeLimits{}, err
	}
	if err := json.Unmarshal(raw, &limits); err != nil {
		return RuntimeLimits{}, ErrUnavailable
	}
	for _, count := range []int64{limits.Domains, limits.RootDomains, limits.HTTPPorts, limits.StreamPorts} {
		if count < -1 || count > 1_000_000_000 {
			return RuntimeLimits{}, ErrUnavailable
		}
	}
	return limits, nil
}
