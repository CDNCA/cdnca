// Package bridgeauth is the billing bridge credential (ADR 0019 §4.4 鉴权实现约束)
// that the facade (internal/billingbridge) hands to the package commerce,
// package subscription and identity authorization layers. A Grant is built
// only from a verified bridge key (billingbridge.Authenticator); session and
// API key requests never carry one. Each authorization layer re-checks, in
// its own transaction, that the key is still active and unexpired, that its
// owner is still valid and that module.billing.bridge is still licensed, and
// allows only the owner kind's fixed permission set.
package bridgeauth

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	CredentialKind = "bridge"
	OwnerPlatform  = "platform"
	OwnerReseller  = "reseller"

	PermissionResellerCustomersManage = "reseller.customers.manage"
	PermissionSubscriptionsManage     = "package_subscriptions.manage"
	PermissionBillingAdjustments      = "billing.adjustments.manage"
	PermissionIdentityUsersManage     = "identity.users.manage"
)

var (
	// ErrDenied: the key or its owner is no longer valid.
	ErrDenied = errors.New("billing bridge credential is no longer valid")
	// ErrNotLicensed: module.billing.bridge was revoked (entitlement_feature_denied).
	ErrNotLicensed = errors.New("billing bridge module is not licensed")
)

// LicensedTx reports, inside tx, whether module.billing.bridge is licensed.
type LicensedTx func(context.Context, pgx.Tx) (bool, error)

// Grant is one authenticated bridge call. Its fields are unexported so a
// Grant is only what NewGrant built.
type Grant struct {
	keyRowID     uuid.UUID
	keyID        string
	ownerScopeID uuid.UUID
	ownerKind    string
	actingUserID uuid.UUID
	licensed     LicensedTx
}

// NewGrant is called by the bridge facade after the signature, nonce, IP
// allowlist, key, owner and lease checks passed. actingUserID is the key's
// creator: business rows and audit events need a user, and the bridge acts
// for the owner who issued the key.
func NewGrant(keyRowID uuid.UUID, keyID string, ownerScopeID uuid.UUID, ownerKind string, actingUserID uuid.UUID,
	licensed LicensedTx,
) (*Grant, error) {
	grant := &Grant{keyRowID: keyRowID, keyID: keyID, ownerScopeID: ownerScopeID, ownerKind: ownerKind,
		actingUserID: actingUserID, licensed: licensed}
	if !grant.Valid() {
		return nil, ErrDenied
	}
	return grant, nil
}

func (g *Grant) Valid() bool {
	return g != nil && g.keyRowID != uuid.Nil && g.keyID != "" && g.ownerScopeID != uuid.Nil &&
		g.actingUserID != uuid.Nil && g.licensed != nil && (g.ownerKind == OwnerPlatform || g.ownerKind == OwnerReseller)
}

func (g *Grant) KeyID() string           { return g.keyID }
func (g *Grant) OwnerScopeID() uuid.UUID { return g.ownerScopeID }
func (g *Grant) OwnerKind() string       { return g.ownerKind }
func (g *Grant) ActingUserID() uuid.UUID { return g.actingUserID }
func (g *Grant) Platform() bool          { return g.Valid() && g.ownerKind == OwnerPlatform }
func (g *Grant) Reseller() bool          { return g.Valid() && g.ownerKind == OwnerReseller }
func (g *Grant) String() string          { return "bridgeauth.Grant{" + g.ownerKind + "}" }

// Allows reports whether permission is in the owner kind's fixed set:
// A (reseller) reseller.customers.manage; B (platform)
// package_subscriptions.manage, billing.adjustments.manage,
// identity.users.manage. Nothing else, ever.
func (g *Grant) Allows(permission string) bool {
	if !g.Valid() {
		return false
	}
	if g.ownerKind == OwnerReseller {
		return permission == PermissionResellerCustomersManage
	}
	switch permission {
	case PermissionSubscriptionsManage, PermissionBillingAdjustments, PermissionIdentityUsersManage:
		return true
	}
	return false
}

// verifyKeySQL locks the key row (a concurrent revoke waits for this
// transaction) and checks it is active, unexpired, still the same owner, and
// that the owner is valid: the platform scope, or an active reseller whose
// tenant is active (same rule as migration 556).
const verifyKeySQL = `
	SELECT k.status = 'active' AND (k.expires_at IS NULL OR k.expires_at > now())
	   AND k.owner_scope_id = $2 AND k.owner_kind = $3 AND k.key_id = $4 AND k.created_by = $5
	   AND CASE k.owner_kind
	       WHEN 'platform' THEN EXISTS (SELECT 1 FROM access_scopes WHERE id = k.owner_scope_id AND kind = 'platform')
	       ELSE reseller_scope_active_480(k.owner_scope_id) AND EXISTS (SELECT 1 FROM access_scopes scope
	            JOIN tenants tenant ON tenant.id = scope.tenant_id
	            WHERE scope.id = k.owner_scope_id AND scope.kind = 'tenant' AND tenant.status = 'active') END
	FROM billing_bridge_keys k WHERE k.id = $1 FOR SHARE OF k`

// VerifyTx re-checks the key, owner and lease inside tx.
func (g *Grant) VerifyTx(ctx context.Context, tx pgx.Tx) error {
	if !g.Valid() || tx == nil {
		return ErrDenied
	}
	var live bool
	err := tx.QueryRow(ctx, verifyKeySQL, g.keyRowID, g.ownerScopeID, g.ownerKind, g.keyID, g.actingUserID).Scan(&live)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !live {
		return ErrDenied
	}
	if err != nil {
		return err
	}
	licensed, err := g.licensed(ctx, tx)
	if err != nil {
		return err
	}
	if !licensed {
		return ErrNotLicensed
	}
	return nil
}

// DirectCustomerTx reports whether tenantScopeID is a platform direct
// customer (tenants.parent_scope_id IS NULL).
func DirectCustomerTx(ctx context.Context, tx pgx.Tx, tenantScopeID uuid.UUID) (bool, error) {
	var direct bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM access_scopes scope JOIN tenants tenant ON tenant.id = scope.tenant_id
		WHERE scope.id = $1 AND scope.kind = 'tenant' AND tenant.parent_scope_id IS NULL)`, tenantScopeID).Scan(&direct)
	return direct, err
}

// ResellerCustomerTx reports whether tenantScopeID is a customer of reseller.
func ResellerCustomerTx(ctx context.Context, tx pgx.Tx, reseller, tenantScopeID uuid.UUID) (bool, error) {
	var mine bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM access_scopes scope JOIN tenants tenant ON tenant.id = scope.tenant_id
		WHERE scope.id = $2 AND scope.kind = 'tenant' AND tenant.parent_scope_id = $1)`, reseller, tenantScopeID).Scan(&mine)
	return mine, err
}
