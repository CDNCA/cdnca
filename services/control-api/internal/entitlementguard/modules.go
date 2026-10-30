package entitlementguard

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ModulesChangedAction is written whenever an installed lease grants a
// different set of module/pack/theme codes than the one it replaces.
const ModulesChangedAction = "system.entitlement_modules.change"

// ModuleGrants is the module, pack and theme codes the verified local lease
// grants right now. Codes is empty unless Status is valid: CheckFeature
// denies every non-valid state (grace included), and the menu, API entry and
// publication gate must agree with it.
type ModuleGrants struct {
	Status      string
	LeaseSerial uint64
	Codes       []string
}

func (grants ModuleGrants) Has(code string) bool {
	return slices.Contains(grants.Codes, code)
}

// ModuleCheck is CheckFeature restricted to module feature codes.
type ModuleCheck struct {
	TargetScopeID uuid.UUID
	ActorScopeID  uuid.UUID
	ActorUserID   uuid.UUID
	ResourceType  string
	ResourceID    uuid.UUID
	RequestID     string
	Operation     string
	Module        string
}

// CheckModule is the API-entry gate of a module: the same locked, audited
// signed-lease check as CheckFeature, accepting only module/pack/theme codes.
func (g *Guard) CheckModule(ctx context.Context, tx pgx.Tx, check ModuleCheck) (FeatureDecision, error) {
	if _, _, ok := entitlement.ParseModuleFeatureCode(check.Module); !ok {
		return FeatureDecision{}, fmt.Errorf("entitlement module check needs a module feature code")
	}
	return g.CheckFeature(ctx, tx, FeatureCheck{
		TargetScopeID: check.TargetScopeID, ActorScopeID: check.ActorScopeID, ActorUserID: check.ActorUserID,
		ResourceType: check.ResourceType, ResourceID: check.ResourceID, RequestID: check.RequestID,
		Operation: check.Operation, Feature: check.Module,
	})
}

// AuthorizeModule runs CheckModule in its own transaction: nil when the lease
// grants the module; a denial (IsDenial) commits its audit event and
// validation state and is returned; any other error rolls back. It is the
// shared gate of module API routes and module workers.
func (g *Guard) AuthorizeModule(ctx context.Context, pool *pgxpool.Pool, check ModuleCheck) error {
	if pool == nil {
		return fmt.Errorf("entitlement module authorization needs a pool")
	}
	var denial error
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := g.CheckModule(ctx, tx, check)
		if IsDenial(err) {
			denial = err
			return nil
		}
		return err
	}); err != nil {
		return err
	}
	return denial
}

// GrantedModules reads the verified local lease without locking, writing
// validation state or auditing: it backs read-only views (GET /v1/modules,
// menus). Lease and revocation verification match CheckFeature; any failure
// yields no modules.
func (g *Guard) GrantedModules(ctx context.Context, tx pgx.Tx) (ModuleGrants, error) {
	if tx == nil {
		return ModuleGrants{}, fmt.Errorf("entitlement module read needs a transaction")
	}
	codes := communityModuleCodes()
	purchased, err := communityPurchasedCodes(ctx, tx, g.now())
	if err != nil {
		return ModuleGrants{}, err
	}
	codes = append(codes, purchased...)
	sort.Strings(codes)
	return ModuleGrants{Status: string(entitlement.StatusValid), Codes: slices.Compact(codes)}, nil
}

func (g *Guard) grantedLeaseModules(ctx context.Context, tx pgx.Tx) (ModuleGrants, error) {
	if tx == nil {
		return ModuleGrants{}, fmt.Errorf("entitlement module read needs a transaction")
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
		WHERE installation.singleton = true`,
	).Scan(&installationID, &serial, &encodedLease, &cachedStatus)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (serial == nil || len(encodedLease) == 0)) {
		return ModuleGrants{Status: StatusUninstalled, Codes: []string{}}, nil
	}
	if err != nil {
		return ModuleGrants{}, err
	}
	denied := ModuleGrants{Status: StatusInvalid, LeaseSerial: uint64(*serial), Codes: []string{}}
	if g.trust == nil {
		return denied, nil
	}
	signed, err := entitlement.Decode(encodedLease)
	if err != nil {
		return denied, nil
	}
	now := g.now().UTC()
	options := entitlement.VerifyOptions{Now: now, ExpectedAudience: entitlement.ControlAudience,
		ExpectedInstallationID: installationID}
	verified, err := g.trust.Verify(signed, options)
	if err != nil || verified.Lease.Serial != uint64(*serial) {
		return denied, nil
	}
	revocation, err := loadRevocationLKGTx(ctx, tx, g.trust, now, verified.Lease.CustomerID, installationID,
		verified.Lease.LicenseID)
	if err != nil {
		return denied, nil
	}
	options.RevokedSerials = revocation.RevokedSerials
	if verified, err = g.trust.Verify(signed, options); err != nil {
		return denied, nil
	}
	status := verified.Status
	if cachedStatus != nil && *cachedStatus == string(entitlement.StatusRevoked) {
		status = entitlement.StatusRevoked
	}
	grants := ModuleGrants{Status: string(status), LeaseSerial: verified.Lease.Serial, Codes: []string{}}
	if leaseUsable(status) {
		grants.Codes = verified.Lease.ModuleCodes()
	}
	return grants, nil
}

type moduleChange struct {
	Code           string `json:"code"`
	RevokeBehavior string `json:"revoke_behavior"`
}

// auditModuleChange runs inside Install, after the new lease is verified and
// before it becomes current. The previous lease was verified when it was
// installed, so only its features are decoded here.
func auditModuleChange(ctx context.Context, tx pgx.Tx, pool *pgxpool.Pool, previousSerial *int64, next entitlement.Lease) error {
	before := []string{}
	var serialBefore any
	if previousSerial != nil {
		serialBefore = *previousSerial
		var encoded []byte
		err := tx.QueryRow(ctx, `SELECT signed_lease FROM entitlement_cached_leases WHERE serial=$1`,
			*previousSerial).Scan(&encoded)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if signed, decodeErr := entitlement.Decode(encoded); err == nil && decodeErr == nil {
			before = signed.Lease.ModuleCodes()
		}
	}
	after := next.ModuleCodes()
	if slices.Equal(before, after) {
		return nil
	}
	var platformScopeID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		// install-entitlement runs before bootstrap creates the platform
		// scope; the license-service audit records that grant.
		return nil
	}
	if err != nil {
		return err
	}
	added, removed := []moduleChange{}, []moduleChange{}
	for _, code := range after {
		if !slices.Contains(before, code) {
			added = append(added, describeModuleChange(code))
		}
	}
	for _, code := range before {
		if !slices.Contains(after, code) {
			removed = append(removed, describeModuleChange(code))
		}
	}
	return audit.New(pool).Append(ctx, tx, audit.Event{
		ScopeID: platformScopeID, Action: ModulesChangedAction, ResourceType: "platform_entitlement",
		ResourceID: next.InstallationID, RequestID: fmt.Sprintf("lease-%d", next.Serial), Result: "success",
		Payload: map[string]any{
			"actor": "system", "scope": "platform", "ip": "",
			"object_type": "platform_entitlement", "object_id": next.InstallationID,
			"license_id": next.LicenseID,
		},
		// modules and lease_serial before -> after; added / removed list the
		// changed modules with their revoke behaviour.
		Changes: []audit.Change{
			{Field: "modules", Before: before, After: after},
			{Field: "lease_serial", Before: serialBefore, After: next.Serial},
			{Field: "modules_added", After: added},
			{Field: "modules_removed", After: removed},
		},
	})
}

func describeModuleChange(code string) moduleChange {
	change := moduleChange{Code: code}
	if descriptor, ok := entitlement.LookupModule(code); ok {
		change.RevokeBehavior = string(descriptor.Revoke)
	}
	return change
}
