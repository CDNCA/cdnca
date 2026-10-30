package edgepublish

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrModuleNotEntitled refuses a publication that needs a module, pack or
// theme the local lease does not grant (ADR 0007 §3.1, §4.5). The HTTP layer
// answers entitlement_feature_denied, the same code as the API entry gate.
var ErrModuleNotEntitled = errors.New("edge publication needs a module the entitlement does not grant")

// ModuleRequirement is the publication-gate part of a module: RequiredBy
// reports whether a compiled source snapshot uses the module. Module carries
// the code and the declared revoke behavior; catalog modules use the
// libs/entitlement catalog entry.
type ModuleRequirement struct {
	Module     entitlement.ModuleDescriptor
	RequiredBy func(snapshot []byte) bool
}

// ModuleGrantReader returns the module codes the verified local lease grants
// (empty unless the lease is valid). The production EntitlementAuthorizer
// implements it; Config.ModuleGrants overrides it.
type ModuleGrantReader interface {
	GrantedModuleCodes(context.Context, pgx.Tx) ([]string, error)
}

// ModuleNotEntitledError lists the missing module codes.
type ModuleNotEntitledError struct {
	Modules []string
}

func (e *ModuleNotEntitledError) Error() string {
	return ErrModuleNotEntitled.Error() + ": " + strings.Join(e.Modules, ",")
}

func (e *ModuleNotEntitledError) Unwrap() error { return ErrModuleNotEntitled }

func validateModuleRequirements(requirements []ModuleRequirement) error {
	seen := map[string]bool{}
	for _, requirement := range requirements {
		if requirement.Module.Validate() != nil || requirement.RequiredBy == nil || seen[requirement.Module.Code] {
			return ErrInvalidInput
		}
		if catalog, ok := entitlement.LookupModule(requirement.Module.Code); ok && catalog != requirement.Module {
			return ErrInvalidInput
		}
		seen[requirement.Module.Code] = true
	}
	return nil
}

func (s *Service) moduleGrantReader() ModuleGrantReader {
	if s.config.ModuleGrants != nil {
		return s.config.ModuleGrants
	}
	reader, _ := s.authorizer.(ModuleGrantReader)
	return reader
}

// validateModuleEntitlements is the publication gate: every module the
// snapshot uses must be granted. Without registered requirements it reads
// nothing.
func (s *Service) validateModuleEntitlements(ctx context.Context, tx pgx.Tx, snapshot []byte) error {
	var required []string
	for _, requirement := range s.config.ModuleRequirements {
		if requirement.RequiredBy(snapshot) {
			required = append(required, requirement.Module.Code)
		}
	}
	if len(required) == 0 {
		return nil
	}
	slices.Sort(required)
	var granted []string
	if reader := s.moduleGrantReader(); reader != nil {
		codes, err := reader.GrantedModuleCodes(ctx, tx)
		if err != nil {
			return err
		}
		granted = codes
	}
	var missing []string
	for _, code := range required {
		if !slices.Contains(granted, code) {
			missing = append(missing, code)
		}
	}
	if len(missing) > 0 {
		return &ModuleNotEntitledError{Modules: missing}
	}
	return nil
}

// recordModuleDenial audits a refused publication after its transaction
// rolled back, so the refusal survives the rollback.
func (s *Service) recordModuleDenial(ctx context.Context, request PublishRequest, publishErr error) {
	var refusal *ModuleNotEntitledError
	if s == nil || ctx == nil || !errors.As(publishErr, &refusal) || request.ConfigurationScopeID == uuid.Nil {
		return
	}
	actor := "system"
	if request.Actor.system == nil && request.Actor.UserID != uuid.Nil {
		actor = request.Actor.UserID.String()
	}
	_ = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.ConfigurationScopeID, ActorUserID: auditActorUserID(request.Actor),
			Action: "site.publication.module_denied", ResourceType: "edge_configuration_scope",
			ResourceID: request.ConfigurationScopeID.String(), RequestID: request.RequestID, Result: "denied",
			Payload: map[string]any{
				"actor": actor, "scope_id": request.ConfigurationScopeID.String(), "ip": "", "reason": "entitlement_feature_denied",
				"object_type": "edge_configuration_scope", "object_id": request.ConfigurationScopeID.String(),
				"source_revision": request.ExpectedSourceRevision,
				"changes":         map[string]any{"missing_modules": slices.Clone(refusal.Modules)},
			},
		})
	})
}
