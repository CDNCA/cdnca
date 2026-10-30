package edgepublish

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/jackc/pgx/v5"
)

func probeRequirement(code string) ModuleRequirement {
	return ModuleRequirement{
		Module:     entitlement.ModuleDescriptor{Code: code, NameZH: "探针", NameEN: "Probe", Revoke: entitlement.RevokeKeepExisting},
		RequiredBy: func([]byte) bool { return true },
	}
}

func TestValidateModuleRequirements(t *testing.T) {
	if err := validateModuleRequirements(nil); err != nil {
		t.Fatalf("no requirements: %v", err)
	}
	catalog, _ := entitlement.LookupModule("module.aggregated_edge")
	ok := []ModuleRequirement{probeRequirement("module.pa15_probe"),
		{Module: catalog, RequiredBy: func([]byte) bool { return false }}}
	if err := validateModuleRequirements(ok); err != nil {
		t.Fatalf("valid requirements: %v", err)
	}
	noRevoke := probeRequirement("module.no_revoke")
	noRevoke.Module.Revoke = ""
	noPredicate := probeRequirement("module.no_predicate")
	noPredicate.RequiredBy = nil
	drifted := ModuleRequirement{Module: catalog, RequiredBy: func([]byte) bool { return false }}
	drifted.Module.Revoke = entitlement.RevokeRemoveExisting
	for name, requirements := range map[string][]ModuleRequirement{
		"no revoke behavior": {noRevoke},
		"no predicate":       {noPredicate},
		"plain feature":      {probeRequirement("sites.manage")},
		"duplicate":          {probeRequirement("module.x"), probeRequirement("module.x")},
		"catalog drift":      {drifted},
	} {
		if err := validateModuleRequirements(requirements); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

type nonModuleAuthorizer struct{ EntitlementAuthorizer }

type grantingAuthorizer struct {
	EntitlementAuthorizer
	codes []string
}

func (authorizer grantingAuthorizer) GrantedModuleCodes(context.Context, pgx.Tx) ([]string, error) {
	return authorizer.codes, nil
}

func TestModuleGateFailsClosedWithoutGrantReader(t *testing.T) {
	service := &Service{authorizer: nonModuleAuthorizer{},
		config: Config{ModuleRequirements: []ModuleRequirement{probeRequirement("module.pa15_probe")}}}
	var refusal *ModuleNotEntitledError
	if err := service.validateModuleEntitlements(context.Background(), nil, []byte("{}")); !errors.As(err, &refusal) {
		t.Fatalf("no grant reader: %v", err)
	}
	service.authorizer = grantingAuthorizer{codes: []string{"module.pa15_probe"}}
	if err := service.validateModuleEntitlements(context.Background(), nil, []byte("{}")); err != nil {
		t.Fatalf("authorizer grants the module: %v", err)
	}
}
