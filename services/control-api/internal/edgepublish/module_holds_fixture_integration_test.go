//go:build integration

package edgepublish

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/jackc/pgx/v5"
)

// ModuleProbeCode is the module the scope's probe site uses (its domain is
// in every release of the scope).
const ModuleProbeCode = "module.default_modules_probe"

// ModuleGrants is a settable lease module grant for module watcher tests.
type ModuleGrants struct {
	mu    sync.Mutex
	codes []string
}

func (grants *ModuleGrants) GrantedModuleCodes(context.Context, pgx.Tx) ([]string, error) {
	grants.mu.Lock()
	defer grants.mu.Unlock()
	return append([]string(nil), grants.codes...), nil
}

func (grants *ModuleGrants) Set(codes ...string) {
	grants.mu.Lock()
	defer grants.mu.Unlock()
	grants.codes = codes
}

// UseProbeModule rebuilds the scope's publication service with a module
// requirement every release of the scope meets, gated by grants, and returns
// the requirements for the module watcher.
func (scope *SystemRepublishScope) UseProbeModule(t *testing.T, grants *ModuleGrants) []ModuleRequirement {
	t.Helper()
	requirements := []ModuleRequirement{{
		Module: entitlement.ModuleDescriptor{Code: ModuleProbeCode, NameZH: "探针", NameEN: "Probe",
			Revoke: entitlement.RevokeKeepExisting},
		RequiredBy: func(snapshot []byte) bool { return bytes.Contains(snapshot, []byte("system-republish.example.com")) },
	}}
	config := scope.fixture.config(nil, nil)
	config.ModuleGrants = grants
	config.ModuleRequirements = requirements
	service, err := newServiceWithWriteAuthorizer(scope.Pool, scope.fixture.deploymentStore(t), scope.fixture.signer, config,
		fixtureWriteAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	scope.fixture.service = service
	if scope.republisher, err = NewSystemRepublisher(service, SystemRepublisherConfig{
		WorkerID: "syspub-test", LeaseDuration: time.Minute, RetryDelay: 0,
	}); err != nil {
		t.Fatal(err)
	}
	return requirements
}
