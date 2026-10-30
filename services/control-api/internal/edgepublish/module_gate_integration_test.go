//go:build integration

package edgepublish

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/jackc/pgx/v5"
)

type moduleGrantStub struct {
	mu    sync.Mutex
	codes []string
	reads int
}

func (stub *moduleGrantStub) GrantedModuleCodes(context.Context, pgx.Tx) ([]string, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.reads++
	return append([]string(nil), stub.codes...), nil
}

func (stub *moduleGrantStub) set(codes ...string) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.codes = codes
}

// Acceptance (PA-15 publication gate): a source that uses a module the lease
// does not grant is refused with ErrModuleNotEntitled, nothing is persisted,
// and the refusal is audited after the rollback; granting the module lets the
// same revision publish.
func TestPublishRefusesSourceUsingUngrantedModule(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "pa15-probe-origin.example", 80, false)
	grants := &moduleGrantStub{}
	config := fixture.config(nil, nil)
	config.ModuleGrants = grants
	config.ModuleRequirements = []ModuleRequirement{{
		Module: entitlement.ModuleDescriptor{Code: "module.pa15_probe", NameZH: "探针", NameEN: "Probe",
			Revoke: entitlement.RevokeKeepExisting},
		RequiredBy: func(snapshot []byte) bool { return bytes.Contains(snapshot, []byte("pa15-probe-origin.example")) },
	}}
	service, err := newServiceWithWriteAuthorizer(fixture.pool, fixture.deploymentStore(t), fixture.signer, config,
		fixtureWriteAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}

	request := fixture.publishRequest("pa15-module-denied", fixture.nodeID)
	_, err = service.Publish(t.Context(), request)
	var refusal *ModuleNotEntitledError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrModuleNotEntitled) ||
		!reflect.DeepEqual(refusal.Modules, []string{"module.pa15_probe"}) {
		t.Fatalf("Publish(module not granted) error = %v", err)
	}
	assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	denials := audittest.Query(t, fixture.pool, `action='site.publication.module_denied' AND scope_id=$1 AND result='denied'`,
		fixture.scopeID)
	if len(denials) != 1 {
		t.Fatalf("module denial audits = %d, want 1", len(denials))
	}
	payload := denials[0].Payload
	missing, _ := denials[0].Change("missing_modules")
	if payload["actor"] != fixture.platformUserID.String() || payload["reason"] != "entitlement_feature_denied" ||
		!reflect.DeepEqual(missing.After, []any{"module.pa15_probe"}) {
		t.Fatalf("module denial audit payload = %#v changes %v", payload, denials[0].Changes)
	}

	grants.set("module.pa15_probe")
	request = fixture.publishRequest("pa15-module-granted", fixture.nodeID)
	if _, err := service.Publish(t.Context(), request); err != nil {
		t.Fatalf("Publish(module granted) error = %v", err)
	}
	assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
}

// Sources that use no registered module never read the grants.
func TestPublishWithoutModuleUseSkipsGrantRead(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "plain-origin.example", 80, false)
	grants := &moduleGrantStub{}
	config := fixture.config(nil, nil)
	config.ModuleGrants = grants
	config.ModuleRequirements = []ModuleRequirement{{
		Module: entitlement.ModuleDescriptor{Code: "module.pa15_probe", NameZH: "探针", NameEN: "Probe",
			Revoke: entitlement.RevokeKeepExisting},
		RequiredBy: func(snapshot []byte) bool { return bytes.Contains(snapshot, []byte("pa15-probe-origin.example")) },
	}}
	service, err := newServiceWithWriteAuthorizer(fixture.pool, fixture.deploymentStore(t), fixture.signer, config,
		fixtureWriteAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Publish(t.Context(), fixture.publishRequest("pa15-no-module", fixture.nodeID)); err != nil {
		t.Fatalf("Publish(no module) error = %v", err)
	}
	if grants.reads != 0 {
		t.Fatalf("grant reads = %d, want 0", grants.reads)
	}
}
