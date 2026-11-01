package firewallactioncontrol

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSystemDefaultIsAValidPolicy(t *testing.T) {
	if _, err := normalizePolicy(SystemDefaultPolicy()); err != nil {
		t.Fatalf("system default rejected: %v", err)
	}
}

func TestInheritedDocumentUsesSiteAndDistinctPolicyID(t *testing.T) {
	scopeID, siteID := uuid.MustParse(testTenant), uuid.MustParse(testSite)
	policy, _ := normalizePolicy(validInput())
	stored, err := encodeDefaultDocument(policy)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := InheritedDocument(scopeID, siteID, 4, stored)
	if err != nil {
		t.Fatal(err)
	}
	var edge EdgePolicy
	if err := json.Unmarshal(raw, &edge); err != nil {
		t.Fatal(err)
	}
	if edge.SchemaVersion != SchemaVersion || edge.PolicyVersion != 4 || edge.ExpectedActivePolicyVersion != 0 ||
		edge.TenantID != testTenant || edge.SiteID != testSite || edge.PolicyID != InheritedPolicyID(scopeID, siteID).String() ||
		edge.EngageThreshold != policy.EngageThreshold || len(edge.BlockNetworks) != len(policy.BlockNetworks) {
		t.Fatalf("inherited document = %+v", edge)
	}
	if InheritedPolicyID(scopeID, siteID) == OwnPolicyID(scopeID, siteID) {
		t.Fatal("inherited delivery reuses the site's own policy ID")
	}
	other, _ := InheritedDocument(scopeID, uuid.New(), 4, stored)
	if string(other) == string(raw) {
		t.Fatal("two sites share one inherited document")
	}
	again, _ := InheritedDocument(scopeID, siteID, 4, stored)
	if string(again) != string(raw) {
		t.Fatal("inherited document is not deterministic")
	}
	if _, err := InheritedDocument(scopeID, siteID, 0, stored); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("revision 0 error = %v", err)
	}
	if _, err := InheritedDocument(scopeID, siteID, 1, []byte(`{"unknown":1}`)); err == nil {
		t.Fatal("unknown stored field accepted")
	}
}

func TestDefaultChangesListsScalarsAndMarksLists(t *testing.T) {
	before := validInput()
	after := validInput()
	after.EngageThreshold, after.BlockNetworks = 200, []string{"198.51.100.0/24"}
	changes := defaultChanges(before, after)
	engage, ok := changes["engage_threshold"].(map[string]any)
	if !ok || engage["before"] != uint64(100) || engage["after"] != uint64(200) {
		t.Fatalf("engage change = %#v", changes["engage_threshold"])
	}
	if _, ok := changes["block_networks"].(map[string]any)["changed"]; !ok {
		t.Fatalf("block network change = %#v", changes["block_networks"])
	}
	if _, ok := changes["recover_threshold"]; ok {
		t.Fatalf("unchanged field listed: %#v", changes)
	}
}

func TestDefaultServiceValidatesAndSealsRequest(t *testing.T) {
	tenantID := uuid.MustParse(testTenant)
	store := &serviceStoreStub{defaultPolicy: DefaultPolicy{TenantScopeID: tenantID, Revision: 1}}
	request := DefaultPutRequest{Actor: testActor(ScopeTenant, tenantID, PermissionManage), TargetScopeID: tenantID,
		IdempotencyKey: "fw-default", RequestID: "44444444-4444-4444-8444-444444444444", Policy: validInput()}
	if _, err := NewService(store).PutDefault(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if store.defaultRequest.RequestSHA256 == ([32]byte{}) || store.defaultRequest.Policy.BlockNetworks[0] != "198.51.100.0/24" {
		t.Fatalf("default request not sealed/normalized: %+v", store.defaultRequest)
	}
	invalid := request
	invalid.Policy.RecoverThreshold = invalid.Policy.EngageThreshold
	if _, err := NewService(&serviceStoreStub{}).PutDefault(t.Context(), invalid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid default error = %v", err)
	}
	for name, test := range map[string]struct {
		actor Actor
		want  error
	}{
		"unauthenticated": {Actor{}, ErrUnauthenticated},
		"cross_tenant":    {testActor(ScopeTenant, uuid.New(), PermissionManage), ErrNotFound},
		"read_only":       {testActor(ScopeTenant, tenantID, PermissionRead), ErrPermissionDenied},
	} {
		t.Run(name, func(t *testing.T) {
			denied := request
			denied.Actor = test.actor
			if _, err := NewService(&serviceStoreStub{}).PutDefault(t.Context(), denied); !errors.Is(err, test.want) {
				t.Fatalf("PutDefault() error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := NewService(&serviceStoreStub{}).GetDefault(t.Context(), DefaultReadRequest{
		Actor: testActor(ScopeTenant, uuid.New(), PermissionRead), TargetScopeID: tenantID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross tenant GetDefault() error = %v", err)
	}
}

func TestInheritServiceRequiresOwnRevisionAndMetadata(t *testing.T) {
	tenantID, siteID := uuid.MustParse(testTenant), uuid.MustParse(testSite)
	base := InheritRequest{Actor: testActor(ScopeTenant, tenantID, PermissionManage), TargetScopeID: tenantID, SiteID: siteID,
		ExpectedRevision: 3, IdempotencyKey: "fw-inherit", RequestID: "44444444-4444-4444-8444-444444444444"}
	store := &serviceStoreStub{}
	if _, err := NewService(store).Inherit(t.Context(), base); err != nil || store.inheritRequest.RequestSHA256 == ([32]byte{}) {
		t.Fatalf("Inherit() = %v request=%+v", err, store.inheritRequest)
	}
	recoverDigest := (&serviceStoreStub{})
	_, _ = NewService(recoverDigest).Recover(t.Context(), RecoverRequest{Actor: base.Actor, TargetScopeID: tenantID, SiteID: siteID,
		ExpectedRevision: 3, IdempotencyKey: "fw-inherit", RequestID: base.RequestID})
	if recoverDigest.recoverRequest.RequestSHA256 == store.inheritRequest.RequestSHA256 {
		t.Fatal("inherit and recover share one idempotency digest")
	}
	for name, mutate := range map[string]func(*InheritRequest){
		"zero_revision": func(request *InheritRequest) { request.ExpectedRevision = 0 },
		"no_site":       func(request *InheritRequest) { request.SiteID = uuid.Nil },
		"bad_key":       func(request *InheritRequest) { request.IdempotencyKey = "bad key" },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if _, err := NewService(&serviceStoreStub{}).Inherit(t.Context(), request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Inherit() error = %v", err)
			}
		})
	}
	readOnly := base
	readOnly.Actor = testActor(ScopeTenant, tenantID, PermissionRead)
	if _, err := NewService(&serviceStoreStub{}).Inherit(t.Context(), readOnly); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("read-only Inherit() error = %v", err)
	}
}
