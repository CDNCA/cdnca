package firewallactioncontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

const (
	testTenant = "11111111-1111-4111-8111-111111111111"
	testSite   = "22222222-2222-4222-8222-222222222222"
	testUser   = "33333333-3333-4333-8333-333333333333"
)

type serviceStoreStub struct {
	putRequest     PutRequest
	recoverRequest RecoverRequest
	policy         Policy
	err            error
}

func (store *serviceStoreStub) Put(_ context.Context, request PutRequest) (WriteResult, error) {
	store.putRequest = request
	if store.err != nil {
		return WriteResult{}, store.err
	}
	return WriteResult{Policy: store.policy}, nil
}

func (store *serviceStoreStub) Get(_ context.Context, _ ReadRequest) (Policy, error) {
	return store.policy, store.err
}

func (store *serviceStoreStub) Recover(_ context.Context, request RecoverRequest) (WriteResult, error) {
	store.recoverRequest = request
	if store.err != nil {
		return WriteResult{}, store.err
	}
	return WriteResult{Policy: store.policy}, nil
}

func testActor(scopeKind string, scopeID uuid.UUID, permissions ...string) Actor {
	return Actor{UserID: uuid.MustParse(testUser), ScopeID: scopeID, ScopeKind: scopeKind, Permissions: permissions}
}

func validInput() PolicyInput {
	return PolicyInput{
		NormalAction: ActionReturnPage, EscalatedAction: ActionNFTables,
		EngageThreshold: 100, RecoverThreshold: 20, RecoveryWindows: 3,
		BlockNetworks:   []string{"2001:db8:2::/48", "198.51.100.0/24"},
		TrustedProxies:  []string{"192.0.2.0/24"},
		TrustedCrawlers: []TrustedCrawler{{Name: "search", Networks: []string{"203.0.113.0/24"}, UserAgentPrefixes: []string{"SearchBot/"}}},
		ReturnPage:      ReturnPage{Status: 429, ContentType: "text/plain; charset=utf-8", Body: "Request limited"},
	}
}

func TestPutBuildsCanonicalImmutableCandidate(t *testing.T) {
	tenantID, siteID := uuid.MustParse(testTenant), uuid.MustParse(testSite)
	store := &serviceStoreStub{policy: Policy{ID: uuid.New(), TenantScopeID: tenantID, SiteID: siteID, Revision: 1}}
	service := NewService(store)
	result, err := service.Put(t.Context(), PutRequest{
		Actor: testActor(ScopeTenant, tenantID, PermissionManage), TargetScopeID: tenantID, SiteID: siteID,
		ExpectedRevision: 0, IdempotencyKey: "sec06-put", RequestID: "44444444-4444-4444-8444-444444444444", Policy: validInput(),
	})
	if err != nil || result.Policy.Revision != 1 {
		t.Fatalf("Put() = (%+v, %v)", result, err)
	}
	request := store.putRequest
	if request.Document.SchemaVersion != SchemaVersion || request.Document.PolicyVersion != 1 ||
		request.Document.ExpectedActivePolicyVersion != 0 || request.Document.TenantID != testTenant || request.Document.SiteID != testSite ||
		request.Document.NormalAction != ActionReturnPage || request.Document.EscalatedAction != ActionNFTables ||
		request.RequestSHA256 == ([32]byte{}) || request.DocumentSHA256 == ([32]byte{}) {
		t.Fatalf("candidate was not sealed: %+v", request)
	}
	encoded, _ := json.Marshal(request.Document)
	if bytes.Contains(encoded, []byte(`"enabled"`)) {
		t.Fatalf("candidate leaked control-only enabled field: %s", encoded)
	}
	if got := request.Policy.BlockNetworks; len(got) != 2 || got[0] != "198.51.100.0/24" || got[1] != "2001:db8:2::/48" {
		t.Fatalf("block networks not canonical: %#v", got)
	}
	other := &serviceStoreStub{policy: store.policy}
	_, err = NewService(other).Put(t.Context(), PutRequest{
		Actor: testActor(ScopeTenant, tenantID, PermissionManage), TargetScopeID: tenantID, SiteID: siteID,
		ExpectedRevision: 0, IdempotencyKey: "sec06-put", RequestID: "55555555-5555-4555-8555-555555555555", Policy: validInput(),
	})
	if err != nil || other.putRequest.RequestSHA256 == request.RequestSHA256 {
		t.Fatalf("original request ID was not bound into idempotency digest: %v", err)
	}
}

func TestPutRejectsUnsafeThresholdsAndTrustedOverlap(t *testing.T) {
	tenantID, siteID := uuid.MustParse(testTenant), uuid.MustParse(testSite)
	actor := testActor(ScopeTenant, tenantID, PermissionManage)
	for name, mutate := range map[string]func(*PolicyInput){
		"no_hysteresis":                 func(input *PolicyInput) { input.RecoverThreshold = input.EngageThreshold },
		"no_recovery_window":            func(input *PolicyInput) { input.RecoveryWindows = 0 },
		"trusted_proxy_in_kernel_set":   func(input *PolicyInput) { input.BlockNetworks = append(input.BlockNetworks, "192.0.2.128/25") },
		"trusted_crawler_in_kernel_set": func(input *PolicyInput) { input.BlockNetworks = append(input.BlockNetworks, "203.0.113.0/25") },
		"scriptable_page":               func(input *PolicyInput) { input.ReturnPage.Body = "<script>" },
	} {
		t.Run(name, func(t *testing.T) {
			input := validInput()
			mutate(&input)
			_, err := NewService(&serviceStoreStub{}).Put(t.Context(), PutRequest{Actor: actor, TargetScopeID: tenantID, SiteID: siteID,
				ExpectedRevision: 0, IdempotencyKey: "sec06-invalid", RequestID: "44444444-4444-4444-8444-444444444444", Policy: input})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Put() error = %v", err)
			}
		})
	}
}

func TestScopeRBACAndStoreConflictsRemainDistinct(t *testing.T) {
	tenantID, siteID := uuid.MustParse(testTenant), uuid.MustParse(testSite)
	otherTenant := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	base := PutRequest{TargetScopeID: tenantID, SiteID: siteID, ExpectedRevision: 0, IdempotencyKey: "sec06-auth",
		RequestID: "44444444-4444-4444-8444-444444444444", Policy: validInput()}
	for name, actor := range map[string]struct {
		actor Actor
		want  error
	}{
		"unauthenticated": {Actor{}, ErrUnauthenticated},
		"cross_tenant":    {testActor(ScopeTenant, otherTenant, PermissionManage), ErrNotFound},
		"denied":          {testActor(ScopeTenant, tenantID, PermissionRead), ErrPermissionDenied},
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			request.Actor = actor.actor
			_, err := NewService(&serviceStoreStub{}).Put(t.Context(), request)
			if !errors.Is(err, actor.want) {
				t.Fatalf("Put() error = %v, want %v", err, actor.want)
			}
		})
	}
	base.Actor = testActor(ScopePlatform, uuid.MustParse("66666666-6666-4666-8666-666666666666"), "platform.admin")
	store := &serviceStoreStub{err: ErrRevisionConflict}
	if _, err := NewService(store).Put(t.Context(), base); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("platform Put() error = %v", err)
	}
	store.err = ErrIdempotencyConflict
	if _, err := NewService(store).Put(t.Context(), base); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency error = %v", err)
	}
}

func TestRecoverAlwaysTargetsDurableLKG(t *testing.T) {
	tenantID, siteID := uuid.MustParse(testTenant), uuid.MustParse(testSite)
	store := &serviceStoreStub{policy: Policy{TenantScopeID: tenantID, SiteID: siteID, Revision: 8, ActiveRevision: 6, LKGRevision: 6, DeploymentState: StatePending}}
	request := RecoverRequest{Actor: testActor(ScopeTenant, tenantID, PermissionManage), TargetScopeID: tenantID, SiteID: siteID,
		ExpectedRevision: 7, IdempotencyKey: "sec06-recover", RequestID: "44444444-4444-4444-8444-444444444444"}
	result, err := NewService(store).Recover(t.Context(), request)
	if err != nil || result.Policy.LKGRevision != 6 || store.recoverRequest.ExpectedRevision != 7 {
		t.Fatalf("Recover() = (%+v, %v), request=%+v", result, err, store.recoverRequest)
	}
}

func TestOutcomeKeepsLKGOnFailureAndPromotesOnlyAcceptedCandidate(t *testing.T) {
	digest := [32]byte{1, 2, 3}
	current := Policy{Revision: 8, ActiveRevision: 6, LKGRevision: 6, DeploymentState: StatePending,
		DocumentSHA256: "0102030000000000000000000000000000000000000000000000000000000000"}
	rejected, state, err := applyOutcome(current, OutcomeRequest{Revision: 8, DocumentSHA256: digest, ReasonCode: "candidate_rejected"}, time.Unix(10, 0))
	if err != nil || state != "failed" || rejected.DeploymentState != StateFailed || rejected.ActiveRevision != 6 || rejected.LKGRevision != 6 {
		t.Fatalf("rejected outcome = (%+v, %q, %v)", rejected, state, err)
	}
	accepted, state, err := applyOutcome(current, OutcomeRequest{Revision: 8, DocumentSHA256: digest, Applied: true, ReasonCode: "applied"}, time.Unix(11, 0))
	if err != nil || state != "acked" || accepted.DeploymentState != StateActive || accepted.ActiveRevision != 8 || accepted.LKGRevision != 8 {
		t.Fatalf("accepted outcome = (%+v, %q, %v)", accepted, state, err)
	}
}
