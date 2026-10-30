package firewallcontrol

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

type recordingStore struct {
	putRequest PutRequest
	result     WriteResult
	err        error
}

func (store *recordingStore) Put(_ context.Context, request PutRequest) (WriteResult, error) {
	store.putRequest = request
	return store.result, store.err
}
func (store *recordingStore) Get(context.Context, ReadRequest) (Policy, error) {
	return Policy{}, store.err
}
func (store *recordingStore) Recover(context.Context, RecoverRequest) (WriteResult, error) {
	return store.result, store.err
}
func (store *recordingStore) ListHits(context.Context, HitFilter) (HitPage, error) {
	return HitPage{}, store.err
}

func TestServicePutNormalizesDeterministicallyAndBindsActorScope(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	siteID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	actor := Actor{UserID: uuid.New(), ScopeID: tenantID, ScopeKind: ScopeTenant, Permissions: []string{PermissionManage}}
	store := &recordingStore{result: WriteResult{Policy: Policy{Revision: 1}}}
	service := NewService(store, func() time.Time { return time.Date(2026, 8, 7, 1, 2, 3, 0, time.UTC) })

	request := PutRequest{
		Actor: actor, TargetScopeID: tenantID, ExpectedRevision: 0,
		IdempotencyKey: "global-fw-create", RequestID: uuid.NewString(),
		Policy: PolicyInput{Enabled: true, DefaultAction: ActionAllow, Rules: []RuleInput{
			{ID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), Priority: 20, Action: ActionDeny, CIDRs: []string{"2001:0DB8:1::/48"}, Protocol: ProtocolUDP, PortStart: 53, PortEnd: 53, SiteIDs: []uuid.UUID{siteID}},
			{ID: uuid.MustParse("44444444-4444-4444-8444-444444444444"), Priority: 10, Action: ActionAllow, CIDRs: []string{"192.0.2.10"}, Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443, SiteIDs: []uuid.UUID{siteID}},
		}},
	}
	if _, err := service.Put(context.Background(), request); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	got := store.putRequest.Policy.Rules
	if len(got) != 2 || got[0].Priority != 10 || got[0].CIDRs[0] != "192.0.2.10/32" || got[1].CIDRs[0] != "2001:db8:1::/48" {
		t.Fatalf("normalized rules = %#v", got)
	}
	if store.putRequest.DocumentSHA256 == ([32]byte{}) {
		t.Fatal("normalized document digest was not bound to the write")
	}
	first := store.putRequest
	store.putRequest = PutRequest{}
	if _, err := service.Put(context.Background(), request); err != nil {
		t.Fatalf("replayed Put() error = %v", err)
	}
	if !reflect.DeepEqual(first.Policy, store.putRequest.Policy) || first.DocumentSHA256 != store.putRequest.DocumentSHA256 {
		t.Fatal("equivalent input did not normalize deterministically")
	}
}

func TestServicePutRejectsTenantRBACAndUnsafeRuleScope(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	otherTenant := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	base := PutRequest{
		Actor:         Actor{UserID: uuid.New(), ScopeID: tenantID, ScopeKind: ScopeTenant, Permissions: []string{PermissionManage}},
		TargetScopeID: tenantID, IdempotencyKey: "global-fw", RequestID: uuid.NewString(),
		Policy: PolicyInput{Enabled: true, DefaultAction: ActionAllow, Rules: []RuleInput{{
			Priority: 1, Action: ActionDeny, CIDRs: []string{"198.51.100.0/24"}, Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443,
		}}},
	}
	tests := map[string]struct {
		mutate func(*PutRequest)
		want   error
	}{
		"cross tenant":       {func(request *PutRequest) { request.TargetScopeID = otherTenant }, ErrNotFound},
		"missing permission": {func(request *PutRequest) { request.Actor.Permissions = nil }, ErrPermissionDenied},
		"noncanonical cidr":  {func(request *PutRequest) { request.Policy.Rules[0].CIDRs[0] = "198.51.100.1/24" }, ErrInvalidInput},
		"any with port":      {func(request *PutRequest) { request.Policy.Rules[0].Protocol = ProtocolAny }, ErrInvalidInput},
		"icmp with port":     {func(request *PutRequest) { request.Policy.Rules[0].Protocol = ProtocolICMP }, ErrInvalidInput},
		"reversed port": {func(request *PutRequest) {
			request.Policy.Rules[0].PortStart, request.Policy.Rules[0].PortEnd = 8443, 443
		}, ErrInvalidInput},
		"duplicate cidr": {func(request *PutRequest) {
			request.Policy.Rules[0].CIDRs = append(request.Policy.Rules[0].CIDRs, request.Policy.Rules[0].CIDRs[0])
		}, ErrInvalidInput},
	}
	for name, item := range tests {
		t.Run(name, func(t *testing.T) {
			request := base
			request.Actor.Permissions = append([]string(nil), base.Actor.Permissions...)
			request.Policy.Rules = append([]RuleInput(nil), base.Policy.Rules...)
			request.Policy.Rules[0].CIDRs = append([]string(nil), base.Policy.Rules[0].CIDRs...)
			item.mutate(&request)
			_, err := NewService(&recordingStore{}, time.Now).Put(context.Background(), request)
			if !errors.Is(err, item.want) {
				t.Fatalf("Put() error = %v, want %v", err, item.want)
			}
		})
	}
}

func TestServiceRecoverRequiresReasonAndPreservesExplicitLKG(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	store := &recordingStore{result: WriteResult{Policy: Policy{Revision: 4, ActiveRevision: 2}}}
	service := NewService(store, time.Now)
	actor := Actor{UserID: uuid.New(), ScopeID: tenantID, ScopeKind: ScopeTenant, Permissions: []string{PermissionManage}}
	request := RecoverRequest{Actor: actor, TargetScopeID: tenantID, ExpectedRevision: 3, RecoverRevision: 2, Reason: RecoveryFalsePositive, IdempotencyKey: "recover-fp", RequestID: uuid.NewString()}
	result, err := service.Recover(context.Background(), request)
	if err != nil || result.Policy.ActiveRevision != 2 {
		t.Fatalf("Recover() = (%+v, %v)", result, err)
	}
	request.Reason = ""
	if _, err := service.Recover(context.Background(), request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing reason error = %v", err)
	}
}
