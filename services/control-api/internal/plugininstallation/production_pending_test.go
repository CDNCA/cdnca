package plugininstallation

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// pendingResolver is a mergeResolver that also talks to a license service with migration 076.
type pendingResolver struct {
	mergeResolver
	pending     Page
	pendingErr  error
	confirmed   []PendingConfirmRequest
	confirmErr  error
	newRevision uint64
	// replays maps idempotency keys the license service already confirmed to the stored revision.
	replays map[string]uint64
}

func (resolver *pendingResolver) DiscoverPending(context.Context, CandidateDiscoveryRequest) (Page, error) {
	return resolver.pending, resolver.pendingErr
}

func (resolver *pendingResolver) ConfirmPending(_ context.Context, request PendingConfirmRequest) (PendingConfirmResult, error) {
	resolver.confirmed = append(resolver.confirmed, request)
	if revision, found := resolver.replays[request.IdempotencyKey]; found {
		return PendingConfirmResult{AuthorizationID: request.AuthorizationID, Revision: revision}, nil
	}
	pending := false
	for _, item := range resolver.pending.Items {
		pending = pending || item.Installation.AuthorizationID == request.AuthorizationID
	}
	if !pending { // the license service refuses anything that is not a pending market authorization
		return PendingConfirmResult{}, ErrFactDenied
	}
	return PendingConfirmResult{AuthorizationID: request.AuthorizationID, Revision: resolver.newRevision}, resolver.confirmErr
}

func TestProductionOffersAndConfirmsPendingMarketAuthorizations(t *testing.T) {
	tenantID := uuid.New()
	installed := mergeView(tenantID, "acme.audit", "1.0.0", StatusEnabled, "")
	waiting := mergeView(tenantID, "acme.market", "1.0.0", StatusPendingConfirmation, StatusPendingConfirmation)
	waiting.Installation.Revision = 1
	resolver := &pendingResolver{pending: Page{Items: []InstallationView{waiting}}, newRevision: 2}
	domain, err := NewProductionDomain(mergeRepository{heads: map[uuid.UUID]InstallationView{
		installed.Installation.AuthorizationID: installed}}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "list-1",
		Username: "ctl-admin"}
	page, err := domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 20})
	if err != nil || len(page.Items) != 2 || page.Items[0].Installation.AuthorizationID != waiting.Installation.AuthorizationID ||
		page.Items[0].AuthorizationStatus != StatusPendingConfirmation {
		t.Fatalf("list=%+v err=%v", page.Items, err)
	}
	if filtered, err := domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 20,
		Status: StatusEnabled}); err != nil || len(filtered.Items) != 1 {
		t.Fatalf("enabled filter=%+v err=%v", filtered.Items, err)
	}
	if got, err := domain.Get(context.Background(), actor, waiting.Installation.AuthorizationID); err != nil ||
		got.AuthorizationStatus != StatusPendingConfirmation {
		t.Fatalf("get pending=%+v err=%v", got, err)
	}

	mutate := func(revision uint64, verification uuid.UUID) error {
		actor.RequestID = "confirm-1"
		_, err := domain.Mutate(context.Background(), actor, MutationRequest{TenantID: tenantID,
			AuthorizationID: waiting.Installation.AuthorizationID, VerificationID: verification, Action: ActionConfirm,
			ExpectedRevision: revision, IdempotencyKey: "confirm-1", RequestID: "confirm-1",
			ApprovedScopes: []string{"plugin.read"}, SensitivePermissionsConfirmed: true})
		return err
	}
	if err := mutate(5, waiting.Installation.VerificationID); !errors.Is(err, ErrRevisionConflict) || len(resolver.confirmed) != 0 {
		t.Fatalf("stale revision err=%v confirms=%d", err, len(resolver.confirmed))
	}
	if err := mutate(1, uuid.New()); !errors.Is(err, ErrFactDenied) || len(resolver.confirmed) != 0 {
		t.Fatalf("other verification err=%v confirms=%d", err, len(resolver.confirmed))
	}
	// The license confirmation goes first; the install then resolves against the confirmed revision.
	if err := mutate(1, waiting.Installation.VerificationID); !errors.Is(err, ErrFactDenied) {
		t.Fatalf("confirm err=%v (the fake resolve denies after the license confirmation)", err)
	}
	if len(resolver.confirmed) != 1 || resolver.confirmed[0].Username != "ctl-admin" ||
		resolver.confirmed[0].UserID != actor.UserID || resolver.confirmed[0].ExpectedRevision != 1 ||
		!resolver.confirmed[0].SensitivePermissionsConfirmed || resolver.resolve.KnownLifecycleRevision != 2 ||
		resolver.resolve.Action != ActivationInstall {
		t.Fatalf("confirmed=%+v resolve=%+v", resolver.confirmed, resolver.resolve)
	}
	// A refused license confirmation stops before the install.
	resolver.confirmErr, resolver.resolve = ErrConsentRequired, ActivationResolveRequest{}
	if err := mutate(1, waiting.Installation.VerificationID); !errors.Is(err, ErrConsentRequired) ||
		resolver.resolve.Action != "" {
		t.Fatalf("refused confirmation err=%v resolve=%+v", err, resolver.resolve)
	}
}

// A license service without migration 076 (or unreachable for the pending sync) changes nothing.
func TestProductionWithoutPendingSupportBehavesAsBefore(t *testing.T) {
	tenantID := uuid.New()
	installed := mergeView(tenantID, "acme.audit", "1.0.0", StatusEnabled, "")
	resolver := &pendingResolver{pendingErr: ErrFactDenied}
	domain, err := NewProductionDomain(mergeRepository{heads: map[uuid.UUID]InstallationView{
		installed.Installation.AuthorizationID: installed}}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "list-2", Username: "a"}
	page, err := domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 20})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list=%+v err=%v", page.Items, err)
	}
	authorized := mergeView(tenantID, "acme.new", "1.0.0", StatusPendingConfirmation, "authorized")
	resolver.remote = Page{Items: []InstallationView{authorized}}
	actor.RequestID = "confirm-2"
	_, err = domain.Mutate(context.Background(), actor, MutationRequest{TenantID: tenantID,
		AuthorizationID: authorized.Installation.AuthorizationID, VerificationID: authorized.Installation.VerificationID,
		Action: ActionConfirm, ExpectedRevision: 3, IdempotencyKey: "confirm-2", RequestID: "confirm-2",
		ApprovedScopes: []string{"plugin.read"}})
	// One replay probe is refused (not a market confirmation); the install uses the revision the tenant saw.
	if !errors.Is(err, ErrFactDenied) || len(resolver.confirmed) != 1 || resolver.resolve.KnownLifecycleRevision != 3 {
		t.Fatalf("operator-confirmed install err=%v confirms=%d resolve=%+v", err, len(resolver.confirmed), resolver.resolve)
	}
}

// A retry after the license confirmation succeeded (the item is no longer pending) replays the stored
// confirmation and installs against the confirmed revision.
func TestProductionRetryAfterLicenseConfirmationReplays(t *testing.T) {
	tenantID := uuid.New()
	confirmed := mergeView(tenantID, "acme.market", "1.0.0", StatusPendingConfirmation, "authorized")
	confirmed.Installation.Revision = 2
	resolver := &pendingResolver{replays: map[string]uint64{"confirm-3": 2}}
	resolver.remote = Page{Items: []InstallationView{confirmed}}
	domain, err := NewProductionDomain(mergeRepository{heads: map[uuid.UUID]InstallationView{}}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "confirm-3", Username: "a"}
	_, err = domain.Mutate(context.Background(), actor, MutationRequest{TenantID: tenantID,
		AuthorizationID: confirmed.Installation.AuthorizationID, VerificationID: confirmed.Installation.VerificationID,
		Action: ActionConfirm, ExpectedRevision: 1, IdempotencyKey: "confirm-3", RequestID: "confirm-3",
		ApprovedScopes: []string{"plugin.read"}})
	if !errors.Is(err, ErrFactDenied) || len(resolver.confirmed) != 1 || resolver.resolve.KnownLifecycleRevision != 2 {
		t.Fatalf("retry err=%v confirms=%d resolve=%+v", err, len(resolver.confirmed), resolver.resolve)
	}
}
