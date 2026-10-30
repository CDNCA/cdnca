package plugininstallation

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// 报告 A：平台主题（resource_scope=platform）只在主控平台作用域里出现并由平台管理员确认；
// 租户作用域既看不到、也确认不了它；平台作用域也看不到、确认不了租户扩展。
func scopedView(scopeID uuid.UUID, pluginID, resourceScope, status, remoteStatus string) InstallationView {
	view := mergeView(scopeID, pluginID, "1.0.0", status, remoteStatus)
	view.Installation.ResourceScope = resourceScope
	if resourceScope == ResourceScopePlatform {
		view.Installation.EntrypointType = EntrypointTheme
	}
	return view
}

func TestProductionSeparatesPlatformAndTenantResourceScopes(t *testing.T) {
	platformScope, tenantScope := uuid.New(), uuid.New()
	theme := scopedView(uuid.Nil, "acme.theme", ResourceScopePlatform, StatusPendingConfirmation, StatusPendingConfirmation)
	theme.Installation.Revision = 1
	extension := scopedView(uuid.Nil, "acme.extension", ResourceScopeTenant, StatusPendingConfirmation, StatusPendingConfirmation)
	extension.Installation.Revision = 1
	resolver := &pendingResolver{pending: Page{Items: []InstallationView{theme, extension}}, newRevision: 2}
	domain, err := NewProductionDomain(mergeRepository{heads: map[uuid.UUID]InstallationView{}}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	platformActor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: platformScope,
		ScopeKind: ResourceScopePlatform, RequestID: "platform-list", Username: "platform-admin"}
	tenantActor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantScope,
		ScopeKind: ResourceScopeTenant, RequestID: "tenant-list", Username: "tenant-admin"}

	// Discovery projects remote candidates onto the caller's local scope, then keeps only its resource scope.
	resolver.pending = Page{Items: []InstallationView{relabel(theme, platformScope), relabel(extension, platformScope)}}
	page, err := domain.List(context.Background(), platformActor, ListRequest{TenantID: platformScope, Limit: 20})
	if err != nil || len(page.Items) != 1 || page.Items[0].Installation.PluginID != "acme.theme" {
		t.Fatalf("platform list=%+v err=%v", page.Items, err)
	}
	resolver.pending = Page{Items: []InstallationView{relabel(theme, tenantScope), relabel(extension, tenantScope)}}
	page, err = domain.List(context.Background(), tenantActor, ListRequest{TenantID: tenantScope, Limit: 20})
	if err != nil || len(page.Items) != 1 || page.Items[0].Installation.PluginID != "acme.extension" {
		t.Fatalf("tenant list=%+v err=%v", page.Items, err)
	}
	if _, err := domain.Get(context.Background(), tenantActor, theme.Installation.AuthorizationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant get of platform theme err=%v", err)
	}

	// A tenant cannot confirm the platform theme: no license confirmation is sent.
	tenantActor.RequestID = "tenant-confirm"
	_, err = domain.Mutate(context.Background(), tenantActor, MutationRequest{TenantID: tenantScope,
		AuthorizationID: theme.Installation.AuthorizationID, VerificationID: theme.Installation.VerificationID,
		Action: ActionConfirm, ExpectedRevision: 1, IdempotencyKey: "tenant-confirm", RequestID: "tenant-confirm",
		ApprovedScopes: []string{"plugin.read"}, SensitivePermissionsConfirmed: true})
	if !errors.Is(err, ErrFactDenied) || len(resolver.confirmed) != 0 {
		t.Fatalf("tenant confirm of platform theme err=%v confirms=%d", err, len(resolver.confirmed))
	}

	// The platform administrator confirms; the signed activation must also say platform.
	resolver.pending = Page{Items: []InstallationView{relabel(theme, platformScope)}}
	platformActor.RequestID = "platform-confirm"
	_, err = domain.Mutate(context.Background(), platformActor, MutationRequest{TenantID: platformScope,
		AuthorizationID: theme.Installation.AuthorizationID, VerificationID: theme.Installation.VerificationID,
		Action: ActionConfirm, ExpectedRevision: 1, IdempotencyKey: "platform-confirm", RequestID: "platform-confirm",
		ApprovedScopes: []string{"plugin.read"}, SensitivePermissionsConfirmed: true})
	if len(resolver.confirmed) != 1 || resolver.confirmed[0].Username != "platform-admin" ||
		resolver.resolve.Action != ActivationInstall {
		t.Fatalf("platform confirm err=%v confirmed=%+v resolve=%+v", err, resolver.confirmed, resolver.resolve)
	}
}

// The activation fact decides the scope: a candidate signed for another resource scope is refused before
// any local head is written.
func TestProductionRefusesActivationForAnotherResourceScope(t *testing.T) {
	platformScope := uuid.New()
	extension := scopedView(platformScope, "acme.extension", ResourceScopeTenant, StatusPendingConfirmation, "authorized")
	candidate := candidateFromInstallation(extension.Installation)
	resolver := &scopedActivationResolver{candidate: candidate}
	resolver.remote = Page{Items: []InstallationView{extension}}
	repository := &recordingRepository{}
	domain, err := NewProductionDomain(repository, resolver)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: platformScope, ScopeKind: ResourceScopePlatform,
		RequestID: "platform-confirm-2", Username: "platform-admin"}
	_, err = domain.Mutate(context.Background(), actor, MutationRequest{TenantID: platformScope,
		AuthorizationID: candidate.AuthorizationID, VerificationID: candidate.VerificationID, Action: ActionConfirm,
		ExpectedRevision: 3, IdempotencyKey: "platform-confirm-2", RequestID: "platform-confirm-2",
		ApprovedScopes: []string{"plugin.read"}})
	if !errors.Is(err, ErrFactDenied) || repository.applied {
		t.Fatalf("cross-scope activation err=%v applied=%v", err, repository.applied)
	}
}

func relabel(view InstallationView, scopeID uuid.UUID) InstallationView {
	view.Installation.TenantID = scopeID
	return view
}

type scopedActivationResolver struct {
	mergeResolver
	candidate Candidate
}

func (resolver *scopedActivationResolver) Resolve(_ context.Context, request ActivationResolveRequest) (ActivationResult, error) {
	resolver.resolve = request
	return ActivationResult{Candidate: resolver.candidate, verified: true}, nil
}

type recordingRepository struct {
	mergeRepository
	applied bool
}

func (*recordingRepository) HasReceipt(context.Context, Actor, uuid.UUID, string) (bool, error) {
	return false, nil
}

func (repository *recordingRepository) Apply(context.Context, Actor, Command, CandidateVerifier) (MutationResult, error) {
	repository.applied = true
	return MutationResult{}, errors.New("not used")
}
