package plugininstallation

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// 主控平台管理员确认全部可安装插件——平台主题、规则包装在平台作用域；
// 租户扩展（页面插件、外部服务）也在平台作用域确认并选择装给哪些租户。租户控制台不再看到候选、也不能确认。
func scopedView(scopeID uuid.UUID, pluginID, resourceScope, status, remoteStatus string) InstallationView {
	view := mergeView(scopeID, pluginID, "1.0.0", status, remoteStatus)
	view.Installation.ResourceScope = resourceScope
	if resourceScope == ResourceScopePlatform {
		view.Installation.EntrypointType = EntrypointTheme
	}
	return view
}

func TestProductionPlatformAdministratorConfirmsAllResourceScopes(t *testing.T) {
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

	// The platform administrator sees both waiting plugins: the theme and the tenant extension.
	resolver.pending = Page{Items: []InstallationView{relabel(theme, platformScope), relabel(extension, platformScope)}}
	page, err := domain.List(context.Background(), platformActor, ListRequest{TenantID: platformScope, Limit: 20})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("platform list=%+v err=%v", page.Items, err)
	}
	// A tenant is offered nothing to confirm and cannot read a candidate.
	resolver.pending = Page{Items: []InstallationView{relabel(theme, tenantScope), relabel(extension, tenantScope)}}
	page, err = domain.List(context.Background(), tenantActor, ListRequest{TenantID: tenantScope, Limit: 20})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("tenant list=%+v err=%v", page.Items, err)
	}
	for _, view := range []InstallationView{theme, extension} {
		if _, err := domain.Get(context.Background(), tenantActor, view.Installation.AuthorizationID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("tenant get of candidate %s err=%v", view.Installation.PluginID, err)
		}
	}

	// A tenant cannot confirm either plugin: no license confirmation is sent.
	tenantActor.RequestID = "tenant-confirm"
	for _, view := range []InstallationView{theme, extension} {
		_, err = domain.Mutate(context.Background(), tenantActor, MutationRequest{TenantID: tenantScope,
			AuthorizationID: view.Installation.AuthorizationID, VerificationID: view.Installation.VerificationID,
			Action: ActionConfirm, ExpectedRevision: 1, IdempotencyKey: "tenant-confirm", RequestID: "tenant-confirm",
			ApprovedScopes: []string{"plugin.read"}, SensitivePermissionsConfirmed: true})
		if !errors.Is(err, ErrPlatformManaged) || len(resolver.confirmed) != 0 {
			t.Fatalf("tenant confirm of %s err=%v confirms=%d", view.Installation.PluginID, err, len(resolver.confirmed))
		}
	}

	// Targets belong to tenant plugins only: a theme confirmed with targets is refused before the license service.
	resolver.pending = Page{Items: []InstallationView{relabel(theme, platformScope), relabel(extension, platformScope)}}
	platformActor.RequestID = "platform-confirm"
	confirm := func(view InstallationView, key string, targets *Targets) error {
		platformActor.RequestID = key
		_, err := domain.Mutate(context.Background(), platformActor, MutationRequest{TenantID: platformScope,
			AuthorizationID: view.Installation.AuthorizationID, VerificationID: view.Installation.VerificationID,
			Action: ActionConfirm, ExpectedRevision: 1, IdempotencyKey: key, RequestID: key,
			ApprovedScopes: []string{"plugin.read"}, SensitivePermissionsConfirmed: true, Targets: targets})
		return err
	}
	if err := confirm(theme, "theme-targets", &Targets{AllTenants: true}); !errors.Is(err, ErrTargetsInvalid) || len(resolver.confirmed) != 0 {
		t.Fatalf("theme with targets err=%v confirms=%d", err, len(resolver.confirmed))
	}
	if err := confirm(extension, "extension-no-targets", nil); !errors.Is(err, ErrTargetsInvalid) || len(resolver.confirmed) != 0 {
		t.Fatalf("extension without targets err=%v confirms=%d", err, len(resolver.confirmed))
	}
	_ = confirm(theme, "platform-confirm", nil)
	if len(resolver.confirmed) != 1 || resolver.confirmed[0].Username != "platform-admin" ||
		resolver.resolve.Action != ActivationInstall {
		t.Fatalf("platform theme confirm confirmed=%+v resolve=%+v", resolver.confirmed, resolver.resolve)
	}
	_ = confirm(extension, "extension-confirm", &Targets{TenantScopeIDs: []uuid.UUID{tenantScope}})
	if len(resolver.confirmed) != 2 || resolver.confirmed[1].AuthorizationID != extension.Installation.AuthorizationID {
		t.Fatalf("platform extension confirm confirmed=%+v", resolver.confirmed)
	}
}

// The activation fact still decides the plugin: a tenant plugin the platform administrator confirms without
// naming its tenants is refused before any local head is written, and so is one confirmed with targets that
// turns out (signed) to be a platform resource.
func TestProductionRefusesActivationWithoutMatchingTargets(t *testing.T) {
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
	request := MutationRequest{TenantID: platformScope,
		AuthorizationID: candidate.AuthorizationID, VerificationID: candidate.VerificationID, Action: ActionConfirm,
		ExpectedRevision: 3, IdempotencyKey: "platform-confirm-2", RequestID: "platform-confirm-2",
		ApprovedScopes: []string{"plugin.read"}}
	if _, err = domain.Mutate(context.Background(), actor, request); !errors.Is(err, ErrTargetsInvalid) || repository.applied {
		t.Fatalf("no targets err=%v applied=%v", err, repository.applied)
	}
	theme := candidate
	theme.ResourceScope, theme.EntrypointType = ResourceScopePlatform, EntrypointTheme
	resolver.candidate = theme
	request.Targets = &Targets{AllTenants: true}
	if _, err = domain.Mutate(context.Background(), actor, request); !errors.Is(err, ErrTargetsInvalid) || repository.applied {
		t.Fatalf("platform resource with targets err=%v applied=%v", err, repository.applied)
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
