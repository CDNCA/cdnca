package plugininstallation

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type mergeRepository struct {
	heads map[uuid.UUID]InstallationView
}

func (repository mergeRepository) List(context.Context, Actor, ListRequest) (Page, error) {
	page := Page{Items: []InstallationView{}}
	for _, head := range repository.heads {
		page.Items = append(page.Items, head)
	}
	return page, nil
}

func (repository mergeRepository) Get(_ context.Context, _ Actor, id uuid.UUID) (InstallationView, error) {
	if head, found := repository.heads[id]; found {
		return head, nil
	}
	return InstallationView{}, ErrNotFound
}

func (mergeRepository) HasReceipt(context.Context, Actor, uuid.UUID, string) (bool, error) {
	return false, nil
}

func (mergeRepository) Apply(context.Context, Actor, Command, CandidateVerifier) (MutationResult, error) {
	return MutationResult{}, errors.New("not used")
}

type mergeResolver struct {
	remote  Page
	fail    bool
	resolve ActivationResolveRequest
}

func (resolver *mergeResolver) Resolve(_ context.Context, request ActivationResolveRequest) (ActivationResult, error) {
	resolver.resolve = request
	return ActivationResult{}, ErrFactDenied
}

func (resolver *mergeResolver) Discover(context.Context, CandidateDiscoveryRequest) (Page, error) {
	if resolver.fail {
		return Page{}, ErrFactUnavailable
	}
	return resolver.remote, nil
}

func (*mergeResolver) ReportLifecycle(context.Context, LifecycleReportRequest) (LifecycleReportResult, error) {
	return LifecycleReportResult{}, nil
}

func mergeView(tenantID uuid.UUID, pluginID, version, status, remoteStatus string) InstallationView {
	candidate := Candidate{TenantID: tenantID, ResourceScope: ResourceScopeTenant, EntrypointType: EntrypointExternalHTTPS, AuthorizationID: uuid.New(), InstallationID: uuid.New(),
		VerificationID: uuid.New(), PluginID: pluginID, Version: version, ManifestSHA256: digest("a"),
		ConfigurationSchemaSHA256: digest("1"), ManifestScopes: []string{"plugin.read"},
		ApprovedScopes: []string{"plugin.read"}, SensitiveScopes: []string{}}
	view := InstallationView{Installation: installationFromCandidate(candidate, testNow()),
		AuthorizationStatus: remoteStatus}
	view.Installation.Status, view.Installation.Revision = status, 3
	return view
}

func TestProductionListMergesNewAuthorizationsAndAnnotatesInstalledPlugins(t *testing.T) {
	tenantID := uuid.New()
	installed := mergeView(tenantID, "acme.audit", "1.0.0", StatusEnabled, "")
	upgraded := installed
	upgraded.Installation.VerificationID, upgraded.Installation.Version = uuid.New(), "1.1.0"
	upgraded.AuthorizationStatus = StatusEnabled
	fresh := mergeView(tenantID, "acme.node-probe", "1.0.0", StatusPendingConfirmation, "authorized")
	resolver := &mergeResolver{remote: Page{Items: []InstallationView{upgraded, fresh}}}
	domain, err := NewProductionDomain(mergeRepository{heads: map[uuid.UUID]InstallationView{
		installed.Installation.AuthorizationID: installed}}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "merge-1"}
	page, err := domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 50})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	first, second := page.Items[0], page.Items[1]
	if first.Installation.AuthorizationID != installed.Installation.AuthorizationID ||
		first.AuthorizationStatus != StatusEnabled || first.AvailableUpgrade == nil ||
		first.AvailableUpgrade.Version != "1.1.0" ||
		first.AvailableUpgrade.VerificationID != upgraded.Installation.VerificationID {
		t.Fatalf("installed row=%+v upgrade=%+v", first, first.AvailableUpgrade)
	}
	if second.Installation.AuthorizationID != fresh.Installation.AuthorizationID ||
		second.Installation.Status != StatusPendingConfirmation {
		t.Fatalf("new authorization row=%+v", second)
	}

	paused := installed
	paused.AuthorizationStatus = StatusDisabled
	resolver.remote = Page{Items: []InstallationView{paused}}
	page, err = domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 50})
	if err != nil || len(page.Items) != 1 || page.Items[0].AuthorizationStatus != StatusDisabled ||
		page.Items[0].AvailableUpgrade != nil {
		t.Fatalf("paused page=%+v err=%v", page, err)
	}

	resolver.fail = true
	page, err = domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 50})
	if err != nil || len(page.Items) != 1 || page.Items[0].AuthorizationStatus != "" {
		t.Fatalf("license offline must keep the local page, page=%+v err=%v", page, err)
	}
}

func TestProductionListOffersOnlyUninstalledAuthorizationsFromEmptyStore(t *testing.T) {
	tenantID := uuid.New()
	enabled := mergeView(tenantID, "acme.audit", "1.0.0", StatusEnabled, StatusEnabled)
	fresh := mergeView(tenantID, "acme.node-probe", "1.0.0", StatusPendingConfirmation, "authorized")
	domain, err := NewProductionDomain(mergeRepository{heads: map[uuid.UUID]InstallationView{}},
		&mergeResolver{remote: Page{Items: []InstallationView{enabled, fresh}}})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "merge-2"}
	page, err := domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 50})
	if err != nil || len(page.Items) != 1 || page.Items[0].Installation.PluginID != "acme.node-probe" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}

func TestProductionUpgradeDoesNotSendControlRevisionAsLicenseRevision(t *testing.T) {
	tenantID := uuid.New()
	installed := mergeView(tenantID, "acme.audit", "1.0.0", StatusEnabled, "")
	resolver := &mergeResolver{}
	domain, err := NewProductionDomain(mergeRepository{heads: map[uuid.UUID]InstallationView{
		installed.Installation.AuthorizationID: installed}}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "upgrade-1"}
	_, err = domain.Mutate(context.Background(), actor, MutationRequest{TenantID: tenantID,
		AuthorizationID: installed.Installation.AuthorizationID, VerificationID: uuid.New(), Action: ActionUpgrade,
		ExpectedRevision: 3, IdempotencyKey: "upgrade-1", RequestID: "upgrade-1",
		ApprovedScopes: []string{"plugin.read"}})
	if !errors.Is(err, ErrFactDenied) || resolver.resolve.Action != ActivationUpgrade ||
		resolver.resolve.KnownLifecycleRevision != 0 {
		t.Fatalf("err=%v resolve=%+v", err, resolver.resolve)
	}
}
