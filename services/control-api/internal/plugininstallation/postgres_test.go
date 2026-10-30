package plugininstallation

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProductionPluginInstallationDomainResolvesForwardAndKeepsProtectiveActionsLocal(t *testing.T) {
	tenantID, authorizationID, installationID, verificationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	candidate := Candidate{TenantID: tenantID, ResourceScope: ResourceScopeTenant, EntrypointType: EntrypointExternalHTTPS, AuthorizationID: authorizationID, InstallationID: installationID,
		VerificationID: verificationID, PluginID: "acme.example", Version: "1.2.0",
		ManifestSHA256: digest("a"), ConfigurationSchemaSHA256: digest("1"),
		ManifestScopes: []string{"plugin.read"}, ApprovedScopes: []string{"plugin.read"}, SensitiveScopes: []string{}}
	current := InstallationView{Installation: installationFromCandidate(candidate, testNow())}
	current.Installation.Status, current.Installation.Revision, current.Installation.IdentityGeneration = StatusEnabled, 7, 2
	repository := &productionRepositoryTest{current: current, result: MutationResult{Installation: current.Installation,
		Receipt: Receipt{ID: uuid.New(), TenantID: tenantID, AuthorizationID: authorizationID,
			Action: ActionUpgrade, IdempotencyKey: "upgrade-1", RequestID: "request-1",
			FromRevision: 7, ToRevision: 8, Result: ReceiptUpgradeApplied, Snapshot: current.Installation}}}
	licenseCandidate := candidate
	licenseCandidate.TenantID = uuid.New()
	provider := &activationResolverTest{result: ActivationResult{Candidate: licenseCandidate,
		LifecycleStatus: "authorized", LifecycleRevision: 7, verified: true}}
	domain, err := NewProductionDomain(repository, provider)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "request-1"}
	_, err = domain.Mutate(context.Background(), actor, MutationRequest{TenantID: tenantID,
		AuthorizationID: authorizationID, VerificationID: verificationID, Action: ActionUpgrade,
		ExpectedRevision: 7, IdempotencyKey: "upgrade-1", RequestID: "request-1",
		ApprovedScopes: []string{"plugin.read"}, NewPermissionsConfirmed: true})
	if err != nil || provider.resolveCalls != 1 || provider.reportCalls != 1 || repository.command.Action != ActionUpgrade ||
		repository.command.Candidate.ManifestSHA256 != candidate.ManifestSHA256 ||
		repository.command.Candidate.TenantID != tenantID || repository.verifier == nil {
		t.Fatalf("forward mutation err=%v resolve=%d report=%d command=%+v", err,
			provider.resolveCalls, provider.reportCalls, repository.command)
	}
	repository.result = MutationResult{Installation: current.Installation, Receipt: Receipt{ID: uuid.New(),
		TenantID: tenantID, AuthorizationID: authorizationID, Action: ActionDisable,
		IdempotencyKey: "disable-1", RequestID: "request-1", FromRevision: 7, ToRevision: 8,
		Result: ReceiptDisabled, Reason: "containment", Snapshot: current.Installation}}
	_, err = domain.Mutate(context.Background(), actor, MutationRequest{TenantID: tenantID,
		AuthorizationID: authorizationID, Action: ActionDisable, ExpectedRevision: 7,
		IdempotencyKey: "disable-1", RequestID: "request-1", Reason: "containment"})
	if err != nil || provider.resolveCalls != 1 || provider.reportCalls != 2 || repository.command.Action != ActionDisable || repository.verifier != nil {
		t.Fatalf("protective mutation err=%v resolve=%d report=%d command=%+v", err,
			provider.resolveCalls, provider.reportCalls, repository.command)
	}
}

func TestProductionPluginInstallationDomainDiscoversInitialCandidatesWhenLocalStoreIsEmpty(t *testing.T) {
	tenantID, authorizationID, installationID, verificationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	candidate := Candidate{TenantID: tenantID, ResourceScope: ResourceScopeTenant, EntrypointType: EntrypointExternalHTTPS, AuthorizationID: authorizationID, InstallationID: installationID,
		VerificationID: verificationID, PluginID: "acme.example", Version: "1.2.0",
		ManifestSHA256: digest("a"), ConfigurationSchemaSHA256: digest("1"),
		ManifestScopes: []string{"plugin.read"}, ApprovedScopes: []string{"plugin.read"}}
	view := InstallationView{Installation: installationFromCandidate(candidate, testNow()), AuthorizationStatus: "authorized"}
	view.Installation.Status, view.Installation.Revision = StatusPendingConfirmation, 2
	repository := &productionRepositoryTest{}
	provider := &activationResolverTest{discovery: Page{Items: []InstallationView{view}}}
	domain, err := NewProductionDomain(repository, provider)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "discover-1"}
	page, err := domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 50})
	if err != nil || provider.discoverCalls != 1 || len(page.Items) != 1 ||
		provider.discoveryRequest.TenantID != tenantID ||
		page.Items[0].Installation.AuthorizationID != authorizationID ||
		page.Items[0].Installation.VerificationID != verificationID {
		t.Fatalf("discovery page=%+v calls=%d err=%v", page, provider.discoverCalls, err)
	}
}

func TestProductionPluginInstallationDomainPreflightsRemoteCursorAndMapsLifecycleActions(t *testing.T) {
	tenantID := uuid.New()
	repository := &productionRepositoryTest{}
	provider := &activationResolverTest{}
	domain, err := NewProductionDomain(repository, provider)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "discover-next-1"}
	cursor := "license:" + uuid.NewString()
	if _, err := domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 50, Cursor: cursor}); err != nil || repository.listCalls != 1 || provider.discoverCalls != 1 ||
		provider.discoveryRequest.Cursor != cursor {
		t.Fatalf("remote cursor err=%v local_calls=%d discovery=%+v", err, repository.listCalls,
			provider.discoveryRequest)
	}
	if lifecycleReportAction(ReceiptDisabled) != ActionDisable ||
		lifecycleReportAction(ReceiptUninstalled) != ActionUninstall ||
		lifecycleReportAction(ReceiptResumed) != "enable" || !validLifecycleReportRevision("enable", 2, 3) ||
		!validLifecycleReportRevision(ReceiptInstalled, 0, 1) ||
		validLifecycleReportRevision(ActionDisable, 0, 1) {
		t.Fatal("lifecycle receipt mapping or revision validation is not fail closed")
	}
}

func TestPluginInstallationPostgresSourceLocksRechecksPersistsAndAudits(t *testing.T) {
	encoded, err := os.ReadFile("postgres.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(encoded)
	for _, required := range []string{
		"pg_advisory_xact_lock(hashtextextended('plugin-installation:'",
		"auth_sessions AS session",
		"permission_name=$4",
		"FOR UPDATE",
		"plugin_installation_receipts",
		"request_digest",
		"response_snapshot",
		"audit.Event{",
		"plugin_installation_heads",
		"ORDER BY updated_at DESC,authorization_id DESC",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("postgres source missing %q", required)
		}
	}
}

type productionRepositoryTest struct {
	current   InstallationView
	result    MutationResult
	command   Command
	verifier  CandidateVerifier
	listCalls int
}

func (repository *productionRepositoryTest) List(context.Context, Actor, ListRequest) (Page, error) {
	repository.listCalls++
	if repository.current.Installation.AuthorizationID == uuid.Nil {
		return Page{Items: []InstallationView{}}, nil
	}
	return Page{Items: []InstallationView{repository.current}}, nil
}

func (repository *productionRepositoryTest) Get(context.Context, Actor, uuid.UUID) (InstallationView, error) {
	return repository.current, nil
}

func (*productionRepositoryTest) HasReceipt(context.Context, Actor, uuid.UUID, string) (bool, error) {
	return false, nil
}

func (repository *productionRepositoryTest) Apply(_ context.Context, _ Actor, command Command,
	verifier CandidateVerifier) (MutationResult, error) {
	repository.command, repository.verifier = command, verifier
	return repository.result, nil
}

type activationResolverTest struct {
	result           ActivationResult
	discovery        Page
	discoveryRequest CandidateDiscoveryRequest
	resolveCalls     int
	discoverCalls    int
	reportCalls      int
}

func (resolver *activationResolverTest) Resolve(context.Context, ActivationResolveRequest) (ActivationResult, error) {
	resolver.resolveCalls++
	return resolver.result, nil
}

func (resolver *activationResolverTest) Discover(_ context.Context, request CandidateDiscoveryRequest) (Page, error) {
	resolver.discoverCalls++
	resolver.discoveryRequest = request
	return resolver.discovery, nil
}

func (resolver *activationResolverTest) ReportLifecycle(_ context.Context,
	request LifecycleReportRequest) (LifecycleReportResult, error) {
	resolver.reportCalls++
	return LifecycleReportResult{AuthorizationID: request.Receipt.AuthorizationID,
		LifecycleRevision: request.Receipt.ToRevision, Status: request.Receipt.Snapshot.Status}, nil
}

func testNow() time.Time {
	return time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
}
