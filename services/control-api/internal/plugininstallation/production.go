package plugininstallation

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/mod/semver"
)

type ActivationResolver interface {
	Resolve(context.Context, ActivationResolveRequest) (ActivationResult, error)
	Discover(context.Context, CandidateDiscoveryRequest) (Page, error)
	ReportLifecycle(context.Context, LifecycleReportRequest) (LifecycleReportResult, error)
}

// PendingConfirmer is implemented by activation resolvers that talk to a license service with migration 076:
// market authorizations wait in pending_confirmation until this controller's administrator confirms them.
// Without it (or when the license service does not know the requests) the controller behaves as before:
// those authorizations only appear once a license operator confirmed them.
type PendingConfirmer interface {
	DiscoverPending(context.Context, CandidateDiscoveryRequest) (Page, error)
	ConfirmPending(context.Context, PendingConfirmRequest) (PendingConfirmResult, error)
}

type CandidateDiscoveryRequest struct {
	RequestID string
	TenantID  uuid.UUID
	Limit     int
	Cursor    string
	Status    string
	PluginID  string
}

type LifecycleReportRequest struct {
	Receipt Receipt
}

type LifecycleReportResult struct {
	AuthorizationID   uuid.UUID
	LifecycleRevision uint64
	Status            string
}

type InstallationRepository interface {
	List(context.Context, Actor, ListRequest) (Page, error)
	Get(context.Context, Actor, uuid.UUID) (InstallationView, error)
	Apply(context.Context, Actor, Command, CandidateVerifier) (MutationResult, error)
	// HasReceipt reports whether this scope already holds a persisted receipt of the authorization under the
	// idempotency key; it requires the manage permission like Apply.
	HasReceipt(ctx context.Context, actor Actor, authorizationID uuid.UUID, idempotencyKey string) (bool, error)
}

type ProductionDomain struct {
	repository InstallationRepository
	activation ActivationResolver
}

func NewProductionDomain(repository InstallationRepository, activation ActivationResolver) (*ProductionDomain, error) {
	if repository == nil || activation == nil {
		return nil, ErrInvalidInput
	}
	return &ProductionDomain{repository: repository, activation: activation}, nil
}

func (domain *ProductionDomain) List(ctx context.Context, actor Actor, request ListRequest) (Page, error) {
	page, err := domain.list(ctx, actor, request)
	if err != nil || request.Cursor != "" {
		return page, err
	}
	// Market authorizations waiting for this controller's administrator, ahead of the regular candidates.
	pending := domain.pending(ctx, actor, request)
	if len(pending) == 0 {
		return page, nil
	}
	seen := make(map[uuid.UUID]bool, len(page.Items))
	for _, item := range page.Items {
		seen[item.Installation.AuthorizationID] = true
	}
	merged := make([]InstallationView, 0, len(page.Items)+len(pending))
	for _, item := range pending {
		if !seen[item.Installation.AuthorizationID] && len(merged) < request.Limit {
			merged = append(merged, item)
		}
	}
	for _, item := range page.Items {
		if len(merged) < request.Limit {
			merged = append(merged, item)
		}
	}
	page.Items = merged
	return page, nil
}

// pending returns this installation's market authorizations waiting for the controller administrator
// (AuthorizationStatus pending_confirmation, local status pending_confirmation). Any failure, including a
// license service without migration 076, yields none: the controller then behaves as before.
func (domain *ProductionDomain) pending(ctx context.Context, actor Actor, request ListRequest) []InstallationView {
	confirmer, ok := domain.activation.(PendingConfirmer)
	if !ok {
		return nil
	}
	if request.Status != "" && request.Status != StatusPendingConfirmation {
		return nil
	}
	page, err := confirmer.DiscoverPending(ctx, CandidateDiscoveryRequest{RequestID: actor.RequestID,
		TenantID: actor.TenantID, Limit: 100, PluginID: request.PluginID})
	if err != nil {
		return nil
	}
	items := make([]InstallationView, 0, len(page.Items))
	for _, item := range page.Items {
		if item.Installation.TenantID == actor.TenantID && item.Installation.ResourceScope == actor.resourceScope() &&
			item.AuthorizationStatus == StatusPendingConfirmation {
			items = append(items, item)
		}
	}
	return items
}

// pendingElsewhere reports a pending market authorization of this installation that belongs to the other
// resource scope (a platform theme seen from a tenant, or a tenant plugin seen from the platform scope).
func (domain *ProductionDomain) pendingElsewhere(ctx context.Context, actor Actor, authorizationID uuid.UUID) bool {
	confirmer, ok := domain.activation.(PendingConfirmer)
	if !ok {
		return false
	}
	page, err := confirmer.DiscoverPending(ctx, CandidateDiscoveryRequest{RequestID: actor.RequestID,
		TenantID: actor.TenantID, Limit: 100})
	if err != nil {
		return false
	}
	for _, item := range page.Items {
		if item.Installation.AuthorizationID == authorizationID && item.Installation.ResourceScope != actor.resourceScope() {
			return true
		}
	}
	return false
}

func (domain *ProductionDomain) list(ctx context.Context, actor Actor, request ListRequest) (Page, error) {
	if ctx == nil || domain == nil || domain.repository == nil || domain.activation == nil {
		return Page{}, ErrFactUnavailable
	}
	if strings.HasPrefix(request.Cursor, "license:") {
		preflight := request
		preflight.Cursor = ""
		if _, err := domain.repository.List(ctx, actor, preflight); err != nil {
			return Page{}, err
		}
		return domain.discover(ctx, actor, request)
	}
	page, err := domain.repository.List(ctx, actor, request)
	if err != nil {
		return page, err
	}
	if len(page.Items) == 0 && request.Cursor == "" {
		return domain.discover(ctx, actor, request)
	}
	remote, err := domain.remoteAuthorizations(ctx, actor)
	if err != nil {
		// The local store stays authoritative while the license service is unreachable.
		return page, nil
	}
	local := make(map[uuid.UUID]bool, len(page.Items))
	for index := range page.Items {
		local[page.Items[index].Installation.AuthorizationID] = true
		annotateInstallation(&page.Items[index], remote)
	}
	if request.Cursor != "" {
		return page, nil
	}
	// New authorizations granted after the first install. The local page is the authority for installed rows;
	// remote rows only add plugins this installation has never confirmed.
	known, err := domain.knownAuthorizations(ctx, actor, remote)
	if err != nil {
		return page, nil
	}
	for _, candidate := range remote {
		if len(page.Items) >= request.Limit {
			break
		}
		id := candidate.Installation.AuthorizationID
		if local[id] || known[id] || candidate.AuthorizationStatus != "authorized" ||
			request.Status != "" && request.Status != StatusPendingConfirmation ||
			request.PluginID != "" && request.PluginID != candidate.Installation.PluginID {
			continue
		}
		page.Items = append(page.Items, candidate)
	}
	return page, nil
}

func (domain *ProductionDomain) Get(ctx context.Context, actor Actor,
	authorizationID uuid.UUID) (InstallationView, error) {
	if domain == nil || domain.repository == nil {
		return InstallationView{}, ErrFactUnavailable
	}
	result, err := domain.repository.Get(ctx, actor, authorizationID)
	if err == nil {
		if remote, remoteErr := domain.remoteAuthorizations(ctx, actor); remoteErr == nil {
			annotateInstallation(&result, remote)
		}
		return result, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return result, err
	}
	page, discoveryErr := domain.discover(ctx, actor, ListRequest{TenantID: actor.TenantID, Limit: 100})
	if discoveryErr != nil {
		return InstallationView{}, discoveryErr
	}
	for _, candidate := range page.Items {
		if candidate.Installation.AuthorizationID == authorizationID &&
			candidate.AuthorizationStatus == "authorized" {
			return candidate, nil
		}
	}
	for _, candidate := range domain.pending(ctx, actor, ListRequest{TenantID: actor.TenantID, Limit: 100}) {
		if candidate.Installation.AuthorizationID == authorizationID {
			return candidate, nil
		}
	}
	return InstallationView{}, ErrNotFound
}

// remoteAuthorizations reads every non-uninstalled platform authorization of this installation (one signed page
// per 100 rows), keyed by authorization ID.
func (domain *ProductionDomain) remoteAuthorizations(ctx context.Context,
	actor Actor) (map[uuid.UUID]InstallationView, error) {
	result := map[uuid.UUID]InstallationView{}
	cursor := ""
	for range 10 {
		page, err := domain.discoverAll(ctx, actor, ListRequest{TenantID: actor.TenantID, Limit: 100, Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, item := range page.Items {
			result[item.Installation.AuthorizationID] = item
		}
		if page.NextCursor == "" {
			return result, nil
		}
		cursor = page.NextCursor
	}
	return result, nil
}

// knownAuthorizations reports which remote authorizations already have a local head beyond the current page
// (for example an uninstalled head filtered out by status), so they are not offered for confirmation again.
func (domain *ProductionDomain) knownAuthorizations(ctx context.Context, actor Actor,
	remote map[uuid.UUID]InstallationView) (map[uuid.UUID]bool, error) {
	known := map[uuid.UUID]bool{}
	for id, candidate := range remote {
		if candidate.AuthorizationStatus != "authorized" {
			continue
		}
		if _, err := domain.repository.Get(ctx, actor, id); err == nil {
			known[id] = true
		} else if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	return known, nil
}

// annotateInstallation attaches the platform authorization state and an operator-approved newer version.
func annotateInstallation(view *InstallationView, remote map[uuid.UUID]InstallationView) {
	candidate, found := remote[view.Installation.AuthorizationID]
	if !found || view.Installation.Status == StatusUninstalled {
		return
	}
	view.AuthorizationStatus = candidate.AuthorizationStatus
	view.PausedBy, view.PausedReason = candidate.PausedBy, candidate.PausedReason
	remoteVersion, localVersion := "v"+candidate.Installation.Version, "v"+view.Installation.Version
	if candidate.AuthorizationStatus != "authorized" &&
		candidate.Installation.VerificationID != view.Installation.VerificationID &&
		semver.IsValid(remoteVersion) && semver.Compare(remoteVersion, localVersion) > 0 {
		view.AvailableUpgrade = &AvailableUpgrade{VerificationID: candidate.Installation.VerificationID,
			Version:         candidate.Installation.Version,
			ManifestScopes:  append([]string{}, candidate.Installation.ManifestScopes...),
			ApprovedScopes:  append([]string{}, candidate.Installation.ApprovedScopes...),
			SensitiveScopes: append([]string{}, candidate.Installation.SensitiveScopes...),
			NewScopes:       append([]string{}, candidate.NewScopes...)}
	}
}

func (domain *ProductionDomain) Mutate(ctx context.Context, actor Actor,
	request MutationRequest) (InstallationView, error) {
	if ctx == nil || domain == nil || domain.repository == nil || domain.activation == nil ||
		actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil || actor.TenantID == uuid.Nil ||
		request.TenantID != actor.TenantID || request.AuthorizationID == uuid.Nil ||
		request.ExpectedRevision == 0 || request.RequestID != actor.RequestID {
		return InstallationView{}, ErrInvalidInput
	}
	command := Command{TenantID: request.TenantID, AuthorizationID: request.AuthorizationID,
		Action: request.Action, ExpectedRevision: request.ExpectedRevision,
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
		SensitivePermissionsConfirmed: request.SensitivePermissionsConfirmed,
		NewPermissionsConfirmed:       request.NewPermissionsConfirmed, Reason: request.Reason}
	var verifier CandidateVerifier
	switch request.Action {
	case ActionConfirm, ActionUpgrade:
		action := ActivationInstall
		if request.Action == ActionUpgrade {
			action = ActivationUpgrade
		}
		// The license and control revisions advance independently once a plugin is installed (the license also
		// records operator transitions). Only an initial install carries the license revision the tenant saw; an
		// upgrade is serialized by the local head CAS and by license lifecycle receipts instead.
		knownRevision := request.ExpectedRevision
		if request.Action == ActionUpgrade {
			knownRevision = 0
		}
		if request.Action == ActionConfirm && domain.pendingElsewhere(ctx, actor, request.AuthorizationID) {
			return InstallationView{}, ErrFactDenied
		}
		if request.Action == ActionConfirm {
			// A market authorization still waiting for this controller: the administrator's confirmation goes to
			// the license service first (pending_confirmation → authorized), then the install continues as usual.
			confirmed, err := domain.confirmPending(ctx, actor, request)
			if err != nil {
				return InstallationView{}, err
			}
			if confirmed != 0 {
				knownRevision = confirmed
			}
		}
		activation, err := domain.activation.Resolve(ctx, ActivationResolveRequest{RequestID: request.RequestID,
			IdempotencyKey: request.IdempotencyKey, VerificationID: request.VerificationID, Action: action,
			KnownLifecycleRevision: knownRevision,
			RequestedScopes:        append([]string{}, request.ApprovedScopes...)})
		if err != nil {
			return InstallationView{}, err
		}
		// The signed resource scope decides who confirms: never relabel a platform resource into a tenant
		// scope (or the reverse).
		if !activation.verified ||
			activation.Candidate.AuthorizationID != request.AuthorizationID ||
			activation.Candidate.VerificationID != request.VerificationID ||
			activation.Candidate.ResourceScope != actor.resourceScope() {
			return InstallationView{}, ErrFactDenied
		}
		activation.Candidate.TenantID = request.TenantID
		if err := activation.Verifier().VerifyCandidate(ctx, activation.Candidate, nil); err != nil {
			return InstallationView{}, ErrFactDenied
		}
		command.InstallationID = activation.Candidate.InstallationID
		command.Candidate = activation.Candidate
		command.Applied = true
		verifier = activation.Verifier()
	case ActionDisable, ActionUninstall:
		current, err := domain.repository.Get(ctx, actor, request.AuthorizationID)
		if err != nil {
			return InstallationView{}, err
		}
		command.InstallationID = current.Installation.InstallationID
		command.Candidate = candidateFromInstallation(current.Installation)
	case ActionResume:
		current, err := domain.repository.Get(ctx, actor, request.AuthorizationID)
		if err != nil {
			return InstallationView{}, err
		}
		// An exact retry of a resume that already committed (its lifecycle report succeeded or its outcome is
		// unknown) finds the local head enabled. Its persisted receipt decides: Apply replays it when the request
		// digest (scope, authorization, candidate, revision) matches and refuses any other request under the key,
		// then the report below is delivered again. Only a new request goes through the pause checks.
		replay, err := domain.repository.HasReceipt(ctx, actor, request.AuthorizationID, request.IdempotencyKey)
		if err != nil {
			return InstallationView{}, err
		}
		if replay {
			err = domain.requireResumeReplayable(ctx, actor, current.Installation, request.ExpectedRevision)
		} else {
			err = domain.requireOwnPause(ctx, actor, current.Installation)
		}
		if err != nil {
			return InstallationView{}, err
		}
		command.InstallationID = current.Installation.InstallationID
		command.Candidate = candidateFromInstallation(current.Installation)
	default:
		return InstallationView{}, ErrInvalidInput
	}
	result, err := domain.repository.Apply(ctx, actor, command, verifier)
	if err != nil {
		return InstallationView{}, err
	}
	if _, err := domain.activation.ReportLifecycle(ctx, LifecycleReportRequest{Receipt: result.Receipt}); err != nil {
		return InstallationView{}, fmt.Errorf("%w: report license lifecycle: %v", ErrResultUnknown, err)
	}
	return installationView(result.Installation), nil
}

// requireOwnPause checks the signed license snapshot before a resume: the authorization is still the one this
// controller installed (verification, version, digests and scopes unchanged, no new permission to approve) and it
// is disabled by this controller's own pause. A platform pause (operator, market delisting or advisory) is
// ErrPlatformPaused; an unreachable license service keeps the plugin paused (ErrFactUnavailable).
func (domain *ProductionDomain) requireOwnPause(ctx context.Context, actor Actor, local Installation) error {
	if local.Status != StatusDisabled {
		return ErrTransitionInvalid
	}
	remote, err := domain.remoteAuthorizations(ctx, actor)
	if err != nil {
		return err
	}
	candidate, found := remote[local.AuthorizationID]
	if !found || candidate.AuthorizationStatus != StatusDisabled {
		return ErrFactDenied
	}
	if !sameCurrentCandidate(local, candidateFromInstallation(candidate.Installation)) || len(candidate.NewScopes) > 0 {
		return ErrFactDenied
	}
	if candidate.PausedBy != PausedByInstallation {
		return ErrPlatformPaused
	}
	return nil
}

// requireResumeReplayable admits an exact resume retry only while that resume is still the head's last transition
// (enabled at expected+1: not paused again, uninstalled or moved on) and the signed license snapshot still names the
// same authorization, verification and scopes, either enabled (the report arrived) or paused by this controller
// (it did not). An operator or service pause, a revocation, an end or a permission drift is refused as for a new
// resume.
func (domain *ProductionDomain) requireResumeReplayable(ctx context.Context, actor Actor, local Installation,
	expectedRevision uint64) error {
	if local.Status != StatusEnabled || expectedRevision == ^uint64(0) || local.Revision != expectedRevision+1 {
		return ErrTransitionInvalid
	}
	remote, err := domain.remoteAuthorizations(ctx, actor)
	if err != nil {
		return err
	}
	candidate, found := remote[local.AuthorizationID]
	if !found || !sameCurrentCandidate(local, candidateFromInstallation(candidate.Installation)) || len(candidate.NewScopes) > 0 {
		return ErrFactDenied
	}
	switch {
	case candidate.AuthorizationStatus == StatusEnabled:
		return nil
	case candidate.AuthorizationStatus == StatusDisabled && candidate.PausedBy == PausedByInstallation:
		return nil
	case candidate.AuthorizationStatus == StatusDisabled:
		return ErrPlatformPaused
	default:
		return ErrFactDenied
	}
}

// confirmPending confirms the authorization with the license service when it is one of this installation's
// pending market authorizations, and returns its new license revision (0 when it was not pending).
func (domain *ProductionDomain) confirmPending(ctx context.Context, actor Actor, request MutationRequest) (uint64, error) {
	confirmer, ok := domain.activation.(PendingConfirmer)
	if !ok {
		return 0, nil
	}
	var target *InstallationView
	pending := domain.pending(ctx, actor, ListRequest{TenantID: actor.TenantID, Limit: 100})
	for index := range pending {
		if pending[index].Installation.AuthorizationID == request.AuthorizationID {
			target = &pending[index]
		}
	}
	if target != nil {
		if target.Installation.VerificationID != request.VerificationID {
			return 0, ErrFactDenied
		}
		if target.Installation.Revision != request.ExpectedRevision {
			return 0, ErrRevisionConflict
		}
	}
	if actor.Username == "" {
		if target != nil {
			return 0, ErrInvalidInput
		}
		return 0, nil
	}
	result, err := confirmer.ConfirmPending(ctx, PendingConfirmRequest{RequestID: actor.RequestID,
		IdempotencyKey: request.IdempotencyKey, AuthorizationID: request.AuthorizationID,
		VerificationID: request.VerificationID, ExpectedRevision: request.ExpectedRevision,
		ApprovedScopes:                append([]string{}, request.ApprovedScopes...),
		SensitivePermissionsConfirmed: request.SensitivePermissionsConfirmed,
		NewPermissionsConfirmed:       request.NewPermissionsConfirmed, UserID: actor.UserID, Username: actor.Username})
	if target == nil {
		// Not pending (any more): a retry after the license confirmation succeeded replays the stored result
		// under the same idempotency key; anything else is not a controller confirmation and installs as before.
		if err != nil {
			return 0, nil
		}
		return result.Revision, nil
	}
	if err != nil {
		return 0, err
	}
	return result.Revision, nil
}

// discover lists platform authorizations not yet installed here (license status authorized) as
// pending_confirmation candidates.
func (domain *ProductionDomain) discover(ctx context.Context, actor Actor, request ListRequest) (Page, error) {
	page, err := domain.discoverAll(ctx, actor, request)
	if err != nil {
		return Page{}, err
	}
	items := page.Items[:0]
	for _, item := range page.Items {
		if item.AuthorizationStatus == "authorized" {
			items = append(items, item)
		}
	}
	page.Items = items
	return page, nil
}

// discoverAll returns every non-uninstalled platform authorization page, including installed ones.
func (domain *ProductionDomain) discoverAll(ctx context.Context, actor Actor, request ListRequest) (Page, error) {
	page, err := domain.activation.Discover(ctx, CandidateDiscoveryRequest{RequestID: actor.RequestID,
		TenantID: actor.TenantID, Limit: request.Limit, Cursor: request.Cursor,
		Status: request.Status, PluginID: request.PluginID})
	if err != nil {
		return Page{}, err
	}
	items := make([]InstallationView, 0, len(page.Items))
	for _, item := range page.Items {
		if item.Installation.TenantID != actor.TenantID {
			return Page{}, ErrFactDenied
		}
		// Platform resources (themes, rule data packs) belong to the platform scope; tenant plugins to tenants.
		if item.Installation.ResourceScope == actor.resourceScope() {
			items = append(items, item)
		}
	}
	page.Items = items
	return page, nil
}

func candidateFromInstallation(value Installation) Candidate {
	return Candidate{TenantID: value.TenantID, InstallationID: value.InstallationID,
		AuthorizationID: value.AuthorizationID, VerificationID: value.VerificationID,
		PluginID: value.PluginID, Version: value.Version, ResourceScope: value.ResourceScope,
		EntrypointType:            value.EntrypointType,
		ManifestSHA256:            value.ManifestSHA256,
		ConfigurationSchemaSHA256: value.ConfigurationSchemaSHA256,
		ManifestScopes:            append([]string{}, value.ManifestScopes...),
		ApprovedScopes:            append([]string{}, value.ApprovedScopes...),
		SensitiveScopes:           append([]string{}, value.SensitiveScopes...)}
}
