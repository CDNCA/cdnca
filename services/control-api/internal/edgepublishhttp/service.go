package edgepublishhttp

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	tenantReadPermission   = "sites.read"
	tenantManagePermission = "sites.manage"
)

type Service struct {
	publications PublicationDomain
	rollouts     RolloutDomain
	commands     RolloutCommandDomain
	cursors      CursorCodec
	lockedReads  bool
}

func newRuntimeService(
	publications PublicationDomain,
	rollouts RolloutDomain,
	commands RolloutCommandDomain,
	cursors CursorCodec,
) (*Service, error) {
	service, err := NewService(publications, rollouts, cursors)
	if err != nil {
		return nil, err
	}
	if nilPort(commands) {
		return nil, ErrInvalidRequest
	}
	service.commands = commands
	service.lockedReads = true
	return service, nil
}

func NewService(publications PublicationDomain, rollouts RolloutDomain, cursors CursorCodec) (*Service, error) {
	if nilPort(publications) || nilPort(rollouts) || nilPort(cursors) {
		return nil, ErrInvalidRequest
	}
	return &Service{publications: publications, rollouts: rollouts, cursors: cursors}, nil
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map ||
		kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

func (s *Service) Publish(
	ctx context.Context,
	principal identity.Principal,
	input PublishInput,
	metadata WriteMetadata,
) (PublicationView, error) {
	if err := validatePublishInput(input); err != nil {
		return PublicationView{}, err
	}
	if err := validateWriteMetadata(metadata); err != nil {
		return PublicationView{}, err
	}
	return PublicationView{}, ErrUnsafeRolloutCommands
}

func (s *Service) PublishSession(
	ctx context.Context,
	session AuthenticatedSession,
	input PublishInput,
	metadata WriteMetadata,
) (PublicationView, error) {
	if err := requirePrincipal(session.Principal, AudiencePlatform, edgepublish.PermissionManage); err != nil {
		return PublicationView{}, err
	}
	actor, err := edgepublish.NewSessionActor(
		session.Principal.UserID,
		session.Principal.ScopeID,
		session.Principal.ScopeKind,
		session.SessionID,
		session.rawToken(),
	)
	if err != nil {
		return PublicationView{}, ErrUnauthenticated
	}
	if err := validatePublishInput(input); err != nil {
		return PublicationView{}, err
	}
	if err := validateWriteMetadata(metadata); err != nil {
		return PublicationView{}, err
	}
	result, err := s.publications.Publish(ctx, edgepublish.PublishRequest{
		Actor: actor, ConfigurationScopeID: input.ConfigurationScopeID,
		ExpectedSourceRevision: input.ExpectedSourceRevision, NodeIDs: slices.Clone(input.NodeIDs),
		TargetSnapshot: cloneTargetSnapshot(input.TargetSnapshot), HealthCheck: input.HealthCheck,
		MaxAttempts: input.MaxAttempts, Deadline: input.Deadline, IdempotencyKey: metadata.IdempotencyKey,
		RequestID: metadata.RequestID, CorrelationID: metadata.CorrelationID,
		Traceparent: metadata.Traceparent, TaskID: cloneString(metadata.TaskID),
		Rollout: input.Rollout,
	})
	if err != nil {
		return PublicationView{}, err
	}
	return publicationView(result, AudiencePlatform)
}

func (s *Service) PublishTenantSession(
	ctx context.Context,
	session AuthenticatedSession,
	input PublishInput,
	metadata WriteMetadata,
) (PublicationView, error) {
	if err := requirePrincipal(session.Principal, AudienceTenant, tenantManagePermission); err != nil {
		return PublicationView{}, err
	}
	if input.ConfigurationScopeID != session.Principal.ScopeID {
		return PublicationView{}, ErrPermissionDenied
	}
	actor, err := edgepublish.NewSessionActor(
		session.Principal.UserID,
		session.Principal.ScopeID,
		session.Principal.ScopeKind,
		session.SessionID,
		session.rawToken(),
	)
	if err != nil {
		return PublicationView{}, ErrUnauthenticated
	}
	if err := validatePublishInput(input); err != nil {
		return PublicationView{}, err
	}
	if err := validateWriteMetadata(metadata); err != nil {
		return PublicationView{}, err
	}
	result, err := s.publications.Publish(ctx, edgepublish.PublishRequest{
		Actor: actor, ConfigurationScopeID: input.ConfigurationScopeID,
		ExpectedSourceRevision: input.ExpectedSourceRevision, NodeIDs: slices.Clone(input.NodeIDs),
		TargetSnapshot: cloneTargetSnapshot(input.TargetSnapshot), HealthCheck: input.HealthCheck,
		MaxAttempts: input.MaxAttempts, Deadline: input.Deadline, IdempotencyKey: metadata.IdempotencyKey,
		RequestID: metadata.RequestID, CorrelationID: metadata.CorrelationID,
		Traceparent: metadata.Traceparent, TaskID: cloneString(metadata.TaskID), Rollout: input.Rollout,
	})
	if err != nil {
		return PublicationView{}, err
	}
	return publicationView(result, AudienceTenant)
}

func (s *Service) RollbackSession(
	ctx context.Context,
	session AuthenticatedSession,
	input RollbackInput,
	metadata WriteMetadata,
) (RollbackView, error) {
	if err := requirePrincipal(session.Principal, AudiencePlatform, edgepublish.PermissionManage); err != nil {
		return RollbackView{}, err
	}
	actor, err := edgepublish.NewSessionActor(
		session.Principal.UserID,
		session.Principal.ScopeID,
		session.Principal.ScopeKind,
		session.SessionID,
		session.rawToken(),
	)
	if err != nil {
		return RollbackView{}, ErrUnauthenticated
	}
	if err := validateRollbackInput(input); err != nil {
		return RollbackView{}, err
	}
	if err := validateWriteMetadata(metadata); err != nil {
		return RollbackView{}, err
	}
	result, err := s.publications.Rollback(ctx, edgepublish.RollbackRequest{
		Actor: actor, ConfigurationScopeID: input.ConfigurationScopeID, PublicationID: input.PublicationID,
		NodeIDs: slices.Clone(input.NodeIDs), TargetSnapshot: cloneTargetSnapshot(input.TargetSnapshot),
		HealthCheck: input.HealthCheck, MaxAttempts: input.MaxAttempts, Deadline: input.Deadline,
		IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID,
		CorrelationID: metadata.CorrelationID, Traceparent: metadata.Traceparent,
		TaskID: cloneString(metadata.TaskID), Rollout: input.Rollout,
	})
	if err != nil {
		return RollbackView{}, err
	}
	return rollbackView(result)
}

func (s *Service) ListPublications(
	ctx context.Context,
	principal identity.Principal,
	audience string,
	requestedScopeID *uuid.UUID,
	request edgepublish.PublicationPageRequest,
) (PublicationPageView, error) {
	actor, scopeID, err := s.publicationReadActor(principal, audience, requestedScopeID)
	if err != nil {
		return PublicationPageView{}, err
	}
	binding := CursorBinding{Audience: audience, ScopeID: scopeID, ResourceKind: CursorResourcePublications}
	request.Cursor, err = s.decodePageCursor(binding, request.Cursor)
	if err != nil {
		return PublicationPageView{}, err
	}
	page, err := s.publications.ListPublications(ctx, actor, scopeID, request)
	if err != nil {
		return PublicationPageView{}, err
	}
	if page.CurrentSourceRevision < 1 || !validDomainCursor(page.NextCursor) {
		return PublicationPageView{}, ErrInvalidResponse
	}
	nextCursor, err := s.encodePageCursor(binding, page.NextCursor)
	if err != nil {
		return PublicationPageView{}, err
	}
	result := PublicationPageView{
		Items: make([]PublicationView, len(page.Items)), NextCursor: nextCursor,
		CurrentSourceRevision: page.CurrentSourceRevision,
	}
	if failure := page.AutomaticFailure; failure != nil {
		switch failure.Reason {
		case edgepublish.AutomaticFailureNoTargetNodes, edgepublish.AutomaticFailureNodeCapability,
			edgepublish.AutomaticFailureNodeArtifactsSyncing, edgepublish.AutomaticFailureNodeScopeConflict:
		default:
			return PublicationPageView{}, ErrInvalidResponse
		}
		sync := failure.ArtifactSync
		if failure.SourceRevision < 1 || sync != nil && (failure.Reason != edgepublish.AutomaticFailureNodeArtifactsSyncing ||
			sync.TotalSegments < 1 || sync.ReceivedSegments < 0 || sync.ReceivedSegments > sync.TotalSegments || sync.RemainingMinutes < 1) {
			return PublicationPageView{}, ErrInvalidResponse
		}
		result.AutomaticFailure = &AutomaticFailureView{Reason: failure.Reason, SourceRevision: failure.SourceRevision,
			FailedAt: failure.FailedAt.UTC().Format(time.RFC3339Nano)}
		if sync != nil {
			result.AutomaticFailure.ArtifactSync = &ArtifactSyncView{ReceivedSegments: sync.ReceivedSegments,
				TotalSegments: sync.TotalSegments, RemainingMinutes: sync.RemainingMinutes}
		}
	}
	for _, hold := range page.PendingModules {
		result.PendingModules = append(result.PendingModules,
			PendingModuleView{Module: hold.Module, SourceRevision: hold.SourceRevision})
	}
	for index, item := range page.Items {
		if item.ConfigurationScopeID != scopeID {
			return PublicationPageView{}, ErrInvalidResponse
		}
		result.Items[index], err = publicationView(item, audience)
		if err != nil {
			return PublicationPageView{}, err
		}
	}
	return result, nil
}

func (s *Service) GetPublication(
	ctx context.Context,
	principal identity.Principal,
	audience string,
	requestedScopeID *uuid.UUID,
	publicationID uuid.UUID,
) (PublicationView, error) {
	actor, scopeID, err := s.publicationReadActor(principal, audience, requestedScopeID)
	if err != nil || publicationID == uuid.Nil {
		return PublicationView{}, firstError(err, ErrInvalidRequest)
	}
	result, err := s.publications.GetPublication(ctx, actor, scopeID, publicationID)
	if err != nil {
		return PublicationView{}, err
	}
	if result.ConfigurationScopeID != scopeID || result.PublicationID != publicationID {
		return PublicationView{}, ErrInvalidResponse
	}
	return publicationView(result, audience)
}

func (s *Service) ListRollouts(
	ctx context.Context,
	principal identity.Principal,
	audience string,
	requestedScopeID *uuid.UUID,
	request edgedeployment.RolloutPageRequest,
) (RolloutPageView, error) {
	actor, scopeID, err := s.rolloutReadActor(principal, audience, requestedScopeID)
	if err != nil {
		return RolloutPageView{}, err
	}
	binding := CursorBinding{Audience: audience, ScopeID: scopeID, ResourceKind: CursorResourceRollouts}
	request.Cursor, err = s.decodePageCursor(binding, request.Cursor)
	if err != nil {
		return RolloutPageView{}, err
	}
	page, err := s.rollouts.ListRollouts(ctx, actor, scopeID, request)
	if err != nil {
		return RolloutPageView{}, err
	}
	if !validDomainCursor(page.NextCursor) {
		return RolloutPageView{}, ErrInvalidResponse
	}
	nextCursor, err := s.encodePageCursor(binding, page.NextCursor)
	if err != nil {
		return RolloutPageView{}, err
	}
	result := RolloutPageView{Items: make([]RolloutView, len(page.Items)), NextCursor: nextCursor}
	for index, item := range page.Items {
		if item.ConfigurationScopeID != scopeID {
			return RolloutPageView{}, ErrInvalidResponse
		}
		result.Items[index], err = rolloutView(item, audience, false)
		if err != nil {
			return RolloutPageView{}, err
		}
	}
	return result, nil
}

func (s *Service) GetRollout(
	ctx context.Context,
	principal identity.Principal,
	audience string,
	requestedScopeID *uuid.UUID,
	rolloutID uuid.UUID,
) (RolloutView, error) {
	actor, scopeID, err := s.rolloutReadActor(principal, audience, requestedScopeID)
	if err != nil || rolloutID == uuid.Nil {
		return RolloutView{}, firstError(err, ErrInvalidRequest)
	}
	result, err := s.rollouts.GetRollout(ctx, actor, scopeID, rolloutID)
	if err != nil {
		return RolloutView{}, err
	}
	if result.ConfigurationScopeID != scopeID || result.ID != rolloutID {
		return RolloutView{}, ErrInvalidResponse
	}
	return rolloutView(result, audience, false)
}

func (s *Service) ListDeployments(
	ctx context.Context,
	principal identity.Principal,
	audience string,
	requestedScopeID *uuid.UUID,
	rolloutID uuid.UUID,
	request edgedeployment.DeploymentPageRequest,
) (DeploymentPageView, error) {
	actor, scopeID, err := s.rolloutReadActor(principal, audience, requestedScopeID)
	if err != nil || rolloutID == uuid.Nil {
		return DeploymentPageView{}, firstError(err, ErrInvalidRequest)
	}
	binding := CursorBinding{
		Audience: audience, ScopeID: scopeID, ResourceKind: CursorResourceDeployments, ResourceID: &rolloutID,
	}
	request.Cursor, err = s.decodePageCursor(binding, request.Cursor)
	if err != nil {
		return DeploymentPageView{}, err
	}
	rollout, err := s.rollouts.GetRollout(ctx, actor, scopeID, rolloutID)
	if err != nil {
		return DeploymentPageView{}, err
	}
	if rollout.ConfigurationScopeID != scopeID || rollout.ID != rolloutID {
		return DeploymentPageView{}, ErrInvalidResponse
	}
	if _, err := rolloutView(rollout, audience, false); err != nil {
		return DeploymentPageView{}, err
	}
	page, err := s.rollouts.ListDeployments(ctx, actor, scopeID, rolloutID, request)
	if err != nil {
		return DeploymentPageView{}, err
	}
	if !validDomainCursor(page.NextCursor) {
		return DeploymentPageView{}, ErrInvalidResponse
	}
	nextCursor, err := s.encodePageCursor(binding, page.NextCursor)
	if err != nil {
		return DeploymentPageView{}, err
	}
	result := DeploymentPageView{Items: make([]DeploymentView, len(page.Items)), NextCursor: nextCursor}
	for index, item := range page.Items {
		result.Items[index], err = deploymentView(item, audience, rollout.Policy.Strategy == edgedeployment.RolloutStrategyCanary)
		if err != nil {
			return DeploymentPageView{}, err
		}
	}
	return result, nil
}

func (s *Service) StartRollout(
	ctx context.Context, session AuthenticatedSession, input RolloutCommandInput, metadata WriteMetadata,
) (RolloutView, error) {
	return s.runRolloutCommand(ctx, session, input, metadata, "start")
}

func (s *Service) PauseRollout(
	ctx context.Context, session AuthenticatedSession, input RolloutCommandInput, metadata WriteMetadata,
) (RolloutView, error) {
	return s.runRolloutCommand(ctx, session, input, metadata, "pause")
}

func (s *Service) ResumeRollout(
	ctx context.Context, session AuthenticatedSession, input RolloutCommandInput, metadata WriteMetadata,
) (RolloutView, error) {
	return s.runRolloutCommand(ctx, session, input, metadata, "resume")
}

func (s *Service) CancelRollout(
	ctx context.Context,
	session AuthenticatedSession,
	input RolloutCommandInput,
	metadata WriteMetadata,
) (RolloutView, error) {
	return s.runRolloutCommand(ctx, session, input, metadata, "cancel")
}

func (s *Service) RetryFailedRollout(
	ctx context.Context,
	session AuthenticatedSession,
	input RolloutCommandInput,
	metadata WriteMetadata,
) (RolloutView, error) {
	return s.runRolloutCommand(ctx, session, input, metadata, "retry")
}

func (s *Service) runRolloutCommand(
	ctx context.Context,
	session AuthenticatedSession,
	input RolloutCommandInput,
	metadata WriteMetadata,
	operation string,
) (RolloutView, error) {
	if s.commands == nil {
		return RolloutView{}, ErrUnsafeRolloutCommands
	}
	if err := requirePrincipal(session.Principal, AudiencePlatform, edgepublish.PermissionManage); err != nil {
		return RolloutView{}, err
	}
	actor, err := edgedeployment.NewSessionActor(
		session.Principal.UserID,
		session.Principal.ScopeID,
		session.Principal.ScopeKind,
		session.SessionID,
		session.rawToken(),
	)
	if err != nil {
		return RolloutView{}, ErrUnauthenticated
	}
	if input.ConfigurationScopeID == uuid.Nil || input.RolloutID == uuid.Nil || input.ExpectedRevision <= 0 {
		return RolloutView{}, ErrInvalidRequest
	}
	if err := validateWriteMetadata(metadata); err != nil {
		return RolloutView{}, err
	}
	request := edgedeployment.RolloutCommandRequest{
		Actor: actor, ConfigurationScopeID: input.ConfigurationScopeID, RolloutID: input.RolloutID,
		ExpectedRevision: input.ExpectedRevision, IdempotencyKey: metadata.IdempotencyKey,
		RequestID: metadata.RequestID, CorrelationID: metadata.CorrelationID,
		Traceparent: metadata.Traceparent, TaskID: cloneString(metadata.TaskID),
	}
	var result edgedeployment.RolloutCommandResult
	switch operation {
	case "start":
		result, err = s.commands.StartRollout(ctx, request)
	case "pause":
		result, err = s.commands.PauseRollout(ctx, request)
	case "resume":
		result, err = s.commands.ResumeRollout(ctx, request)
	case "retry":
		result, err = s.commands.RetryRollout(ctx, request)
	case "cancel":
		result, err = s.commands.CancelRollout(ctx, request)
	default:
		return RolloutView{}, ErrInvalidRequest
	}
	if err != nil {
		return RolloutView{}, err
	}
	if result.Rollout.ConfigurationScopeID != input.ConfigurationScopeID || result.Rollout.ID != input.RolloutID {
		return RolloutView{}, ErrInvalidResponse
	}
	return rolloutView(result.Rollout, AudiencePlatform, result.Replayed)
}

func (s *Service) publicationReadActor(
	principal identity.Principal,
	audience string,
	requestedScopeID *uuid.UUID,
) (edgepublish.Actor, uuid.UUID, error) {
	scopeID, err := s.readScope(principal, audience, requestedScopeID)
	if err != nil {
		return edgepublish.Actor{}, uuid.Nil, err
	}
	return edgepublish.Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
	}, scopeID, nil
}

func validatePublishInput(input PublishInput) error {
	if input.ConfigurationScopeID == uuid.Nil || input.ExpectedSourceRevision <= 0 ||
		(input.TargetKind == TargetNodes && (len(input.NodeIDs) == 0 || input.TargetSnapshot != nil)) ||
		(input.TargetKind == TargetLineGroup && (len(input.NodeIDs) != 0 || input.TargetSnapshot == nil)) ||
		(input.TargetKind != TargetNodes && input.TargetKind != TargetLineGroup) || !validHTTPRolloutPolicy(input.Rollout) {
		return ErrInvalidRequest
	}
	return nil
}

func validateRollbackInput(input RollbackInput) error {
	if input.ConfigurationScopeID == uuid.Nil || input.PublicationID == uuid.Nil ||
		(input.TargetKind == TargetNodes && (len(input.NodeIDs) == 0 || input.TargetSnapshot != nil)) ||
		(input.TargetKind == TargetLineGroup && (len(input.NodeIDs) != 0 || input.TargetSnapshot == nil)) ||
		(input.TargetKind != TargetNodes && input.TargetKind != TargetLineGroup) || !validHTTPRolloutPolicy(input.Rollout) {
		return ErrInvalidRequest
	}
	return nil
}

func validHTTPRolloutPolicy(policy edgedeployment.RolloutPolicy) bool {
	return policy == (edgedeployment.RolloutPolicy{}) ||
		policy.Strategy == edgedeployment.RolloutStrategyCanary && policy.CanarySize >= 1 && policy.CanarySize <= 1000 &&
			policy.BatchSize >= 1 && policy.BatchSize <= 1000 && policy.FailureThreshold >= 1 &&
			policy.FailureThreshold <= 10000 && policy.CohortCount == 0
}

func validateWriteMetadata(metadata WriteMetadata) error {
	if !idempotencyKeyPattern.MatchString(metadata.IdempotencyKey) {
		return ErrInvalidRequest
	}
	requestID, requestErr := canonicalUUID(metadata.RequestID)
	correlationID, correlationErr := canonicalUUID(metadata.CorrelationID)
	if requestErr != nil || correlationErr != nil || requestID == uuid.Nil || correlationID == uuid.Nil ||
		!validTraceparent(metadata.Traceparent) || metadata.TaskID != nil && !taskIDPattern.MatchString(*metadata.TaskID) {
		return ErrInvalidRequest
	}
	return nil
}

func (s *Service) rolloutReadActor(
	principal identity.Principal,
	audience string,
	requestedScopeID *uuid.UUID,
) (edgedeployment.Actor, uuid.UUID, error) {
	scopeID, err := s.readScope(principal, audience, requestedScopeID)
	if err != nil {
		return edgedeployment.Actor{}, uuid.Nil, err
	}
	return edgedeployment.Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
	}, scopeID, nil
}

func (s *Service) readScope(principal identity.Principal, audience string, requestedScopeID *uuid.UUID) (uuid.UUID, error) {
	permission := edgepublish.PermissionRead
	if audience == AudienceTenant {
		permission = tenantReadPermission
	}
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return uuid.Nil, ErrUnauthenticated
	}
	if principal.ScopeKind != audience {
		return uuid.Nil, ErrPermissionDenied
	}
	if !s.lockedReads {
		if err := identity.Authorize(principal, permission); err != nil {
			return uuid.Nil, ErrPermissionDenied
		}
	}
	if audience == AudienceTenant && (principal.TenantID == nil || *principal.TenantID == uuid.Nil) && s.lockedReads {
		return uuid.Nil, ErrPermissionDenied
	}
	switch audience {
	case AudiencePlatform:
		if requestedScopeID == nil || *requestedScopeID == uuid.Nil {
			return uuid.Nil, ErrInvalidRequest
		}
		return *requestedScopeID, nil
	case AudienceTenant:
		if requestedScopeID != nil {
			return uuid.Nil, ErrPermissionDenied
		}
		return principal.ScopeID, nil
	default:
		return uuid.Nil, ErrInvalidRequest
	}
}

func requirePrincipal(principal identity.Principal, audience, permission string) error {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return ErrUnauthenticated
	}
	if principal.ScopeKind != audience {
		return ErrPermissionDenied
	}
	if err := identity.Authorize(principal, permission); err != nil {
		return ErrPermissionDenied
	}
	return nil
}

func publicationView(item edgepublish.PublishResult, audience string) (PublicationView, error) {
	if item.PublicationID == uuid.Nil || item.ConfigurationScopeID == uuid.Nil || item.SourceRevision <= 0 ||
		item.ConfigVersionID == uuid.Nil || item.RolloutID == uuid.Nil || item.NodeCount <= 0 || item.NodeCount > 10000 ||
		item.CreatedAt.IsZero() || item.CanonicalSnapshotSHA256 == ([32]byte{}) || item.ArtifactSHA256 == ([32]byte{}) ||
		item.TargetSnapshotSHA256 == ([32]byte{}) ||
		(item.TargetKind == edgepublish.TargetKindExplicit && item.TargetSnapshot != nil) ||
		(item.TargetKind == edgepublish.TargetKindResolver &&
			(item.TargetSnapshot == nil || item.TargetSnapshot.ID == uuid.Nil || item.TargetSnapshot.Revision <= 0 ||
				item.TargetSnapshot.SHA256 == ([32]byte{}))) ||
		(item.TargetKind != edgepublish.TargetKindExplicit && item.TargetKind != edgepublish.TargetKindResolver) {
		return PublicationView{}, ErrInvalidResponse
	}
	result := PublicationView{
		ID: item.PublicationID, SourceRevision: item.SourceRevision, ConfigVersionID: item.ConfigVersionID,
		RolloutID: item.RolloutID, NodeCount: item.NodeCount, CreatedAt: formatTime(item.CreatedAt), Replayed: item.Replayed,
	}
	if item.TargetKind == edgepublish.TargetKindExplicit {
		result.Target.Kind = TargetNodes
	} else {
		result.Target.Kind = TargetLineGroup
	}
	if audience == AudiencePlatform {
		scopeID := item.ConfigurationScopeID
		result.ConfigurationScopeID = &scopeID
		sourceDigest, artifactDigest, targetDigest := digestString(item.CanonicalSnapshotSHA256),
			digestString(item.ArtifactSHA256), digestString(item.TargetSnapshotSHA256)
		result.CanonicalSourceSHA256, result.ArtifactSHA256, result.Target.ResolvedSHA256 =
			&sourceDigest, &artifactDigest, &targetDigest
		if item.TargetSnapshot != nil {
			snapshotID, revision, resolverDigest := item.TargetSnapshot.ID, item.TargetSnapshot.Revision,
				digestString(item.TargetSnapshot.SHA256)
			result.Target.SnapshotID, result.Target.Revision, result.Target.ResolverSHA256 =
				&snapshotID, &revision, &resolverDigest
		}
	}
	return result, nil
}

func rollbackView(item edgepublish.RollbackResult) (RollbackView, error) {
	if item.PublicationID == uuid.Nil || item.ConfigurationScopeID == uuid.Nil || item.ConfigVersionID == uuid.Nil ||
		item.RolloutID == uuid.Nil || item.NodeCount <= 0 || item.NodeCount > 10000 || item.CreatedAt.IsZero() ||
		item.TargetSnapshotSHA256 == ([32]byte{}) ||
		(item.TargetKind == edgepublish.TargetKindExplicit && item.TargetSnapshot != nil) ||
		(item.TargetKind == edgepublish.TargetKindResolver &&
			(item.TargetSnapshot == nil || item.TargetSnapshot.ID == uuid.Nil || item.TargetSnapshot.Revision <= 0 ||
				item.TargetSnapshot.SHA256 == ([32]byte{}))) ||
		(item.TargetKind != edgepublish.TargetKindExplicit && item.TargetKind != edgepublish.TargetKindResolver) {
		return RollbackView{}, ErrInvalidResponse
	}
	result := RollbackView{
		PublicationID: item.PublicationID, ConfigurationScopeID: item.ConfigurationScopeID,
		ConfigVersionID: item.ConfigVersionID, RolloutID: item.RolloutID, Action: "rollback",
		NodeCount: item.NodeCount, CreatedAt: formatTime(item.CreatedAt), Replayed: item.Replayed,
	}
	resolvedDigest := digestString(item.TargetSnapshotSHA256)
	result.Target.ResolvedSHA256 = &resolvedDigest
	if item.TargetKind == edgepublish.TargetKindExplicit {
		result.Target.Kind = TargetNodes
	} else {
		result.Target.Kind = TargetLineGroup
		snapshotID, revision, resolverDigest := item.TargetSnapshot.ID, item.TargetSnapshot.Revision,
			digestString(item.TargetSnapshot.SHA256)
		result.Target.SnapshotID, result.Target.Revision, result.Target.ResolverSHA256 =
			&snapshotID, &revision, &resolverDigest
	}
	return result, nil
}

func rolloutView(item edgedeployment.RolloutSnapshot, audience string, replayed bool) (RolloutView, error) {
	if item.ID == uuid.Nil || item.ConfigurationScopeID == uuid.Nil || item.ConfigVersionID == uuid.Nil ||
		item.Revision <= 0 || item.MaxAttempts == 0 || item.MaxAttempts > 10 ||
		item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() ||
		!validRolloutState(item.State) || (item.Action != "apply" && item.Action != "rollback") ||
		item.Progress.Total <= 0 || item.Progress.Total > 10000 ||
		item.Progress.Pending < 0 || item.Progress.Pending > 10000 ||
		item.Progress.Running < 0 || item.Progress.Running > 10000 ||
		item.Progress.Succeeded < 0 || item.Progress.Succeeded > 10000 ||
		item.Progress.Failed < 0 || item.Progress.Failed > 10000 ||
		item.Progress.Cancelled < 0 || item.Progress.Cancelled > 10000 ||
		item.Progress.Superseded < 0 || item.Progress.Superseded > 10000 ||
		item.Progress.Pending+item.Progress.Running+item.Progress.Succeeded+
			item.Progress.Failed+item.Progress.Cancelled+item.Progress.Superseded != item.Progress.Total {
		return RolloutView{}, ErrInvalidResponse
	}
	result := RolloutView{
		ID: item.ID, ConfigVersionID: item.ConfigVersionID, Action: item.Action, State: item.State,
		Revision: item.Revision, MaxAttempts: item.MaxAttempts,
		Progress: RolloutProgressView{
			Total: item.Progress.Total, Pending: item.Progress.Pending, Running: item.Progress.Running,
			Succeeded: item.Progress.Succeeded, Failed: item.Progress.Failed, Cancelled: item.Progress.Cancelled,
			Superseded: item.Progress.Superseded, Frozen: item.Progress.Frozen,
		},
		CanCancel: item.CanCancel, CanRetry: item.CanRetry, CreatedAt: formatTime(item.CreatedAt),
		UpdatedAt: formatTime(item.UpdatedAt), Replayed: replayed, CanStart: item.CanStart,
		CanPause: item.CanPause, CanResume: item.CanResume, PauseReason: item.PauseReason,
	}
	if item.Policy.Strategy == edgedeployment.RolloutStrategyCanary {
		if item.Policy.CanarySize < 1 || item.Policy.CanarySize > 1000 ||
			item.Policy.BatchSize < 1 || item.Policy.BatchSize > 1000 ||
			item.Policy.FailureThreshold < 1 || item.Policy.FailureThreshold > 10000 ||
			item.Policy.CohortCount < 1 || item.Policy.CohortCount > 10000 ||
			item.ReleasedCohort < -1 || item.ReleasedCohort > 10000 ||
			(item.PauseReason != "" && item.PauseReason != "operator" && item.PauseReason != "failure_threshold") {
			return RolloutView{}, ErrInvalidResponse
		}
		result.Rollout = &RolloutPolicyView{Strategy: item.Policy.Strategy, CanarySize: item.Policy.CanarySize,
			BatchSize: item.Policy.BatchSize, FailureThreshold: item.Policy.FailureThreshold,
			CohortCount: item.Policy.CohortCount, ReleasedCohort: item.ReleasedCohort}
	} else if item.Policy != (edgedeployment.RolloutPolicy{}) || item.PauseReason != "" ||
		item.CanStart || item.CanPause || item.CanResume {
		return RolloutView{}, ErrInvalidResponse
	}
	if audience == AudiencePlatform {
		scopeID := item.ConfigurationScopeID
		result.ConfigurationScopeID = &scopeID
	}
	return result, nil
}

func deploymentView(item edgedeployment.DeploymentSnapshot, audience string, progressive ...bool) (DeploymentView, error) {
	if item.ID == uuid.Nil || item.NodeID == uuid.Nil || item.Attempt == 0 || item.MaxAttempts == 0 || item.MaxAttempts > 10 ||
		item.Attempt > item.MaxAttempts || item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() ||
		!validDeploymentState(item.State) || !validDeploymentErrorCode(item.ErrorCode) {
		return DeploymentView{}, ErrInvalidResponse
	}
	result := DeploymentView{
		ID: item.ID, Attempt: item.Attempt, MaxAttempts: item.MaxAttempts, State: item.State,
		ErrorCode: item.ErrorCode, CreatedAt: formatTime(item.CreatedAt), UpdatedAt: formatTime(item.UpdatedAt),
		CanRetry: item.CanRetry, Superseded: item.Superseded, Frozen: item.Frozen,
	}
	if len(progressive) != 0 && progressive[0] {
		if item.Cohort < 0 || item.Cohort > 10000 {
			return DeploymentView{}, ErrInvalidResponse
		}
		cohort, released := item.Cohort, item.Released
		result.Cohort, result.Released = &cohort, &released
	}
	if audience == AudiencePlatform {
		nodeID := item.NodeID
		result.NodeID = &nodeID
		// Node faults (protection, maintenance) are the platform's to see.
		result.Warnings = item.Warnings
	}
	return result, nil
}

func validRolloutState(value string) bool {
	switch value {
	case edgedeployment.RolloutStateQueued, edgedeployment.RolloutStateRunning,
		edgedeployment.RolloutStatePaused,
		edgedeployment.RolloutStateSucceeded, edgedeployment.RolloutStatePartialFailed,
		edgedeployment.RolloutStateFailed, edgedeployment.RolloutStateCancelled:
		return true
	default:
		return false
	}
}

func validDeploymentState(value string) bool {
	switch value {
	case "queued", "delivered", "agent_queued", "started", "staged", "prechecked", "activated", "healthy",
		"failed", "reverting", "reverted", "rollback_failed", "cancelled":
		return true
	default:
		return false
	}
}

func validDeploymentErrorCode(value string) bool {
	if len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validDomainCursor(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > maxCursorBytes {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func (s *Service) decodePageCursor(binding CursorBinding, encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	inner, err := s.cursors.Decode(binding, encoded)
	if err != nil || inner == "" || !validDomainCursor(inner) {
		return "", ErrInvalidRequest
	}
	return inner, nil
}

func (s *Service) encodePageCursor(binding CursorBinding, inner string) (string, error) {
	if inner == "" {
		return "", nil
	}
	if !validDomainCursor(inner) {
		return "", ErrInvalidResponse
	}
	encoded, err := s.cursors.Encode(binding, inner)
	if err != nil || encoded == "" || !validDomainCursor(encoded) {
		return "", ErrInvalidResponse
	}
	return encoded, nil
}

func digestString(value [32]byte) string {
	return fmt.Sprintf("%x", value[:])
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func cloneTargetSnapshot(value *edgepublish.TargetSnapshotReference) *edgepublish.TargetSnapshotReference {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func firstError(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}
