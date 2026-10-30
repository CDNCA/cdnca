package nodetrafficpolicy

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Repository interface {
	Get(context.Context, uuid.UUID, uuid.UUID) (PolicyState, error)
	Put(context.Context, Actor, PutRequest) (WriteResult, error)
	ApplyEvaluation(context.Context, ApplyEvaluationRequest) (EvaluationRecord, error)
}

type SyncTaskRepository interface {
	GetSyncTask(context.Context, uuid.UUID, uuid.UUID) (SyncTask, error)
}

type EvaluationReplayRepository interface {
	ReplayEvaluation(context.Context, EvaluateRequest) (EvaluationRecord, bool, error)
}

type UsageReader interface {
	Read(context.Context, UsageQuery) (UsageEvidence, error)
}

type Service struct {
	repository Repository
	usage      UsageReader
	now        func() time.Time
}

func NewService(repository Repository, usage UsageReader, now func() time.Time) (*Service, error) {
	if repository == nil || usage == nil || now == nil {
		return nil, ErrInvalidConfig
	}
	return &Service{repository: repository, usage: usage, now: now}, nil
}

func (service *Service) Get(ctx context.Context, actor Actor, scopeID, nodeID uuid.UUID) (PolicyState, error) {
	if err := authorize(actor, scopeID, PermissionRead); err != nil {
		return PolicyState{}, err
	}
	if nodeID == uuid.Nil {
		return PolicyState{}, ErrInvalidInput
	}
	return service.repository.Get(ctx, scopeID, nodeID)
}

func (service *Service) Put(ctx context.Context, actor Actor, request PutRequest) (WriteResult, error) {
	if err := authorize(actor, request.Policy.ScopeID, PermissionManage); err != nil {
		return WriteResult{}, err
	}
	if request.Policy.ID == uuid.Nil {
		request.Policy.ID = PolicyID(request.Policy.ScopeID, request.Policy.NodeID)
	}
	request.Policy.Override.Mode = normalizeOverrideMode(request.Policy.Override.Mode)
	if err := ValidatePolicy(request.Policy); err != nil || request.ExpectedRevision < 0 ||
		!validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if request.Policy.Override.Mode != OverrideNone && !request.Policy.Override.ExpiresAt.After(service.now()) {
		return WriteResult{}, ErrInvalidInput
	}
	return service.repository.Put(ctx, actor, request)
}

func (service *Service) Evaluate(ctx context.Context, actor Actor, request EvaluateRequest) (EvaluationRecord, error) {
	if err := authorize(actor, request.ScopeID, PermissionManage); err != nil {
		return EvaluationRecord{}, err
	}
	return service.evaluate(ctx, actor.UserID, request)
}

func (service *Service) EvaluateSystem(ctx context.Context, request EvaluateRequest) (EvaluationRecord, error) {
	return service.evaluate(ctx, uuid.Nil, request)
}

func (service *Service) evaluate(ctx context.Context, actorUserID uuid.UUID, request EvaluateRequest) (EvaluationRecord, error) {
	if request.NodeID == uuid.Nil || !validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) {
		return EvaluationRecord{}, ErrInvalidInput
	}
	if repository, ok := service.repository.(EvaluationReplayRepository); ok {
		if replay, found, err := repository.ReplayEvaluation(ctx, request); err != nil || found {
			return replay, err
		}
	}
	state, err := service.repository.Get(ctx, request.ScopeID, request.NodeID)
	if err != nil {
		return EvaluationRecord{}, err
	}
	now := service.now().UTC()
	period, err := PeriodFor(now, state.Policy.Timezone)
	if err != nil {
		return EvaluationRecord{}, err
	}
	usage, err := service.usage.Read(ctx, UsageQuery{
		ScopeID: request.ScopeID, NodeID: request.NodeID, Period: period, SnapshotAt: now,
	})
	if err != nil {
		return EvaluationRecord{}, errors.Join(ErrUsageUnavailable, err)
	}
	if !usage.SnapshotAt.Equal(now) || usage.FinalizedThrough.After(now) ||
		usage.FinalizedThrough.Before(period.Start) || !validDigest(usage.SourceDigest) {
		return EvaluationRecord{}, ErrUsageUnavailable
	}
	decision, err := Evaluate(EvaluationInput{
		Policy: state.Policy, Now: now, Usage: usage, AdminState: state.AdminState, Previous: state.LastEvaluation,
	})
	if err != nil {
		return EvaluationRecord{}, err
	}
	var syncTask *SyncTask
	if decision.SyncRequired {
		if state.CurrentConfigVersionID == nil || *state.CurrentConfigVersionID == uuid.Nil {
			return EvaluationRecord{}, ErrConfigUnavailable
		}
		syncTask = &SyncTask{
			ID: uuid.New(), ScopeID: request.ScopeID, NodeID: request.NodeID,
			ConfigVersionID: *state.CurrentConfigVersionID, Status: SyncTaskQueued,
			CreatedAt: now, UpdatedAt: now,
		}
	}
	return service.repository.ApplyEvaluation(ctx, ApplyEvaluationRequest{
		ScopeID: request.ScopeID, NodeID: request.NodeID, ActorUserID: actorUserID,
		AdminState: state.AdminState, PolicyRevision: state.Policy.Revision,
		Decision: decision, SyncTask: syncTask,
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
	})
}

func (service *Service) GetSyncTask(ctx context.Context, actor Actor, taskID uuid.UUID) (SyncTask, error) {
	if taskID == uuid.Nil || actor.ScopeID == uuid.Nil {
		return SyncTask{}, ErrInvalidInput
	}
	if err := authorize(actor, actor.ScopeID, PermissionRead); err != nil {
		return SyncTask{}, err
	}
	repository, ok := service.repository.(SyncTaskRepository)
	if !ok {
		return SyncTask{}, ErrUnavailable
	}
	return repository.GetSyncTask(ctx, actor.ScopeID, taskID)
}

func authorize(actor Actor, scopeID uuid.UUID, permission string) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != ScopeKindPlatform ||
		scopeID == uuid.Nil || actor.ScopeID != scopeID {
		return ErrUnauthenticated
	}
	if !slices.Contains(actor.Permissions, permission) {
		return ErrPermissionDenied
	}
	return nil
}

func validMetadata(value string) bool {
	return metadataPattern.MatchString(value)
}

func normalizeOverrideMode(value string) string {
	if value == "" {
		return OverrideNone
	}
	return value
}
