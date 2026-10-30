package certificateasset

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
)

const CertificatePublicationSchemaV1 = "cdnca.certificate-publication.v1"

const (
	PublicationAck       PublicationOutcome = "ack"
	PublicationRetry     PublicationOutcome = "retry"
	PublicationPermanent PublicationOutcome = "permanent"
)

const (
	publicationFailureUnavailable = "publisher_unavailable"
	publicationFailureTimeout     = "publisher_timeout"
	publicationFailureCancelled   = "publisher_cancelled"
	publicationFailurePanic       = "publisher_panic"
	publicationFailureContract    = "publisher_contract_invalid"
)

var (
	ErrPublicationPublisherUnavailable = errors.New("certificate publication publisher unavailable")
	ErrPublicationPublisherTimeout     = errors.New("certificate publication publisher timeout")
	ErrPublicationPublisherPanic       = errors.New("certificate publication publisher panic")
	ErrPublicationPublisherContract    = errors.New("certificate publication publisher contract invalid")
)

type PublicationOutcome string

type PublicationResult struct {
	Outcome             PublicationOutcome
	FailureCode         string
	PublicationID       uuid.UUID
	PublicationRevision int64
	ConfigVersionID     uuid.UUID
	RolloutID           uuid.UUID
	RolloutRevision     int64
}

type CertificatePublicationCommandV1 struct {
	Schema               string
	TenantScopeID        uuid.UUID
	SiteID               uuid.UUID
	AssetID              uuid.UUID
	VersionID            uuid.UUID
	BindingRevision      int64
	Operation            string
	Default              bool
	RequestID            string
	ActorScopeID         uuid.UUID
	ActorUserID          uuid.UUID
	ActorSessionID       uuid.UUID
	ActorScopeKind       string
	ActorUserRevision    int64
	TargetTenantID       uuid.UUID
	TargetTenantRevision int64
	Deadline             time.Time
	IdempotencyKey       string
	CreatedAt            time.Time
}

type CertificatePublisher interface {
	Publish(context.Context, CertificatePublicationCommandV1) (PublicationResult, error)
}

type PublicationIntentRepository interface {
	ClaimPublicationIntent(context.Context, string) (PublicationIntentLease, bool, error)
	CompletePublicationIntent(context.Context, PublicationIntentLease, PublicationResult) error
	FailPublicationIntent(context.Context, PublicationIntentLease, string) error
	PermanentlyFailPublicationIntent(context.Context, PublicationIntentLease, string) error
}

type PublicationWorkerConfig struct {
	WorkerID          string
	PublishTimeout    time.Duration
	SettlementTimeout time.Duration
}

func DefaultPublicationWorkerConfig() PublicationWorkerConfig {
	return PublicationWorkerConfig{
		PublishTimeout: 30 * time.Second, SettlementTimeout: 5 * time.Second,
	}
}

type PublicationWorker struct {
	repository PublicationIntentRepository
	publisher  CertificatePublisher
	config     PublicationWorkerConfig
}

func NewPublicationWorker(
	repository PublicationIntentRepository,
	publisher CertificatePublisher,
	config PublicationWorkerConfig,
) (*PublicationWorker, error) {
	if nilPublicationDependency(repository) || nilPublicationDependency(publisher) ||
		!validPublicationWorkerID(config.WorkerID) || config.PublishTimeout <= 0 ||
		config.PublishTimeout > time.Hour || config.SettlementTimeout <= 0 ||
		config.SettlementTimeout > time.Hour {
		return nil, ErrInvalidInput
	}
	return &PublicationWorker{repository: repository, publisher: publisher, config: config}, nil
}

func (worker *PublicationWorker) RunOnce(ctx context.Context) (bool, error) {
	if worker == nil || worker.repository == nil || worker.publisher == nil || ctx == nil {
		return false, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	lease, found, err := worker.repository.ClaimPublicationIntent(ctx, worker.config.WorkerID)
	if err != nil || !found {
		return false, err
	}
	if !validPublicationIntentLease(lease) {
		return true, ErrInvalidStore
	}
	command := publicationCommandV1(lease)
	if !validCertificatePublicationCommandV1(command) {
		return true, ErrInvalidStore
	}

	publishCtx, cancel := context.WithTimeout(ctx, worker.config.PublishTimeout)
	result, publishErr, panicked := callCertificatePublisher(publishCtx, worker.publisher, command)
	publishCtxErr := publishCtx.Err()
	cancel()

	if parentErr := ctx.Err(); parentErr != nil {
		if settleErr := worker.retry(ctx, lease, publicationFailureCancelled); settleErr != nil {
			return true, settleErr
		}
		return true, parentErr
	}
	if panicked {
		if settleErr := worker.retry(ctx, lease, publicationFailurePanic); settleErr != nil {
			return true, settleErr
		}
		return true, ErrPublicationPublisherPanic
	}
	if errors.Is(publishCtxErr, context.DeadlineExceeded) || errors.Is(publishErr, context.DeadlineExceeded) {
		if settleErr := worker.retry(ctx, lease, publicationFailureTimeout); settleErr != nil {
			return true, settleErr
		}
		return true, ErrPublicationPublisherTimeout
	}
	if publishErr != nil {
		if settleErr := worker.retry(ctx, lease, publicationFailureUnavailable); settleErr != nil {
			return true, settleErr
		}
		return true, ErrPublicationPublisherUnavailable
	}
	if !validPublicationResult(result) {
		if settleErr := worker.permanentlyFail(ctx, lease, publicationFailureContract); settleErr != nil {
			return true, settleErr
		}
		return true, ErrPublicationPublisherContract
	}

	switch result.Outcome {
	case PublicationAck:
		return true, worker.complete(ctx, lease, result)
	case PublicationRetry:
		return true, worker.retry(ctx, lease, result.FailureCode)
	case PublicationPermanent:
		return true, worker.permanentlyFail(ctx, lease, result.FailureCode)
	default:
		return true, ErrPublicationPublisherContract
	}
}

func (worker *PublicationWorker) complete(
	ctx context.Context,
	lease PublicationIntentLease,
	result PublicationResult,
) error {
	settleCtx, cancel := worker.settlementContext(ctx)
	defer cancel()
	return worker.repository.CompletePublicationIntent(settleCtx, lease, result)
}

func (worker *PublicationWorker) retry(
	ctx context.Context,
	lease PublicationIntentLease,
	failureCode string,
) error {
	settleCtx, cancel := worker.settlementContext(ctx)
	defer cancel()
	return worker.repository.FailPublicationIntent(settleCtx, lease, failureCode)
}

func (worker *PublicationWorker) permanentlyFail(
	ctx context.Context,
	lease PublicationIntentLease,
	failureCode string,
) error {
	settleCtx, cancel := worker.settlementContext(ctx)
	defer cancel()
	return worker.repository.PermanentlyFailPublicationIntent(settleCtx, lease, failureCode)
}

func (worker *PublicationWorker) settlementContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), worker.config.SettlementTimeout)
}

func publicationCommandV1(lease PublicationIntentLease) CertificatePublicationCommandV1 {
	return CertificatePublicationCommandV1{
		Schema: CertificatePublicationSchemaV1, TenantScopeID: lease.TenantScopeID,
		SiteID: lease.SiteID, AssetID: lease.AssetID, VersionID: lease.VersionID,
		BindingRevision: lease.BindingRevision, Operation: lease.Operation, Default: lease.Default,
		RequestID: lease.RequestID, ActorScopeID: lease.ActorScopeID, ActorUserID: lease.ActorUserID,
		ActorSessionID: lease.ActorSessionID, ActorScopeKind: lease.ActorScopeKind,
		ActorUserRevision: lease.ActorUserRevision, TargetTenantID: lease.TargetTenantID,
		TargetTenantRevision: lease.TargetTenantRevision, Deadline: lease.Deadline,
		IdempotencyKey: lease.IdempotencyKey, CreatedAt: lease.CreatedAt,
	}
}

func callCertificatePublisher(
	ctx context.Context,
	publisher CertificatePublisher,
	command CertificatePublicationCommandV1,
) (result PublicationResult, err error, panicked bool) {
	defer func() {
		if recover() != nil {
			result = PublicationResult{}
			err = nil
			panicked = true
		}
	}()
	result, err = publisher.Publish(ctx, command)
	return result, err, false
}

func validCertificatePublicationCommandV1(command CertificatePublicationCommandV1) bool {
	return command.Schema == CertificatePublicationSchemaV1 && command.TenantScopeID != uuid.Nil &&
		command.SiteID != uuid.Nil && command.AssetID != uuid.Nil && command.VersionID != uuid.Nil &&
		command.ActorScopeID != uuid.Nil && command.ActorUserID != uuid.Nil && command.ActorSessionID != uuid.Nil &&
		(command.ActorScopeKind == ScopeTenant || command.ActorScopeKind == ScopePlatform) &&
		command.ActorUserRevision > 0 && command.TargetTenantID != uuid.Nil && command.TargetTenantRevision > 0 &&
		command.BindingRevision > 0 && !command.CreatedAt.IsZero() &&
		!command.Deadline.IsZero() && command.Deadline.After(command.CreatedAt) &&
		(command.Operation == "publish" || command.Operation == "unpublish") && command.RequestID != "" &&
		command.RequestID == strings.TrimSpace(command.RequestID) &&
		command.IdempotencyKey == publicationIntentIdempotencyKey(
			command.TenantScopeID, command.SiteID, command.BindingRevision,
		)
}

func validPublicationResult(result PublicationResult) bool {
	switch result.Outcome {
	case PublicationAck:
		return result.FailureCode == "" && result.PublicationID != uuid.Nil &&
			result.PublicationRevision > 0 && result.ConfigVersionID != uuid.Nil &&
			result.RolloutID != uuid.Nil && result.RolloutRevision > 0
	case PublicationRetry, PublicationPermanent:
		return validPublicationFailureCode(result.FailureCode) && result.PublicationID == uuid.Nil &&
			result.PublicationRevision == 0 && result.ConfigVersionID == uuid.Nil &&
			result.RolloutID == uuid.Nil && result.RolloutRevision == 0
	default:
		return false
	}
}

func nilPublicationDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ PublicationIntentRepository = (*PublicationIntentStore)(nil)
