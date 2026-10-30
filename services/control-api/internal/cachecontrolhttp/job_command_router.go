package cachecontrolhttp

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/jobhttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// JobCommandRouter executes the task center's cancel/retry of a cache
// operation (fix-cacheflow2 §2, CACHE-ADD-05) with the cache module's own
// Service.Cancel/Retry: the same session re-authorization, entitlement check,
// cancel outbox, retry scheduling, cache.operation.* and job.* audit and
// unified-job receipt as the cache page, in one transaction. A session or a
// tenant API key (fix-cacheflow3 §1) is re-authorized in that transaction.
type JobCommandRouter struct {
	service *Service
	pool    *pgxpool.Pool
}

var jobCommandKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func NewProductionJobCommandRouter(config ProductionConfig, dependencies ProductionDependencies) (*JobCommandRouter, error) {
	if dependencies.Pool == nil || dependencies.Entitlement == nil || dependencies.IAM == nil ||
		!dependencies.IAM.Configured() || len(config.CursorKey) < 32 {
		return nil, ErrInvalidRequest
	}
	store, err := newProductionControlStore(config, dependencies)
	if err != nil {
		return nil, err
	}
	reader, err := newProductionPostgresReader(dependencies.Pool, dependencies.IAM)
	if err != nil {
		return nil, err
	}
	service, err := NewService(runtimeControlStore{inner: store}, reader, config.CursorKey)
	if err != nil {
		return nil, err
	}
	return &JobCommandRouter{service: service, pool: dependencies.Pool}, nil
}

func (router *JobCommandRouter) ExecuteProducerCommand(
	ctx context.Context,
	input jobhttp.ProducerCommandInput,
) (jobhttp.ProducerCommandResult, error) {
	if router == nil || router.service == nil || router.pool == nil || ctx == nil ||
		input.Job.Kind != "cache.operation" || input.Job.TaskID == uuid.Nil ||
		!jobCommandKeyPattern.MatchString(input.IdempotencyKey) {
		return jobhttp.ProducerCommandResult{}, jobhttp.ErrInvalidRequest
	}
	rawToken := input.Principal.SessionToken()
	apiKeyID, rawAPIKey := input.Principal.APIKeyCredential()
	if (rawToken == "") == (rawAPIKey == "") ||
		rawAPIKey != "" && (apiKeyID == uuid.Nil || input.Audience != jobhttp.AudienceTenant ||
			input.Principal.ScopeKind != jobhttp.ScopeTenant) {
		// Exactly one credential; API keys are tenant-only (fix-cacheflow3 §1):
		// the cache store re-authorizes the key's scopes intersected with the
		// holder's current permissions and audits it as api_key:<id>.
		return jobhttp.ProducerCommandResult{}, jobhttp.ErrPermissionDenied
	}
	principal := identity.Principal{
		UserID: input.Principal.UserID, ScopeID: input.Principal.ScopeID,
		ScopeKind: string(input.Principal.ScopeKind),
	}
	for permission := range input.Principal.Permissions {
		principal.Permissions = append(principal.Permissions, permission)
	}
	audience := AudienceTenant
	var targetScopeID *uuid.UUID
	if input.Audience == jobhttp.AudiencePlatform {
		audience = AudiencePlatform
		// The cache operation lives in its tenant's scope.
		var scopeID uuid.UUID
		if err := router.pool.QueryRow(ctx, `SELECT id FROM access_scopes
			WHERE kind='tenant' AND tenant_id=$1`, input.Job.TenantID).Scan(&scopeID); err != nil {
			return jobhttp.ProducerCommandResult{}, fmt.Errorf("%w: cache operation scope", jobhttp.ErrNotFound)
		}
		targetScopeID = &scopeID
	}
	sessionCtx := context.WithValue(ctx, runtimeSessionKey{}, runtimeSessionResult{
		session: runtimeSession{principal: principal, rawToken: rawToken, apiKeyID: apiKeyID, rawAPIKey: rawAPIKey},
	})
	command := CommandInput{OperationID: input.Job.TaskID, WriteMetadata: WriteMetadata{
		// The task center key is namespaced so it never replays a cache-page command.
		IdempotencyKey: "job-" + input.IdempotencyKey, RequestID: input.RequestID,
	}}
	if len(command.IdempotencyKey) > 128 || !metadataPattern.MatchString(command.RequestID) {
		return jobhttp.ProducerCommandResult{}, jobhttp.ErrInvalidRequest
	}
	if input.ReplayOnly {
		// A stale If-Match: only an already accepted command with this key is
		// answered (as a replay); nothing is executed.
		action := cachecontrol.WriteCancel
		if input.Operation == jobhttp.CommandRetry {
			action = cachecontrol.WriteRetry
		} else if input.Operation != jobhttp.CommandCancel {
			return jobhttp.ProducerCommandResult{}, jobhttp.ErrInvalidRequest
		}
		receipt, err := router.service.WriteReceipt(sessionCtx, principal, audience, targetScopeID, cachecontrol.WriteReceiptRequest{
			Action: action, OperationID: input.Job.TaskID, IdempotencyKey: command.IdempotencyKey,
		})
		if err != nil {
			return jobhttp.ProducerCommandResult{}, jobCommandError(err)
		}
		return jobhttp.ProducerCommandResult{Replayed: receipt.Status == string(cachecontrol.WriteAccepted)}, nil
	}
	var result WriteResult[OperationView]
	var err error
	switch input.Operation {
	case jobhttp.CommandCancel:
		result, err = router.service.Cancel(sessionCtx, principal, audience, targetScopeID, command)
	case jobhttp.CommandRetry:
		result, err = router.service.Retry(sessionCtx, principal, audience, targetScopeID, command)
	default:
		return jobhttp.ProducerCommandResult{}, jobhttp.ErrInvalidRequest
	}
	if err != nil {
		return jobhttp.ProducerCommandResult{}, jobCommandError(err)
	}
	return jobhttp.ProducerCommandResult{Replayed: result.Replayed}, nil
}

// jobCommandError maps the cache module's refusals to the task center's
// stable command errors.
func jobCommandError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrInvalidRequest):
		return jobhttp.ErrInvalidRequest
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrUnauthenticated), errors.Is(err, ErrEntitlementDenied):
		return jobhttp.ErrPermissionDenied
	case errors.Is(err, ErrNotFound):
		return jobhttp.ErrNotFound
	case errors.Is(err, ErrIdempotencyConflict):
		return jobhttp.ErrIdempotencyConflict
	case errors.Is(err, ErrInvalidTransition):
		return jobhttp.ErrInvalidTransition
	case errors.Is(err, ErrRetriesExhausted):
		return jobhttp.ErrRetriesExhausted
	default:
		return jobhttp.ErrStoreUnavailable
	}
}

var _ jobhttp.ProducerCommandRouter = (*JobCommandRouter)(nil)
