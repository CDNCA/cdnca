package jobhttp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const commandDigestDomain = "cdnca.job-command.v1"

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (service *Service) Command(
	ctx context.Context,
	principal Principal,
	input CommandRequest,
) (CommandResult, error) {
	if ctx == nil || input.TaskID == uuid.Nil ||
		!idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		(input.Operation != CommandCancel && input.Operation != CommandRetry && input.Operation != CommandReplay) {
		return CommandResult{}, ErrInvalidRequest
	}
	if service.commands == nil {
		return CommandResult{}, ErrStoreUnavailable
	}
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return CommandResult{}, ErrPermissionDenied
	}
	if err := authorizeCommandCredential(principal, input); err != nil {
		return CommandResult{}, err
	}
	requestID := requestIDFromContext(ctx)
	if requestID == "" {
		requestID = newRequestID()
	}
	if result, handled, err := service.producerCommand(ctx, principal, input, requestID); handled {
		if err != nil {
			return CommandResult{}, err
		}
		return result, nil
	}
	result, err := service.commands.Execute(ctx, CommandInput{
		Principal: principal, Audience: input.Audience, TaskID: input.TaskID,
		Operation: input.Operation, IdempotencyKey: input.IdempotencyKey,
		Digest: commandDigestWithRevision(
			principal, input.Audience, input.TaskID, input.Operation, input.ExpectedRevision,
		),
		RequestID: requestID, ExpectedRevision: input.ExpectedRevision,
	})
	if err != nil {
		return CommandResult{}, normalizeCommandError(ctx, err)
	}
	if validateCommandResult(result.Data, input.Operation) != nil || result.Data.TaskID != input.TaskID {
		return CommandResult{}, ErrInvalidStoreResponse
	}
	return result, nil
}

// authorizeCommandCredential 按本次凭据的有效权限（API 密钥为 key.scopes 与用户权限的交集）
// 校验命令，必须在 Execute 之前执行：PostgresReader 只核所属用户的实时角色，不能替代凭据范围
// （API-JOBS-01）。权限名与 authorizeLiveCommand 保持一致，两层都通过才执行。
func authorizeCommandCredential(principal Principal, input CommandRequest) error {
	switch input.Audience {
	case AudiencePlatform:
		if principal.ScopeKind != ScopePlatform {
			return ErrScopeForbidden
		}
		if !principal.HasPermission(PermissionManageAll) && !principal.HasPermission(PermissionAdmin) {
			return ErrPermissionDenied
		}
	case AudienceTenant:
		// 租户 replay 仍交给 authorizeLiveCommand 拒绝并写 denied 审计，不在此提前拦截。
		if principal.ScopeKind != ScopeTenant {
			return ErrScopeForbidden
		}
		if !principal.HasPermission(PermissionManage) {
			return ErrPermissionDenied
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

// The NUL-delimited preimage is the character-level v1 command contract.
func commandDigest(
	principal Principal,
	audience Audience,
	taskID uuid.UUID,
	operation CommandOperation,
) CommandDigest {
	return commandDigestWithRevision(principal, audience, taskID, operation, "")
}

func commandDigestWithRevision(
	principal Principal,
	audience Audience,
	taskID uuid.UUID,
	operation CommandOperation,
	expectedRevision string,
) CommandDigest {
	parts := []string{
		commandDigestDomain,
		string(audience),
		string(principal.ScopeKind),
		principal.ScopeID.String(),
		principal.UserID.String(),
		taskID.String(),
		string(operation),
	}
	if expectedRevision != "" {
		parts = append(parts, expectedRevision)
	}
	parts = append(parts, "{}")
	preimage := strings.Join(parts, "\x00")
	return sha256.Sum256([]byte(preimage))
}

func normalizeCommandError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrPermissionDenied),
		errors.Is(err, ErrScopeForbidden), errors.Is(err, ErrNotFound),
		errors.Is(err, ErrIdempotencyConflict), errors.Is(err, ErrInvalidTransition),
		errors.Is(err, ErrRetriesExhausted), errors.Is(err, ErrRevisionConflict),
		errors.Is(err, ErrProducerCommand), errors.Is(err, ErrStoreUnavailable),
		errors.Is(err, ErrInvalidStoreResponse),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w", ErrStoreUnavailable)
	}
}
