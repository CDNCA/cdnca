package protocol

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const maxScopes = 64

type Operation string

const (
	OperationSessionCreate        Operation = "identity.session.create"
	OperationSessionRotate        Operation = "identity.session.rotate"
	OperationSessionRevoke        Operation = "identity.session.revoke"
	OperationBootstrap            Operation = "identity.bootstrap"
	OperationUserCreate           Operation = "identity.user.create"
	OperationUserUpdate           Operation = "identity.user.update"
	OperationSelfUpdate           Operation = "identity.self.update"
	OperationPasswordChange       Operation = "identity.password.change"
	OperationMembershipSuspend    Operation = "identity.membership.suspend"
	OperationAPIKeySelfCreate     Operation = "api_key.self.create"
	OperationAPIKeySelfUpdate     Operation = "api_key.self.update"
	OperationAPIKeySelfActivate   Operation = "api_key.self.activate"
	OperationAPIKeySelfRotate     Operation = "api_key.self.rotate"
	OperationAPIKeySelfRevoke     Operation = "api_key.self.revoke"
	OperationAPIKeyAdminCreate    Operation = "api_key.admin.create_pending"
	OperationAPIKeyAdminRevoke    Operation = "api_key.admin.revoke"
	OperationCustomRoleCreate     Operation = "identity.custom_role.create"
	OperationCustomRoleRename     Operation = "identity.custom_role.rename"
	OperationCustomRolePublish    Operation = "identity.custom_role.publish"
	OperationCustomRoleDeactivate Operation = "identity.custom_role.deactivate"
	OperationCustomRoleAssign     Operation = "identity.custom_role.assign"
	OperationCustomRoleRevoke     Operation = "identity.custom_role.revoke"
)

var (
	ErrInvalidInput     = errors.New("IAM lock input invalid")
	ErrProtocolRequired = errors.New("IAM global lock protocol required")
	ErrLockOrder        = errors.New("IAM lock order invalid")
	ErrUpgradeForbidden = errors.New("IAM shared to exclusive upgrade forbidden")
	ErrPermissionDenied = errors.New("IAM authorization permission denied")
	ErrUnavailable      = errors.New("IAM authorization unavailable")
)

func AcquireShared(ctx context.Context, tx pgx.Tx) error {
	if tx == nil {
		return ErrInvalidInput
	}
	_, err := tx.Exec(ctx, `SELECT iam_global_lock_shared_v1()`)
	return mapError(err)
}

func AcquireExclusive(ctx context.Context, tx pgx.Tx) error {
	if tx == nil {
		return ErrInvalidInput
	}
	_, err := tx.Exec(ctx, `SELECT iam_global_lock_exclusive_v1()`)
	return mapError(err)
}

func AcquireScopes(ctx context.Context, tx pgx.Tx, scopes []uuid.UUID) ([]uuid.UUID, error) {
	return acquireScopes(ctx, tx, `SELECT iam_scope_locks_v1($1::uuid[])`, nil, scopes)
}

func BeginAuthorityMutation(
	ctx context.Context,
	tx pgx.Tx,
	operation Operation,
	scopes []uuid.UUID,
) ([]uuid.UUID, error) {
	if !validOperation(operation) {
		return nil, ErrInvalidInput
	}
	return acquireScopes(ctx, tx,
		`SELECT iam_begin_authority_mutation_v1($1::text,$2::uuid[])`, operation, scopes)
}

func acquireScopes(
	ctx context.Context,
	tx pgx.Tx,
	query string,
	operation any,
	scopes []uuid.UUID,
) ([]uuid.UUID, error) {
	if tx == nil {
		return nil, ErrInvalidInput
	}
	canonical, err := canonicalScopes(scopes)
	if err != nil {
		return nil, err
	}
	var locked []uuid.UUID
	if operation == nil {
		err = tx.QueryRow(ctx, query, canonical).Scan(&locked)
	} else {
		err = tx.QueryRow(ctx, query, operation, canonical).Scan(&locked)
	}
	if err != nil {
		return nil, mapError(err)
	}
	if len(locked) != len(canonical) {
		return nil, ErrProtocolRequired
	}
	for index := range locked {
		if locked[index] != canonical[index] {
			return nil, ErrProtocolRequired
		}
	}
	return locked, nil
}

func canonicalScopes(scopes []uuid.UUID) ([]uuid.UUID, error) {
	if len(scopes) < 1 || len(scopes) > maxScopes {
		return nil, ErrInvalidInput
	}
	result := append([]uuid.UUID(nil), scopes...)
	for _, scopeID := range result {
		if scopeID == uuid.Nil {
			return nil, ErrInvalidInput
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i][:], result[j][:]) < 0
	})
	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] == result[write-1] {
			continue
		}
		result[write] = result[read]
		write++
	}
	return result[:write], nil
}

func validOperation(operation Operation) bool {
	switch operation {
	case OperationSessionCreate, OperationSessionRotate, OperationSessionRevoke,
		OperationBootstrap, OperationUserCreate, OperationUserUpdate, OperationSelfUpdate,
		OperationPasswordChange, OperationMembershipSuspend, OperationAPIKeySelfCreate, OperationAPIKeySelfUpdate,
		OperationAPIKeySelfActivate, OperationAPIKeySelfRotate, OperationAPIKeySelfRevoke,
		OperationAPIKeyAdminCreate, OperationAPIKeyAdminRevoke, OperationCustomRoleCreate,
		OperationCustomRoleRename, OperationCustomRolePublish, OperationCustomRoleDeactivate,
		OperationCustomRoleAssign, OperationCustomRoleRevoke:
		return true
	default:
		return false
	}
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "P6900", "P7000":
			return ErrInvalidInput
		case "P6901":
			return ErrProtocolRequired
		case "P6902":
			return ErrLockOrder
		case "P6903":
			return ErrUpgradeForbidden
		}
	}
	return unavailableError{cause: err}
}

// unavailableError keeps the public text stable (no SQL detail) while letting
// a caller's log read the SQLSTATE through SQLState (notif-sub: a lock wait
// timeout in the helper used to surface as an unexplained 500).
type unavailableError struct{ cause error }

func (unavailableError) Error() string        { return ErrUnavailable.Error() + ": execute IAM lock helper" }
func (unavailableError) Is(target error) bool { return target == ErrUnavailable }

// SQLState is the PostgreSQL error code of the failed helper call, or "".
func (e unavailableError) SQLState() string {
	var pgErr *pgconn.PgError
	if errors.As(e.cause, &pgErr) {
		return pgErr.Code
	}
	return ""
}
