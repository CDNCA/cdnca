package iamstage2b

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const maxScopes = 64

type Operation string

const (
	OperationAccountRecoveryRequest Operation = "identity.account_recovery.request"
	OperationAccountRecoveryReset   Operation = "identity.account_recovery.reset"
	OperationMFABeginEnrollment     Operation = "mfa.enrollment.begin"
	OperationMFAActivateEnrollment  Operation = "mfa.enrollment.activate"
	OperationMFAIssueStepUp         Operation = "mfa.step_up.issue"
	OperationMFAConsumeStepUp       Operation = "mfa.step_up.consume"
	OperationMFADisable             Operation = "mfa.disable"
	OperationMFAReset               Operation = "mfa.reset"
	OperationImpersonationCreate    Operation = "identity.impersonation.create"
	OperationImpersonationExchange  Operation = "identity.impersonation.exchange"
	OperationImpersonationRevoke    Operation = "identity.impersonation.revoke"
)

var operations = [...]Operation{
	OperationAccountRecoveryRequest,
	OperationAccountRecoveryReset,
	OperationMFABeginEnrollment,
	OperationMFAActivateEnrollment,
	OperationMFAIssueStepUp,
	OperationMFAConsumeStepUp,
	OperationMFADisable,
	OperationMFAReset,
	OperationImpersonationCreate,
	OperationImpersonationExchange,
	OperationImpersonationRevoke,
}

func AllOperations() []Operation {
	return append([]Operation(nil), operations[:]...)
}

func BeginAuthorityMutation(
	ctx context.Context,
	tx pgx.Tx,
	operation Operation,
	scopes []uuid.UUID,
) ([]uuid.UUID, error) {
	if tx == nil || !validOperation(operation) {
		return nil, protocol.ErrInvalidInput
	}
	canonical, err := canonicalScopes(scopes)
	if err != nil {
		return nil, err
	}
	var locked []uuid.UUID
	err = tx.QueryRow(ctx, `SELECT iam_begin_stage2b_authority_mutation_v1($1::text,$2::uuid[])`,
		operation, canonical).Scan(&locked)
	if err != nil {
		return nil, mapError(err)
	}
	if !equalScopes(locked, canonical) {
		return nil, protocol.ErrProtocolRequired
	}
	return locked, nil
}

func AssertAuthorityMutation(
	ctx context.Context,
	tx pgx.Tx,
	operation Operation,
	scopes []uuid.UUID,
) error {
	if tx == nil || !validOperation(operation) {
		return protocol.ErrInvalidInput
	}
	canonical, err := canonicalScopes(scopes)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `SELECT iam_assert_stage2b_authority_mutation_v1($1::text,$2::uuid[])`,
		operation, canonical)
	return mapError(err)
}

func validOperation(operation Operation) bool {
	switch operation {
	case OperationAccountRecoveryRequest, OperationAccountRecoveryReset,
		OperationMFABeginEnrollment, OperationMFAActivateEnrollment,
		OperationMFAIssueStepUp, OperationMFAConsumeStepUp,
		OperationMFADisable, OperationMFAReset,
		OperationImpersonationCreate, OperationImpersonationExchange,
		OperationImpersonationRevoke:
		return true
	default:
		return false
	}
}

func canonicalScopes(scopes []uuid.UUID) ([]uuid.UUID, error) {
	if len(scopes) < 1 || len(scopes) > maxScopes {
		return nil, protocol.ErrInvalidInput
	}
	result := append([]uuid.UUID(nil), scopes...)
	for _, scopeID := range result {
		if scopeID == uuid.Nil {
			return nil, protocol.ErrInvalidInput
		}
	}
	sort.Slice(result, func(left, right int) bool {
		return bytes.Compare(result[left][:], result[right][:]) < 0
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

func equalScopes(left, right []uuid.UUID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "P6900", "P7100":
			return protocol.ErrInvalidInput
		case "P6901":
			return protocol.ErrProtocolRequired
		case "P6902", "P7101":
			return protocol.ErrLockOrder
		case "P6903":
			return protocol.ErrUpgradeForbidden
		}
	}
	return fmt.Errorf("%w: execute IAM Stage2B lock helper", protocol.ErrUnavailable)
}
