package iamstage2b

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestValidOperationUsesFrozenStage2BSet(t *testing.T) {
	want := []Operation{
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
	if len(AllOperations()) != len(want) {
		t.Fatalf("operations = %v, want %v", AllOperations(), want)
	}
	for index, operation := range want {
		if AllOperations()[index] != operation || !validOperation(operation) {
			t.Fatalf("operation[%d] = %q, want %q", index, AllOperations()[index], operation)
		}
	}
	for _, operation := range []Operation{"", "identity.session.revoke", "identity.stage2b.unknown"} {
		if validOperation(operation) {
			t.Fatalf("operation %q accepted", operation)
		}
	}
	operations := AllOperations()
	operations[0] = "tampered"
	if AllOperations()[0] != OperationAccountRecoveryRequest {
		t.Fatal("AllOperations returned mutable backing storage")
	}
}

func TestCanonicalScopesRejectsInvalidAndNormalizes(t *testing.T) {
	first := uuid.MustParse("2e3b59e0-cc21-4548-73fd-ec3b8f1c0744")
	second := uuid.MustParse("e67ca162-05d5-3aad-1b66-0bec1ae748d7")
	got, err := canonicalScopes([]uuid.UUID{second, first, first})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("canonical scopes = %v, want [%s %s]", got, first, second)
	}
	for _, scopes := range [][]uuid.UUID{nil, {}, {uuid.Nil}, make([]uuid.UUID, maxScopes+1)} {
		if _, err := canonicalScopes(scopes); !errors.Is(err, protocol.ErrInvalidInput) {
			t.Fatalf("canonicalScopes(%v) error = %v, want invalid input", scopes, err)
		}
	}
}

func TestMapErrorReturnsStableProtocolErrors(t *testing.T) {
	tests := []struct {
		code string
		want error
	}{
		{code: "P6900", want: protocol.ErrInvalidInput},
		{code: "P7100", want: protocol.ErrInvalidInput},
		{code: "P6901", want: protocol.ErrProtocolRequired},
		{code: "P6902", want: protocol.ErrLockOrder},
		{code: "P7101", want: protocol.ErrLockOrder},
		{code: "P6903", want: protocol.ErrUpgradeForbidden},
		{code: "40001", want: protocol.ErrUnavailable},
		{code: "40P01", want: protocol.ErrUnavailable},
		{code: "55P03", want: protocol.ErrUnavailable},
		{code: "23505", want: protocol.ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			err := mapError(&pgconn.PgError{Code: test.code, Message: "reviewer database detail"})
			if !errors.Is(err, test.want) {
				t.Fatalf("mapError(%s) = %v, want %v", test.code, err, test.want)
			}
			for _, leaked := range []string{"reviewer", "database detail", "SQLSTATE", test.code} {
				if strings.Contains(err.Error(), leaked) {
					t.Fatalf("public error leaked %q: %v", leaked, err)
				}
			}
		})
	}
}

func TestNilTransactionFailsClosed(t *testing.T) {
	scopeID := uuid.New()
	if _, err := BeginAuthorityMutation(t.Context(), nil, OperationMFAReset, []uuid.UUID{scopeID}); !errors.Is(err, protocol.ErrInvalidInput) {
		t.Fatalf("BeginAuthorityMutation nil tx error = %v", err)
	}
	if err := AssertAuthorityMutation(t.Context(), nil, OperationMFAConsumeStepUp, []uuid.UUID{scopeID}); !errors.Is(err, protocol.ErrInvalidInput) {
		t.Fatalf("AssertAuthorityMutation nil tx error = %v", err)
	}
}
