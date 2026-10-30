package protocol

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestMapErrorReturnsStableTypedErrors(t *testing.T) {
	tests := []struct {
		code string
		want error
	}{
		{code: "P6900", want: ErrInvalidInput},
		{code: "P7000", want: ErrInvalidInput},
		{code: "P6901", want: ErrProtocolRequired},
		{code: "P6902", want: ErrLockOrder},
		{code: "P6903", want: ErrUpgradeForbidden},
		{code: "40001", want: ErrUnavailable},
		{code: "40P01", want: ErrUnavailable},
		{code: "55P03", want: ErrUnavailable},
		{code: "23505", want: ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			err := mapError(&pgconn.PgError{Code: test.code, Message: "reviewer database detail"})
			if !errors.Is(err, test.want) {
				t.Fatalf("mapError(%s) = %v, want %v", test.code, err, test.want)
			}
			assertStableProtocolError(t, err)
		})
	}

	err := mapError(errors.New("reviewer SQLSTATE 40001 database detail"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("mapError(non-PG) = %v, want unavailable", err)
	}
	assertStableProtocolError(t, err)
}

func TestValidOperationIncludesMembershipSuspensionOnly(t *testing.T) {
	if !validOperation(OperationMembershipSuspend) {
		t.Fatal("identity.membership.suspend was rejected")
	}
	if validOperation(Operation("identity.membership.revoke")) {
		t.Fatal("unimplemented permanent membership revocation was accepted")
	}
	if validOperation(Operation("identity.membership.suspend.extra")) {
		t.Fatal("unknown membership operation was accepted")
	}
}

func assertStableProtocolError(t *testing.T, err error) {
	t.Helper()
	for _, leaked := range []string{"reviewer", "database detail", "SQLSTATE", "40001", "40P01", "55P03"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("public protocol error leaked %q: %v", leaked, err)
		}
	}
}

// notif-sub：对外文本仍不带 SQL 细节，但调用方日志能取到 SQLSTATE。
func TestUnavailableErrorExposesSQLStateOnly(t *testing.T) {
	err := mapError(&pgconn.PgError{Code: "55P03", Message: "reviewer database detail"})
	var state interface{ SQLState() string }
	if !errors.As(err, &state) || state.SQLState() != "55P03" {
		t.Fatalf("SQLState of %v not exposed", err)
	}
	assertStableProtocolError(t, err)
	if !errors.As(mapError(errors.New("plain")), &state) || state.SQLState() != "" {
		t.Fatal("non-PG error should expose empty SQLState")
	}
}
