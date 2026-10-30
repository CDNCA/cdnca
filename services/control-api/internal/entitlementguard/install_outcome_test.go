package entitlementguard

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// notSentError is how pgconn marks a failure before any byte reached the
// server (pgconn.SafeToRetry).
type notSentError struct{}

func (notSentError) Error() string     { return "connection busy" }
func (notSentError) SafeToRetry() bool { return true }

// LIC-REC-03: only a COMMIT that may have reached PostgreSQL leaves the
// install outcome unknown; a COMMIT known to have rolled back, or one that was
// never sent, means the lease was not installed.
func TestCommitFailureOutcome(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		unknown bool
	}{
		{"acknowledgement lost after commit", io.ErrUnexpectedEOF, true},
		{"deadline while committing", context.DeadlineExceeded, true},
		{"server answered ROLLBACK", pgx.ErrTxCommitRollback, false},
		{"commit never sent", notSentError{}, false},
		{"server refused commit", &pgconn.PgError{Code: "40001"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := commitFailure(test.err)
			if got := errors.Is(err, ErrInstallOutcomeUnknown); got != test.unknown {
				t.Fatalf("commitFailure(%v) unknown = %v, want %v (err %v)", test.err, got, test.unknown, err)
			}
			if !errors.Is(err, test.err) {
				t.Fatalf("commitFailure(%v) lost the cause: %v", test.err, err)
			}
		})
	}
}
