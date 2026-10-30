package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// N2: on 73 the log said only error="security activation worker stopped".
// The shutdown path joins runErr with close errors (errors.Join(runErr, nil)
// still wraps), so errors.Unwrap found no cause. The cause must be logged
// through the join; Error() itself stays the redacted stage.
func TestCommandFailureAttrsLogsCauseThroughJoin(t *testing.T) {
	cause := errors.New("reconcile security activation 5f7e619f: edge deployment idempotency conflict")
	stage := runtimeStageError{stage: "security activation worker stopped", err: cause}
	for name, err := range map[string]error{
		"plain":                   stage,
		"joined":                  errors.Join(stage, nil),
		"joined with close error": errors.Join(stage, errors.New("close failed")),
	} {
		attrs := commandFailureAttrs(err)
		if len(attrs) != 4 || attrs[2] != "cause" || attrs[3] != cause {
			t.Errorf("%s: attrs = %v, want the inner cause logged", name, attrs)
		}
		if !errors.Is(err, cause) {
			t.Errorf("%s: errors.Is does not reach the cause", name)
		}
		var target runtimeStageError
		if !errors.As(err, &target) || target.stage != stage.stage {
			t.Errorf("%s: errors.As does not reach the runtime stage", name)
		}
	}
	if got := stage.Error(); got != "security activation worker stopped" {
		t.Fatalf("Error() = %q, want the redacted stage only", got)
	}
	plain := errors.New("listener closed")
	if attrs := commandFailureAttrs(plain); len(attrs) != 2 {
		t.Fatalf("attrs for an error without cause = %v", attrs)
	}
}

// Row contention is retried by runWithDBBackoff, not reported as terminal.
func TestIsTransientDBErrorTreatsRowContentionAsTransient(t *testing.T) {
	for _, code := range []string{"55P03", "40001", "40P01"} {
		err := fmt.Errorf("reconcile security activation: %w", &pgconn.PgError{Code: code})
		if !isTransientDBError(err) {
			t.Errorf("SQLSTATE %s is not transient", code)
		}
	}
	if isTransientDBError(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("unique violation must stay terminal")
	}
}
